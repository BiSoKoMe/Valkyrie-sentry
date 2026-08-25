"""Evidence-constructed remediation planning.

WHY THIS EXISTS
---------------
Valkyrie already had two ways to respond, and both were *selection* rather than
*construction*:

  * ``decision.decide()`` picks one action off a five-rung ladder for one
    signal, and
  * ``playbooks.py`` matches an incident against analyst-authored YAML and
    fires that playbook's fixed action list.

Both answer "which of my prepared responses is closest to this?" Neither
answers "what did this intrusion actually *do*, and what is the minimum set of
actions that undoes it?" A playbook that says ``kill_process`` kills the one
process that happened to alert - not the three siblings the same document
spawned, not the run key it wrote, not the domain it was beaconing to. The
attack is a graph; the response was a row.

CrowdStrike states the principle for their agentic layer better than we could:
*response logic should be constructed from evidence, not selected from
templates.* Valkyrie already has the evidence - ``causality.py`` attributes
every DNS query, network connection, file write and registry change to the
process that caused it, and ``subgraph()`` hands back the whole causality tree
under the Causality Group Owner. This module is the missing consumer: it walks
that subgraph and *derives* a remediation plan from what was observed.

WHAT MAKES A PLAN, NOT A LIST
-----------------------------
Three properties, none of which a template can have:

**1. Every action cites the observation that produced it.** A ``block_domain``
in this plan exists because a specific DNS artifact was attributed to a
specific process in the tree. Remove the observation and the action does not
appear. That is what makes the plan auditable rather than merely logged - an
operator can ask "why are you about to block this?" and get an answer that is
not "because a rule said so".

**2. Every action is authorised independently, on its own responder and its own
target.** The four-gate model in ``authority.py`` is per-action for a reason:
an invariant may veto blocking ``login.microsoftonline.com`` while permitting
the block of a DGA domain observed in the same tree, and ``kill_process`` is
irreversible where ``block_domain`` is leasable. Authorising the plan as a unit
would let the safest action's authority carry the most dangerous one - exactly
the failure the floor-not-a-score design exists to prevent. So each candidate
goes through ``authorize()`` separately with ``responder=`` set, and a plan
routinely comes back part-enforcing and part-alert-only.

**3. A hole in the graph caps what the plan may do.** ``subgraph()`` reports
its own honesty flags - ``truncated`` (the descendant walk hit its bound),
``inferred_nodes`` (ancestry was filled in, not observed) and ``evicted``
(nodes were dropped for memory before this query ran). Any of those means the
picture is incomplete, and **an incomplete picture may not authorise an
irreversible action**. You cannot know that killing this process tree is
correct when you cannot see all of it. This is the coverage gate's logic
applied to the graph itself rather than to the sensors feeding it, and it is
the single most important safety property in this module.

ORDERING IS OPERATIONAL, NOT COSMETIC
-------------------------------------
Actions are ordered: close escape routes, then close return routes, then
terminate, then contain.

  1. ``block_domain``       - cut C2 first, so everything that follows happens
                              to a process that can no longer phone home. Also
                              the cheapest and fully reversible.
  2. ``remove_persistence`` - close the return route BEFORE killing, so the
                              termination is not undone by a scheduled task or
                              run key firing minutes later.
  3. ``kill_process``       - irreversible, so it happens once the escape and
                              return routes are already shut.
  4. ``isolate_host``       - broadest blast radius, last, and only when the
                              decision itself reached CONTAIN.

This module is PURE. It plans; it executes nothing. It takes a subgraph dict, a
Signal, a Decision and the same injected gate callables ``authority.authorize``
takes, and returns a ``Plan``. No responder is invoked, no global state is
read, and it can therefore be tested exhaustively offline - which matters,
because this is the component that decides what Valkyrie is allowed to break.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from ..decision import Action, Decision, Signal
from . import reversibility
from .authority import Authority, authorize

# Responder verbs this planner can emit. Anything derived from evidence that
# does not map onto one of these is recorded as unactionable rather than
# silently dropped - see `Plan.unactionable`.
BLOCK_DOMAIN = "block_domain"
REMOVE_PERSISTENCE = "remove_persistence"
KILL_PROCESS = "kill_process"
ISOLATE_HOST = "isolate_host"

# Execution order. See the module docstring: escape routes, return routes,
# terminate, contain.
_ORDER = {BLOCK_DOMAIN: 0, REMOVE_PERSISTENCE: 1, KILL_PROCESS: 2,
          ISOLATE_HOST: 3}

# Artifact kinds that carry a network destination worth blocking.
_NET_KINDS = ("dns", "network", "connection")

# Artifact kinds that may describe an autostart entry.
_PERSIST_KINDS = ("registry", "persistence", "autostart", "service", "task")

# The persistence types `responder.remove_persistence` actually understands.
# A target it cannot parse is worse than no target, so anything outside this
# set becomes unactionable evidence instead of a malformed action.
_ASEP_TYPES = ("scheduled_task", "service_install", "registry_run_key",
               "startup_folder")

# Never plan a kill for these - pid 0/4 are kernel, and the responder refuses
# them anyway; planning them just puts noise in front of an operator.
_UNKILLABLE_PIDS = {0, 4}


@dataclass(frozen=True)
class Evidence:
    """One observation that justifies one planned action.

    ``detail`` is written to be read by a human in an incident timeline, not
    parsed. ``pid``/``process`` name the node it was attributed to so the
    operator can find it in the process tree.
    """
    kind:    str
    detail:  str
    process: str = ""
    pid:     int = 0
    ts:      float = 0.0

    def to_dict(self) -> dict:
        return {"kind": self.kind, "detail": self.detail,
                "process": self.process, "pid": self.pid, "ts": self.ts}


@dataclass(frozen=True)
class PlannedAction:
    """One remediation step, with the evidence that produced it and the
    authority that was granted for it."""
    responder: str
    target:    str
    evidence:  tuple = ()
    authority: Optional[Authority] = None
    reversible: bool = True

    @property
    def enforced(self) -> bool:
        """True when this step is actually permitted to change host state."""
        return self.authority is not None and self.authority.enforces

    def to_dict(self) -> dict:
        return {
            "responder": self.responder,
            "target": self.target,
            "enforced": self.enforced,
            "reversible": self.reversible,
            "evidence": [e.to_dict() for e in self.evidence],
            "authority": self.authority.to_dict() if self.authority else None,
        }


@dataclass(frozen=True)
class Plan:
    """A constructed remediation plan for one causality tree."""
    actions:     tuple = ()
    unactionable: tuple = ()      # tuple[Evidence] - observed, no responder
    blind_spots: tuple = ()       # tuple[str] - why the graph is incomplete
    cgo:         str = ""         # name of the Causality Group Owner
    cgo_pid:     int = 0
    scope_nodes: int = 0          # processes considered
    found:       bool = False     # the subgraph resolved at all

    @property
    def complete(self) -> bool:
        """True when the graph this plan was built from had no holes."""
        return not self.blind_spots

    @property
    def enforcing(self) -> tuple:
        return tuple(a for a in self.actions if a.enforced)

    def to_dict(self) -> dict:
        return {
            "found": self.found,
            "complete": self.complete,
            "blind_spots": list(self.blind_spots),
            "cgo": self.cgo, "cgo_pid": self.cgo_pid,
            "scope_nodes": self.scope_nodes,
            "actions": [a.to_dict() for a in self.actions],
            "enforcing_count": len(self.enforcing),
            "unactionable": [e.to_dict() for e in self.unactionable],
        }


# ---------------------------------------------------------------------------
# Evidence -> candidate derivation
# ---------------------------------------------------------------------------

def _looks_like_domain(value: str) -> bool:
    """Conservative: a blockable domain has a dot, no whitespace, no scheme.

    Deliberately strict. A malformed target handed to `block_domain` either
    fails loudly or - worse - blocks something unintended, so anything
    ambiguous is routed to `unactionable` where an operator can see it instead
    of being guessed at.
    """
    v = (value or "").strip().lower()
    if not v or " " in v or "/" in v or ":" in v:
        return False
    if "." not in v or v.startswith(".") or v.endswith("."):
        return False
    # A bare IPv4 is not a domain; there is no block_ip responder, so an IP
    # observation is honest evidence with no available action.
    if all(part.isdigit() for part in v.split(".")):
        return False
    return True


def _domain_from(art: dict) -> str:
    """Pull a blockable domain out of an artifact, preferring structured data."""
    data = art.get("data") or {}
    for key in ("domain", "qname", "host", "hostname", "entity"):
        cand = str(data.get(key) or "").strip()
        if _looks_like_domain(cand):
            return cand.lower()
    summary = str(art.get("summary") or "").strip()
    return summary.lower() if _looks_like_domain(summary) else ""


def _persistence_target(art: dict) -> str:
    """Build a `<type>::<identity>` target, or "" if the artifact cannot
    supply both halves.

    We never synthesise an identity. `responder.remove_persistence` deletes
    autostart entries; handing it a guessed identity is how you delete the
    wrong one.
    """
    data = art.get("data") or {}
    asep = str(data.get("asep_type") or data.get("type") or "").strip().lower()
    identity = str(data.get("identity") or data.get("name") or
                   data.get("value") or "").strip()
    if asep in _ASEP_TYPES and identity:
        return f"{asep}::{identity}"
    return ""


def _evidence_from_artifact(art: dict) -> Evidence:
    return Evidence(
        kind=str(art.get("kind") or "artifact"),
        detail=str(art.get("summary") or ""),
        process=str(art.get("process") or ""),
        pid=int(art.get("pid") or 0),
        ts=float(art.get("ts") or 0.0),
    )


def _blind_spots(sub: dict) -> tuple:
    """Everything about this graph that makes the plan an incomplete story."""
    spots: list[str] = []
    if sub.get("truncated"):
        spots.append("descendant walk hit its node bound - the process tree "
                     "continues beyond what was planned against")
    inferred = int(sub.get("inferred_nodes") or 0)
    if inferred:
        spots.append(f"{inferred} node(s) in scope were inferred, not observed "
                     f"- ancestry here is reconstructed, not witnessed")
    evicted = int(sub.get("evicted") or 0)
    if evicted:
        spots.append(f"{evicted} node(s) were evicted for memory before this "
                     f"query - earlier branches of this tree are gone")
    return tuple(spots)


# ---------------------------------------------------------------------------
# The planner
# ---------------------------------------------------------------------------

def plan(sub: dict, sig: Signal, decision: Decision, *,
         sensor_state: Optional[Callable[[str], str]] = None,
         budget_permits: Optional[Callable[[], tuple]] = None,
         observed_interval_s: Optional[float] = None,
         max_actions: int = 64) -> Plan:
    """Construct a remediation plan from a causality subgraph.

    ``sub``       the dict returned by ``CausalityGraph.subgraph()``.
    ``sig``       the signal that opened the incident.
    ``decision``  what ``decision.decide()`` concluded for that signal.

    The gate callables are passed straight through to ``authority.authorize``
    for every candidate, so this planner adds no authority of its own - it can
    only ever produce actions the existing four gates already permit.
    """
    if not sub or not sub.get("found"):
        return Plan(found=False)

    spots = _blind_spots(sub)
    incomplete = bool(spots)

    cgo = sub.get("cgo") or {}
    tree = list(sub.get("tree") or [])
    members = ([cgo] if cgo else []) + tree

    candidates: list[tuple] = []          # (responder, target, [Evidence])
    unactionable: list[Evidence] = []
    seen: set = set()

    # --- from artifacts: network destinations and autostart entries --------
    for art in (sub.get("artifacts") or []):
        kind = str(art.get("kind") or "").lower()
        ev = _evidence_from_artifact(art)

        if kind in _NET_KINDS:
            domain = _domain_from(art)
            if domain:
                key = (BLOCK_DOMAIN, domain)
                if key not in seen:
                    seen.add(key)
                    candidates.append((BLOCK_DOMAIN, domain, [ev]))
            else:
                unactionable.append(ev)
            continue

        if kind in _PERSIST_KINDS:
            target = _persistence_target(art)
            if target:
                key = (REMOVE_PERSISTENCE, target)
                if key not in seen:
                    seen.add(key)
                    candidates.append((REMOVE_PERSISTENCE, target, [ev]))
            else:
                unactionable.append(ev)
            continue

        # Everything else (file writes, detections) is real evidence with no
        # responder behind it. Surfacing it is the point: an operator should
        # see what was observed and NOT acted on.
        unactionable.append(ev)

    # --- from process nodes: the tree itself -------------------------------
    for node in members:
        pid = int(node.get("pid") or 0)
        name = str(node.get("name") or "")
        if pid in _UNKILLABLE_PIDS or not pid:
            continue
        if node.get("terminator"):
            # OS infrastructure that launches unrelated work. Killing it is
            # never the remediation for what one of its children did.
            continue
        if node.get("inferred"):
            # We never observed this process; we only deduced it had to exist
            # to explain a ppid. Acting on a deduction is exactly the class of
            # mistake `inferred` was added to prevent.
            unactionable.append(Evidence(
                kind="process", process=name, pid=pid,
                detail=f"inferred ancestor {name!r} (pid {pid}) - not observed, "
                       f"so not acted on"))
            continue
        key = (KILL_PROCESS, str(pid))
        if key in seen:
            continue
        seen.add(key)
        candidates.append((KILL_PROCESS, str(pid), [Evidence(
            kind="process", process=name, pid=pid,
            detail=f"{name!r} (pid {pid}) is in the causality tree under "
                   f"{cgo.get('name') or 'the group owner'!r}",
            ts=float(node.get("first_seen") or 0.0))]))

    # --- host containment, only if the decision itself reached CONTAIN -----
    # Never escalated to by this module: isolating the host is a decision about
    # the host, not something a count of tree nodes should be able to reach.
    if decision.action == Action.CONTAIN:
        candidates.append((ISOLATE_HOST, "host", [Evidence(
            kind="decision",
            detail=f"policy reached CONTAIN for {sig.category or 'this signal'}")]))

    # --- order, bound, authorise ------------------------------------------
    candidates.sort(key=lambda c: (_ORDER.get(c[0], 99), c[1]))
    if len(candidates) > max_actions:
        spots = spots + (f"plan truncated at {max_actions} actions of "
                         f"{len(candidates)} derived",)
        incomplete = True
        candidates = candidates[:max_actions]

    actions: list[PlannedAction] = []
    for responder, target, evidence in candidates:
        rev = reversibility.get(responder)
        is_rev = bool(rev.reversible) if rev is not None else False

        auth = authorize(sig, decision,
                         target=target,
                         responder=responder,
                         sensor_state=sensor_state,
                         budget_permits=budget_permits,
                         observed_interval_s=observed_interval_s)

        # The graph-hole rule. An irreversible action needs a whole picture;
        # a partial one may still justify the reversible steps, which is why
        # this caps rather than abandoning the plan.
        if incomplete and not is_rev and auth.enforces:
            auth = Authority(
                action=Action.ALERT,
                requested=auth.requested,
                lease_ttl_s=None,
                vetoed=auth.vetoed,
                limited_by=tuple(auth.limited_by) + ("graph_incomplete",),
                reasons=tuple(auth.reasons) + (
                    f"{responder!r} is irreversible and the causality graph is "
                    f"incomplete ({spots[0] if spots else 'unknown gap'}); an "
                    f"unseen branch may make this the wrong process to end",),
            )

        actions.append(PlannedAction(responder=responder, target=target,
                                     evidence=tuple(evidence),
                                     authority=auth, reversible=is_rev))

    return Plan(
        actions=tuple(actions),
        unactionable=tuple(unactionable),
        blind_spots=tuple(spots),
        cgo=str(cgo.get("name") or ""),
        cgo_pid=int(cgo.get("pid") or 0),
        scope_nodes=len(members),
        found=True,
    )
