#!/usr/bin/env python3
"""Evidence-constructed remediation planning (valkyrie/edr/remediation.py).

The properties under test are the three that separate a constructed plan from
a selected template:

  1. every action traces back to an observation, and an observation with no
     responder behind it is SURFACED rather than dropped;
  2. each action is authorised on its own responder and target, so one plan
     can be part-enforcing and part-alert-only; and
  3. a hole in the causality graph caps irreversible action - you may not end
     a process tree you cannot fully see.

Pure module, so this runs offline and touches nothing on the host.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402


def _subgraph(*, artifacts=None, tree=None, truncated=False,
              inferred_nodes=0, evicted=0, cgo=None) -> dict:
    """A subgraph() payload shaped exactly like causality.subgraph() returns."""
    owner = cgo or {"key": "100/1.000", "pid": 100, "name": "winword.exe",
                    "path": r"c:\program files\office\winword.exe",
                    "inferred": False, "terminator": False, "first_seen": 1.0}
    return {
        "found": True,
        "cgo": owner,
        "chain": [owner],
        "target": owner,
        "tree": list(tree or []),
        "artifacts": list(artifacts or []),
        "depth": 1,
        "inferred_nodes": inferred_nodes,
        "truncated": truncated,
        "evicted": evicted,
    }


def _node(pid, name, *, inferred=False, terminator=False):
    return {"key": f"{pid}/1.000", "pid": pid, "name": name, "path": "",
            "inferred": inferred, "terminator": terminator, "first_seen": 2.0}


def _art(kind, summary, *, pid=100, process="winword.exe", data=None):
    return {"kind": kind, "summary": summary, "pid": pid, "process": process,
            "ts": 3.0, "data": dict(data or {})}


def main() -> int:
    c = Checks("evidence-constructed remediation planning", expect_min=24)

    # Importing the responder module is what populates the reversibility
    # registry - the engine does this in production, so the test must too or
    # every action would look irreversible.
    from valkyrie.edr import response as _response   # noqa: F401
    from valkyrie.edr import remediation as R, sensor_deps as SD
    from valkyrie.decision import Action, Signal, decide

    live = lambda s: SD.STATE_EFFECTIVE            # noqa: E731

    sig = Signal(category="attack_sequence", source="attack_sequence",
                 severity="critical", process_name="powershell.exe",
                 entity="evil.example", distinct_tactics=3)
    base = decide(sig)

    # ------------------------------------------------------------------ [1]
    print("\n[1] a subgraph that did not resolve produces no plan at all")
    p = R.plan({"found": False}, sig, base, sensor_state=live)
    c.check("found is False", not p.found)
    c.check("no actions invented from nothing", p.actions == ())

    # ------------------------------------------------------------------ [2]
    print("\n[2] actions are DERIVED from observations, not from a template")
    sub = _subgraph(
        tree=[_node(200, "powershell.exe"), _node(201, "curl.exe")],
        artifacts=[
            _art("dns", "beacon lookup", data={"domain": "c2.evil.example"}),
            _art("registry", "run key written",
                 data={"asep_type": "registry_run_key", "identity": r"HKCU\...\Run\evil"}),
        ])
    p = R.plan(sub, sig, base, sensor_state=live)
    verbs = [a.responder for a in p.actions]
    targets = {a.target for a in p.actions}
    c.check("the observed domain became a block", "c2.evil.example" in targets)
    c.check("the observed run key became a de-persist",
            "registry_run_key::HKCU\\...\\Run\\evil" in targets)
    c.check("every observed process in the tree became a kill",
            {"100", "200", "201"}.issubset(targets))
    c.check("no action appears without evidence",
            all(a.evidence for a in p.actions))
    c.check("the CGO is named on the plan", p.cgo == "winword.exe")

    # ------------------------------------------------------------------ [3]
    print("\n[3] ordering: escape routes, then return routes, then terminate")
    order = [R._ORDER[v] for v in verbs]
    c.check("actions are ordered by remediation stage", order == sorted(order))
    c.check("block_domain precedes kill_process",
            verbs.index(R.BLOCK_DOMAIN) < verbs.index(R.KILL_PROCESS))
    c.check("remove_persistence precedes kill_process",
            verbs.index(R.REMOVE_PERSISTENCE) < verbs.index(R.KILL_PROCESS))

    # ------------------------------------------------------------------ [4]
    print("\n[4] evidence with no responder behind it is SURFACED, not dropped")
    sub = _subgraph(artifacts=[
        _art("dns", "lookup", data={"domain": "203.0.113.9"}),   # bare IP
        _art("file", r"wrote c:\users\x\appdata\evil.dll"),      # no responder
        _art("registry", "opened a key", data={"type": "unknown_kind"}),
    ])
    p = R.plan(sub, sig, base, sensor_state=live)
    kinds = [e.kind for e in p.unactionable]
    c.check("a bare IP is not turned into a malformed domain block",
            not any(a.responder == R.BLOCK_DOMAIN for a in p.actions))
    c.check("the IP observation is still reported", "dns" in kinds)
    c.check("the file write is reported as unactionable", "file" in kinds)
    c.check("an unparseable persistence type is not guessed at",
            not any(a.responder == R.REMOVE_PERSISTENCE for a in p.actions))
    c.check("that persistence observation is still reported",
            "registry" in kinds)

    # ------------------------------------------------------------------ [5]
    print("\n[5] terminators and inferred nodes are never killed")
    sub = _subgraph(tree=[
        _node(300, "svchost.exe", terminator=True),
        _node(301, "ghost.exe", inferred=True),
        _node(302, "real.exe"),
    ])
    p = R.plan(sub, sig, base, sensor_state=live)
    killed = {a.target for a in p.actions if a.responder == R.KILL_PROCESS}
    c.check("an OS terminator is not a kill target", "300" not in killed)
    c.check("an inferred node is not a kill target", "301" not in killed)
    c.check("an observed node still is", "302" in killed)
    c.check("the inferred node is surfaced instead of silently skipped",
            any(e.pid == 301 for e in p.unactionable))

    # ------------------------------------------------------------------ [6]
    print("\n[6] THE GRAPH-HOLE RULE: an incomplete picture may not authorise "
          "an irreversible action")
    whole = _subgraph(
        tree=[_node(400, "evil.exe")],
        artifacts=[_art("dns", "beacon", data={"domain": "c2.evil.example"})])
    holed = _subgraph(
        tree=[_node(400, "evil.exe")],
        artifacts=[_art("dns", "beacon", data={"domain": "c2.evil.example"})],
        truncated=True)

    pw = R.plan(whole, sig, base, sensor_state=live)
    ph = R.plan(holed, sig, base, sensor_state=live)

    kill_w = [a for a in pw.actions if a.responder == R.KILL_PROCESS]
    kill_h = [a for a in ph.actions if a.responder == R.KILL_PROCESS]
    block_h = [a for a in ph.actions if a.responder == R.BLOCK_DOMAIN]

    c.check("on a whole graph the plan is complete", pw.complete)
    c.check("on a truncated graph the plan is NOT complete", not ph.complete)
    c.check("the blind spot is named, not just flagged",
            any("bound" in s for s in ph.blind_spots))
    c.check("kill is capped when the tree is truncated",
            bool(kill_h) and not kill_h[0].enforced)
    c.check("the cap says WHY",
            "graph_incomplete" in kill_h[0].authority.limited_by)
    c.check("the reversible block still stands on the same holed graph",
            bool(block_h) and block_h[0].enforced)
    if kill_w:
        c.check("the same kill is permitted once the graph is whole",
                kill_w[0].enforced)
    else:
        c.fail("the same kill is permitted once the graph is whole",
               "no kill action was planned on the whole graph")

    # ------------------------------------------------------------------ [7]
    print("\n[7] inferred ancestry and eviction are holes too")
    for label, kw in (("inferred ancestry", {"inferred_nodes": 2}),
                      ("evicted nodes", {"evicted": 5})):
        p = R.plan(_subgraph(tree=[_node(500, "evil.exe")], **kw),
                   sig, base, sensor_state=live)
        k = [a for a in p.actions if a.responder == R.KILL_PROCESS]
        c.check(f"{label} caps the irreversible action",
                bool(k) and not k[0].enforced)

    # ------------------------------------------------------------------ [8]
    print("\n[8] host isolation is reached by the DECISION, never by the "
          "size of the tree")
    # `base` above is already a CONTAIN decision, so it would reach
    # isolate_host legitimately. To test that the TREE cannot escalate on its
    # own, the decision has to be one rung lower.
    mild_sig = Signal(category="process", source="behavioral", severity="high",
                      process_name="evil.exe", entity="evil.example")
    mild = decide(mild_sig)
    c.check("the milder signal really is below CONTAIN",
            mild.action != Action.CONTAIN)
    big = _subgraph(tree=[_node(600 + i, f"p{i}.exe") for i in range(20)])
    p = R.plan(big, mild_sig, mild, sensor_state=live)
    c.check("a large tree alone does not reach isolate_host",
            not any(a.responder == R.ISOLATE_HOST for a in p.actions))
    c.check("but the tree is still fully planned against",
            len([a for a in p.actions if a.responder == R.KILL_PROCESS]) == 21)

    contain = decide(Signal(category="attack_sequence",
                            source="attack_sequence", severity="critical",
                            process_name="evil.exe", entity="evil.example",
                            distinct_tactics=4, labels=("ransomware",)))
    if contain.action == Action.CONTAIN:
        p = R.plan(_subgraph(), sig, contain, sensor_state=live)
        c.check("a CONTAIN decision does reach isolate_host",
                any(a.responder == R.ISOLATE_HOST for a in p.actions))
    else:
        c.skip("a CONTAIN decision does reach isolate_host",
               f"policy returned {contain.action.value}, not contain")

    # ------------------------------------------------------------------ [9]
    print("\n[9] the plan serialises whole (a console has to draw this)")
    p = R.plan(_subgraph(
        tree=[_node(700, "evil.exe")],
        artifacts=[_art("dns", "beacon", data={"domain": "c2.evil.example"})]),
        sig, base, sensor_state=live)
    d = p.to_dict()
    c.check("to_dict carries the actions", len(d["actions"]) == len(p.actions))
    c.check("to_dict carries per-action authority",
            all(a["authority"] is not None for a in d["actions"]))
    c.check("to_dict carries the evidence citations",
            all(a["evidence"] for a in d["actions"]))

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
