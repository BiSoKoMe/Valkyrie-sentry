"""Causal detection — the graph becomes a DETECTOR, not just a storyteller.

THE GAP THIS CLOSES
-------------------
`killchain.py` says it plainly in its own docstring: *"this correlates detections
that were ALREADY produced — it raises no new primary signal."* Everything below
the graph can only escalate what a rule or the anomaly scorer already found. So
an intrusion whose every individual step looks unremarkable — a document opens a
shell, the shell writes a run key, the run key's process reaches the network —
produces no detection at all, even though the *relationship structure* is
obviously an intrusion.

This module lets the causality graph originate a detection from structure alone.

WHY THIS IS THE MOST FALSE-POSITIVE-PRONE THING IN THE CODEBASE
--------------------------------------------------------------
And therefore why most of this file is guards rather than detection.

The canonical malicious motif — `document -> shell -> persistence -> network` —
is *also* precisely what a software installer does. And an updater. And every IT
deployment script, and half the developer tooling on a working machine. **The
structure alone does not separate them.** A naive structural detector scores
brilliantly on an attack battery and is unusable on a real desktop, which for a
product whose north star is "never interfere with people's work" is a total
failure, not a tuning problem.

So the discriminator here is deliberately NOT "is this shape malicious?" but:

    **How unusual is this structure ON THIS MACHINE?**

That is the one question a cloud EDR cannot afford to answer well — their
economics force them to model the world broadly and each host thinly. Valkyrie
models exactly one host, forever, at zero marginal cost, because nothing leaves
the machine. A per-host causal baseline is the competitive advantage AND the
false-positive answer, which is why it is the foundation of this module rather
than an enhancement to it.

THE FOUR GUARDS (all must pass before a detection is originated)
---------------------------------------------------------------
1. **Baseline maturity.** On a fresh install *everything* is novel, so a
   rarity-based detector would fire on all normal activity for the first days.
   The baseline must have observed `MIN_OBSERVATIONS` structures across
   `MIN_SESSIONS` distinct sessions before this module may emit anything at all.
   Until then it learns silently. This single guard prevents the entire class of
   "new machine, alert storm".
2. **Motif AND rarity.** A known-suspicious structure that is ROUTINE on this
   host does not fire (that is the installer). A rare structure that matches no
   suspicious motif does not fire (that is a user doing something new). Only the
   intersection is evidence.
3. **Graph completeness.** A truncated walk, inferred ancestry, or evicted nodes
   mean the structure being scored is not the real structure. Reusing the
   principle from `remediation.py`: an incomplete picture may not originate an
   irreversible judgement. It caps at a lower confidence rather than firing.
4. **Trusted-lineage exemption.** A chain whose owner is a signed, trusted OS or
   installer path is held to a much higher bar - this is the explicit carve-out
   for the update/install traffic that produces the malicious-looking motif
   legitimately.

Pure and deterministic: `score_subgraph` is a function of (subgraph, baseline)
with no clock reads and no I/O, so the logic that decides whether Valkyrie
invents a detection is exhaustively testable offline.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

# --- maturity thresholds -----------------------------------------------------
# Deliberately conservative. The cost of firing too early is an alert storm on a
# machine the user just installed on; the cost of firing too late is a few days
# of reduced coverage while the rule/anomaly layers still run normally.
MIN_OBSERVATIONS = 300      # distinct structures learned
MIN_SESSIONS = 3            # across at least this many engine sessions

# Score at/above which a structure may originate a detection.
FIRE_THRESHOLD = 0.70
# Cap applied when the graph is incomplete (guard 3) - enough to inform, never
# enough to fire on its own.
INCOMPLETE_CAP = 0.55


# ---------------------------------------------------------------------------
# 1. The per-host causal baseline — "what is normal on THIS machine"
# ---------------------------------------------------------------------------
@dataclass
class CausalBaseline:
    """Learns the causal shapes this host produces in normal operation.

    Three things are learned, all cheap and all bounded:
      * ``edges``      parent_name -> child_name  (how processes spawn here)
      * ``artifacts``  process_name -> artifact kind (what a process normally does)
      * ``owners``     which processes normally act as a causality group owner

    Names only - never paths, command lines, or user data. The baseline is a
    behavioural fingerprint of the machine, not a record of what was run on it.
    """
    edges: dict = field(default_factory=dict)        # "parent>child" -> count
    artifacts: dict = field(default_factory=dict)    # "proc>kind"    -> count
    owners: dict = field(default_factory=dict)       # "proc"         -> count
    observations: int = 0
    sessions: int = 0

    # -- learning ----------------------------------------------------------
    def start_session(self) -> None:
        self.sessions += 1

    def observe_subgraph(self, sub: dict) -> None:
        """Learn from one causality subgraph. Silent; never emits anything."""
        if not sub or not sub.get("found"):
            return
        cgo = sub.get("cgo") or {}
        owner = _name(cgo)
        if owner:
            self.owners[owner] = self.owners.get(owner, 0) + 1

        # every parent->child edge in the tree
        by_key = {}
        for n in ([cgo] + list(sub.get("tree") or [])):
            if isinstance(n, dict) and n.get("key"):
                by_key[n["key"]] = n
        for n in by_key.values():
            parent = by_key.get(n.get("parent_key") or "")
            if parent is not None:
                self.add_edge(_name(parent), _name(n))

        for a in (sub.get("artifacts") or []):
            proc = str(a.get("process") or "").lower()
            kind = str(a.get("kind") or "").lower()
            if proc and kind:
                self.add_artifact(proc, kind)
        self.observations += 1

    def add_edge(self, parent: str, child: str) -> None:
        if not parent or not child:
            return
        k = f"{parent}>{child}"
        self.edges[k] = self.edges.get(k, 0) + 1

    def add_artifact(self, proc: str, kind: str) -> None:
        k = f"{proc}>{kind}"
        self.artifacts[k] = self.artifacts.get(k, 0) + 1

    # -- querying ----------------------------------------------------------
    @property
    def mature(self) -> bool:
        """GUARD 1. Until this is True the detector emits NOTHING - on a fresh
        machine every structure is novel and a rarity detector would flood."""
        return (self.observations >= MIN_OBSERVATIONS
                and self.sessions >= MIN_SESSIONS)

    def edge_count(self, parent: str, child: str) -> int:
        return self.edges.get(f"{(parent or '').lower()}>{(child or '').lower()}", 0)

    def artifact_count(self, proc: str, kind: str) -> int:
        return self.artifacts.get(f"{(proc or '').lower()}>{(kind or '').lower()}", 0)

    def edge_rarity(self, parent: str, child: str) -> float:
        """0.0 = routine here, 1.0 = never seen on this machine."""
        c = self.edge_count(parent, child)
        if c >= 20:
            return 0.0
        if c == 0:
            return 1.0
        return max(0.0, 1.0 - (c / 20.0))

    def artifact_rarity(self, proc: str, kind: str) -> float:
        c = self.artifact_count(proc, kind)
        if c >= 20:
            return 0.0
        if c == 0:
            return 1.0
        return max(0.0, 1.0 - (c / 20.0))

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "CausalBaseline":
        return cls(edges=dict(d.get("edges") or {}),
                   artifacts=dict(d.get("artifacts") or {}),
                   owners=dict(d.get("owners") or {}),
                   observations=int(d.get("observations") or 0),
                   sessions=int(d.get("sessions") or 0))


def _name(node: dict) -> str:
    return str((node or {}).get("name") or "").lower()


# ---------------------------------------------------------------------------
# 2. Causal motifs — generalised STRUCTURES, not commands
# ---------------------------------------------------------------------------
# Each motif describes a relationship shape. None of them is malicious on its
# own (guard 2) - they only become evidence when the shape is ALSO rare here.

_DOC_OWNERS = ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
               "acrord32.exe", "chrome.exe", "msedge.exe", "firefox.exe",
               "thunderbird.exe")
_SHELLS = ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
           "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
_PERSIST_KINDS = ("registry", "persistence", "autostart", "service",
                  "scheduled_task", "startup_folder")
_NET_KINDS = ("dns", "network", "connection")
_CRED_HINTS = ("lsass", "credential", "login data", "id_rsa", ".aws", "ntds")


@dataclass
class Motif:
    id: str
    description: str
    technique: str
    weight: float


MOTIFS: tuple = (
    Motif("doc-to-shell-to-persistence",
          "A document/browser owner spawned a script host that established persistence",
          "T1547 — Boot or Logon Autostart Execution", 0.45),
    Motif("doc-to-shell-to-network",
          "A document/browser owner spawned a script host that reached the network",
          "T1071 — Application Layer Protocol", 0.40),
    Motif("full-intrusion-shape",
          "One lineage covered execution, persistence AND network egress",
          "T1059 — Command and Scripting Interpreter", 0.60),
    Motif("credential-access-in-lineage",
          "A lineage rooted at a non-system owner touched credential material",
          "T1003 — OS Credential Dumping", 0.55),
    Motif("shell-chain-depth",
          "An unusually deep chain of script hosts spawning script hosts",
          "T1059 — Command and Scripting Interpreter", 0.35),
)


def match_motifs(sub: dict) -> list:
    """Which structural motifs this subgraph exhibits. Pure."""
    cgo = sub.get("cgo") or {}
    owner = _name(cgo)
    tree = [n for n in (sub.get("tree") or []) if isinstance(n, dict)]
    arts = [a for a in (sub.get("artifacts") or []) if isinstance(a, dict)]

    names = [owner] + [_name(n) for n in tree]
    kinds = {str(a.get("kind") or "").lower() for a in arts}
    summaries = " ".join(str(a.get("summary") or "").lower() for a in arts)

    doc_owner = owner in _DOC_OWNERS
    has_shell = any(n in _SHELLS for n in names[1:]) or owner in _SHELLS
    has_persist = bool(kinds & set(_PERSIST_KINDS))
    has_net = bool(kinds & set(_NET_KINDS))
    has_cred = any(h in summaries for h in _CRED_HINTS)
    shell_depth = sum(1 for n in names if n in _SHELLS)

    hit = []
    for m in MOTIFS:
        if m.id == "doc-to-shell-to-persistence" and doc_owner and has_shell and has_persist:
            hit.append(m)
        elif m.id == "doc-to-shell-to-network" and doc_owner and has_shell and has_net:
            hit.append(m)
        elif m.id == "full-intrusion-shape" and has_shell and has_persist and has_net:
            hit.append(m)
        elif m.id == "credential-access-in-lineage" and has_cred and owner and not _is_system_owner(owner):
            hit.append(m)
        elif m.id == "shell-chain-depth" and shell_depth >= 3:
            hit.append(m)
    return hit


_SYSTEM_OWNERS = ("services.exe", "svchost.exe", "system", "wininit.exe",
                  "smss.exe", "lsass.exe", "csrss.exe")


def _is_system_owner(name: str) -> bool:
    return (name or "").lower() in _SYSTEM_OWNERS


# GUARD 4: lineages owned by a trusted installer/updater shape are held to a
# higher bar, because they legitimately produce the malicious-looking motif.
_TRUSTED_OWNER_HINTS = ("msiexec.exe", "setup.exe", "install", "update",
                        "trustedinstaller.exe", "wuauclt.exe", "devenv.exe",
                        "code.exe", "python.exe", "node.exe", "git.exe")


def _trusted_lineage(sub: dict) -> bool:
    """GUARD 4 - is this owner a lineage that LEGITIMATELY produces the
    suspicious shape (installer/updater/dev tooling)?

    IMPORTANT: a trusted INSTALL PATH is deliberately NOT sufficient on its own.
    An early version of this returned True for any owner living under
    ``C:\\Program Files\\`` or ``C:\\Windows\\`` - which silently exempted
    ``winword.exe``, ``excel.exe`` and every browser, because those are all
    installed there. That halved the score for the single most common real-world
    initial-access shape (a malicious document spawning a shell), i.e. the guard
    against false positives was quietly disabling the detector's most important
    true positive.

    So trust is decided by what the process IS (an installer/updater/dev tool),
    not by where it lives - and a known document/browser owner is explicitly
    never trusted here, however well-signed its binary is."""
    cgo = sub.get("cgo") or {}
    owner = _name(cgo)
    if owner in _DOC_OWNERS:
        return False          # never exempt the document/browser attack class
    if any(h in owner for h in _TRUSTED_OWNER_HINTS):
        return True
    # An OS-path owner is a weak benign hint, and only counts for processes that
    # are not otherwise interesting - never for shells, which live in
    # System32 and are the primary tool of the attacks this module exists for.
    path = str(cgo.get("path") or "").lower()
    if owner in _SHELLS:
        return False
    return path.startswith(("c:\\windows\\system32\\",
                            "c:\\program files\\common files\\"))


# ---------------------------------------------------------------------------
# 3. Scoring and the detection decision
# ---------------------------------------------------------------------------
@dataclass
class CausalFinding:
    score: float
    motifs: tuple = ()
    rarity: float = 0.0
    rare_edges: tuple = ()
    reasons: tuple = ()
    fires: bool = False
    suppressed_by: str = ""     # which guard held it, if any
    technique: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["motifs"] = list(self.motifs)
        d["rare_edges"] = list(self.rare_edges)
        d["reasons"] = list(self.reasons)
        return d


def score_subgraph(sub: dict, baseline: CausalBaseline) -> CausalFinding:
    """Score one causality subgraph for structural suspicion. Pure.

    Returns a CausalFinding; ``fires`` is True only when EVERY guard passed and
    the combined score cleared FIRE_THRESHOLD.
    """
    if not sub or not sub.get("found"):
        return CausalFinding(0.0, suppressed_by="no_subgraph")

    # ---- GUARD 1: baseline maturity -------------------------------------
    if not baseline.mature:
        return CausalFinding(
            0.0, suppressed_by="baseline_immature",
            reasons=(f"baseline has {baseline.observations}/{MIN_OBSERVATIONS} "
                     f"observations across {baseline.sessions}/{MIN_SESSIONS} "
                     f"sessions - still learning this machine's normal, so no "
                     f"structural detection may be originated yet",))

    motifs = match_motifs(sub)
    if not motifs:
        return CausalFinding(0.0, suppressed_by="no_motif",
                             reasons=("no suspicious structure present",))

    # ---- rarity of THIS structure on THIS machine ------------------------
    cgo = sub.get("cgo") or {}
    by_key = {}
    for n in ([cgo] + list(sub.get("tree") or [])):
        if isinstance(n, dict) and n.get("key"):
            by_key[n["key"]] = n

    edge_rarities: list = []
    rare_edges: list = []
    for n in by_key.values():
        parent = by_key.get(n.get("parent_key") or "")
        if parent is None:
            continue
        p, c = _name(parent), _name(n)
        r = baseline.edge_rarity(p, c)
        edge_rarities.append(r)
        if r >= 0.9:
            rare_edges.append(f"{p} -> {c}")

    art_rarities = [
        baseline.artifact_rarity(str(a.get("process") or ""),
                                 str(a.get("kind") or ""))
        for a in (sub.get("artifacts") or []) if isinstance(a, dict)
    ]

    pool = edge_rarities + art_rarities
    rarity = (sum(pool) / len(pool)) if pool else 0.0

    # ---- GUARD 2: motif AND rarity, never either alone -------------------
    if rarity < 0.25:
        return CausalFinding(
            0.0, motifs=tuple(m.id for m in motifs), rarity=rarity,
            suppressed_by="routine_on_this_host",
            reasons=(f"the structure matches {len(motifs)} motif(s) but is "
                     f"ROUTINE on this machine (rarity {rarity:.2f}) - this is "
                     f"the installer/updater case, and firing here is exactly "
                     f"the interference the prime directive forbids",))

    motif_weight = max(m.weight for m in motifs)
    # combined: the structure's suspicion, amplified by how abnormal it is here
    score = min(1.0, motif_weight + (rarity * 0.5))
    reasons = [f"structure matches {', '.join(m.id for m in motifs)}",
               f"rarity on this host {rarity:.2f}"]

    # ---- GUARD 4: trusted lineage needs much more --------------------------
    if _trusted_lineage(sub):
        score *= 0.5
        reasons.append("owner is a trusted installer/OS lineage - score halved, "
                       "because this lineage legitimately produces this shape")

    # ---- GUARD 3: graph completeness ---------------------------------------
    incomplete = bool(sub.get("truncated") or sub.get("inferred_nodes")
                      or sub.get("evicted"))
    if incomplete and score > INCOMPLETE_CAP:
        score = INCOMPLETE_CAP
        reasons.append("graph is incomplete (truncated/inferred/evicted) - "
                       "capped: an incomplete structure may not originate a "
                       "detection on its own")

    fires = score >= FIRE_THRESHOLD
    return CausalFinding(
        score=round(score, 3), motifs=tuple(m.id for m in motifs),
        rarity=round(rarity, 3), rare_edges=tuple(rare_edges[:8]),
        reasons=tuple(reasons), fires=fires,
        suppressed_by="" if fires else "below_threshold",
        technique=max(motifs, key=lambda m: m.weight).technique)
