#!/usr/bin/env python3
"""Causal detection — the graph as a detector (valkyrie/edr/causal_detect.py).

Two things this suite must prove, and they pull in opposite directions:

  * [X] ABLATION — the headline claim. An intrusion structure whose individual
        events trip NO rule is still detected from its shape alone. This is what
        "the graph originates a detection" means, and it is the whole point of
        the module.
  * [FP] The installer problem — the SAME structure, when it is routine on this
        machine, must NOT fire. A structural detector that cannot tell an
        intrusion from a software update is unusable on a real desktop, and for
        a "never interfere with the user's work" product that is total failure,
        not a tuning issue.

Everything else is the guards that make the second possible without losing the
first. Pure logic, runs offline.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402
from valkyrie.edr.causal_detect import (  # noqa: E402
    CausalBaseline, score_subgraph, match_motifs, MIN_OBSERVATIONS,
    MIN_SESSIONS, FIRE_THRESHOLD,
)


def _node(key, pid, name, parent_key="", path="", inferred=False, term=False):
    return {"key": key, "pid": pid, "name": name, "parent_key": parent_key,
            "path": path, "inferred": inferred, "terminator": term,
            "cmdline": "", "create_time": 1.0, "first_seen": 1.0,
            "last_seen": 2.0, "ppid": 0, "artifact_count": 0}


def _art(kind, summary, process, pid=200):
    return {"kind": kind, "summary": summary, "process": process, "pid": pid,
            "ts": 1.0, "data": {}}


def _intrusion(owner="winword.exe", truncated=False, inferred_nodes=0):
    """document -> shell -> (persistence + network): the canonical shape."""
    cgo = _node("100/1.0", 100, owner, path=r"c:\program files\office\winword.exe")
    shell = _node("200/1.0", 200, "powershell.exe", parent_key="100/1.0")
    return {"found": True, "cgo": cgo, "chain": [cgo], "target": shell,
            "tree": [shell],
            "artifacts": [_art("registry", r"HKCU\...\Run\updater", "powershell.exe"),
                          _art("dns", "beacon.evil.example", "powershell.exe")],
            "depth": 2, "inferred_nodes": inferred_nodes,
            "truncated": truncated, "evicted": 0}


def _mature(baseline=None, **kw):
    b = baseline or CausalBaseline(**kw)
    b.observations = max(b.observations, MIN_OBSERVATIONS)
    b.sessions = max(b.sessions, MIN_SESSIONS)
    return b


def main() -> int:
    c = Checks("causal detection — the graph as a detector", expect_min=18)

    # ================================================================ [X]
    print("\n[X] ABLATION: an intrusion whose individual events trip NO rule is "
          "detected from STRUCTURE alone")
    # A baseline that knows this machine well, but has NEVER seen winword spawn
    # powershell, nor powershell touch the registry / DNS.
    b = _mature(CausalBaseline())
    for _ in range(30):                       # this host's actual normal
        b.add_edge("explorer.exe", "chrome.exe")
        b.add_edge("services.exe", "svchost.exe")
        b.add_artifact("chrome.exe", "dns")
    f = score_subgraph(_intrusion(), b)
    c.check("the structure fires with no rule involved", f.fires)
    c.check("score cleared the threshold", f.score >= FIRE_THRESHOLD)
    c.check("it names the motif it matched", len(f.motifs) >= 1)
    c.check("it names the rare edge as evidence",
            any("winword.exe -> powershell.exe" in e for e in f.rare_edges))
    c.check("it carries an ATT&CK technique", f.technique.startswith("T"))

    # ================================================================ [FP]
    print("\n[FP] THE INSTALLER PROBLEM: the SAME structure, routine on this "
          "machine, must NOT fire")
    b2 = _mature(CausalBaseline())
    for _ in range(30):        # on THIS host, this shape happens constantly
        b2.add_edge("winword.exe", "powershell.exe")
        b2.add_artifact("powershell.exe", "registry")
        b2.add_artifact("powershell.exe", "dns")
    f2 = score_subgraph(_intrusion(), b2)
    c.check("a routine structure does NOT fire", not f2.fires)
    c.check("it is suppressed as routine-on-this-host",
            f2.suppressed_by == "routine_on_this_host")
    c.check("the reason names the interference risk explicitly",
            any("prime directive" in r or "installer" in r for r in f2.reasons))

    # ================================================================ [1]
    print("\n[1] GUARD 1 — an immature baseline emits NOTHING (no new-machine "
          "alert storm)")
    fresh = CausalBaseline()
    fresh.observations, fresh.sessions = 10, 1
    f3 = score_subgraph(_intrusion(), fresh)
    c.check("immature baseline suppresses entirely", not f3.fires)
    c.check("suppression is attributed to maturity",
            f3.suppressed_by == "baseline_immature")
    c.check("it reports its learning progress", any("learning" in r for r in f3.reasons))

    # ================================================================ [2]
    print("\n[2] GUARD 2 — rarity WITHOUT a suspicious motif does not fire")
    plain = {"found": True,
             "cgo": _node("1/1.0", 1, "somenewapp.exe"),
             "chain": [], "target": {}, "tree": [], "artifacts": [],
             "depth": 1, "inferred_nodes": 0, "truncated": False, "evicted": 0}
    f4 = score_subgraph(plain, _mature(CausalBaseline()))
    c.check("a novel-but-unremarkable structure does not fire", not f4.fires)
    c.check("suppressed for having no motif", f4.suppressed_by == "no_motif")

    # ================================================================ [3]
    print("\n[3] GUARD 3 — an INCOMPLETE graph is capped, never fires alone")
    f5 = score_subgraph(_intrusion(truncated=True), b)
    c.check("a truncated graph cannot originate a detection", not f5.fires)
    c.check("the cap is explained", any("incomplete" in r for r in f5.reasons))
    f5b = score_subgraph(_intrusion(inferred_nodes=2), b)
    c.check("inferred ancestry is also capped", not f5b.fires)

    # ================================================================ [4]
    print("\n[4] GUARD 4 — a trusted installer lineage is held to a higher bar")
    f6 = score_subgraph(_intrusion(owner="msiexec.exe"), b)
    c.check("trusted lineage scores lower than an untrusted one",
            f6.score < score_subgraph(_intrusion(), b).score)

    # ================================================================ [5]
    print("\n[5] motifs are STRUCTURES, not commands")
    ids = {m.id for m in match_motifs(_intrusion())}
    c.check("doc->shell->persistence recognised",
            "doc-to-shell-to-persistence" in ids)
    c.check("the full intrusion shape recognised", "full-intrusion-shape" in ids)

    # ================================================================ [6]
    print("\n[6] the baseline learns from real subgraphs and round-trips")
    b3 = CausalBaseline()
    b3.observe_subgraph(_intrusion())
    c.check("learning recorded the parent->child edge",
            b3.edge_count("winword.exe", "powershell.exe") == 1)
    c.check("learning recorded the process->artifact pattern",
            b3.artifact_count("powershell.exe", "dns") == 1)
    back = CausalBaseline.from_dict(b3.to_dict())
    c.check("baseline survives serialisation",
            back.edge_count("winword.exe", "powershell.exe") == 1)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
