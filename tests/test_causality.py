#!/usr/bin/env python3
"""Causality graph tests - process ancestry as a queryable structure.

SCOPE STATEMENT (read before quoting any number from this file): these are
STRUCTURAL CORRECTNESS tests. They prove the graph builds the right shape from
a given event stream - the right CGO, the right chain order, no fabricated
edges, honest flags on guessed data, hard bounds on memory. They say NOTHING
about detection rate, and no result here is evidence Valkyrie detects anything.
Detection efficacy is measured only by a live Atomic Red Team run on a VM; the
only real Tier B figure on record remains 1/40. Nothing in this file changes it,
because the causality graph raises no detections at all - it explains the ones
other layers already raised.

  [1] Terminators: the path-aware rule that makes a CGO meaningful, and the
      masquerade case (a fake svchost must NOT truncate a chain)
  [2] Node identity: create_time keying, pid-only degradation
  [3] Chain + CGO: correct owner, CGO-first order, terminator stops the walk
  [4] PID reuse: a parent that started after its supposed child is rejected
  [5] Inferred ancestry: named placeholders, promotion on real observation,
      and the name-mismatch case where promotion must NOT merge
  [6] Artifacts: attribution, the unattributable drop, the per-node cap
  [7] subgraph(): wire format + every honesty flag
  [8] Bounds: eviction is capped and counted
  [9] Cycle guards: corrupt ppid data terminates both walks
 [10] Engine end-to-end: benign ancestry is recorded below the alert gate, and
      a detection is stamped with its causality owner
 [11] attribute_causality(): the public entry a sensor outside the telemetry
      pipeline (Nyx's TLS interception, ADR 0057) uses to attach an
      observation to the process that caused it - and the honest drop when
      the process is unresolvable
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def main() -> int:
    from valkyrie.edr.causality import (
        CausalityGraph, is_terminator, node_key, CAUSALITY_TERMINATORS,
        _MAX_ARTIFACTS_PER_NODE,
    )

    print("\n=== causality graph ===\n")

    # ------------------------------------------------------------------
    print("[1] Causality terminators (pure, path-aware)")
    _check("real explorer.exe terminates the walk",
           is_terminator("explorer.exe", r"C:\Windows\explorer.exe"))
    _check("real services.exe terminates",
           is_terminator("services.exe", r"C:\Windows\System32\services.exe"))
    _check("name is case-insensitive",
           is_terminator("EXPLORER.EXE", r"C:\Windows\explorer.exe"))
    _check("a full path is accepted as the name",
           is_terminator(r"C:\Windows\explorer.exe", r"C:\Windows\explorer.exe"))
    _check("unreadable path assumes the real system binary",
           is_terminator("svchost.exe", ""))
    # The evasion case: name alone must never terminate a chain.
    _check("masqueraded svchost in %TEMP% does NOT terminate",
           not is_terminator(
               "svchost.exe",
               r"C:\Users\v\AppData\Local\Temp\svchost.exe"))
    _check("svchost dropped in a user profile does NOT terminate",
           not is_terminator("svchost.exe", r"C:\Users\v\Downloads\svchost.exe"))
    # The interesting middle of a chain must never be a terminator.
    for interp in ("powershell.exe", "cmd.exe", "wscript.exe", "rundll32.exe",
                   "mshta.exe", "winword.exe"):
        _check(f"{interp} is not a terminator",
               interp not in CAUSALITY_TERMINATORS)

    # ------------------------------------------------------------------
    print("\n[2] Node identity (PID reuse needs create_time)")
    _check("create_time is part of the key", node_key(100, 5.0) == "100/5.000")
    _check("same pid, different start → different nodes",
           node_key(100, 5.0) != node_key(100, 6.0))
    _check("no create_time degrades to a pid-only key",
           node_key(100, 0.0) == "100/~")

    # ------------------------------------------------------------------
    print("\n[3] Chain + CGO")
    g = CausalityGraph()
    # explorer -> winword -> cmd -> powershell : the canonical phishing shape.
    g.observe_process(10, "explorer.exe", ppid=4, create_time=1.0,
                      path=r"C:\Windows\explorer.exe", ts=1.0)
    g.observe_process(20, "winword.exe", ppid=10, create_time=2.0,
                      path=r"C:\Program Files\Microsoft Office\winword.exe", ts=2.0)
    g.observe_process(30, "cmd.exe", ppid=20, create_time=3.0,
                      path=r"C:\Windows\System32\cmd.exe", ts=3.0)
    g.observe_process(40, "powershell.exe", ppid=30, create_time=4.0,
                      cmdline="powershell -enc SQBFAFgA", ts=4.0)

    cgo = g.cgo(40)
    _check("CGO is winword.exe, not explorer.exe and not System",
           cgo is not None and cgo.name == "winword.exe")
    names = [n.name for n in g.chain(40)]
    _check("chain is CGO-first, target-last",
           names == ["winword.exe", "cmd.exe", "powershell.exe"])
    _check("the terminator itself is excluded from the chain",
           "explorer.exe" not in names)
    _check("a terminator is its own CGO",
           (g.cgo(10) or object()).name == "explorer.exe" if g.cgo(10) else False)
    _check("an unobserved pid has no chain", g.chain(99999) == [])
    kids = [n.name for n in g.descendants(20)]
    _check("descendants walk the whole subtree",
           set(kids) == {"cmd.exe", "powershell.exe"})
    _check("descendants exclude the root", "winword.exe" not in kids)

    # Masquerade: the same tree, but 'explorer.exe' runs from %TEMP%. Because it
    # is no longer a terminator, the chain must extend THROUGH it and name it -
    # the exact ancestry a name-only terminator list would have hidden.
    gm = CausalityGraph()
    gm.observe_process(10, "explorer.exe", ppid=4, create_time=1.0,
                       path=r"C:\Users\v\AppData\Local\Temp\explorer.exe", ts=1.0)
    gm.observe_process(20, "winword.exe", ppid=10, create_time=2.0, ts=2.0)
    gm.observe_process(30, "powershell.exe", ppid=20, create_time=3.0, ts=3.0)
    mnames = [n.name for n in gm.chain(30)]
    _check("fake explorer does not truncate the chain",
           mnames == ["explorer.exe", "winword.exe", "powershell.exe"])
    _check("CGO becomes the masquerading process",
           (gm.cgo(30) or object()).name == "explorer.exe" if gm.cgo(30) else False)

    # ------------------------------------------------------------------
    print("\n[4] PID reuse guard")
    gr = CausalityGraph()
    # Positive control: a parent that really did start first links normally.
    gr.observe_process(100, "parent.exe", create_time=5.0, ts=5.0)
    gr.observe_process(200, "child.exe", ppid=100, create_time=10.0, ts=10.0)
    _check("a genuine parent links", len(gr.chain(200)) == 2)
    # The reuse case: pid 100 is now held by a process that started LATER than
    # its supposed child, so it demonstrably cannot be that child's parent.
    gx = CausalityGraph()
    gx.observe_process(100, "recycled.exe", create_time=50.0, ts=50.0)
    gx.observe_process(200, "child.exe", ppid=100, create_time=10.0, ts=10.0)
    ch = gx.chain(200)
    _check("a parent that started after its child is rejected", len(ch) == 1)
    _check("no fabricated process heads the chain",
           ch and ch[0].name == "child.exe")

    # ------------------------------------------------------------------
    print("\n[5] Inferred ancestry")
    gi = CausalityGraph()
    # cmd.exe names winword.exe as its parent, but no collector ever saw
    # winword start (it exited between two polls of the userland poller).
    gi.observe_process(30, "cmd.exe", ppid=20, create_time=3.0,
                       parent_name="winword.exe", ts=3.0)
    ic = gi.chain(30)
    _check("an unobserved parent still appears, by name",
           [n.name for n in ic] == ["winword.exe", "cmd.exe"])
    _check("the guessed ancestor is flagged inferred", ic[0].inferred is True)
    _check("the observed node is NOT flagged inferred", ic[1].inferred is False)
    _check("subgraph counts the guess",
           gi.subgraph(30)["inferred_nodes"] == 1)
    # Promotion: the real winword is later observed. The placeholder must be
    # absorbed, not forked - chain() and descendants() must agree afterwards.
    gi.observe_process(20, "winword.exe", ppid=10, create_time=2.0,
                       path=r"C:\Program Files\winword.exe", ts=6.0)
    pc = gi.chain(30)
    _check("promotion keeps the chain at one ancestor", len(pc) == 2)
    _check("the promoted ancestor is no longer inferred", pc[0].inferred is False)
    _check("promotion carried the real path over",
           pc[0].path.endswith("winword.exe"))
    _check("descendants agree with chain after promotion",
           [n.name for n in gi.descendants(20)] == ["cmd.exe"])
    _check("no orphan placeholder left behind",
           gi.stats()["nodes"] == 2)
    # Name mismatch -> pid reuse, so promotion must NOT merge the two.
    gn = CausalityGraph()
    gn.observe_process(30, "cmd.exe", ppid=20, create_time=3.0,
                       parent_name="winword.exe", ts=3.0)
    gn.observe_process(20, "chrome.exe", create_time=9.0, ts=9.0)
    _check("a differently-named process does not absorb the placeholder",
           gn.stats()["nodes"] == 3)
    _check("the chain keeps the named guess, not the unrelated process",
           [n.name for n in gn.chain(30)] == ["winword.exe", "cmd.exe"])

    # ------------------------------------------------------------------
    print("\n[6] Artifact attribution")
    _check("artifact attaches to a known process",
           g.attribute(40, "dns", "c2.example.test", ts=5.0,
                       data={"domain": "c2.example.test"}) is True)
    _check("unattributable observation is dropped, not guessed",
           g.attribute(99999, "dns", "orphan.test") is False)
    _check("a named observation may create its own node",
           g.attribute(77, "file", "ransom.note", name="mal.exe", ts=6.0) is True)
    _check("that node exists afterwards",
           (g.node(77) or object()).name == "mal.exe" if g.node(77) else False)
    _check("pid 0 is never attributable", g.attribute(0, "dns", "x") is False)
    gcap = CausalityGraph()
    gcap.observe_process(1, "beacon.exe", create_time=1.0, ts=1.0)
    for i in range(_MAX_ARTIFACTS_PER_NODE + 60):
        gcap.attribute(1, "network", f"beacon-{i}", ts=float(i))
    node1 = gcap.node(1)
    _check("artifacts are capped per node",
           node1 is not None and len(node1.artifacts) == _MAX_ARTIFACTS_PER_NODE)
    _check("the cap keeps the most recent, drops the oldest",
           node1 is not None
           and node1.artifacts[-1].summary
           == f"beacon-{_MAX_ARTIFACTS_PER_NODE + 59}")

    # ------------------------------------------------------------------
    print("\n[7] subgraph() wire format + honesty flags")
    sub = g.subgraph(40)
    _check("subgraph is found", sub["found"] is True)
    _check("subgraph names the CGO", sub["cgo"]["name"] == "winword.exe")
    _check("subgraph carries the chain",
           [n["name"] for n in sub["chain"]]
           == ["winword.exe", "cmd.exe", "powershell.exe"])
    _check("subgraph names the target", sub["target"]["name"] == "powershell.exe")
    _check("subgraph carries the owner's whole tree",
           {n["name"] for n in sub["tree"]} == {"cmd.exe", "powershell.exe"})
    _check("attributed artifacts roll up to the subgraph",
           any(a["kind"] == "dns" and a["summary"] == "c2.example.test"
               for a in sub["artifacts"]))
    _check("artifacts name their owning process",
           all("process" in a and "pid" in a for a in sub["artifacts"]))
    _check("fully-observed chain reports zero guesses",
           sub["inferred_nodes"] == 0)
    _check("depth is reported", sub["depth"] == 3)
    _check("nothing truncated at default bounds", sub["truncated"] is False)
    _check("eviction count is on every payload", "evicted" in sub)
    miss = g.subgraph(99999)
    _check("unknown pid reports not-found, not an empty success",
           miss["found"] is False)
    _check("truncation is reported when the bound is hit",
           g.subgraph(40, max_nodes=1)["truncated"] is True)

    # ------------------------------------------------------------------
    print("\n[8] Bounds and eviction")
    gb = CausalityGraph(max_nodes=64)
    for i in range(1, 220):
        gb.observe_process(i, f"p{i}.exe", create_time=float(i), ts=float(i))
    st = gb.stats()
    _check("node count is hard-capped", st["nodes"] <= 64)
    _check("eviction is counted, not silent", st["evicted"] > 0)
    _check("capacity is reported", st["capacity"] == 64)
    _check("a tiny cap is floored to something usable",
           CausalityGraph(max_nodes=1).stats()["capacity"] == 64)

    # ------------------------------------------------------------------
    print("\n[9] Cycle guards (corrupt / spoofed ppid data)")
    gc = CausalityGraph()
    # A claims B is its parent and B claims A - identical create_times so the
    # pid-reuse guard cannot be what saves us; only the seen-set can.
    gc.observe_process(1, "a.exe", ppid=2, create_time=5.0, ts=5.0)
    gc.observe_process(2, "b.exe", ppid=1, create_time=5.0, ts=5.0)
    cyc = gc.chain(1)
    _check("upward walk terminates on a cycle", len(cyc) <= 2)
    _check("no node repeats in the chain",
           len({n.key for n in cyc}) == len(cyc))
    _check("descendant walk terminates on a cycle",
           len(gc.descendants(1)) <= 2)
    gs = CausalityGraph()
    gs.observe_process(7, "self.exe", ppid=7, create_time=1.0, ts=1.0)
    _check("a process parented to itself does not loop",
           len(gs.chain(7)) == 1)

    # ------------------------------------------------------------------
    print("\n[10] Engine end-to-end (below the alert gate)")
    import tempfile
    from valkyrie.store import Store
    from valkyrie.edr import EdrEngine
    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "causality.db")
        store.start()
        engine = EdrEngine(store)
        engine.start()
        base = 1_000_000.0

        def _proc(pid, name, ppid, ts, *, path="", cmdline="",
                  severity="info", action="observed", parent_name=""):
            engine.ingest_telemetry({
                "category": "process", "activity": "exec", "action": action,
                "severity": severity, "source": "process_collector",
                "reason": f"exec {name}", "ts": ts,
                "actor_name": name, "actor_path": path, "actor_pid": pid,
                "fields": {"ppid": ppid, "parent_name": parent_name,
                           "cmdline": cmdline},
            })

        # The ancestry is entirely INFO severity - every one of these is below
        # the gate that decides what becomes an incident, and none of them
        # should raise one. The graph must record them anyway.
        _proc(10, "explorer.exe", 4, base + 1, path=r"C:\Windows\explorer.exe")
        _proc(20, "winword.exe", 10, base + 2,
              path=r"C:\Program Files\Microsoft Office\winword.exe")
        _proc(30, "cmd.exe", 20, base + 3, path=r"C:\Windows\System32\cmd.exe")

        pre = engine.causality_subgraph(30)
        _check("benign ancestry is recorded despite never alerting",
               pre["found"] is True and pre["cgo"]["name"] == "winword.exe")
        _check("recording structure raised no incident",
               len(engine.list_incidents()) == 0)

        # Now the alerting hop.
        _proc(40, "powershell.exe", 30, base + 4,
              cmdline="powershell -nop -w hidden -enc SQBFAFgA",
              severity="high", action="flagged")
        # A blocked DNS query from the same process: low severity, so the gate
        # drops it - but it must still be attributed as an artifact.
        engine.ingest_telemetry({
            "category": "dns", "activity": "query", "action": "blocked",
            "severity": "low", "source": "dns_interceptor",
            "reason": "blocked c2.example.test", "ts": base + 5,
            "actor_name": "powershell.exe", "actor_pid": 40,
            "target": {"domain": "c2.example.test"}, "fields": {},
        })
        time.sleep(0.2)

        sg = engine.causality_subgraph(40)
        _check("engine builds the full chain from live telemetry",
               [n["name"] for n in sg["chain"]]
               == ["winword.exe", "cmd.exe", "powershell.exe"])
        _check("engine CGO is the document, not the desktop",
               sg["cgo"]["name"] == "winword.exe")
        _check("sub-threshold DNS is still attributed to its process",
               any(a["kind"] == "dns" and "c2.example.test" in a["summary"]
                   for a in sg["artifacts"]))
        _check("the detection itself is attributed into the graph",
               any(a["kind"] == "detection" for a in sg["artifacts"]))
        _check("live chain has no guessed ancestry", sg["inferred_nodes"] == 0)
        _check("graph stats are exposed", engine.causality_stats()["nodes"] >= 4)

        # The detection carries its causality owner into the incident record.
        incs = engine.list_incidents()
        _check("the flagged process did raise an incident", len(incs) >= 1)
        stamped = None
        for i in incs:
            full = engine.get_incident(i["id"])
            for det in (full.get("detections") or []):
                c = (det.get("details") or {}).get("causality")
                if c and c.get("cgo"):
                    stamped = c
                    break
            if stamped:
                break
        _check("a detection was stamped with its causality owner",
               stamped is not None)
        _check("the stamp names winword.exe as the owner",
               stamped is not None and stamped.get("cgo") == "winword.exe")
        _check("the stamp carries a readable chain path",
               stamped is not None
               and stamped.get("path")
               == "winword.exe -> cmd.exe -> powershell.exe")
        _check("the stamp records whether ancestry was guessed",
               stamped is not None and stamped.get("inferred") is False)

        # ------------------------------------------------------------------
        print("\n[11] attribute_causality() - the Nyx entry point (ADR 0057)")
        # cmd.exe (pid 30) is already a live node from section [10] above.
        ok = engine.attribute_causality(
            30, "nyx_leak", "example.test sent your device identifier to "
                            "an unrelated server (tracker.example)",
            data={"category": "identifier",
                  "destination_host": "tracker.example"})
        _check("a resolvable pid attributes successfully", ok is True)
        sg2 = engine.causality_subgraph(30)
        _check("the Nyx observation appears as an artifact on that process",
               any(a["kind"] == "nyx_leak" and "tracker.example" in a["summary"]
                   for a in sg2["artifacts"]))
        _check("attaching a Nyx leak raised no incident of its own",
               len(engine.list_incidents()) == len(incs))

        # The honest-drop case: a pid the graph has never seen, and no name
        # supplied to create a node from - same rule section [6] already
        # proved for the process/network telemetry path.
        not_ok = engine.attribute_causality(999999, "nyx_leak", "unattached")
        _check("an unresolvable pid is dropped, not guessed", not_ok is False)

        engine.stop()
        store.stop()

    print("\n" + "=" * 50)
    if _FAILURES:
        print(f"FAILED ({len(_FAILURES)}): " + "; ".join(_FAILURES))
        return 1
    print("All causality-graph structural checks passed.")
    print("NOTE: structure only — this is not a detection-rate measurement.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
