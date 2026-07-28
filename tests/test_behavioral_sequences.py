#!/usr/bin/env python3
"""Behavioral sequence IOA tests (valkyrie/behavioral_sequences.py).

CrowdStrike-style Event Stream Processing: a NAMED attack pattern fires only
when its ordered behaviours complete on ONE process lineage within the window —
tool-agnostically, and NOT when the pieces are out of order, too slow, or on
unrelated processes (the precision boundary that separates a real ESP IOA from
noise).

  [1] Each shipped sequence fires on its in-order behaviour chain
  [2] Every sequence's culminating technique maps to a chain-ready tactic
  [3] Order matters — the reverse order does NOT fire
  [4] Window matters — too slow does NOT fire
  [5] Lineage — a child process's behaviour advances its parent's sequence
  [6] Isolation — the same behaviours split across unrelated actors do NOT fire
  [7] Tool-agnostic — a novel tool with the same behaviour labels still fires
  [8] Pipeline: a completed sequence becomes one 'attack_sequence' incident
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def main() -> int:
    from valkyrie.behavioral_sequences import SequenceEngine, SEQUENCES, Step
    from valkyrie.edr.killchain import tactic_for

    print("\n=== behavioral sequence IOAs (ESP) ===\n")

    # Representative in-order behaviour chains (technique, labels) per rule.
    # Each behaviour is one detection on the same actor pid unless noted.
    CHAINS = {
        "inject-then-creds": [
            ("T1055 — Process Injection", ["remote_thread"]),
            ("T1003.001 — LSASS Memory", ["lsass_access"]),
        ],
        "creds-then-exfil": [
            ("T1003.001 — LSASS Memory", ["lsass_access"]),
            ("T1071 — Application Layer Protocol", ["c2"]),
        ],
        "macro-dropper-c2": [
            ("T1059 — Command & Scripting Interpreter", ["office_child_shell"]),
            ("T1105 — Ingress Tool Transfer", ["download_cradle"]),
        ],
        "ransomware-detonation": [
            ("T1490 — Inhibit System Recovery", ["shadow_delete"]),
            ("T1486 — Data Encrypted for Impact", ["mass_encryption"]),
        ],
        "download-then-persist": [
            ("T1105 — Ingress Tool Transfer", ["certutil_download"]),
            ("T1547.001 — Registry Run Keys / Startup", ["persistence_runkey"]),
        ],
    }

    print(f"[1] Each shipped sequence ({len(SEQUENCES)}) fires in order")
    _check("a representative chain exists for every sequence",
           {r.id for r in SEQUENCES} == set(CHAINS))
    for rule in SEQUENCES:
        eng = SequenceEngine()
        fired = None
        for i, (tech, labels) in enumerate(CHAINS[rule.id]):
            fired = eng.observe("actor.exe", tech, labels, "", ts=100.0 + i,
                                pid=1000, ppid=1) or fired
        _check(f"{rule.id} fires", fired is not None and fired["rule_id"] == rule.id)

    print("\n[2] Culminating technique maps to a chain-ready tactic")
    for rule in SEQUENCES:
        _check(f"{rule.id} → {rule.technique.split(' ')[0]} has a tactic",
               tactic_for(rule.technique) is not None)

    print("\n[3] Order matters — reversed does NOT fire")
    eng = SequenceEngine()
    fired = None
    for i, (tech, labels) in enumerate(reversed(CHAINS["inject-then-creds"])):
        fired = eng.observe("a.exe", tech, labels, "", ts=200.0 + i, pid=7, ppid=1) or fired
    _check("credential-access THEN injection does not complete inject-then-creds",
           fired is None or fired["rule_id"] != "inject-then-creds")

    print("\n[4] Window matters — too slow does NOT fire")
    eng = SequenceEngine()
    r = next(x for x in SEQUENCES if x.id == "inject-then-creds")
    f1 = eng.observe("a.exe", "T1055 — Process Injection", ["remote_thread"], "",
                     ts=0.0, pid=9, ppid=1)
    f2 = eng.observe("a.exe", "T1003.001 — LSASS Memory", ["lsass_access"], "",
                     ts=r.window + 5.0, pid=9, ppid=1)   # past the window
    _check("second step past the window does not fire", f1 is None and f2 is None)

    print("\n[5] Lineage — a child's behaviour advances the parent's sequence")
    eng = SequenceEngine()
    # Parent (pid 100) injects; child (pid 200, ppid 100) reads LSASS.
    eng.observe("powershell.exe", "T1055 — Process Injection", ["remote_thread"], "",
                ts=10.0, pid=100, ppid=1)
    fired = eng.observe("rundll32.exe", "T1003.001 — LSASS Memory", ["lsass_access"], "",
                        ts=12.0, pid=200, ppid=100)
    _check("child LSASS access completes the parent's injection sequence",
           fired is not None and fired["rule_id"] == "inject-then-creds")

    print("\n[6] Isolation — unrelated actors do NOT fire")
    eng = SequenceEngine()
    eng.observe("a.exe", "T1055 — Process Injection", ["remote_thread"], "",
                ts=1.0, pid=11, ppid=1)
    fired = eng.observe("b.exe", "T1003.001 — LSASS Memory", ["lsass_access"], "",
                        ts=2.0, pid=22, ppid=1)   # different lineage
    _check("injection on one actor + creds on an unrelated actor does not fire",
           fired is None)

    print("\n[7] Tool-agnostic — a novel tool with the same behaviour still fires")
    eng = SequenceEngine()
    eng.observe("brandnew_injector_v9.exe", "T1055 — Process Injection",
                ["remote_thread"], "", ts=1.0, pid=33, ppid=1)
    fired = eng.observe("never_seen_dumper.exe", "T1003.001 — LSASS Memory",
                        ["lsass_access"], "", ts=2.0, pid=33, ppid=1)
    _check("unknown tooling with the right behaviours completes the sequence",
           fired is not None and fired["rule_id"] == "inject-then-creds")

    print("\n[8] Pipeline — a completed sequence → one 'attack_sequence' incident")
    import tempfile
    from valkyrie.store import Store
    from valkyrie.edr import EdrEngine
    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "s.db"); store.start()
        engine = EdrEngine(store); engine.start()
        # Feed two real detections on one actor: injection, then LSASS access.
        engine.ingest_telemetry({
            "category": "process", "activity": "thread_inject", "action": "flagged",
            "severity": "high", "labels": ["remote_thread"], "reason": "remote thread",
            "actor_name": "evil.exe", "actor_pid": 4242,
            "fields": {"technique": "T1055 — Process Injection", "ppid": 1}})
        engine.ingest_telemetry({
            "category": "process", "activity": "lsass_access", "action": "flagged",
            "severity": "high", "labels": ["lsass_access"], "reason": "lsass read",
            "actor_name": "evil.exe", "actor_pid": 4242,
            "fields": {"technique": "T1003.001 — LSASS Memory", "ppid": 1}})
        # Detections are populated by get_incident (list_incidents is a summary).
        seq_inc = None
        for inc in engine.list_incidents():
            dets = engine.get_incident(inc["id"]).get("detections") or []
            if any(d.get("category") == "attack_sequence" for d in dets):
                seq_inc = inc
                break
        _check("a named attack_sequence incident was raised", seq_inc is not None)
        if seq_inc:
            _check("sequence incident is critical (inject→creds)",
                   seq_inc["severity"] == "critical")
        engine.stop(); store.stop()

    print("\n" + "=" * 56)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print(f"All checks PASSED ({len(SEQUENCES)} sequences).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
