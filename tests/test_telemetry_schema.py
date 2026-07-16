#!/usr/bin/env python3
"""Normalized telemetry event schema + DNS adapter (ADR-0011)."""

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
    from valkyrie import telemetry as T

    print("\n=== normalized telemetry schema ===\n")

    print("[1] Construct + round-trip")
    ev = T.TelemetryEvent(
        category=T.CAT_PROCESS, activity="exec", action=T.ACT_OBSERVED,
        actor_pid=1234, actor_name="powershell.exe",
        target={"path": "C:/x.ps1"}, severity=T.SEV_MEDIUM, source="proc")
    d = ev.to_dict()
    ev2 = T.TelemetryEvent.from_dict(d)
    _check("to_dict/from_dict round-trips", ev2.to_dict() == d)
    _check("category preserved", ev2.category == T.CAT_PROCESS)
    _check("actor_pid preserved", ev2.actor_pid == 1234)
    _check("target preserved", ev2.target["path"] == "C:/x.ps1")

    print("\n[2] bus_message wrapping")
    msg = ev.bus_message()
    _check("wrapped type is 'telemetry'", msg["type"] == "telemetry")
    _check("wrapped event is the dict", msg["event"]["activity"] == "exec")

    print("\n[3] severity ordering")
    _check("info < medium < critical",
           T.severity_rank(T.SEV_INFO) < T.severity_rank(T.SEV_MEDIUM)
           < T.severity_rank(T.SEV_CRITICAL))
    _check("unknown severity ranks as info(0)", T.severity_rank("bogus") == 0)

    print("\n[4] DNS adapter maps decisions -> action/severity")
    cases = {
        "allowed":    (T.ACT_ALLOWED, T.SEV_INFO),
        "flagged":    (T.ACT_FLAGGED, T.SEV_LOW),
        "behavioral": (T.ACT_BLOCKED, T.SEV_MEDIUM),
    }
    for decision, (want_action, want_sev) in cases.items():
        te = T.from_dns_event({"domain": "x.com", "decision": decision,
                               "process_name": "chrome", "suspicion": 0.5})
        _check(f"{decision} -> action {want_action}", te.action == want_action)
        _check(f"{decision} -> severity {want_sev}", te.severity == want_sev)
        _check(f"{decision} -> category dns", te.category == T.CAT_DNS)
        _check(f"{decision} -> target domain", te.target["domain"] == "x.com")

    print("\n[5] High-suspicion block escalates severity")
    te = T.from_dns_event({"domain": "evil.com", "decision": "blocked",
                           "process_name": "mal", "suspicion": 0.95})
    _check("suspicion>=0.9 block -> high", te.severity == T.SEV_HIGH)
    _check("actor_name carried", te.actor_name == "mal")
    _check("source is dns_interceptor", te.source == "dns_interceptor")

    print("\n[6] Adapter accepts full bus message too")
    te = T.from_dns_event({"type": "event", "event": {
        "domain": "y.com", "decision": "blocked", "suspicion": 0.3}})
    _check("unwraps {'type':'event','event':...}", te.target["domain"] == "y.com")
    _check("unwrapped block severity medium", te.severity == T.SEV_MEDIUM)

    print("\n" + "=" * 48)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
