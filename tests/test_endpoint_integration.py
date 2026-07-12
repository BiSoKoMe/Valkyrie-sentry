#!/usr/bin/env python3
"""End-to-end: process telemetry -> EDR incident (ADR-0013).

Proves the wiring that turns a flagged process observation into a correlated
incident through the same engine that handles DNS detections, and that benign
observations are not escalated.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def main() -> int:
    from valkyrie.store import Store
    from valkyrie.edr import EdrEngine
    from valkyrie.process_telemetry import ProcInfo
    from valkyrie import telemetry as T

    print("\n=== endpoint telemetry -> EDR incident ===\n")

    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "edr_ep.db")
        store.start()
        edr = EdrEngine(store)
        edr.start()

        print("[1] A high-severity process exec becomes an incident")
        ev = ProcInfo(pid=4321, name="cmd.exe", path="C:/x/cmd.exe",
                      ppid=100, parent_name="winword.exe",
                      create_time=1000.0).to_event()
        _check("event is flagged/high before ingest",
               ev.action == T.ACT_FLAGGED and ev.severity == T.SEV_HIGH)
        inc_id = edr.ingest_telemetry(ev)
        _check("ingest returned an incident id", bool(inc_id))
        incidents = edr.list_incidents()
        _check("one incident now exists", len(incidents) == 1)
        if incidents:
            inc = incidents[0]
            _check("incident carries the process name",
                   inc.get("process_name") == "cmd.exe")
            _check("incident severity is high", inc.get("severity") == "high")

        print("\n[2] Accepts a plain dict too (loose coupling)")
        inc_id2 = edr.ingest_telemetry(ev.to_dict())
        _check("dict ingest also correlates", bool(inc_id2))

        print("\n[3] Benign (info) observations are NOT escalated")
        benign = ProcInfo(pid=5, name="chrome.exe",
                          path="C:/Program Files/chrome.exe",
                          create_time=1001.0).to_event()
        _check("benign event is observed/info",
               benign.action == T.ACT_OBSERVED and benign.severity == T.SEV_INFO)
        before = len(edr.list_incidents())
        res = edr.ingest_telemetry(benign)
        after = len(edr.list_incidents())
        _check("benign ingest creates no incident", res is None and after == before)

        edr.stop()
        store.stop()

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
