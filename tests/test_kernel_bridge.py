#!/usr/bin/env python3
"""Kernel-driver bridge tests — the user-mode side of driver/valkyrie_km.

The kernel driver itself cannot be built/loaded here (no WDK/signing), so these
tests exercise exactly the part that runs in user mode: the pure record PARSER
(bytes off the device → normalised telemetry) and the graceful-absence
contract. Synthesised records use the exact shared layout
(driver/valkyrie_km/valkyrie_shared.h).

  [1] Record parsing: each event kind → correct normalised event; version
      mismatch and short buffers rejected; FILETIME → epoch
  [2] Lineage: a kernel process-create carries ppid through for correlation
  [3] Graceful absence: the sensor self-disables with no driver loaded
  [4] Pipeline: an LSASS-block event raises a real high credential-access
      detection through the unchanged EDR ingest path
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def _pack(version, etype, ts, pid, ppid, flags, granted, image="", extra=""):
    from valkyrie.kernel_bridge import _HEADER, _PATH_BYTES
    hdr = _HEADER.pack(version, etype, ts, pid, ppid, flags, granted)

    def field(s):
        b = s.encode("utf-16-le")[: _PATH_BYTES - 2]
        return b + b"\x00" * (_PATH_BYTES - len(b))
    return hdr + field(image) + field(extra)


def main() -> int:
    from valkyrie import kernel_bridge as kb

    print("\n=== kernel-driver bridge ===\n")

    print("[1] Record parsing")
    # LSASS access blocked — requestor mimikatz.exe, some rights left.
    ft = 133_000_000_000_000_000        # a plausible FILETIME
    rec = _pack(kb.VLK_PROTO_VERSION, kb.VLK_EVT_LSASS_ACCESS_BLOCKED, ft,
                4321, 0, 0, 0x1000, extra=r"C:\tools\mimikatz.exe")
    ev = kb.record_to_event(rec)
    _check("LSASS block parses", ev is not None)
    _check("LSASS block is high severity", ev and ev["severity"] == "high")
    _check("LSASS block is flagged (→ becomes a detection)", ev and ev["action"] == "flagged")
    _check("LSASS block carries the lsass_access label (→ T1003.001)",
           ev and ev["labels"] == ["lsass_access"])
    _check("LSASS actor is the requestor image basename",
           ev and ev["actor_name"] == "mimikatz.exe")
    _check("LSASS granted_access preserved", ev and ev["fields"]["granted_access"] == 0x1000)

    # Process create with parent — the lineage the correlator needs.
    rec = _pack(kb.VLK_PROTO_VERSION, kb.VLK_EVT_PROCESS_CREATE, ft,
                200, 100, 0, 0, image=r"C:\Windows\System32\rundll32.exe")
    ev = kb.record_to_event(rec)
    _check("process-create parses", ev is not None)
    _check("process-create is visibility (info)", ev and ev["severity"] == "info")
    _check("process-create actor basename", ev and ev["actor_name"] == "rundll32.exe")
    _check("process-create carries ppid for lineage", ev and ev["fields"]["ppid"] == 100)

    # Image load — remote is a flagged anomaly, local is visibility.
    r_remote = _pack(kb.VLK_PROTO_VERSION, kb.VLK_EVT_IMAGE_LOAD, ft, 500, 0,
                     kb.VLK_FLAG_REMOTE_IMAGE, 0, extra=r"\\evil\share\eviltool.dll")
    ev = kb.record_to_event(r_remote)
    _check("remote image load is flagged medium", ev and ev["severity"] == "medium"
           and ev["action"] == "flagged")
    r_local = _pack(kb.VLK_PROTO_VERSION, kb.VLK_EVT_IMAGE_LOAD, ft, 500, 0, 0, 0,
                    extra=r"C:\Windows\System32\ntdll.dll")
    ev = kb.record_to_event(r_local)
    _check("local image load is visibility (info observed)",
           ev and ev["severity"] == "info" and ev["action"] == "observed")

    # Process exit → no actionable signal.
    _check("process-exit yields no event",
           kb.record_to_event(_pack(kb.VLK_PROTO_VERSION, kb.VLK_EVT_PROCESS_EXIT,
                                    ft, 200, 0, 0, 0)) is None)
    # Version mismatch → refuse to parse (never misread kernel memory).
    _check("version mismatch rejected",
           kb.record_to_event(_pack(999, kb.VLK_EVT_PROCESS_CREATE, ft, 1, 0, 0, 0)) is None)
    # Short buffer → None.
    _check("short buffer rejected", kb.record_to_event(b"\x00" * 10) is None)
    # FILETIME → epoch (2022-ish for this tick value), sane range.
    epoch = kb._win_filetime_to_epoch(ft)
    _check("FILETIME converts to a sane epoch", 1.5e9 < epoch < 2.5e9)

    print("\n[2] Multi-record buffer")
    buf = (_pack(kb.VLK_PROTO_VERSION, kb.VLK_EVT_PROCESS_CREATE, ft, 200, 100, 0, 0,
                 image=r"C:\a.exe")
           + _pack(kb.VLK_PROTO_VERSION, kb.VLK_EVT_PROCESS_EXIT, ft, 200, 0, 0, 0)  # dropped
           + _pack(kb.VLK_PROTO_VERSION, kb.VLK_EVT_LSASS_ACCESS_BLOCKED, ft, 4321, 0, 0,
                   0, extra=r"C:\m.exe"))
    evs = kb.parse_records(buf)
    _check("buffer splits into the 2 actionable events (exit dropped)", len(evs) == 2)

    print("\n[3] Graceful absence (no driver loaded here)")
    sensor = kb.KernelSensor()
    _check("sensor unavailable without the driver", sensor.available() is False)
    _check("record size matches the shared layout (32 + 520 + 520)",
           kb.RECORD_SIZE == 1072)

    print("\n[4] Pipeline — LSASS block → real credential-access detection")
    import tempfile
    from valkyrie.store import Store
    from valkyrie.edr import EdrEngine
    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "k.db"); store.start()
        engine = EdrEngine(store); engine.start()
        lsass = kb.record_to_event(_pack(kb.VLK_PROTO_VERSION,
                    kb.VLK_EVT_LSASS_ACCESS_BLOCKED, ft, 4321, 0, 0, 0,
                    extra=r"C:\tools\mimikatz.exe"))
        inc_id = engine.ingest_telemetry(lsass)
        _check("LSASS block created an incident", inc_id is not None)
        if inc_id:
            inc = engine.get_incident(inc_id)
            det = (inc.get("detections") or [{}])[0]
            _check("detection maps to LSASS credential access (T1003.001)",
                   "T1003.001" in (det.get("technique") or ""))
            _check("incident is high severity", inc["severity"] == "high")
        engine.stop(); store.stop()

    print("\n" + "=" * 50)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
