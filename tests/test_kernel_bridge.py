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
  [5] v2 prevention/telemetry: thread-injection, autostart-registry,
      process-BLOCKED (prevention) and self-protect (tamper) events
  [6] Policy: FNV-1a hash matches the kernel; build_policy round-trips + is
      safe (detection-only default, block list capped, hashes deduped)
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

    print("\n[5] v2 prevention + telemetry events")
    # Thread injection: pid = target, ppid = creator (the injector/actor).
    tinj = kb.record_to_event(_pack(kb.VLK_PROTO_VERSION, kb.VLK_EVT_THREAD_CREATE,
                ft, 900, 4321, kb.VLK_FLAG_REMOTE_THREAD, 0,
                image=r"C:\tools\injector.exe"))
    _check("thread-inject parses high + flagged", tinj and tinj["severity"] == "high"
           and tinj["action"] == "flagged")
    _check("thread-inject actor is the injector (creator/ppid)",
           tinj and tinj["actor_pid"] == 4321 and tinj["actor_name"] == "injector.exe")
    _check("thread-inject carries T1055 + target pid",
           tinj and "T1055" in tinj["fields"]["technique"] and tinj["fields"]["target_pid"] == 900)

    # Autostart registry write → persistence T1547.
    reg = kb.record_to_event(_pack(kb.VLK_PROTO_VERSION, kb.VLK_EVT_REGISTRY_SET,
                ft, 700, 0, kb.VLK_FLAG_AUTOSTART, 0, image=r"C:\evil.exe",
                extra=r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"))
    _check("registry-set parses high + flagged", reg and reg["severity"] == "high"
           and reg["action"] == "flagged")
    _check("registry-set is persistence T1547", reg and "T1547" in reg["fields"]["technique"])
    _check("registry-set carries the key path", reg and "CurrentVersion\\Run" in reg["fields"]["key"])

    # Process BLOCKED = prevention. This is action=blocked, the detect->prevent leap.
    blk = kb.record_to_event(_pack(kb.VLK_PROTO_VERSION, kb.VLK_EVT_PROCESS_BLOCKED,
                ft, 808, 100, kb.VLK_FLAG_BLOCKED, 0, image=r"C:\Users\v\Downloads\malware.exe"))
    _check("process-blocked is action=blocked (prevention)", blk and blk["action"] == "blocked")
    _check("process-blocked is critical + labelled prevented",
           blk and blk["severity"] == "critical" and "prevented" in blk["labels"])
    _check("process-blocked names the image", blk and blk["actor_name"] == "malware.exe")

    # Self-protect = tamper attempt against the agent, stripped in kernel.
    sp = kb.record_to_event(_pack(kb.VLK_PROTO_VERSION, kb.VLK_EVT_SELF_PROTECT,
                ft, 666, 4242, kb.VLK_FLAG_TAMPER, 0, extra=r"C:\bad\killer.exe"))
    _check("self-protect is action=blocked critical", sp and sp["action"] == "blocked"
           and sp["severity"] == "critical")
    _check("self-protect actor is the tamperer", sp and sp["actor_name"] == "killer.exe")
    _check("self-protect is T1562.001 + records agent pid",
           sp and "T1562.001" in sp["fields"]["technique"] and sp["fields"]["agent_pid"] == 4242)

    print("\n[6] Enforcement policy — hash parity + safe serialisation")
    # FNV-1a must equal a hand-computed reference so the kernel + bridge agree.
    def _fnv_ref(name: str) -> int:
        h = 2166136261
        for ch in name.lower():
            h ^= (ord(ch) & 0xFF)
            h = (h * 16777619) & 0xFFFFFFFF
        return h
    _check("fnv1a_32 matches reference for 'mimikatz.exe'",
           kb.fnv1a_32("mimikatz.exe") == _fnv_ref("mimikatz.exe"))
    _check("fnv1a_32 is basename-only + case-insensitive",
           kb.fnv1a_32(r"C:\X\Mimikatz.EXE") == kb.fnv1a_32("mimikatz.exe"))
    # build_policy: default is detection-only (no enable bits).
    pol = kb.build_policy()
    ver, flags, agent, count = struct.unpack_from("<IIII", pol, 0)
    _check("policy version stamped", ver == kb.VLK_PROTO_VERSION)
    _check("default policy is detection-only (no enable flags)", flags == 0)
    _check("policy struct is exactly the shared size",
           len(pol) == kb._POLICY.size)
    # Prevention + self-protect enabled, with a deduped block list.
    pol2 = kb.build_policy(agent_pid=1234, block_names=["evil.exe", "EVIL.EXE", "x.exe"],
                           prevention=True, self_protect=True)
    ver, flags, agent, count = struct.unpack_from("<IIII", pol2, 0)
    _check("prevention + self-protect bits set",
           flags == (kb.VLK_POLICY_ENABLE_PREVENTION | kb.VLK_POLICY_ENABLE_SELFPROTECT))
    _check("agent pid carried", agent == 1234)
    _check("block list deduped (evil.exe==EVIL.EXE) → 2 entries", count == 2)
    hashes = struct.unpack_from("<%dI" % kb.VLK_MAX_BLOCK_HASHES, pol2, 16)
    _check("first block hash matches fnv1a_32('evil.exe')",
           hashes[0] == kb.fnv1a_32("evil.exe"))
    # Overflow safety: more than the cap → clamped, never overflows the array.
    big = kb.build_policy(block_names=[f"m{i}.exe" for i in range(kb.VLK_MAX_BLOCK_HASHES + 50)])
    _, _, _, bigcount = struct.unpack_from("<IIII", big, 0)
    _check("block list capped at VLK_MAX_BLOCK_HASHES",
           bigcount == kb.VLK_MAX_BLOCK_HASHES and len(big) == kb._POLICY.size)

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
