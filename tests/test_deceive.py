#!/usr/bin/env python3
"""DECEIVE mechanism — tracker/telemetry gets a decoy dead-end (Standard profile)
instead of a hard block, so the app keeps working while its telemetry goes
nowhere. Stricter profiles hard-block. Malware is NEVER deceived — only blocked.

Pins the profile-aware deceive-vs-block decision at the DNS layer.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))
sys.path.insert(0, str(_HERE))

from valkyrie.decision import should_deceive, Profile
import valkyrie.dns_interceptor as dnsi
from test_dns_decision_matrix import _build, _Scanner, _ScanResult, _PROC

_fail = 0


def _check(label, ok):
    global _fail
    if not ok:
        _fail += 1
    print(f"  [{'ok  ' if ok else 'FAIL'}] {label}")


def _set_profile(p):
    dnsi._PROFILE_CACHE["val"] = p
    dnsi._PROFILE_CACHE["ts"] = time.time()


def main() -> int:
    print("=" * 60)
    print("DECEIVE mechanism")
    print("=" * 60)

    print("[1] should_deceive: trackers only, Standard profile only")
    _check("tracker + Standard -> deceive", should_deceive("tracker", Profile.STANDARD))
    _check("telemetry + Standard -> deceive", should_deceive("telemetry", Profile.STANDARD))
    _check("tracker + High-Risk -> NO deceive (hard block)",
           not should_deceive("tracker", Profile.HIGH_RISK))
    _check("tracker + Clean-Room -> NO deceive", not should_deceive("tracker", Profile.CLEAN_ROOM))
    _check("a malware category is never deceived", not should_deceive("scanner", Profile.STANDARD))

    print("[2] _decide: a tracker is DECEIVED in Standard, BLOCKED in strict profiles")
    di, _ = _build(scanner=_Scanner(
        {"metrics.tracker.io": _ScanResult("block", ("analytics beacon",), 0.9, "tracker")}))
    _set_profile(Profile.STANDARD)
    dec, _, _, cat = di._decide("metrics.tracker.io", 1, _PROC)
    _check("tracker in Standard -> 'deceived'", dec == "deceived")
    _check("category preserved (tracker)", cat == "tracker")
    _set_profile(Profile.HIGH_RISK)
    dec2, _, _, _ = di._decide("metrics.tracker.io", 1, _PROC)
    _check("same tracker in High-Risk -> 'blocked'", dec2 == "blocked")

    print("[3] malware is NEVER deceived — blocked even in Standard")
    di2, _ = _build(scanner=_Scanner(
        {"evil-c2.io": _ScanResult("block", ("malware",), 1.0, "scanner")}))
    _set_profile(Profile.STANDARD)
    dec3, _, _, _ = di2._decide("evil-c2.io", 1, _PROC)
    _check("malware in Standard stays 'blocked' (not deceived)", dec3 == "blocked")

    print("[4] a 'deceived' verdict returns a decoy (dead-end), like a sinkhole")
    import inspect
    src = inspect.getsource(dnsi.DNSInterceptor._build_response)
    _check("deceived shares the decoy/sinkhole branch with blocked",
           '"deceived"' in src and "_sinkhole_response" in src)

    print("-" * 60)
    if _fail:
        print(f"{_fail} check(s) FAILED.")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
