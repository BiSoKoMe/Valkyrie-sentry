#!/usr/bin/env python3
"""Efficacy-harness tests (valkyrie/efficacy.py).

Pins the measurement layer: detection/response/FP scoring and the sensor-health
preflight shape. This is the "proof" the validation-pipeline plan asks for — the
scorer itself must be correct, or the numbers it produces mean nothing.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.efficacy import (
    score, is_false_positive, sensor_health, ATOMIC_REGRESSION_SET, SensorHealth,
)

_fail = 0


def _check(label, ok):
    global _fail
    if not ok:
        _fail += 1
    print(f"  [{'ok  ' if ok else 'FAIL'}] {label}")


def test_detection_scoring():
    print("[1] detection rate counts matched ATT&CK ids")
    observed = [
        {"technique": "T1003.001 — LSASS Memory", "title": "comsvcs dump",
         "process_name": "rundll32.exe"},
        {"technique": "", "title": "Regsvr32 loaded a remote scriptlet (T1218.010)",
         "process_name": "regsvr32.exe"},
        {"technique": "T1053.005 — Scheduled Task", "process_name": "schtasks.exe"},
    ]
    sc = score(observed)
    _check("LSASS detected", "T1003.001" in sc.detected)
    _check("regsvr32 detected via title", "T1218.010" in sc.detected)
    _check("scheduled task detected", "T1053.005" in sc.detected)
    _check("mshta missed", "T1218.005" in sc.missed)
    _check("rate = 3 / total", abs(sc.detection_rate - 3 / len(ATOMIC_REGRESSION_SET)) < 1e-9)


def test_false_positive_detection():
    print("[2] FP = only unambiguously-benign (self / public resolver), NOT LOLBins")
    _check("valkyrie.exe is a FP", is_false_positive({"process_name": "valkyrie.exe"}))
    _check("public resolver 8.8.8.8 flagged is a FP",
           is_false_positive({"process_name": "conhost.exe", "entity": "8.8.8.8"}))
    # THE bug this pins: a System32 LOLBin doing something malicious is a REAL
    # detection, never a false positive, even though it's a signed OS binary.
    _check("System32 rundll32 (LSASS dump) is NOT a FP",
           not is_false_positive({"process_name": "rundll32.exe",
                                  "entity": r"C:\Windows\System32\rundll32.exe"}))
    _check("real attacker path is NOT a FP",
           not is_false_positive({"process_name": "evil.exe",
                                 "entity": r"C:\Users\u\AppData\Local\Temp\evil.exe"}))
    _check("a bad domain is NOT a FP",
           not is_false_positive({"process_name": "x", "entity": "evil-c2.example"}))
    sc = score([{"technique": "T1003.001", "process_name": "rundll32.exe"},
                {"technique": "", "title": "anomaly", "process_name": "valkyrie.exe"}])
    _check("scorer counts 1 FP (self only, not the rundll32 detection)", sc.fp_count == 1)


def test_window_excludes_stale():
    print("[5] window filter excludes stale incidents (the ghost-FP bug)")
    stale = {"created_at": "2026-08-01T02:45:00+00:00", "process_name": "valkyrie.exe",
             "technique": "", "title": "old self-FP"}
    fresh = {"created_at": "2026-08-02T05:00:00+00:00", "process_name": "rundll32.exe",
             "technique": "T1003.001", "title": "LSASS"}
    sc_all = score([stale, fresh])
    sc_win = score([stale, fresh], since="2026-08-02T00:00:00+00:00")
    _check("all-time counts the stale self-FP", sc_all.fp_count == 1)
    _check("windowed run drops the stale FP", sc_win.fp_count == 0)
    _check("windowed run keeps the real detection", "T1003.001" in sc_win.detected)
    print("[6] only_ran: an un-exercised technique is 'not tested', not 'missed'")
    sc_ran = score([fresh], since="2026-08-02T00:00:00+00:00",
                   only_ran={"T1003.001", "T1047"})
    _check("expected set restricted to what ran", sc_ran.total_expected == 2)
    _check("T1047 (never ran) is the only miss", sc_ran.missed == ["T1047"])


def test_response_rate():
    print("[3] response rate = detected techniques with a real enforced response")
    observed = [{"technique": "T1053.005 — Scheduled Task", "process_name": "schtasks.exe"}]
    responses = [{"technique": "T1053.005", "target": "scheduled_task::ValkTest",
                  "status": "succeeded", "dry_run": 0}]
    sc = score(observed, responses=responses)
    _check("responded to scheduled task", "T1053.005" in sc.responded)
    _check("response rate 100% of detected", abs(sc.response_rate - 1.0) < 1e-9)
    # A dry-run response does NOT count as an enforced response.
    sc2 = score(observed, responses=[{"technique": "T1053.005", "status": "dry_run",
                                      "dry_run": 1}])
    _check("dry-run is not an enforced response", sc2.response_rate == 0.0)


def test_sensor_health_shape():
    print("[4] sensor_health returns a well-formed preflight (no raise)")
    h = sensor_health()
    _check("is SensorHealth", isinstance(h, SensorHealth))
    _check("source is one of the known values",
           h.command_line_source in ("sysmon", "windows-4688", "none"))
    _check("ready == eye_open", h.ready == h.command_line_eye_open)
    _check("has a human detail", bool(h.detail))
    print(f"       (this box: eye={h.command_line_eye_open} via {h.command_line_source})")


def main() -> int:
    print("=" * 60)
    print("Efficacy-harness tests")
    print("=" * 60)
    test_detection_scoring()
    test_false_positive_detection()
    test_response_rate()
    test_sensor_health_shape()
    test_window_excludes_stale()
    print("-" * 60)
    if _fail:
        print(f"{_fail} check(s) FAILED.")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
