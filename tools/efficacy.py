#!/usr/bin/env python3
r"""Valkyrie efficacy scorecard — the test -> measure -> fix -> retest loop.

Run this on a test box AFTER running an attack battery (e.g. Invoke-AtomicTest).
It answers three questions, in the order that matters:

  1. CAN Valkyrie see?      (sensor-health preflight — the command-line eye)
  2. What did it catch?     (detection rate vs the regression set)
  3. Did it act, cleanly?   (response rate + false-positive count)

The preflight comes first on purpose: if the command-line eye is closed, a low
detection score means Valkyrie is BLIND, not wrong — do not tune rules, fix the
sensor. (That exact confusion cost days once.)

Usage:
    python tools/efficacy.py                     # live: query the running engine
    python tools/efficacy.py --incidents f.json  # score a saved incidents dump
    python tools/efficacy.py --save baseline.json  # write the scorecard as a
                                                    # regression artifact

Reads the engine over the loopback API (default http://127.0.0.1:8090); needs no
source tree beyond this repo. Exits non-zero if the eye is closed or detection
regressed below --min-detection (default 0.6), so it can gate a CI/retest run.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.efficacy import sensor_health, score, ATOMIC_REGRESSION_SET


def _get(base: str, path: str):
    try:
        with urllib.request.urlopen(base.rstrip("/") + path, timeout=5) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as exc:      # noqa: BLE001
        print(f"  ! could not reach {path}: {exc}")
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Valkyrie efficacy scorecard")
    ap.add_argument("--base", default="http://127.0.0.1:8090",
                    help="engine loopback API base")
    ap.add_argument("--incidents", help="score a saved incidents JSON instead of live")
    ap.add_argument("--save", help="write the scorecard JSON here (regression artifact)")
    ap.add_argument("--min-detection", type=float, default=0.6,
                    help="fail (exit 2) if detection rate is below this")
    args = ap.parse_args()

    print("=" * 66)
    print("VALKYRIE EFFICACY SCORECARD")
    print("=" * 66)

    # 1. Preflight — can it see?
    health = sensor_health()
    eye = "OPEN" if health.command_line_eye_open else "CLOSED"
    print(f"\n[1] Command-line eye: {eye}  (source: {health.command_line_source})")
    print(f"    {health.detail}")
    if not health.command_line_eye_open:
        print("\n>>> BLIND: fix the sensor before trusting any detection score. "
              "A miss below is plumbing, not a rule gap.")

    # 2/3. Gather observed incidents + responses.
    if args.incidents:
        incidents = json.loads(Path(args.incidents).read_text(encoding="utf-8"))
        responses = []
    else:
        incidents = _get(args.base, "/api/edr/incidents") or []
        responses = []
        for inc in incidents[:60]:
            det = _get(args.base, f"/api/edr/incidents/{inc.get('id')}")
            if det:
                responses += det.get("responses", [])

    sc = score(incidents, responses=responses)

    print(f"\n[2] Detection: {len(sc.detected)}/{sc.total_expected} "
          f"({sc.detection_rate:.0%})   [{sc.total_incidents} incidents scanned]")
    for tid in sc.detected:
        print(f"    + {tid:<11} {ATOMIC_REGRESSION_SET.get(tid, '')}")
    for tid in sc.missed:
        print(f"    - {tid:<11} {ATOMIC_REGRESSION_SET.get(tid, '')}   MISSED")

    print(f"\n[3] Response: {sc.response_rate:.0%} of detected auto-actioned"
          f"   ·   False positives: {sc.fp_count}")
    for fp in sc.false_positives:
        print(f"    FP  {fp}")

    print("\n" + "-" * 66)
    print("SUMMARY:", sc.summary())

    out = {"sensor_health": health.to_dict(), "scorecard": sc.to_dict()}
    if args.save:
        Path(args.save).write_text(json.dumps(out, indent=2), encoding="utf-8")
        print(f"saved regression artifact -> {args.save}")

    # Gate: blind, or detection regressed.
    if not health.command_line_eye_open:
        return 3
    if sc.detection_rate < args.min_detection:
        print(f"FAIL: detection {sc.detection_rate:.0%} < min {args.min_detection:.0%}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
