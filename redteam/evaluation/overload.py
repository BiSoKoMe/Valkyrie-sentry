#!/usr/bin/env python3
"""Progressive-overload cycle - ONE command, safe to loop or schedule.

    python redteam/evaluation/overload.py

Runs one rep:
  1. the evasion harness (obfuscated variants through the real classifiers), then
  2. the ratchet (compare to the high-water mark; refuse to slide back).

Exit code is the whole point of it being automatable:
  * 0  - the ratchet HELD (steady or gained). Ledger updated on a gain.
  * 1  - the ratchet BROKE - a variant that once resisted now evades. The
         ledger is left at the last good state. Wire this into a loop, a
         pre-commit hook or a scheduled task and a regression stops the line
         instead of landing silently.

Designed to be driven by `/loop` or Windows Task Scheduler. It is OFFLINE and
pure of the host - it starts no service, touches no network, no firewall, no
Sysmon - so it is safe to run on a cadence on a live machine. What it measures
is classifier evasion RESISTANCE, not live end-to-end detection; see
ratchet.py's honest-scope note.

--fail-on-headroom makes any currently-evading variant (not just a regression)
non-zero too - stricter, for when you want the loop to keep nagging until the
newest plate is lifted rather than merely holding what you have.
"""

from __future__ import annotations

import argparse
import glob
import io
import json
import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

import ratchet as R            # noqa: E402
import evasion_harness         # noqa: E402


def _newest_result() -> str | None:
    hits = sorted(glob.glob(str(_HERE / "results" / "*__evasion.json")))
    return hits[-1] if hits else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ledger", default=str(_HERE / "evasion_ratchet.json"))
    ap.add_argument("--no-save", action="store_true",
                    help="report only; never persist the ledger")
    ap.add_argument("--fail-on-headroom", action="store_true",
                    help="exit non-zero if ANY variant currently evades, not "
                         "only on a regression")
    args = ap.parse_args()

    print("=" * 60)
    print(" PROGRESSIVE-OVERLOAD REP: evasion harness -> ratchet")
    print("=" * 60)

    # --- rep, phase 1: run the harness ------------------------------------
    print("\n[1/2] evasion harness ...")
    rc = evasion_harness.main()
    if rc != 0:
        print(f"harness exited {rc}; aborting the rep before scoring.")
        return 2

    result_path = _newest_result()
    if not result_path:
        print("no evasion result produced; cannot score.")
        return 2

    # --- rep, phase 2: ratchet -------------------------------------------
    print("\n[2/2] ratchet ...")
    run_summary = json.load(io.open(result_path, encoding="utf-8"))
    ledger = None
    if os.path.exists(args.ledger):
        ledger = json.load(io.open(args.ledger, encoding="utf-8"))

    new_led, report = R.update_ledger(ledger, run_summary)
    print(f"\nresult: {os.path.basename(result_path)}")
    print(R.render(report))

    if report.ok and not args.no_save:
        io.open(args.ledger, "w", encoding="utf-8").write(json.dumps(new_led, indent=2))
        print(f"\nledger updated: {os.path.basename(args.ledger)}")
    elif not report.ok:
        print("\nledger NOT updated - resolve the regression, or reset the "
              "ledger deliberately with a recorded reason.")

    # --- verdict ----------------------------------------------------------
    if not report.ok:
        return 1
    if args.fail_on_headroom and report.headroom:
        total = sum(len(d.headroom) for d in report.headroom)
        print(f"\n--fail-on-headroom: {total} variant(s) still evade - "
              f"the next plate is not lifted yet.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
