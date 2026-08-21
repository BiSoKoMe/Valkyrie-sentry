#!/usr/bin/env python3
"""Union Tier B coverage across runs — the only number that is actually honest.

WHY THIS EXISTS
---------------
No single live run on a GitHub-hosted runner is trustworthy. Measured on the
same config: one run reported 4/39, another 27/39. The variance is not the
detector changing its mind — it is the *rig*:

  * the genuinely destructive atomics (service stop/RPC, Defender disable,
    event-log clear) can crash the runner mid-battery,
  * the job can hit its timeout,
  * SensorManager's bounded queue deliberately drops the OLDEST event under a
    burst of near-simultaneous atomics, so a technique can execute and simply
    not be delivered.

Every one of those failure modes UNDERCOUNTS and none of them can overcount:
a technique is only ever recorded as detected when a matching incident was
actually observed. So the union across runs is a *floor*, not an average —
"we have proven Valkyrie detects at least these techniques live" — and it is
the number to quote.

It reads both the final aggregate JSONs and the crash-proof `.partial.jsonl`
streams, so a run that died halfway still contributes everything it proved.

USAGE
  python redteam/evaluation/union_coverage.py                       # all results/
  python redteam/evaluation/union_coverage.py path/to/*.json ...    # explicit
  python redteam/evaluation/union_coverage.py --json                # machine-readable
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "results")


def _iter_records(path: str):
    """Yield records from either an aggregate .json or a .partial.jsonl stream."""
    try:
        if path.endswith(".jsonl"):
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        # A crash can truncate the final line mid-write. Losing
                        # one record is fine; losing the file is not.
                        continue
        else:
            with open(path, encoding="utf-8") as fh:
                blob = json.load(fh)
            for rec in blob.get("records", []):
                yield rec
    except (OSError, json.JSONDecodeError) as exc:
        print(f"  ! skipping {os.path.basename(path)}: {exc}", file=sys.stderr)


def collect(paths: list[str]) -> tuple[dict, dict, list[str]]:
    """-> (per-technique union state, per-run summary, files actually read)"""
    union: dict[str, dict] = {}
    per_run: dict[str, dict] = {}
    read: list[str] = []

    for path in sorted(paths):
        base = os.path.basename(path)
        run_detected, run_seen = set(), set()
        any_rec = False

        for rec in _iter_records(path):
            tid = rec.get("technique_id") or rec.get("id")
            if not tid:
                continue
            any_rec = True
            ident = rec.get("id") or tid
            outcome = rec.get("outcome") or ""
            detected = bool(rec.get("counted_as_detected"))

            run_seen.add(ident)
            if detected:
                run_detected.add(ident)

            slot = union.setdefault(ident, {
                "id": ident,
                "technique_id": tid,
                "technique_name": rec.get("technique_name", ""),
                "tactic": rec.get("tactic", ""),
                "destructive": bool(rec.get("destructive")),
                "detected": False,
                "proven_by": None,
                "outcomes": set(),
                "attempts": 0,
                "matched_source": None,
            })
            slot["attempts"] += 1
            if outcome:
                slot["outcomes"].add(outcome)
            # First proof wins and is never downgraded — a later run that
            # dropped the event does not un-prove an earlier real detection.
            if detected and not slot["detected"]:
                slot["detected"] = True
                slot["proven_by"] = base
                slot["matched_source"] = rec.get("matched_source")

        if any_rec:
            read.append(base)
            per_run[base] = {"detected": len(run_detected), "seen": len(run_seen)}

    return union, per_run, read


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", help="result files (default: all Tier B in results/)")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args()

    paths = args.paths
    if not paths:
        paths = (glob.glob(os.path.join(RESULTS, "*tierB.json"))
                 + glob.glob(os.path.join(RESULTS, "*tierB.partial.jsonl")))
    if not paths:
        print("No Tier B result files found. Run the workflow first, or pass paths.",
              file=sys.stderr)
        return 2

    union, per_run, read = collect(paths)
    if not union:
        print("No usable records in the given files.", file=sys.stderr)
        return 2

    detected = sorted(k for k, v in union.items() if v["detected"])
    missed = sorted(k for k, v in union.items() if not v["detected"])
    total = len(union)
    pct = (100.0 * len(detected) / total) if total else 0.0

    if args.json:
        out = {
            "files_read": read,
            "per_run": per_run,
            "total_techniques_attempted": total,
            "union_detected": len(detected),
            "union_percent": round(pct, 1),
            "detected": detected,
            "not_detected": missed,
            "techniques": {
                k: {**v, "outcomes": sorted(v["outcomes"])} for k, v in union.items()
            },
        }
        print(json.dumps(out, indent=2))
        return 0

    print("=" * 74)
    print("  TIER B UNION COVERAGE — the proven floor across all runs")
    print("=" * 74)
    print(f"  Files read: {len(read)}")
    for base in read:
        r = per_run[base]
        print(f"    {r['detected']:>3}/{r['seen']:<3} detected   {base}")
    print()
    print(f"  UNION: {len(detected)}/{total} techniques proven detectable live "
          f"({pct:.1f}%)")
    print()
    print("  This is a FLOOR, not an average: every rig failure mode "
          "(runner crash,\n  job timeout, sensor-queue drop) undercounts and "
          "none can overcount.")
    print()

    by_tactic: dict[str, list] = defaultdict(list)
    for ident in missed:
        by_tactic[union[ident]["tactic"] or "(untagged)"].append(union[ident])
    if missed:
        print(f"  NOT YET PROVEN ({len(missed)}):")
        for tactic in sorted(by_tactic):
            print(f"    {tactic}")
            for v in sorted(by_tactic[tactic], key=lambda x: x["id"]):
                outs = ", ".join(sorted(v["outcomes"])) or "no outcome recorded"
                print(f"      - {v['id']:<34} {v['technique_id']:<12} [{outs}]")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
