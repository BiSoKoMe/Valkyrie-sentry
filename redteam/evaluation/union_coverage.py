#!/usr/bin/env python3
"""Union Tier B coverage across runs - the only number that is actually honest.

WHY THIS EXISTS
---------------
No single live run on a GitHub-hosted runner is trustworthy. Measured on the
same config: one run reported 4/39, another 27/39. The variance is not the
detector changing its mind - it is the *rig*:

  * the genuinely destructive atomics (service stop/RPC, Defender disable,
    event-log clear) can crash the runner mid-battery,
  * the job can hit its timeout,
  * SensorManager's bounded queue deliberately drops the OLDEST event under a
    burst of near-simultaneous atomics, so a technique can execute and simply
    not be delivered.

Every one of those failure modes UNDERCOUNTS and none of them can overcount:
a technique is only ever recorded as detected when a matching incident was
actually observed. So the union across runs is a *floor*, not an average -
"we have proven Valkyrie detects at least these techniques live" - and it is
the number to quote.

It reads both the final aggregate JSONs and the crash-proof `.partial.jsonl`
streams, so a run that died halfway still contributes everything it proved.

USAGE
  python redteam/evaluation/union_coverage.py                       # all results/
  python redteam/evaluation/union_coverage.py path/to/*.json ...    # explicit
  python redteam/evaluation/union_coverage.py --json                # machine-readable

UNIONING REAL CI RUNS
  Each CI run uploads its own `tier-b-results` artifact, so the cross-run union
  has to be assembled locally. Pull several runs and point this at all of them:

      gh run list --workflow=redteam-tierb.yml --limit 10
      for id in <run-id> <run-id> <run-id>; do
          gh run download $id -n tier-b-results -D ci/$id
      done
      python redteam/evaluation/union_coverage.py ci/*/redteam/evaluation/results/*

  A run whose battery CRASHED still contributes: its `.partial.jsonl` is
  uploaded alongside the aggregate JSON precisely so its proven techniques are
  not lost with the job.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "results")

_DETECTED_TECH = re.compile(r"DETECTED-TECH:\s*(T\d{4}(?:\.\d{3})?)")


def read_db_coverage(path: str) -> set[str]:
    """ATT&CK ids from a saved db_coverage.py run.

    db_coverage reads the incident store at rest, so it is the ONLY evidence
    left by a battery that died before writing any record -- which is exactly
    what the old (pre-streaming) script did on every crash. Folding it in means
    no run is ever a total loss.
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return set(_DETECTED_TECH.findall(fh.read()))
    except OSError as exc:
        print(f"  ! skipping db-coverage {os.path.basename(path)}: {exc}",
              file=sys.stderr)
        return set()


def catalog_techniques() -> tuple[set[str], dict[str, str]]:
    """In-scope ATT&CK ids from the catalog, plus id -> out_of_scope_reason.

    Without this the denominator is whatever happened to be observed, so a
    db-coverage-only union prints "31/31 = 100%" -- which reads as full
    coverage and is badly misleading. The catalog is the real denominator.
    """
    path = os.path.join(HERE, "catalog_export.json")
    try:
        with open(path, encoding="utf-8") as fh:
            blob = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return set(), {}
    entries = blob if isinstance(blob, list) else blob.get("techniques", [])
    in_scope, reasons = set(), {}
    for e in entries:
        tid = e.get("technique_id")
        if not tid:
            continue
        reason = e.get("out_of_scope_reason")
        if reason:
            reasons[tid] = reason
        else:
            in_scope.add(tid)
    return in_scope, reasons


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


def collect(paths: list[str]) -> tuple[dict, dict, list[str], dict]:
    """-> (union state, per-run summary, files read, per-run pacing)"""
    union: dict[str, dict] = {}
    per_run: dict[str, dict] = {}
    read: list[str] = []
    # Pacing changes what a run measures, so runs paced differently are not
    # directly comparable and must not be silently merged into one figure.
    pacing: dict[str, int] = {}

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
                "max_backpressure_drops": 0,
            })
            slot["attempts"] += 1
            settle = rec.get("settle_seconds")
            if settle is not None:
                pacing.setdefault(base, settle)
            bp = rec.get("sensor_dropped_backpressure")
            if isinstance(bp, int) and bp > slot["max_backpressure_drops"]:
                slot["max_backpressure_drops"] = bp
            if outcome:
                slot["outcomes"].add(outcome)
            # First proof wins and is never downgraded - a later run that
            # dropped the event does not un-prove an earlier real detection.
            if detected and not slot["detected"]:
                slot["detected"] = True
                slot["proven_by"] = base
                slot["matched_source"] = rec.get("matched_source")

        if any_rec:
            read.append(base)
            per_run[base] = {"detected": len(run_detected), "seen": len(run_seen)}

    return union, per_run, read, pacing


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", help="result files (default: all Tier B in results/)")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    ap.add_argument("--db-coverage", action="append", default=[], metavar="FILE",
                    help="saved db_coverage.py output; folds a crashed run's "
                         "incident-store ground truth into the union "
                         "(repeatable)")
    args = ap.parse_args()

    paths = args.paths
    if not paths:
        paths = (glob.glob(os.path.join(RESULTS, "*tierB.json"))
                 + glob.glob(os.path.join(RESULTS, "*tierB.partial.jsonl")))
    # --db-coverage alone is a legitimate invocation: a battery that crashed
    # before writing any record leaves its evidence ONLY in the incident store,
    # which is exactly the case this flag exists for.
    if not paths and not args.db_coverage:
        print("No Tier B result files found. Run the workflow first, pass paths, "
              "or supply --db-coverage.", file=sys.stderr)
        return 2

    union, per_run, read, pacing = collect(paths)

    # Fold in incident-store ground truth. Matching is on ATT&CK id, not the
    # catalog's test id, so a technique already present from a JSON record is
    # CREDITED, never counted a second time.
    db_techs: set[str] = set()
    for dbfile in args.db_coverage:
        found = read_db_coverage(dbfile)
        if not found:
            continue
        db_techs |= found
        per_run[f"(db) {os.path.basename(dbfile)}"] = {
            "detected": len(found), "seen": len(found)}
        read.append(f"(db) {os.path.basename(dbfile)}")
    if db_techs:
        by_tid: dict[str, list] = defaultdict(list)
        for v in union.values():
            by_tid[v["technique_id"]].append(v)
        for tid in sorted(db_techs):
            if tid in by_tid:
                for v in by_tid[tid]:
                    if not v["detected"]:
                        v["detected"] = True
                        v["proven_by"] = "incident-store"
            else:
                # Proven live but absent from every record file -- the battery
                # died before it could write this one down.
                union[tid] = {
                    "id": tid, "technique_id": tid, "technique_name": "",
                    "tactic": "(from incident store)", "destructive": False,
                    "detected": True, "proven_by": "incident-store",
                    "outcomes": {"detected"}, "attempts": 1,
                    "matched_source": "incident-store",
                    "max_backpressure_drops": 0,
                }

    if not union:
        print("No usable records in the given files.", file=sys.stderr)
        return 2

    detected = sorted(k for k, v in union.items() if v["detected"])
    missed = sorted(k for k, v in union.items() if not v["detected"])

    # Denominator: the CATALOG, not "whatever this invocation happened to see".
    # Falling back to len(union) would let a db-coverage-only run print 100%.
    in_scope, oos_reasons = catalog_techniques()
    proven_tids = {union[k]["technique_id"] for k in detected}
    if in_scope:
        total = len(in_scope)
        # A catalog entry written as a PARENT (T1555) is satisfied by a proven
        # SUB-technique (T1555.003) -- the sub-technique is an instance of it.
        # The reverse is NOT true: detecting the parent T1059 does not prove
        # the specific sub-technique T1059.003, so that never auto-credits.
        credited = set(proven_tids & in_scope)
        for tid in in_scope - credited:
            if any(p.startswith(tid + ".") for p in proven_tids):
                credited.add(tid)
        covered = len(credited)
        denom_note = "catalog in-scope techniques"
        unproven_tids = sorted(in_scope - credited)
    else:
        total = len(union)
        covered = len(detected)
        denom_note = "techniques observed in these files (catalog unavailable)"
        unproven_tids = []
    pct = (100.0 * covered / total) if total else 0.0

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
    print(f"  UNION: {covered}/{total} techniques proven detectable live "
          f"({pct:.1f}%)   [denominator: {denom_note}]")
    print()
    if len(set(pacing.values())) > 1:
        print("  !! MIXED PACING -- these runs did not measure the same thing:")
        for base, sec in sorted(pacing.items()):
            print(f"       {base}: settle={sec}s")
        print("     Correlation/burst detections only fire when atomics run")
        print("     back-to-back, so a paced run and an unpaced one are not")
        print("     comparable. Union with care.")
        print()
    print("  This is a FLOOR, not an average: every rig failure mode "
          "(runner crash,\n  job timeout, sensor-queue drop) undercounts and "
          "none can overcount.")
    print()
    if in_scope and not any(not v["detected"] for v in union.values()):
        # Incident-store evidence says what WAS detected; it cannot say what was
        # attempted. Destructive atomics are skipped by default, so an unproven
        # technique below may simply never have been run.
        print("  NOTE: built from incident-store evidence only, which records what was")
        print("  DETECTED, not what was ATTEMPTED. An unproven technique below may")
        print("  never have been executed (destructive atomics are skipped by default).")
        print()
    if unproven_tids:
        print(f"  CATALOG TECHNIQUES NOT PROVEN ({len(unproven_tids)}):")
        for tid in unproven_tids:
            parent = tid.split(".")[0]
            note = ""
            if parent != tid and parent in proven_tids:
                note = (f"   [parent {parent} was proven, but that does not "
                        f"prove this sub-technique]")
            print(f"    - {tid}{note}")
        print()
    bonus = sorted(proven_tids - in_scope) if in_scope else []
    if bonus:
        print(f"  Also detected, outside the catalog ({len(bonus)}): {', '.join(bonus)}")
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
                if v["max_backpressure_drops"]:
                    print(f"        ^ BLIND SENSOR, not necessarily a rule gap: "
                          f"{v['max_backpressure_drops']} event(s) dropped by "
                          f"backpressure during this technique")
                # Credit is granted on an EXACT ATT&CK id, so a catalog entry
                # written as the parent (T1555) is not auto-credited by a
                # detection recorded against a sub-technique (T1555.003).
                # Under-crediting keeps the floor honest, but silently listing
                # it as unproven would be misleading -- so say so.
                kin = sorted(t for t in db_techs
                             if t.startswith(v["technique_id"] + "."))
                if kin:
                    print(f"        ^ sub-technique(s) {', '.join(kin)} WERE "
                          f"proven; the parent id is not auto-credited")
        print()
        blind = [v for v in union.values()
                 if not v["detected"] and v["max_backpressure_drops"]]
        if blind:
            print(f"  {len(blind)} of those ran while the sensor queue was "
                  f"dropping events -- re-run before calling them detection gaps.")
            print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
