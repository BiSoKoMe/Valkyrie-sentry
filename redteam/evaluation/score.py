"""Scorer + report generator, shared by Tier A (replay) and Tier B (live VM).

Reads one results JSON (the schema both replay_harness.py and
run_live_evaluation.ps1 emit), computes:

  * overall detection percentage
  * detection percentage BY TACTIC, for all 8 requested tactics
  * the missed-techniques list, each with root cause + concrete code fix
  * a reproducibility block (git commit, catalog version, tier, timestamp)

and writes a Markdown report plus one line to HISTORY.md so runs are
comparable over time.

## The scoring rule this file exists to enforce

"If a detection only occurs because of a user-defined DNS block, do not count
it as a behavioral detection." Implemented literally: a record whose
`detection_category` is `user_rule` is excluded from the DETECTED count,
full stop, regardless of what `counted_as_detected` upstream said. This file
is the last line of defense against that specific inflation, so it re-derives
the exclusion here rather than trusting an upstream flag was set correctly.

"If Valkyrie misses a technique, count it as a failure." Implemented as: only
a record with `counted_as_detected == True` AND `detection_category !=
'user_rule'` counts toward the numerator. CONDITIONAL predictions, known
mismatches, and outright misses all count as failures in the headline number
-- they are broken out separately so the report shows WHY, but none of them
inflate the percentage.

Run:  PYTHONUTF8=1 python redteam/evaluation/score.py <results.json>
      (defaults to the newest file in results/ if no path is given)
"""

from __future__ import annotations

import glob
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent.parent))

from catalog import ALL_TACTICS, CATALOG_VERSION, OUT_OF_SCOPE   # noqa: E402
from root_cause import ARCHITECTURAL_FIX, PER_TECHNIQUE, OVERBROAD_RULE_FINDINGS  # noqa: E402

TACTIC_ORDER = ["Execution", "Persistence", "Defense Evasion",
                "Credential Access", "Discovery", "Lateral Movement",
                "Command and Control", "Impact"]


def _git_commit() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                             cwd=str(_HERE), capture_output=True, text=True,
                             timeout=5)
        return out.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _is_counted(rec: dict) -> bool:
    """Re-derive the scored outcome here, not just trust the input file.

    A detection whose category is 'user_rule' (a user-authored always_block
    entry) NEVER counts, no matter what upstream set -- this is the specific
    exclusion the evaluation brief requires, enforced at the one place a
    report can't accidentally skip it.
    """
    if rec.get("detection_category") == "user_rule":
        return False
    if rec.get("known_mismatch"):
        return False
    return bool(rec.get("counted_as_detected"))


def score(records: list[dict]) -> dict:
    by_tactic: dict[str, dict] = {t: {"detected": 0, "total": 0, "missed": []}
                                  for t in TACTIC_ORDER}
    total_detected = 0
    total = len(records)
    missed_records = []
    excluded_user_rule = []

    for rec in records:
        tactic = rec["tactic"]
        by_tactic.setdefault(tactic, {"detected": 0, "total": 0, "missed": []})
        by_tactic[tactic]["total"] += 1
        counted = _is_counted(rec)
        if rec.get("detection_category") == "user_rule" and rec.get("counted_as_detected"):
            # .get, not rec["id"]: a malformed upstream record must not crash
            # the whole report over one missing field -- the finding it would
            # be reporting (a caught inflation attempt) is too important to
            # lose because of that.
            excluded_user_rule.append(rec.get("id", "<record missing 'id'>"))
        if counted:
            total_detected += 1
            by_tactic[tactic]["detected"] += 1
        else:
            missed_records.append(rec)
            by_tactic[tactic]["missed"].append(rec)

    return {
        "total": total,
        "total_detected": total_detected,
        "overall_pct": (100.0 * total_detected / total) if total else 0.0,
        "by_tactic": by_tactic,
        "missed_records": missed_records,
        "excluded_user_rule": excluded_user_rule,
    }


def _root_cause_for(rec: dict) -> tuple[str, str]:
    """(root_cause, code_change) for one missed record. Never generic filler
    -- falls back to the record's own reasoning fields if no dedicated entry
    exists, and says so, rather than inventing a plausible-sounding cause."""
    entry = PER_TECHNIQUE.get(rec["id"])
    if entry:
        return entry["root_cause"], entry["code_change"]
    if rec["id"] in ARCHITECTURAL_FIX["affects"]:
        return ARCHITECTURAL_FIX["root_cause"], ARCHITECTURAL_FIX["code_change"]
    # No dedicated entry: use what the record itself captured rather than
    # fabricate a cause. This path being hit means root_cause.py needs an
    # entry added -- it is a gap in THIS report's authorship, not silently
    # papered over.
    return (rec.get("detector_path", "not documented -- add an entry to "
                   "root_cause.py for this technique"),
            "NOT YET DOCUMENTED -- flagging rather than inventing. Add a "
            f"PER_TECHNIQUE['{rec['id']}'] entry to root_cause.py.")


def render_markdown(data: dict, records: list[dict], tier: str,
                    catalog_version: str, generated_at: str) -> str:
    s = data
    lines: list[str] = []
    a = lines.append

    a("# Valkyrie EDR Evaluation Report")
    a("")
    a(f"**Tier:** {tier}  ")
    a(f"**Generated:** {generated_at} UTC  ")
    a(f"**Git commit:** {_git_commit()}  ")
    a(f"**Catalog version:** {catalog_version}  ")
    a(f"**Reproduce:** `PYTHONUTF8=1 python redteam/evaluation/replay_harness.py` "
      f"(Tier A) or `redteam/evaluation/run_live_evaluation.ps1` (Tier B, VM only)")
    a("")
    if tier.startswith("A_"):
        a("> **This is Tier A: classifier-input replay.** Real Valkyrie code "
          "was executed against synthetic inputs matching what each "
          "technique would produce. NO live attack ran. `attack_executed`, "
          "measured latency, and aggregate false-positive rate are honestly "
          "`null` throughout -- Tier A cannot produce them, and this report "
          "does not pretend otherwise. Scores here are gated by a source-"
          "verified judgment of whether each technique's detection path is "
          "reliably reachable live (see catalog.py), not by whether the "
          "Python call merely returned truthy. Tier B "
          "(`run_live_evaluation.ps1`, VM required) is what turns this into "
          "a live-attack answer.")
        a("")

    a("## Scoring rules applied")
    a("")
    a("- A miss is a miss. `CONDITIONAL` predictions are **not** credited as "
      "detected in the headline number -- only a confirmed, reliably-"
      "delivered `DETECT` counts.")
    a("- A `DETECT` whose catalog entry declares **host preconditions** "
      "(`requires`, e.g. `sysmon_eid8`) is credited only when those "
      "preconditions are verified **on the machine this run executed on**. "
      "The classifier firing is necessary but not sufficient: if the host "
      "cannot deliver the event, the detection cannot happen. Unmet "
      "preconditions are reported per technique with the reason, and the "
      "host snapshot is stored in the result file's `host_environment` so a "
      "score is never separable from the environment that produced it.")
    a("- A detection whose category is a **user-defined DNS block** "
      "(`detection_category == 'user_rule'`) is excluded from the detected "
      "count and reported separately, per the evaluation brief.")
    if s["excluded_user_rule"]:
        a(f"  - Excluded this run: {', '.join(s['excluded_user_rule'])}")
    else:
        a("  - None triggered this run.")
    a("- A rule firing under the **wrong technique label** (`known_mismatch`) "
      "is never credited, even if the underlying code executed without error.")
    a("")

    a("## Overall")
    a("")
    a(f"**{s['total_detected']} / {s['total']} techniques detected "
      f"({s['overall_pct']:.1f}%)**")
    a("")
    a("| Tactic | Detected | Total | % |")
    a("|---|---:|---:|---:|")
    for tactic in TACTIC_ORDER:
        t = s["by_tactic"].get(tactic, {"detected": 0, "total": 0})
        pct = (100.0 * t["detected"] / t["total"]) if t["total"] else 0.0
        a(f"| {tactic} | {t['detected']} | {t['total']} | {pct:.0f}% |")
    a("")

    a(f"**Explicitly out of scope:** {len(OUT_OF_SCOPE)} techniques, each "
      f"with a stated reason (never silently dropped) -- see catalog.py "
      f"`OUT_OF_SCOPE`.")
    a("")

    a("## Per-test results")
    a("")
    a("| Technique | Test | Tactic | Logic fires | Detected | Severity | "
      "Confidence | Delivery |")
    a("|---|---|---|:---:|:---:|---|---:|---|")
    for r in records:
        counted = _is_counted(r)
        a(f"| {r['technique_id']} {r['technique_name'][:40]} "
          f"| {r['test_number']} | {r['tactic']} "
          f"| {'yes' if r.get('classifier_logic_fires') else 'no'} "
          f"| {'**DETECTED**' if counted else 'missed'} "
          f"| {r['severity_assigned']} | {r['confidence_score']:.2f} "
          f"| {r['delivery_mechanism']} |")
    a("")

    a("## Missed techniques — root cause and required code change")
    a("")
    if not s["missed_records"]:
        a("None.")
    for r in s["missed_records"]:
        root_cause, code_change = _root_cause_for(r)
        a(f"### {r['technique_id']} — {r['technique_name']}  `{r['id']}`")
        a("")
        a(f"- **Tactic:** {r['tactic']}")
        a(f"- **Test:** {r['test_number']}")
        a(f"- **Predicted outcome:** {r.get('predicted_tier_b', 'n/a')}")
        if r.get("known_mismatch"):
            a(f"- **Known mismatch:** {r['known_mismatch']}")
        a(f"- **Root cause:** {root_cause}")
        a(f"- **Code change required:** {code_change}")
        a("")

    a("## Standalone findings (discovered by running the harness)")
    a("")
    for key, f in OVERBROAD_RULE_FINDINGS.items():
        a(f"### {key}")
        a("")
        a(f"- **Discovered via:** {f['discovered_via']}")
        a(f"- **Location:** `{f['location']}`")
        a(f"- **Problem:** {f['problem']}")
        a(f"- **Impact:** {f['impact']}")
        a(f"- **Code change:** {f['code_change']}")
        a("")

    a("## The architectural fix (upgrades the largest number of misses at once)")
    a("")
    a(f"**{ARCHITECTURAL_FIX['title']}**")
    a("")
    a(f"Affects: {', '.join(ARCHITECTURAL_FIX['affects'])}")
    a("")
    a(f"**Root cause:** {ARCHITECTURAL_FIX['root_cause']}")
    a("")
    a(f"**Code change:** {ARCHITECTURAL_FIX['code_change']}")
    a("")
    a(f"**Effort:** {ARCHITECTURAL_FIX['estimated_effort']}")
    a("")

    a("## What this report cannot tell you")
    a("")
    a("- Whether the attack **actually executed successfully** on a real "
      "system (Tier A has no attack to execute).")
    a("- **Measured** detection latency (Tier A has no live clock).")
    a("- Aggregate **false-positive rate** under real system load (see "
      "`tests/test_benign_corpus.py` and `tests/efficacy/harness.py` for "
      "this project's actual FP evidence instead of a fabricated number "
      "here).")
    a("- Whether Sysmon-dependent paths (T1055, T1003.001, and everything "
      "the architectural fix would newly cover) actually fire on a live, "
      "Sysmon-instrumented host -- confirmed only by Tier B.")
    a("- Lateral movement against a REAL second host -- this evaluation's "
      "lateral-movement entries are self-target simulations on one VM, "
      "which the report says explicitly rather than implying more coverage "
      "than exists.")
    a("")

    return "\n".join(lines)


def append_history(data: dict, tier: str, generated_at: str) -> None:
    """Append one row per (generated_at, tier) pair -- not one row per call.

    score.py can be re-run against the SAME results file (e.g. while fixing a
    bug in the scorer itself, which is exactly how this was caught during
    development -- four identical rows piled up from re-scoring one run).
    Re-scoring must be idempotent: it corrects LATEST_REPORT.md, but it must
    not spam HISTORY.md with duplicates of a run that didn't actually happen
    again. A NEW row only appears for a (timestamp, tier) HISTORY.md has not
    already recorded.
    """
    hist_path = _HERE / "HISTORY.md"
    header = ("| Timestamp (UTC) | Tier | Commit | Overall | " +
             " | ".join(t[:4] for t in TACTIC_ORDER) + " |\n" +
             "|---|---|---|---|" + "---|" * len(TACTIC_ORDER) + "\n")
    if not hist_path.exists():
        hist_path.write_text(
            "# Evaluation history\n\n"
            "One row per run. `Tier A` = classifier replay (safe, runs "
            "anywhere). `Tier B` = live VM execution (real ground truth). "
            "Percentages are the STRICT headline score (CONDITIONAL and "
            "known-mismatch outcomes count as misses).\n\n" + header,
            encoding="utf-8")

    existing = hist_path.read_text(encoding="utf-8")
    if f"| {generated_at} | {tier} |" in existing:
        print(f"HISTORY.md already has a row for {generated_at}/{tier} -- "
              f"re-scored LATEST_REPORT.md without adding a duplicate.")
        return

    row_cells = []
    for t in TACTIC_ORDER:
        d = data["by_tactic"].get(t, {"detected": 0, "total": 0})
        row_cells.append(f"{d['detected']}/{d['total']}")
    row = (f"| {generated_at} | {tier} | {_git_commit()} | "
          f"{data['total_detected']}/{data['total']} "
          f"({data['overall_pct']:.0f}%) | " + " | ".join(row_cells) + " |\n")
    with hist_path.open("a", encoding="utf-8") as fh:
        fh.write(row)


def main() -> int:
    if len(sys.argv) > 1:
        path = Path(sys.argv[1])
    else:
        candidates = sorted(glob.glob(str(_HERE / "results" / "*.json")))
        if not candidates:
            print("No results files in redteam/evaluation/results/. "
                  "Run replay_harness.py or run_live_evaluation.ps1 first.")
            return 1
        path = Path(candidates[-1])

    payload = json.loads(path.read_text(encoding="utf-8"))
    records = payload["records"]
    tier = payload["tier"]
    catalog_version = payload["catalog_version"]
    generated_at = payload["generated_at"]

    data = score(records)
    md = render_markdown(data, records, tier, catalog_version, generated_at)

    report_path = _HERE / "LATEST_REPORT.md"
    report_path.write_text(md, encoding="utf-8")
    append_history(data, tier, generated_at)

    print(f"{data['total_detected']}/{data['total']} detected "
          f"({data['overall_pct']:.1f}%) -- report: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
