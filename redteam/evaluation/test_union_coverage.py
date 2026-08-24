"""Proves union_coverage.py's aggregation rules, on fixture result files.

Why this file exists: the union is the number this project QUOTES as its live
coverage, so its rules cannot be left to "trust the loop". Three of them are
load-bearing and each is easy to break silently:

  * the union must be a FLOOR -- a later run that dropped the event must never
    un-prove a technique an earlier run really did detect,
  * a battery that CRASHED mid-write must still contribute everything it
    proved, including when its final JSONL line is truncated,
  * a miss that coincided with sensor backpressure must be reported as a blind
    sensor, not as a detection gap.

Run:  PYTHONUTF8=1 python redteam/evaluation/test_union_coverage.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent.parent / "tests"))

from harness import Checks              # noqa: E402
from union_coverage import collect      # noqa: E402


def _rec(ident: str, tid: str, detected: bool, *, outcome: str = "",
         tactic: str = "execution", drops: int | None = None) -> dict:
    r = {
        "schema": "valkyrie-redteam-evaluation/1", "tier": "B_live",
        "id": ident, "technique_id": tid, "technique_name": ident,
        "tactic": tactic, "destructive": False,
        "counted_as_detected": detected,
        "outcome": outcome or ("detected" if detected else "executed_missed"),
        "matched_source": "etw_sysmon" if detected else None,
    }
    if drops is not None:
        r["sensor_dropped_backpressure"] = drops
    return r


def _write_json(d: Path, name: str, records: list[dict]) -> str:
    p = d / name
    p.write_text(json.dumps({"tier": "B_live", "records": records}), encoding="utf-8")
    return str(p)


def _write_jsonl(d: Path, name: str, records: list[dict], truncate: bool = False) -> str:
    p = d / name
    lines = [json.dumps(r) for r in records]
    blob = "\n".join(lines) + "\n"
    if truncate:
        blob += '{"id":"died-mid-wri'      # crash during the final append
    p.write_text(blob, encoding="utf-8")
    return str(p)


def main() -> int:
    c = Checks("redteam union coverage", expect_min=14)

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)

        print("[1] the union is a FLOOR across runs, never an average")
        a = _write_json(d, "20260101T000000Z__tierB.json", [
            _rec("cred-lsass", "T1003.001", True),
            _rec("browser-creds", "T1555", False),
        ])
        b = _write_json(d, "20260102T000000Z__tierB.json", [
            _rec("cred-lsass", "T1003.001", False),   # same technique, dropped here
            _rec("browser-creds", "T1555", True),     # proved here instead
        ])
        union, per_run, read, _pacing = collect([a, b])
        c.check("both runs were read", len(read) == 2)
        c.check("a technique proved in run A stays proved when run B misses it",
                union["cred-lsass"]["detected"] is True)
        c.check("a technique only run B proved is counted",
                union["browser-creds"]["detected"] is True)
        c.check("union exceeds either run alone (1 and 1 -> 2)",
                sum(1 for v in union.values() if v["detected"]) == 2)
        c.check("per-run figures stay honest and separate",
                per_run[Path(a).name]["detected"] == 1
                and per_run[Path(b).name]["detected"] == 1)
        c.check("first proof is attributed to the run that earned it",
                union["cred-lsass"]["proven_by"] == Path(a).name)

        print("[2] a battery that crashed mid-write still contributes")
        crashed = _write_jsonl(d, "20260103T000000Z__tierB.partial.jsonl", [
            _rec("impair-defender", "T1562.001", True),
            _rec("disc-whoami", "T1033", True),
        ], truncate=True)
        union2, _, read2, _ = collect([crashed])
        c.check("the partial stream was read at all", len(read2) == 1)
        c.check("every complete record survives a truncated final line",
                sum(1 for v in union2.values() if v["detected"]) == 2)
        c.check("the truncated fragment is discarded, not crashed on",
                "died-mid-wri" not in union2)

        print("[3] a blind sensor is not a detection gap")
        blind = _write_json(d, "20260104T000000Z__tierB.json", [
            _rec("inject-hollow", "T1055", False, drops=114),
            _rec("c2-dns", "T1071.004", False, drops=0),
            _rec("lateral-rdp", "T1021.002", False, outcome="not_executed_no_command"),
        ])
        union3, _, _, _ = collect([blind])
        c.check("a miss during backpressure carries the drop count",
                union3["inject-hollow"]["max_backpressure_drops"] == 114)
        c.check("a clean miss carries no drops (a REAL gap)",
                union3["c2-dns"]["max_backpressure_drops"] == 0)
        c.check("a technique that never executed keeps that outcome, so it is "
                "not misread as a detector failure",
                "not_executed_no_command" in union3["lateral-rdp"]["outcomes"])

        print("[4] pacing is tracked, because it changes what a run measures")
        fast = _write_json(d, "20260106T000000Z__tierB.json",
                           [dict(_rec("disc-whoami", "T1033", True), settle_seconds=0)])
        slow = _write_json(d, "20260107T000000Z__tierB.json",
                           [dict(_rec("disc-whoami", "T1033", False), settle_seconds=3)])
        _u, _p, _r, pacing = collect([fast, slow])
        c.check("each run's pacing is recorded against it",
                pacing[Path(fast).name] == 0 and pacing[Path(slow).name] == 3)
        c.check("differing pacing is detectable, so paced and unpaced runs are "
                "never silently merged as comparable",
                len(set(pacing.values())) > 1)

        print("[5] rubbish in does not take the tool down")
        junk = d / "20260105T000000Z__tierB.json"
        junk.write_text("{ not json at all", encoding="utf-8")
        union4, _, read4, _ = collect([str(junk)])
        c.check("an unparseable file is skipped, not fatal",
                union4 == {} and read4 == [])

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
