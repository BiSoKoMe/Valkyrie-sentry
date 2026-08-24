"""Proves score.py's scoring rules actually work, on fixture records.

Why this file exists: the live evaluation's Tier A corpus never happens to
contain a `detection_category == 'user_rule'` record (none of the 40
synthetic replays exercise a user-authored always_block rule), so a report
showing "0 excluded" is ambiguous -- it could mean the exclusion rule is
correctly finding nothing to exclude, or it could mean the exclusion code has
literally never run. That ambiguity is exactly the kind of unverified claim
this whole evaluation was commissioned to eliminate, so it gets a dedicated
positive-control test rather than being left to "trust the if-statement."

Run:  PYTHONUTF8=1 python redteam/evaluation/test_scoring.py
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent.parent / "tests"))

from harness import Checks           # noqa: E402
from score import _is_counted, score, TACTIC_ORDER   # noqa: E402


_id_counter = [0]


def _rec(**kw) -> dict:
    _id_counter[0] += 1
    base = {"id": f"fixture-{_id_counter[0]}", "tactic": "Execution",
            "counted_as_detected": True, "detection_category": "behavioral",
            "known_mismatch": None}
    base.update(kw)
    return base


def main() -> int:
    c = Checks("redteam scoring rules", expect_min=10)

    print("[1] the user-defined-DNS-block exclusion actually excludes")
    user_rule_detect = _rec(detection_category="user_rule")
    c.check("a user_rule detection is NOT counted, even though "
            "counted_as_detected=True upstream",
            _is_counted(user_rule_detect) is False)

    blocklist_detect = _rec(detection_category="blocklist")
    c.check("a BLOCKLIST detection (Valkyrie's own curated list, not "
            "user-authored) DOES count -- the exclusion is specific to "
            "user_rule, not to every non-behavioral category",
            _is_counted(blocklist_detect) is True)

    print("\n[2] a known mismatch is never credited")
    mismatch = _rec(known_mismatch="fired the wrong technique entirely")
    c.check("a record with known_mismatch set is NOT counted even though "
            "counted_as_detected=True", _is_counted(mismatch) is False)

    print("\n[3] a clean detection counts")
    clean = _rec()
    c.check("an ordinary behavioral detection IS counted", _is_counted(clean) is True)

    print("\n[4] a miss is a miss")
    miss = _rec(counted_as_detected=False)
    c.check("counted_as_detected=False is never counted", _is_counted(miss) is False)

    print("\n[5] aggregate scoring math, on a small fixture")
    caught_inflation = _rec(tactic="Discovery", detection_category="user_rule")
    fixture = [
        _rec(tactic="Execution", counted_as_detected=True),
        _rec(tactic="Execution", counted_as_detected=False),
        _rec(tactic="Persistence", counted_as_detected=True),
        _rec(tactic="Persistence", counted_as_detected=True),
        caught_inflation,                                            # excluded
        _rec(tactic="Impact", known_mismatch="wrong technique"),      # excluded
    ]
    result = score(fixture)
    c.check(f"overall total is 6 (got {result['total']})", result["total"] == 6)
    c.check(f"overall detected is 3 -- the user_rule and known_mismatch "
            f"records must NOT inflate this (got {result['total_detected']})",
            result["total_detected"] == 3)
    c.check(f"overall pct is 50.0 (got {result['overall_pct']})",
            abs(result["overall_pct"] - 50.0) < 1e-9)
    c.check("Execution tactic: 1/2 detected",
            result["by_tactic"]["Execution"]["detected"] == 1
            and result["by_tactic"]["Execution"]["total"] == 2)
    c.check("Persistence tactic: 2/2 detected",
            result["by_tactic"]["Persistence"]["detected"] == 2)
    c.check("Discovery tactic: 0/1 detected (the user_rule hit does not count)",
            result["by_tactic"]["Discovery"]["detected"] == 0
            and result["by_tactic"]["Discovery"]["total"] == 1)
    c.check("Impact tactic: 0/1 detected (the mismatch does not count)",
            result["by_tactic"]["Impact"]["detected"] == 0)
    # The Discovery fixture row IS a caught inflation attempt: it has
    # counted_as_detected=True (the _rec() default) AND
    # detection_category='user_rule' -- exactly what an upstream tier would
    # produce if a user's own always_block rule fired and got mislabeled as a
    # real detection. score() must report it by id, not swallow it silently.
    c.check(f"the caught user_rule inflation attempt is reported by id "
            f"(got {result['excluded_user_rule']})",
            result["excluded_user_rule"] == [caught_inflation["id"]])

    print("\n[6] all 8 required tactics are recognised by name")
    required = {"Execution", "Persistence", "Defense Evasion",
               "Credential Access", "Discovery", "Lateral Movement",
               "Command and Control", "Impact"}
    c.check(f"TACTIC_ORDER contains exactly the 8 required tactics "
            f"(diff: {required ^ set(TACTIC_ORDER)})",
            set(TACTIC_ORDER) == required)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
