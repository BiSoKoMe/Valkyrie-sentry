#!/usr/bin/env python3
"""The evidence librarian (redteam/evaluation/evidence.py).

Each block pins one principle from the spec, and the whole suite exists to prove
one thing: the reporting system CANNOT accidentally lie about what a test proved.

The keystone test is [X] - it replays the exact shape of the 2026-08-23 live-EDR
run (engine went deaf, battery never fired, stray incident rows present) and
proves the librarian returns "UNMEASURED / INFRASTRUCTURE_FAILURE", never
"5 detected" and never "0%".
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent.parent / "tests"))

from harness import Checks  # noqa: E402
import evidence as E        # noqa: E402
from evidence import (      # noqa: E402
    TestRecord, Evidence, Correction, Tri, Detection, Validity, FailureClass,
    Response, adjudicate, audit, score, why, dashboard, from_tierb_record,
    record_from_dict, TestLibrary,
)


def _rec(**kw) -> TestRecord:
    base = dict(test_id="T-1", campaign="EDR")
    base.update(kw)
    return TestRecord(**base)


def main() -> int:
    c = Checks("evidence librarian (forensic reporting)", expect_min=34)

    # ================================================================ [1]
    print("\n[1] LAYER SEPARATION: a full, clean chain is the ONLY path to DETECTED")
    r = _rec(attack_executed=Tri.YES, engine_responsive=Tri.YES,
             telemetry_available=Tri.YES,
             evidence=[Evidence("rule_ioa", "IOA-146", linked_attack="T-1",
                                is_detection=True)])
    v = adjudicate(r)
    c.check("full chain + linked detection -> DETECTED", v.detection == Detection.DETECTED)
    c.check("DETECTED is VALID", v.validity == Validity.VALID)
    c.check("DETECTED is scorable", v.scorable)

    # ================================================================ [2]
    print("\n[2] a genuine miss (engine up, telemetry present, no detection) is "
          "NOT_DETECTED and VALID - the ONLY path to a scored miss")
    r = _rec(attack_executed=Tri.YES, engine_responsive=Tri.YES,
             telemetry_available=Tri.YES)
    v = adjudicate(r)
    c.check("clean chain, no detection -> NOT_DETECTED", v.detection == Detection.NOT_DETECTED)
    c.check("a real miss is VALID", v.validity == Validity.VALID)
    c.check("a real miss is scorable", v.scorable)

    # ================================================================ [3]
    print("\n[3] LINK 1 broken - attack never executed -> NOT_TESTED, never a miss")
    r = _rec(attack_executed=Tri.NO, engine_responsive=Tri.NO)
    v = adjudicate(r)
    c.check("unexecuted attack -> NOT_TESTED", v.detection == Detection.NOT_TESTED)
    c.check("blamed on infrastructure", v.validity == Validity.INFRASTRUCTURE_FAILURE)
    c.check("failure classified as ENGINE", v.failure_class == FailureClass.ENGINE)
    c.check("the missing link is named", v.missing_link == "attack_execution")
    c.check("NOT scorable (cannot enter a rate)", not v.scorable)

    # ================================================================ [4]
    print("\n[4] LINK 2 broken - engine unresponsive during an executed attack "
          "-> INCONCLUSIVE, NOT a miss (blindness != detection gap)")
    r = _rec(attack_executed=Tri.YES, engine_responsive=Tri.NO)
    v = adjudicate(r)
    c.check("dead engine -> INCONCLUSIVE", v.detection == Detection.INCONCLUSIVE)
    c.check("infrastructure failure", v.validity == Validity.INFRASTRUCTURE_FAILURE)
    c.check("not scorable", not v.scorable)

    # ================================================================ [5]
    print("\n[5] LINK 3 broken - telemetry missing -> INCONCLUSIVE (blind sensor, "
          "not a rule gap)")
    r = _rec(attack_executed=Tri.YES, engine_responsive=Tri.YES,
             telemetry_available=Tri.NO)
    v = adjudicate(r)
    c.check("dark sensor -> INCONCLUSIVE", v.detection == Detection.INCONCLUSIVE)
    c.check("failure classified as TELEMETRY", v.failure_class == FailureClass.TELEMETRY)
    c.check("not scorable", not v.scorable)

    # ================================================================ [X] KEYSTONE
    print("\n[X] THE 2026-08-23 TRAP: attack never ran, engine deaf, but stray "
          "incident rows exist -> must be UNMEASURED, never '5 detected'")
    # Five stray detection-looking rows NOT linked to any executed attack -
    # exactly the engine-self-activity rows misread last week.
    stray = [Evidence("incident", f"T105{i}", linked_attack="", is_detection=True)
             for i in range(5)]
    r = _rec(test_id="EDR-2026-08-23-0042", attack_executed=Tri.NO,
             engine_responsive=Tri.NO, evidence=stray)
    v = adjudicate(r)
    c.check("stray detections do NOT produce DETECTED",
            v.detection != Detection.DETECTED)
    c.check("verdict is NOT_TESTED", v.detection == Detection.NOT_TESTED)
    c.check("validity is INFRASTRUCTURE_FAILURE", v.validity == Validity.INFRASTRUCTURE_FAILURE)
    c.check("it is NOT scorable as detection OR miss", not v.scorable)
    txt = why(r)
    c.check("the why-chain names the excluded stray events",
            "not linked to this attack" in txt.lower() or "excluded" in txt.lower())

    # ================================================================ [6]
    print("\n[6] HONEST SCORING: 34 unexecuted tests -> N/A, never 0%")
    dead = [_rec(test_id=f"d{i}", attack_executed=Tri.NO, engine_responsive=Tri.NO)
            for i in range(34)]
    sc = score(dead, campaign="Live EDR")
    c.check("no valid measurements", sc.valid == 0)
    c.check("34 infrastructure failures", sc.infrastructure_failures == 34)
    c.check("detection rate is N/A (None), NOT 0.0", sc.detection_rate_pct is None)
    c.check("rate basis explains the N/A", "no valid" in sc.rate_basis.lower())

    # ================================================================ [7]
    print("\n[7] HONEST SCORING: 30 valid (27 hit, 3 miss) + 4 infra -> 90% of "
          "valid, not 79% of scheduled")
    recs = []
    for i in range(27):
        recs.append(_rec(test_id=f"h{i}", attack_executed=Tri.YES,
                         engine_responsive=Tri.YES, telemetry_available=Tri.YES,
                         evidence=[Evidence("rule_ioa", f"hit{i}",
                                            linked_attack=f"h{i}", is_detection=True)]))
    for i in range(3):
        recs.append(_rec(test_id=f"m{i}", attack_executed=Tri.YES,
                         engine_responsive=Tri.YES, telemetry_available=Tri.YES))
    for i in range(4):
        recs.append(_rec(test_id=f"i{i}", attack_executed=Tri.NO,
                         engine_responsive=Tri.NO))
    sc = score(recs, campaign="EDR")
    c.check("valid denominator is 30, not 34", sc.valid == 30)
    c.check("infra failures excluded from denominator", sc.infrastructure_failures == 4)
    c.check("rate is 90% of valid", sc.detection_rate_pct == 90.0)

    # ================================================================ [8]
    print("\n[8] CONTRADICTION AUDIT blocks a score")
    # Hand-forge an inconsistent claim: a DETECTED-shaped record whose detection
    # evidence is linked but whose attack never executed.
    bad = _rec(test_id="x", attack_executed=Tri.NO, engine_responsive=Tri.YES,
               telemetry_available=Tri.YES,
               evidence=[Evidence("rule_ioa", "phantom", linked_attack="x",
                                  is_detection=True)])
    contradictions = audit([bad])
    c.check("audit catches the inconsistency", len(contradictions) >= 1)
    sc = score([bad], campaign="EDR")
    c.check("a contradicting set produces NO score", not sc.report_valid)
    c.check("the score withholds a rate", sc.detection_rate_pct is None)

    # duplicate test id
    dup = audit([_rec(test_id="same"), _rec(test_id="same")])
    c.check("duplicate test_id is a contradiction",
            any(k.kind == "duplicate_test_id" for k in dup))

    # not-detected while a linked detection exists (forged)
    class _Forge(TestRecord):
        pass
    # Build a record that WOULD adjudicate NOT_DETECTED path but carries a linked
    # detection - impossible via adjudicate, so we test the audit rule directly:
    contra2 = audit([_rec(test_id="z", attack_executed=Tri.YES,
                          engine_responsive=Tri.YES, telemetry_available=Tri.YES,
                          evidence=[Evidence("x", "d", linked_attack="z",
                                             is_detection=True)])])
    c.check("a consistent DETECTED record raises no contradiction", not contra2)

    # ================================================================ [9]
    print("\n[9] CORRECTIONS are preserved, never overwritten")
    lib = TestLibrary()
    original = _rec(test_id="EDR-42", attack_executed=Tri.NO,
                    engine_responsive=Tri.NO)
    lib.add_run("EDR", "run-001", [original])
    lib.correct("EDR", "run-001", "EDR-42", Correction(
        original="5 techniques detected", corrected_to="unmeasured",
        reason="attack battery did not execute",
        evidence=("engine unresponsive at +15.2s",)))
    stored = lib.runs[("EDR", "run-001")][0]
    c.check("the correction is retained", len(stored.corrections) == 1)
    c.check("the ORIGINAL wrong claim is preserved verbatim",
            stored.corrections[0].original == "5 techniques detected")
    c.check("the correct status is recorded", stored.corrections[0].corrected_to == "unmeasured")
    c.check("append-only: re-adding a run id is refused",
            _raises(lambda: lib.add_run("EDR", "run-001", [])))

    # ================================================================ [10]
    print("\n[10] round-trip: a record survives serialization unchanged")
    back = record_from_dict(original.to_dict())
    c.check("round-trip preserves the verdict",
            adjudicate(back).detection == adjudicate(original).detection)

    # ================================================================ [11]
    print("\n[11] INGESTION is conservative: a harness 'detected' with no "
          "execution proof does NOT become a detection")
    ingested = from_tierb_record({"id": "T1003", "technique_id": "T1003.001",
                                  "counted_as_detected": True}, run_id="r")
    c.check("no attack_executed -> UNKNOWN, not YES",
            ingested.attack_executed == Tri.UNKNOWN)
    c.check("ingested unexecuted 'detection' -> NOT_TESTED",
            adjudicate(ingested).detection == Detection.NOT_TESTED)

    # ================================================================ [12]
    print("\n[12] DASHBOARD reads the whole picture at a glance")
    privacy = score([_rec(test_id=f"p{i}", attack_executed=Tri.YES,
                          engine_responsive=Tri.YES, telemetry_available=Tri.YES,
                          evidence=[Evidence("x", "d", linked_attack=f"p{i}",
                                             is_detection=True)]) for i in range(66)]
                    + [_rec(test_id=f"pm{i}", attack_executed=Tri.YES,
                            engine_responsive=Tri.YES, telemetry_available=Tri.YES)
                       for i in range(3)], campaign="Privacy")
    live_edr = score(dead, campaign="Live EDR")
    dash = dashboard([privacy, live_edr])
    c.check("dashboard shows the valid privacy result", "66/69" in dash)
    c.check("dashboard shows live EDR as UNMEASURED", "UNMEASURED" in dash)
    c.check("dashboard shows N/A for live EDR", "N/A" in dash)
    c.check("dashboard explains the N/A", "infrastructure failure" in dash.lower())

    return c.finish()


def _raises(fn) -> bool:
    try:
        fn()
        return False
    except Exception:
        return True


if __name__ == "__main__":
    raise SystemExit(main())
