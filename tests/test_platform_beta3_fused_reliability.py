#!/usr/bin/env python3
"""Platform Beta 3 (fused pipeline reliability) harness.

Same convention as the other platform-reliability test files: never spins
up a real browser/proxy - tests score() offline against synthetic
visit-report lists. The real browser+collectors+proxy run only happens in
CI.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def _good_visit(pid: int = 100) -> dict:
    return {
        "error": None,
        "subject_pid": pid,
        "subject_event_count": 2,
        "exposure_observation_categories": ["DESTINATION"],
        "unavailable_categories_never_appeared": True,
        "provenance_never_crosses_into_another_visit": True,
    }


def main() -> int:
    import redteam.evaluation.platform_beta3_fused_reliability as m

    print("\n=== Platform Beta 3 (fused reliability) harness (offline) ===\n")

    print("[1] score() - a clean run of several visits passes every check")
    visits = [_good_visit(pid) for pid in (100, 200, 300, 400, 500)]
    good = m.score(visits, [], None)
    _check("overall PASS", good["overall"] == "PASS")
    for name, c in good["checks"].items():
        _check(f"  {name} passes on a clean run", c["pass"])
    _check("unique_subjects counts distinct pids", good["unique_subjects"] == 5)

    print("\n[2] score() - empty run FAILs, not vacuously PASSes")
    empty = m.score([], [], None)
    _check("overall FAILs on zero visits", empty["overall"] == "FAIL")

    print("\n[3] score() - most visits failing to resolve a subject fails "
          "most_visits_resolved_a_real_subject")
    mostly_unresolved = [_good_visit(100)] + [
        {"error": None, "subject_pid": None, "subject_event_count": 0,
        "exposure_observation_categories": [], "unavailable_categories_never_appeared": True,
        "provenance_never_crosses_into_another_visit": True} for _ in range(4)]
    scored = m.score(mostly_unresolved, [], None)
    _check("fails when most visits never resolved a real subject",
           scored["checks"]["most_visits_resolved_a_real_subject"]["pass"] is False)

    print("\n[4] score() - a fabricated unavailable category on even one "
          "visit fails unavailable_categories_never_fabricated_any_visit")
    one_bad = [_good_visit(100), _good_visit(200)]
    one_bad[1]["unavailable_categories_never_appeared"] = False
    scored2 = m.score(one_bad, [], None)
    _check("fails when even ONE visit fabricated an unavailable category",
           scored2["checks"]["unavailable_categories_never_fabricated_any_visit"]["pass"] is False)

    print("\n[5] score() - cross-visit contamination on even one visit fails "
          "no_cross_visit_contamination")
    contaminated = [_good_visit(100), _good_visit(200)]
    contaminated[1]["provenance_never_crosses_into_another_visit"] = False
    scored3 = m.score(contaminated, [], None)
    _check("fails when even ONE visit's provenance crossed into another visit",
           scored3["checks"]["no_cross_visit_contamination"]["pass"] is False)

    print("\n[6] score() - an observe() error on any visit fails "
          "no_observe_errors_any_visit but not the other checks")
    with_err = [_good_visit(100)]
    with_err[0]["observe_errors"] = ["RuntimeError('boom')"]
    scored4 = m.score(with_err, [], None)
    _check("no_observe_errors_any_visit fails",
           scored4["checks"]["no_observe_errors_any_visit"]["pass"] is False)
    _check("other checks still evaluated (not short-circuited)",
           scored4["checks"]["no_cross_visit_contamination"]["pass"] is True)

    print("\n[7] score() - a run_error fails no_process_crash, partial "
          "results still scored")
    crashed = m.score([_good_visit(100)], [], "RuntimeError('boom')")
    _check("no_process_crash fails", crashed["checks"]["no_process_crash"]["pass"] is False)
    _check("other checks still evaluated",
           crashed["checks"]["destination_derived_across_most_visits"]["pass"] is True)

    print("\n[8] score() - resource_trend is exploratory, non-gating, and "
          "handles empty samples")
    rt = m.score([_good_visit(100)], [{"process": {"rss": 100}}, {"process": {"rss": 120}}], None)
    _check("resource_trend reports first/last/max rss",
           rt["resource_trend"] == {"first_rss": 100, "last_rss": 120, "max_rss": 120})
    rt_empty = m.score([_good_visit(100)], [], None)
    _check("resource_trend is None with no samples (not a crash)",
           rt_empty["resource_trend"] is None)

    print("\n" + "=" * 52)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
