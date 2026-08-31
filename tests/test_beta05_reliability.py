#!/usr/bin/env python3
"""Platform Beta 0.5 harness - score() logic tested offline against
synthetic sample timelines, so a scoring bug is caught before any CI minute
is spent on a live run. Never touches a real engine."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def _sample(t: float, phase: str, overall: str, sources: dict,
           loop_drift: float = 0.0, loop_worst: float = 0.0,
           health_ok: bool = True) -> dict:
    return {
        "t": t, "phase": phase, "health_ok": health_ok,
        "watchdog": {
            "overall": overall,
            "degraded_reasons": [] if overall == "HEALTHY" else ["x:stale_poll"],
            "sources": sources,
            "loop": {"last_drift_seconds": loop_drift, "worst_drift_seconds": loop_worst},
        },
    }


def main() -> int:
    from redteam.evaluation.beta05_reliability import score, _independent_stale_bound, Transition

    print("\n=== Beta 0.5 harness: score() ===\n")

    print("[1] _independent_stale_bound uses a DIFFERENT formula than the "
          "watchdog's own (interval*4) - not byte-identical logic")
    b2 = _independent_stale_bound(2.0)
    _check("2.0s interval -> bound is 2*5+5=15, not 2*4=8", b2 == 15.0)

    print("\n[2] a clean run (no deaths, no staleness, no stalls) -> PASS")
    src = lambda last: {"available": True, "healthy": True,
                        "status": {"running": True, "last_poll_completed_at": last,
                                   "poll_interval_s": 2.0}}
    samples = [
        _sample(100.0, "A", "HEALTHY", {"process_collector": src(99.0)}),
        _sample(102.0, "A", "HEALTHY", {"process_collector": src(101.5)}),
        _sample(104.0, "A", "HEALTHY", {"process_collector": src(103.8)}),
    ]
    result = score(samples, [], health_failures=0, health_successes=3,
                  causality_before_c=None, causality_after_c=None, mode="dry-run")
    _check("overall PASS", result["overall"] == "PASS")
    _check("no_silent_collector_deaths passes", result["checks"]["no_silent_collector_deaths"]["pass"])
    _check("no_stale_while_healthy passes", result["checks"]["no_stale_while_healthy"]["pass"])

    print("\n[2b] a source that stays unavailable is not collector progress")
    unavailable = [
        _sample(100.0, "A", "HEALTHY",
                {"process_collector": {"available": False, "status": None}}),
        _sample(102.0, "A", "HEALTHY",
                {"process_collector": {"available": False, "status": None}}),
    ]
    unavailable_result = score(
        unavailable, [], health_failures=0, health_successes=2,
        causality_before_c=None, causality_after_c=None, mode="dry-run")
    _check("unavailable collector FAILS collectors_advance_throughout",
           unavailable_result["checks"]["collectors_advance_throughout"]["pass"] is False)

    print("\n[2c] a DEGRADED interval fails soak even when the collector later recovers")
    recovered_after_stall = [
        _sample(100.0, "E", "DEGRADED",
                {"persistence_collector": {"available": True, "healthy": False,
                 "status": {"running": True, "last_poll_completed_at": 10.0,
                            "poll_interval_s": 15.0}}}),
        _sample(102.0, "E", "HEALTHY",
                {"persistence_collector": {"available": True, "healthy": True,
                 "status": {"running": True, "last_poll_completed_at": 101.0,
                            "poll_interval_s": 15.0}}}),
    ]
    recovered_result = score(
        recovered_after_stall, [], health_failures=0, health_successes=2,
        causality_before_c=None, causality_after_c=None, mode="soak")
    _check("unexpected DEGRADED interval FAILS soak",
           recovered_result["checks"]["no_unexpected_degraded_intervals"]["pass"] is False)

    print("\n[3] a collector reporting running=False -> FAILS "
          "no_silent_collector_deaths, and overall FAILS")
    samples_dead = [
        _sample(100.0, "A", "DEGRADED",
               {"process_collector": {"status": {"running": False,
                                                 "last_poll_completed_at": 50.0,
                                                 "poll_interval_s": 2.0}}}),
    ]
    result2 = score(samples_dead, [], health_failures=0, health_successes=1,
                    causality_before_c=None, causality_after_c=None, mode="dry-run")
    _check("no_silent_collector_deaths FAILS", result2["checks"]["no_silent_collector_deaths"]["pass"] is False)
    _check("overall FAILS", result2["overall"] == "FAIL")

    print("\n[4] THE critical contradiction: watchdog says HEALTHY but the "
          "raw poll age is far past even the harness's OWN (different, "
          "looser) stale bound - this is exactly the failure mode a buggy "
          "watchdog integration would produce, and must be caught")
    samples_contradiction = [
        _sample(1000.0, "E", "HEALTHY",
               {"persistence_collector": {"status": {"running": True,
                                                     "last_poll_completed_at": 100.0,
                                                     "poll_interval_s": 15.0}}}),
    ]
    result3 = score(samples_contradiction, [], health_failures=0, health_successes=1,
                    causality_before_c=None, causality_after_c=None, mode="dry-run")
    _check("no_stale_while_healthy FAILS", result3["checks"]["no_stale_while_healthy"]["pass"] is False)
    _check("overall FAILS", result3["overall"] == "FAIL")

    print("\n[5] a loop stall over 5.0s fails no_unexplained_loop_stalls")
    samples_stall = [
        _sample(100.0, "C", "HEALTHY", {}, loop_drift=0.1, loop_worst=0.1),
        _sample(102.0, "C", "HEALTHY", {}, loop_drift=6.2, loop_worst=6.2),
    ]
    result4 = score(samples_stall, [], health_failures=0, health_successes=2,
                    causality_before_c=None, causality_after_c=None, mode="dry-run")
    _check("no_unexplained_loop_stalls FAILS", result4["checks"]["no_unexplained_loop_stalls"]["pass"] is False)
    _check("worst_drift_seconds recorded correctly", result4["checks"]["no_unexplained_loop_stalls"]["detail"]["worst_drift_seconds"] == 6.2)

    print("\n[6] API failures fail api_responsive")
    samples_api = [_sample(100.0, "A", "HEALTHY", {}, health_ok=False)]
    result5 = score(samples_api, [], health_failures=2, health_successes=5,
                    causality_before_c=None, causality_after_c=None, mode="dry-run")
    _check("api_responsive FAILS with nonzero failures", result5["checks"]["api_responsive"]["pass"] is False)

    print("\n[7] phase C event-count progression: strictly higher after -> pass")
    result6 = score([], [], health_failures=0, health_successes=0,
                    causality_before_c=5, causality_after_c=12, mode="dry-run")
    _check("advancing count passes", result6["checks"]["phase_c_advances_event_count"]["pass"] is True)

    print("\n[8] phase C event-count progression: FLAT count fails "
          "(the pipe went quiet during known telemetry-producing activity)")
    result7 = score([], [], health_failures=0, health_successes=0,
                    causality_before_c=5, causality_after_c=5, mode="dry-run")
    _check("flat count FAILS", result7["checks"]["phase_c_advances_event_count"]["pass"] is False)

    print("\n[9] fault-test mode requires BOTH a degraded and a recovered "
          "transition to be observed - a freeze with no confirmed DEGRADED "
          "transition must not silently pass")
    result8 = score([], [Transition(100.0, "degraded", ["x:stale_poll"])],
                    health_failures=0, health_successes=1,
                    causality_before_c=None, causality_after_c=None, mode="fault-test")
    _check("degraded-only (no recovery) FAILS fault_detected_and_recovered",
           result8["checks"]["fault_detected_and_recovered"]["pass"] is False)

    result9 = score([], [Transition(100.0, "degraded", ["x:stale_poll"]),
                        Transition(120.0, "recovered", ["x:stale_poll"])],
                    health_failures=0, health_successes=1,
                    causality_before_c=None, causality_after_c=None, mode="fault-test")
    _check("degraded+recovered PASSES fault_detected_and_recovered",
           result9["checks"]["fault_detected_and_recovered"]["pass"] is True)

    print("\n[10] fault_detected_and_recovered is NOT even scored outside fault-test mode")
    result10 = score([], [], health_failures=0, health_successes=0,
                     causality_before_c=None, causality_after_c=None, mode="soak")
    _check("no such key in soak-mode results", "fault_detected_and_recovered" not in result10["checks"])

    print("\n[11] a Tier B subset failure/timeout is a SCORED criterion, "
          "never a reason to lose every sample already collected (run 3 of "
          "the 2026-08-30 soak crashed with an uncaught RuntimeError here "
          "before this check existed)")
    result11 = score([], [], health_failures=0, health_successes=0,
                     causality_before_c=None, causality_after_c=None, mode="soak",
                     phase_c_failures=["phase_e_toggle_5"])
    _check("phase_c_technique_execution_completed FAILS with the failure named",
           result11["checks"]["phase_c_technique_execution_completed"]["pass"] is False
           and result11["checks"]["phase_c_technique_execution_completed"]["detail"] == ["phase_e_toggle_5"])
    _check("overall FAILS", result11["overall"] == "FAIL")

    result12 = score([], [], health_failures=0, health_successes=0,
                     causality_before_c=None, causality_after_c=None, mode="soak",
                     phase_c_failures=[])
    _check("empty failure list -> phase_c_technique_execution_completed PASSES",
           result12["checks"]["phase_c_technique_execution_completed"]["pass"] is True)

    print("\n[12] omitting phase_c_failures entirely (older call sites) "
          "defaults to passing, not silently failing")
    result13 = score([], [], health_failures=0, health_successes=0,
                     causality_before_c=None, causality_after_c=None, mode="soak")
    _check("default (no phase_c_failures arg) PASSES",
           result13["checks"]["phase_c_technique_execution_completed"]["pass"] is True)

    print("\n[13] the engine process disappearing entirely is its own "
          "criterion (Beta 0.5.5) - distinct from any per-collector or "
          "per-request check, checked directly against the subprocess")
    result14 = score([], [], health_failures=0, health_successes=0,
                     causality_before_c=None, causality_after_c=None, mode="soak",
                     engine_exit_code=None)
    _check("engine still running (exit_code None) PASSES",
           result14["checks"]["engine_process_alive_throughout"]["pass"] is True)

    result15 = score([], [], health_failures=0, health_successes=0,
                     causality_before_c=None, causality_after_c=None, mode="soak",
                     engine_exit_code=1)
    _check("engine exited (any code) FAILS",
           result15["checks"]["engine_process_alive_throughout"]["pass"] is False)
    _check("exit code recorded in the detail",
           result15["checks"]["engine_process_alive_throughout"]["detail"] == {"exit_code": 1})
    _check("overall FAILS", result15["overall"] == "FAIL")

    print("\n[14] engine_resource_trend (Beta 0.5.5): summarizes first/last/"
          "min/max across real samples, exploratory only - not yet a "
          "pass/fail gate since no measured threshold exists")
    from redteam.evaluation.beta05_reliability import _engine_resource_trend
    samples_with_trend = [
        {"engine_process": {"pid": 1, "rss": 100, "handles": 50, "threads": 10}},
        {"engine_process": {"pid": 1, "rss": 150, "handles": 55, "threads": 10}},
        {"engine_process": {"pid": 1, "rss": 90, "handles": 60, "threads": 11}},
    ]
    trend = _engine_resource_trend(samples_with_trend)
    _check("rss first/last/min/max computed correctly",
           trend["rss_bytes"] == {"first": 100, "last": 90, "min": 90, "max": 150})
    _check("handles trend computed correctly",
           trend["handles"] == {"first": 50, "last": 60, "min": 50, "max": 60})
    _check("sample count matches", trend["samples"] == 3)

    print("\n[15] engine_resource_trend surfaces process errors (e.g. "
          "NoSuchProcess) as evidence rather than hiding them")
    samples_with_error = [
        {"engine_process": {"pid": 1, "rss": 100, "handles": 50, "threads": 10}},
        {"engine_process": {"error": "NoSuchProcess(pid=1)"}},
    ]
    trend2 = _engine_resource_trend(samples_with_error)
    _check("only the real point counts toward samples", trend2["samples"] == 1)
    _check("the error is surfaced, not swallowed",
           trend2["errors"] == ["NoSuchProcess(pid=1)"])

    print("\n[16] no engine_process data at all (e.g. psutil unavailable) "
          "-> reports zero samples, never crashes")
    trend3 = _engine_resource_trend([{"engine_process": None}, {}])
    _check("zero samples, no crash", trend3 == {"samples": 0, "errors": []})

    print("\n[17] score() always includes engine_resource_trend, non-gating")
    samples_clean = [
        _sample(100.0, "A", "HEALTHY", {"process_collector": src(99.0)}),
        _sample(102.0, "A", "HEALTHY", {"process_collector": src(101.5)}),
    ]
    result16 = score(samples_clean, [], health_failures=0, health_successes=1,
                     causality_before_c=None, causality_after_c=None, mode="soak")
    _check("engine_resource_trend key present", "engine_resource_trend" in result16)
    _check("engine_resource_trend does not itself gate a run that is "
           "otherwise clean (no engine_process data collected here)",
           result16["overall"] == "PASS")

    print("\n" + "=" * 48)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
