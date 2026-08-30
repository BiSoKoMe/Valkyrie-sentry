#!/usr/bin/env python3
"""TelemetryWatchdog - reliability aggregation over collector staleness
and the event loop's own heartbeat (Platform Beta 0.5)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def main() -> int:
    from valkyrie.telemetry_watchdog import (
        TelemetryWatchdog, LoopHeartbeat, evaluate_poll_source, PollSourceSpec,
        FaultInjectableTestCollector,
        REASON_NOT_AVAILABLE, REASON_NOT_RUNNING, REASON_NO_POLL_YET,
        REASON_STALE_POLL, REASON_LOOP_NEVER_BEAT, REASON_LOOP_STALLED,
    )

    print("\n=== TelemetryWatchdog ===\n")

    print("[1] evaluate_poll_source: collector never constructed")
    spec = PollSourceSpec("proc", lambda: None, expected_interval=2.0)
    r = evaluate_poll_source(spec, now=100.0, started_at=0.0, startup_grace=60.0)
    _check("unavailable collector reads healthy (nothing to distrust)", r["healthy"] is True)
    _check("but marked not available", r["available"] is False and r["reason"] == REASON_NOT_AVAILABLE)

    print("\n[2] evaluate_poll_source: thread died")
    spec2 = PollSourceSpec("proc", lambda: {"running": False, "last_poll_completed_at": 50.0},
                           expected_interval=2.0)
    r2 = evaluate_poll_source(spec2, now=100.0, started_at=0.0, startup_grace=60.0)
    _check("dead thread -> unhealthy", r2["healthy"] is False)
    _check("reason is not_running", r2["reason"] == REASON_NOT_RUNNING)

    print("\n[3] evaluate_poll_source: alive, still inside startup grace, no poll yet")
    spec3 = PollSourceSpec("persist", lambda: {"running": True, "last_poll_completed_at": 0.0},
                           expected_interval=15.0)
    r3 = evaluate_poll_source(spec3, now=10.0, started_at=0.0, startup_grace=60.0)
    _check("within grace with no poll yet -> healthy", r3["healthy"] is True)

    print("\n[4] evaluate_poll_source: alive, PAST startup grace, still no poll")
    r4 = evaluate_poll_source(spec3, now=70.0, started_at=0.0, startup_grace=60.0)
    _check("past grace with no poll -> unhealthy", r4["healthy"] is False)
    _check("reason is no_poll_completed_within_grace", r4["reason"] == REASON_NO_POLL_YET)

    print("\n[5] evaluate_poll_source: THE 253s-freeze shape - thread alive, "
          "poll completed once, then nothing for far longer than its own interval")
    spec5 = PollSourceSpec("persist", lambda: {"running": True, "last_poll_completed_at": 20.0},
                           expected_interval=15.0, stale_multiplier=4.0)
    # bound = 15*4 = 60s. 20 + 60 = 80 is the edge.
    r5_ok = evaluate_poll_source(spec5, now=75.0, started_at=0.0, startup_grace=5.0)
    _check("just under the stale bound -> still healthy", r5_ok["healthy"] is True)
    r5_bad = evaluate_poll_source(spec5, now=300.0, started_at=0.0, startup_grace=5.0)
    _check("thread alive but stuck since t=20, now=300 -> unhealthy", r5_bad["healthy"] is False)
    _check("reason is stale_poll (is_running() alone would have missed this)",
           r5_bad["reason"] == REASON_STALE_POLL)
    _check("carries how long it has been stale", r5_bad["stale_for_seconds"] == 280.0)

    print("\n[6] LoopHeartbeat: never beaten yet")
    lh = LoopHeartbeat()
    st = lh.status(now=100.0)
    _check("never-beaten loop reads stale, not beating", st["stale"] is True and st["beating"] is False)

    print("\n[7] LoopHeartbeat: fresh beat reads healthy")
    lh.beat(drift=0.05)
    st2 = lh.status(now=lh.last_beat_at + 1.0)
    _check("fresh beat -> beating True", st2["beating"] is True)
    _check("drift recorded", st2["last_drift_seconds"] == 0.05)

    print("\n[8] LoopHeartbeat: worst_drift_seconds tracks the max, not the last")
    lh2 = LoopHeartbeat()
    lh2.beat(drift=3.0)
    lh2.beat(drift=0.1)
    _check("worst stall retained after a calmer beat", lh2.worst_drift_seconds == 3.0)
    _check("last drift reflects the most recent beat", lh2.last_drift_seconds == 0.1)

    print("\n[9] LoopHeartbeat: stale after the beat stops (simulated GIL stall)")
    lh3 = LoopHeartbeat()
    lh3.beat(drift=0.0)
    old_beat_at = lh3.last_beat_at
    st3 = lh3.status(now=old_beat_at + 30.0, stale_after=5.0)
    _check("no beat for 30s against a 5s stale bound -> stale", st3["stale"] is True)

    print("\n[10] TelemetryWatchdog: all sources healthy, no loop wired -> HEALTHY")
    wd = TelemetryWatchdog(started_at=0.0, startup_grace=60.0)
    wd.add_source("process", lambda: {"running": True, "last_poll_completed_at": 95.0}, 2.0)
    wd.add_source("network", lambda: {"running": True, "last_poll_completed_at": 96.0}, 3.0)
    s = wd.status(now=100.0)
    _check("overall HEALTHY", s["overall"] == "HEALTHY")
    _check("no degraded reasons", s["degraded_reasons"] == [])
    _check("both sources present in the detail", set(s["sources"]) == {"process", "network"})

    print("\n[11] TelemetryWatchdog: one stuck collector flips overall DEGRADED "
          "without hiding the healthy ones")
    wd2 = TelemetryWatchdog(started_at=0.0, startup_grace=5.0)
    wd2.add_source("process", lambda: {"running": True, "last_poll_completed_at": 398.0}, 2.0)
    wd2.add_source("persistence", lambda: {"running": True, "last_poll_completed_at": 20.0}, 15.0)
    s2 = wd2.status(now=400.0)
    _check("overall DEGRADED", s2["overall"] == "DEGRADED")
    _check("only persistence named in degraded_reasons",
           s2["degraded_reasons"] == ["persistence:stale_poll"])
    _check("process itself still reports healthy in its own entry",
           s2["sources"]["process"]["healthy"] is True)

    print("\n[12] TelemetryWatchdog: a loop that hasn't beaten yet is NOT "
          "degraded within its own short startup grace (the first ~1s after "
          "boot, before _loop_stall_monitor's first wake, must not read as "
          "an 'unexplained readiness regression')")
    lh4 = LoopHeartbeat()
    wd3 = TelemetryWatchdog(started_at=0.0, startup_grace=5.0, loop_status_fn=lh4.status,
                            loop_grace=10.0)
    s3_early = wd3.status(now=2.0)
    _check("still within loop_grace -> HEALTHY", s3_early["overall"] == "HEALTHY")

    print("\n[13] TelemetryWatchdog: never-beaten loop PAST its grace -> DEGRADED")
    s3 = wd3.status(now=100.0)
    _check("never-beaten loop past grace, zero collectors -> DEGRADED",
           s3["overall"] == "DEGRADED")
    _check("reason names the event loop", s3["degraded_reasons"] == ["event_loop:event_loop_never_beat"])

    print("\n[14] TelemetryWatchdog: a loop_status_fn that raises degrades neither "
          "silently-healthy nor crashes the read")
    def _boom():
        raise RuntimeError("loop status blew up")
    wd4 = TelemetryWatchdog(started_at=0.0, startup_grace=5.0, loop_status_fn=_boom)
    try:
        s4 = wd4.status(now=100.0)
        _check("status() survives a raising loop_status_fn", True)
        _check("loop reads None rather than crashing the whole payload", s4["loop"] is None)
    except Exception:
        _check("status() survives a raising loop_status_fn", False)

    print("\n[15] FaultInjectableTestCollector: healthy while ticking, "
          "the watchdog reads it exactly like a real collector")
    fic = FaultInjectableTestCollector(poll_interval_s=1.0)
    fic.tick()
    wd5 = TelemetryWatchdog(started_at=0.0, startup_grace=5.0)
    wd5.add_source("fault_test", fic.status, fic.poll_interval_s)
    s5 = wd5.status(now=fic.last_poll_completed_at + 0.5)
    _check("ticking test collector reads HEALTHY", s5["overall"] == "HEALTHY")

    print("\n[16] FaultInjectableTestCollector: freeze() stops progress "
          "without killing the thread - the exact 253s-freeze shape - and "
          "the watchdog must catch it once its own stale bound elapses")
    frozen_at = fic.last_poll_completed_at
    fic.freeze()
    _check("is_frozen() reports True", fic.is_frozen() is True)
    s6 = wd5.status(now=frozen_at + fic.poll_interval_s * 4.0 + 1.0)
    _check("frozen collector -> watchdog goes DEGRADED", s6["overall"] == "DEGRADED")
    _check("reason is stale_poll", s6["degraded_reasons"] == ["fault_test:stale_poll"])

    print("\n[17] FaultInjectableTestCollector: unfreeze() produces REAL, "
          "observable recovery - not just a flag flip")
    fic.unfreeze()
    _check("is_frozen() reports False again", fic.is_frozen() is False)
    s7 = wd5.status(now=fic.last_poll_completed_at + 0.1)
    _check("watchdog returns to HEALTHY only after real progress resumed",
           s7["overall"] == "HEALTHY")

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
