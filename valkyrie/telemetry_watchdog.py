"""Central telemetry-reliability watchdog (Platform Beta 0.5).

Distinguishes "sensor thread alive" from "sensor actually producing data" -
the exact gap that let the persistence collector freeze the whole server for
253 seconds while ``is_running()`` stayed True the entire time (see
valkyrie_startup_deafness). ``last_poll_completed_at`` is the raw signal each
collector now exposes; this module is what reads it and turns staleness into
a DEGRADED verdict, mirroring self_test.HeartbeatMonitor's
staleness-with-grace design but as a stateless aggregator rather than its own
background thread - each collector already polls on its own schedule, so the
watchdog only needs to be read (e.g. from an API route), not run.

This is a reliability signal about the telemetry PIPE, never a security
verdict: DEGRADED means "do not trust what this sensor is telling you right
now", not "the host is compromised".
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Optional

REASON_NOT_AVAILABLE = "not_available"
REASON_NOT_RUNNING = "not_running"
REASON_NO_POLL_YET = "no_poll_completed_within_grace"
REASON_STALE_POLL = "stale_poll"
REASON_LOOP_NEVER_BEAT = "event_loop_never_beat"
REASON_LOOP_STALLED = "event_loop_stalled"


@dataclass
class PollSourceSpec:
    """One periodic collector this watchdog tracks.

    ``status_fn`` returns the collector's own ``.status()`` dict, or None if
    the collector was never constructed (e.g. psutil missing) - the watchdog
    only ever talks to a collector through that contract, so a test double
    needs no real collector.
    """
    name: str
    status_fn: Callable[[], Optional[dict]]
    expected_interval: float
    stale_multiplier: float = 4.0


def evaluate_poll_source(spec: PollSourceSpec, now: float, started_at: float,
                          startup_grace: float) -> dict:
    """One collector's HEALTHY/DEGRADED read.

    Three distinct failure shapes, reported separately rather than folded
    into one boolean, because they call for different responses: the thread
    died (NOT_RUNNING), it never got around to a first poll within a
    reasonable startup window (NO_POLL_YET), or - the one is_running() alone
    cannot see - it is alive but has gone far longer than its own interval
    without finishing a poll (STALE_POLL, the 253s-freeze shape).
    """
    status = spec.status_fn()
    if status is None:
        return {"name": spec.name, "healthy": True, "available": False,
                "reason": REASON_NOT_AVAILABLE, "status": None}

    running = bool(status.get("running", False))
    last_poll = float(status.get("last_poll_completed_at", 0.0) or 0.0)

    if not running:
        return {"name": spec.name, "healthy": False, "available": True,
                "reason": REASON_NOT_RUNNING, "status": status}

    if last_poll == 0.0:
        if (now - started_at) > startup_grace:
            return {"name": spec.name, "healthy": False, "available": True,
                    "reason": REASON_NO_POLL_YET, "status": status}
        return {"name": spec.name, "healthy": True, "available": True,
                "reason": None, "status": status}

    staleness = now - last_poll
    stale_bound = spec.expected_interval * spec.stale_multiplier
    if staleness > stale_bound:
        return {"name": spec.name, "healthy": False, "available": True,
                "reason": REASON_STALE_POLL, "status": status,
                "stale_for_seconds": staleness, "stale_bound_seconds": stale_bound}

    return {"name": spec.name, "healthy": True, "available": True,
            "reason": None, "status": status}


class LoopHeartbeat:
    """Queryable record of the asyncio event loop's own responsiveness.

    server.py's ``_loop_stall_monitor`` coroutine calls ``.beat(drift)``
    every time it wakes (about once a second); this class only records the
    result, so a status endpoint (and TelemetryWatchdog) can read the signal
    instead of it existing only as a stderr print in a CI transcript.
    """

    def __init__(self) -> None:
        self.last_beat_at: float = 0.0
        self.last_drift_seconds: float = 0.0
        self.worst_drift_seconds: float = 0.0

    def beat(self, drift: float) -> None:
        self.last_beat_at = time.time()
        self.last_drift_seconds = max(0.0, drift)
        if self.last_drift_seconds > self.worst_drift_seconds:
            self.worst_drift_seconds = self.last_drift_seconds

    def status(self, now: Optional[float] = None, stale_after: float = 5.0) -> dict:
        """``stale_after`` default of 5s against a ~1s beat interval is
        generous the same way HeartbeatMonitor's 4-interval rule is: it
        should catch a monitor that stopped entirely, not flap on a single
        slow wake."""
        now = now if now is not None else time.time()
        never_beat = self.last_beat_at == 0.0
        stale = never_beat or (now - self.last_beat_at) > stale_after
        return {
            "beating": not stale,
            "last_beat_at": self.last_beat_at,
            "last_drift_seconds": self.last_drift_seconds,
            "worst_drift_seconds": self.worst_drift_seconds,
            "stale": stale,
        }


class FaultInjectableTestCollector:
    """TEST-ONLY double for one real periodic collector, used to prove the
    watchdog actually catches the failure class it exists for: a source that
    is alive and was healthy, then silently stops advancing
    last_poll_completed_at while still reporting running=True.

    This never touches a real collector - it is a separate, fake source
    wired into the SAME TelemetryWatchdog instance a real deployment uses,
    gated behind an explicit opt-in (see server.py's
    VALKYRIE_DEBUG_FAULT_COLLECTOR check) so it can never appear in a normal
    run. A background driver (started by the caller) should call
    ``.tick()`` on an interval to simulate a healthy collector; ``.freeze()``
    stops that from having any further effect, simulating the exact
    "thread alive, stopped progressing" shape a real GIL-starved collector
    thread produces; ``.unfreeze()`` lets it resume.
    """

    def __init__(self, poll_interval_s: float = 1.0) -> None:
        # No lock: every field here is a single bool/float assignment, atomic
        # under the GIL, the same no-lock contract LoopHeartbeat above relies
        # on - tick() runs on a background driver thread, freeze()/unfreeze()
        # on the API's threadpool, status() on either.
        self._frozen = False
        self.last_poll_completed_at: float = 0.0
        self.poll_interval_s = poll_interval_s

    def tick(self) -> None:
        if not self._frozen:
            self.last_poll_completed_at = time.time()

    def freeze(self) -> None:
        self._frozen = True

    def unfreeze(self) -> None:
        self._frozen = False
        self.tick()   # an immediate fresh tick, so recovery is observable now

    def is_frozen(self) -> bool:
        return self._frozen

    def status(self) -> dict:
        return {
            "running": True,   # the thread never dies in this fault class
            "last_poll_completed_at": self.last_poll_completed_at,
            "poll_interval_s": self.poll_interval_s,
            "frozen": self._frozen,   # visible for the harness's own bookkeeping only
        }


class TelemetryWatchdog:
    """Aggregates every periodic collector's liveness into one HEALTHY /
    DEGRADED read, plus the event loop's own heartbeat if wired in.

    Deliberately not a background thread of its own: it evaluates staleness
    against wall-clock time at read time, the same way
    HeartbeatMonitor.status() does, rather than polling anything itself.
    """

    def __init__(self, started_at: Optional[float] = None,
                 startup_grace: float = 60.0,
                 loop_status_fn: Optional[Callable[[], Optional[dict]]] = None,
                 loop_grace: float = 10.0) -> None:
        self._sources: list[PollSourceSpec] = []
        self._started_at = started_at if started_at is not None else time.time()
        self._startup_grace = startup_grace
        self._loop_status_fn = loop_status_fn
        # The loop beats about once a second, far faster than any collector,
        # so it needs only a short grace - but it still needs one: without
        # it, every fresh boot reads DEGRADED for the ~1s before the first
        # beat lands, which is a false "unexplained readiness regression",
        # not a real one.
        self._loop_grace = loop_grace

    def add_source(self, name: str, status_fn: Callable[[], Optional[dict]],
                   expected_interval: float, stale_multiplier: float = 4.0) -> None:
        self._sources.append(
            PollSourceSpec(name, status_fn, expected_interval, stale_multiplier))

    def status(self, now: Optional[float] = None) -> dict:
        now = now if now is not None else time.time()
        sources: dict = {}
        degraded_reasons: list[str] = []

        for spec in self._sources:
            result = evaluate_poll_source(spec, now, self._started_at, self._startup_grace)
            sources[spec.name] = result
            if not result["healthy"]:
                degraded_reasons.append(f"{spec.name}:{result['reason']}")

        loop_info = None
        if self._loop_status_fn is not None:
            try:
                loop_info = self._loop_status_fn()
            except Exception:
                loop_info = None
            if loop_info is not None and not loop_info.get("beating", True):
                never_beat = not loop_info.get("last_beat_at")
                in_grace = never_beat and (now - self._started_at) <= self._loop_grace
                if not in_grace:
                    reason = REASON_LOOP_NEVER_BEAT if never_beat else REASON_LOOP_STALLED
                    degraded_reasons.append(f"event_loop:{reason}")

        return {
            "overall": "DEGRADED" if degraded_reasons else "HEALTHY",
            "degraded_reasons": degraded_reasons,
            "sources": sources,
            "loop": loop_info,
            "checked_at": now,
        }
