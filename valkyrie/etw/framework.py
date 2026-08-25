"""Sensor framework - the resilient host for real-time endpoint sensors.

A ``Sensor`` produces ``TelemetryEvent``s from some source (an ETW-backed event-
log channel today; a kernel ETW session later). The ``SensorManager`` owns them
and provides the production-grade properties every sensor needs but none should
re-implement:

  * **Lifecycle** - start/stop all sensors, clean shutdown that drains in flight.
  * **Failure isolation** - one sensor raising never affects the others or the host.
  * **Watchdog** - a dead sensor is automatically restarted (bounded, backoff),
    and the manager exposes ``is_healthy()`` for the global self-heal loop.
  * **Backpressure** - sensors submit into a *bounded* queue; a single dispatcher
    thread forwards to the sink. On overload the oldest event is dropped and
    counted, so memory stays bounded and a burst never blocks a sensor.
  * **De-duplication** - a bounded LRU of recent event fingerprints collapses
    repeats (channels re-deliver; multiple sensors can see the same act).
  * **Observability** - per-sensor and aggregate metrics via ``stats()``.

Nothing here knows about ETW specifics; that lives in the sensors. This module
is pure Python + threads and is fully unit-testable with a fake sensor.
"""

from __future__ import annotations

import threading
import time
import logging
from collections import deque
from typing import Callable, Optional

from ..telemetry import TelemetryEvent

log = logging.getLogger("valkyrie.sensors")

EmitFn = Callable[[TelemetryEvent], None]


class Sensor:
    """Base class. Subclasses implement _run() (a loop) or override start/stop.

    The default implementation runs ``_collect_once`` on an interval in a daemon
    thread; event-driven sensors can override ``start``/``stop`` instead. A
    subclass calls ``self.submit(event)`` to hand an event to the manager.
    """

    name = "sensor"

    def __init__(self) -> None:
        self._submit: Optional[EmitFn] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._started_at = 0.0
        self.emitted = 0
        self.errors = 0
        self.last_error: Optional[str] = None

    # Wiring -----------------------------------------------------------------
    def bind(self, submit: EmitFn) -> None:
        self._submit = submit

    def submit(self, event: TelemetryEvent) -> None:
        self.emitted += 1
        if self._submit is not None:
            self._submit(event)

    # Availability - a sensor that can't run on this host returns False so the
    # manager skips it cleanly (e.g. non-Windows, channel disabled).
    def available(self) -> bool:
        return True

    # Lifecycle --------------------------------------------------------------
    def start(self) -> None:
        if self._running or not self.available():
            return
        self._running = True
        self._started_at = time.time()
        self._thread = threading.Thread(target=self._loop, name=f"sensor-{self.name}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def is_running(self) -> bool:
        return bool(self._running and self._thread and self._thread.is_alive())

    # Default poll loop; override _collect_once (return count) or override
    # start/stop for a push model.
    interval = 1.0

    def _loop(self) -> None:
        while self._running:
            try:
                self._collect_once()
            except Exception as e:                 # failure isolation
                self.errors += 1
                self.last_error = str(e)
                log.warning("sensor %s error: %s", self.name, e)
            for _ in range(int(self.interval * 10)):
                if not self._running:
                    break
                time.sleep(0.1)

    def _collect_once(self) -> None:               # pragma: no cover - overridden
        pass

    def health(self) -> dict:
        return {"name": self.name, "running": self.is_running(),
                "emitted": self.emitted, "errors": self.errors,
                "last_error": self.last_error}


class SensorManager:
    """Owns sensors, dispatches their events (deduped, bounded) to a sink."""

    def __init__(
        self,
        sink: EmitFn,
        *,
        queue_max: int = 10000,
        dedup_max: int = 4096,
        dedup_window: float = 5.0,
        watchdog_interval: float = 15.0,
        max_restarts: int = 5,
    ) -> None:
        self._sink = sink
        self._sensors: list[Sensor] = []
        self._q: deque = deque(maxlen=queue_max)
        self._q_lock = threading.Lock()
        self._q_event = threading.Event()

        self._dedup_max = dedup_max
        self._dedup_window = dedup_window
        self._dedup_keys: dict = {}                # fingerprint -> last_seen ts
        self._dedup_order: deque = deque()

        self._watchdog_interval = watchdog_interval
        self._max_restarts = max_restarts
        self._restarts: dict = {}                  # sensor name -> remaining

        self._running = False
        self._dispatch_thread: Optional[threading.Thread] = None
        self._watchdog_thread: Optional[threading.Thread] = None

        self.metrics = {"submitted": 0, "emitted": 0, "dropped_backpressure": 0,
                        "dropped_dedup": 0, "restarts": 0}

    # Registration -----------------------------------------------------------
    def register(self, sensor: Sensor) -> None:
        sensor.bind(self._submit)
        self._sensors.append(sensor)
        self._restarts[sensor.name] = self._max_restarts

    # Producer side: sensors call this (via Sensor.submit -> bind). Bounded and
    # non-blocking - a full queue drops the OLDEST event (deque maxlen) so a
    # sensor is never blocked and memory is bounded.
    def _submit(self, event: TelemetryEvent) -> None:
        self.metrics["submitted"] += 1
        with self._q_lock:
            if len(self._q) == self._q.maxlen:
                self.metrics["dropped_backpressure"] += 1   # oldest will be evicted
            self._q.append(event)
        self._q_event.set()

    # Dedup fingerprint - an event may carry an explicit key in fields["_dedup"],
    # else derive from its identifying core fields.
    @staticmethod
    def _fingerprint(ev: TelemetryEvent) -> str:
        d = ev.fields.get("_dedup") if isinstance(ev.fields, dict) else None
        if d:
            return f"{ev.category}:{ev.activity}:{d}"
        tgt = ev.target or {}
        key = tgt.get("domain") or tgt.get("ip") or tgt.get("location") or \
            tgt.get("command") or tgt.get("path") or ""
        return f"{ev.category}:{ev.activity}:{ev.actor_pid}:{ev.actor_name}:{key}"

    def _is_duplicate(self, ev: TelemetryEvent) -> bool:
        fp = self._fingerprint(ev)
        now = time.time()
        last = self._dedup_keys.get(fp)
        if last is not None and (now - last) <= self._dedup_window:
            self._dedup_keys[fp] = now
            return True
        self._dedup_keys[fp] = now
        self._dedup_order.append(fp)
        # Bound the LRU.
        while len(self._dedup_order) > self._dedup_max:
            old = self._dedup_order.popleft()
            # Only forget if it wasn't refreshed to a newer position.
            if self._dedup_keys.get(old) is not None and old not in self._dedup_order:
                self._dedup_keys.pop(old, None)
        return False

    # Consumer side: single dispatcher drains the queue -> sink, deduped.
    def _dispatch_loop(self) -> None:
        while self._running or self._pending():
            self._q_event.wait(timeout=0.5)
            self._q_event.clear()
            while True:
                with self._q_lock:
                    if not self._q:
                        break
                    ev = self._q.popleft()
                if self._is_duplicate(ev):
                    self.metrics["dropped_dedup"] += 1
                    continue
                try:
                    self._sink(ev)
                    self.metrics["emitted"] += 1
                except Exception as e:             # a bad sink never kills dispatch
                    log.warning("sensor sink error: %s", e)

    def _pending(self) -> bool:
        with self._q_lock:
            return bool(self._q)

    # Watchdog: restart any sensor that should be running but died.
    def _watchdog_loop(self) -> None:
        while self._running:
            for _ in range(int(self._watchdog_interval * 10)):
                if not self._running:
                    return
                time.sleep(0.1)
            for s in self._sensors:
                if not s.available():
                    continue
                if not s.is_running() and self._restarts.get(s.name, 0) > 0:
                    self._restarts[s.name] -= 1
                    self.metrics["restarts"] += 1
                    log.warning("watchdog restarting sensor %s (%d left)",
                                s.name, self._restarts[s.name])
                    try:
                        s.start()
                    except Exception as e:
                        log.warning("restart of %s failed: %s", s.name, e)

    # Lifecycle --------------------------------------------------------------
    def start(self) -> int:
        if self._running:
            return 0
        self._running = True
        self._dispatch_thread = threading.Thread(target=self._dispatch_loop,
                                                 name="sensor-dispatch", daemon=True)
        self._dispatch_thread.start()
        self._watchdog_thread = threading.Thread(target=self._watchdog_loop,
                                                 name="sensor-watchdog", daemon=True)
        self._watchdog_thread.start()
        started = 0
        for s in self._sensors:
            if s.available():
                try:
                    s.start()
                    started += 1
                except Exception as e:
                    log.warning("sensor %s failed to start: %s", s.name, e)
        log.info("sensor manager started (%d/%d sensors active)", started, len(self._sensors))
        return started

    def stop(self) -> None:
        for s in self._sensors:
            try:
                s.stop()
            except Exception:
                pass
        self._running = False
        self._q_event.set()
        t = self._dispatch_thread
        if t and t.is_alive():
            t.join(timeout=3.0)

    def is_running(self) -> bool:
        return self._running

    # For the global self-heal loop: healthy if the dispatcher is alive and at
    # least one available sensor is running.
    def is_healthy(self) -> bool:
        if not self._running:
            return False
        if not (self._dispatch_thread and self._dispatch_thread.is_alive()):
            return False
        avail = [s for s in self._sensors if s.available()]
        return (not avail) or any(s.is_running() for s in avail)

    def active_sensors(self) -> list[str]:
        return [s.name for s in self._sensors if s.is_running()]

    def stats(self) -> dict:
        return {
            "running": self._running,
            "sensors": [s.health() for s in self._sensors],
            "active": self.active_sensors(),
            **self.metrics,
            "queue_depth": len(self._q),
        }
