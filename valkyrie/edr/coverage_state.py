"""Coverage as the sensor-state oracle for the authority gate.

``authority.authorize()`` takes a ``sensor_state`` callable mapping a control
id to one of sensor_deps' STATE_* values. Those values are, deliberately, the
same vocabulary coverage.py already speaks (effective / degraded / absent), so
coverage IS the oracle -- a detector whose sensors are dark should not buy the
same authority as one whose sensors are live.

Two things make that awkward in the detection path, and this module exists to
solve both without compromising either:

``check_all() costs ~3.3s``
    Measured: secure_file 1.74s, dns_sinkhole 0.52s, killchain_correlator
    0.44s, etw_sysmon 0.43s. Running that per detection would be far worse
    than the API bug just fixed, because it would sit in the path that has to
    react to an attack.

``a missing snapshot must not grant authority``
    So the cold answer is STATE_UNKNOWN, which sensor_deps already treats as
    dark. Unknown yields LESS authority, never more. The first detection after
    startup is therefore judged conservatively rather than optimistically, and
    the refresh happens off the hot path.

Refresh is best-effort and never raises into the caller: a failed refresh
keeps the previous snapshot and, if there is none, everything stays unknown.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Optional

from . import sensor_deps

# How long a coverage snapshot is considered current. Coverage changes on the
# timescale of a service stopping, not of a detection firing.
TTL_S = 120.0


class CoverageStateProvider:
    """TTL-cached control -> state lookup, refreshed off the detection path."""

    def __init__(self, ctx_factory: Callable[[], object],
                 *, ttl_s: float = TTL_S,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._ctx_factory = ctx_factory
        self._ttl_s = ttl_s
        self._clock = clock
        self._states: dict[str, str] = {}
        self._computed_at = 0.0
        self._refreshing = False
        self._lock = threading.RLock()
        self.refreshes = 0
        self.failures = 0
        self.last_error = ""

    # ------------------------------------------------------------------ read
    def state_of(self, control: str) -> str:
        """The sensor_state callable handed to authority.authorize()."""
        with self._lock:
            fresh = (self._states
                     and (self._clock() - self._computed_at) < self._ttl_s)
            state = self._states.get(control, sensor_deps.STATE_UNKNOWN)
        if not fresh:
            self._schedule_refresh()
        # A stale snapshot is still real evidence about the host, so it is
        # served while the refresh runs -- but a control that has NEVER been
        # measured stays unknown, and unknown is the conservative answer.
        return state

    def __call__(self, control: str) -> str:
        return self.state_of(control)

    # --------------------------------------------------------------- refresh
    def _schedule_refresh(self) -> None:
        with self._lock:
            if self._refreshing:
                return
            self._refreshing = True
        threading.Thread(target=self._refresh, daemon=True,
                         name="coverage-state").start()

    def _refresh(self) -> None:
        try:
            from ..coverage import check_all
            results = check_all(self._ctx_factory())
            states = {r.name: r.state for r in results}
            with self._lock:
                self._states = states
                self._computed_at = self._clock()
                self.refreshes += 1
                self.last_error = ""
        except Exception as exc:                              # noqa: BLE001
            with self._lock:
                self.failures += 1
                self.last_error = f"{type(exc).__name__}: {exc}"
        finally:
            with self._lock:
                self._refreshing = False

    # ----------------------------------------------------------------- debug
    def snapshot(self) -> dict:
        with self._lock:
            return {
                "measured": bool(self._states),
                "age_s": (round(self._clock() - self._computed_at, 1)
                          if self._states else None),
                "refreshes": self.refreshes,
                "failures": self.failures,
                "last_error": self.last_error,
                "effective": sum(1 for s in self._states.values()
                                 if s == sensor_deps.STATE_EFFECTIVE),
                "total": len(self._states),
            }


_PROVIDER: Optional[CoverageStateProvider] = None
_PROVIDER_LOCK = threading.RLock()


def install(provider: Optional[CoverageStateProvider]) -> None:
    """Set (or clear) the process-wide provider. Called by the composition root."""
    global _PROVIDER
    with _PROVIDER_LOCK:
        _PROVIDER = provider


def provider() -> Optional[CoverageStateProvider]:
    with _PROVIDER_LOCK:
        return _PROVIDER


def sensor_state() -> Optional[Callable[[str], str]]:
    """The callable for authority.authorize(), or None when not installed.

    None means "skip the coverage gate", which authorize() treats as a no-op
    rather than an implicit pass -- so an engine that never installs a provider
    behaves exactly as it did before this existed.
    """
    p = provider()
    return p.state_of if p is not None else None
