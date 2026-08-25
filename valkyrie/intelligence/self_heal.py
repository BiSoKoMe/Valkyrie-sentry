"""SelfHealing - background watchdog that keeps Valkyrie's components
alive without ever crashing the system itself.

Components register a ``check_fn`` (returns True when healthy) and an
optional ``recover_fn``.  Every SELF_HEAL_INTERVAL seconds each check
runs inside its own try/except; on failure the recovery is attempted
(also isolated) and the incident is logged to the Store as a
``self_heal`` event.  One component failing - or one check raising -
never affects the others.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Optional

from ..config import SELF_HEAL_INTERVAL


def _should_log_failure(consecutive: int) -> bool:
    """Log failure 1, 2, 4, 8, 16, ... - never every single cycle.

    A component that stays down writes one ``self_heal`` row per check
    forever. At a 30s interval that is 2,880 rows a day, and the events table
    is what ``/api/stats`` aggregates and what the UI's Recent Events list
    renders. Two consequences, both bad:

      * real detections get pushed out of the events view by watchdog noise,
        which is detection LOSS in a security product's primary surface;
      * the table grows, ``/api/stats`` slows, and on the old 3s-timeout probe
        that made the next health check likelier to fail. The symptom fed the
        cause.

    Powers of two keep the first failures immediately visible (which is when
    they matter), then decay to a sparse permanent trail. The state itself is
    never hidden -- ``status()`` always reports ok/failures/last_error live.
    """
    return consecutive <= 2 or (consecutive & (consecutive - 1)) == 0


class _Component:
    __slots__ = ("name", "check_fn", "recover_fn", "ok", "last_check",
                 "failures", "recoveries", "last_error", "consecutive")

    def __init__(self, name: str,
                 check_fn: Callable[[], bool],
                 recover_fn: Optional[Callable[[], None]]) -> None:
        self.name       = name
        self.check_fn   = check_fn
        self.recover_fn = recover_fn
        self.ok         = True
        self.last_check = 0.0
        self.failures   = 0
        self.recoveries = 0
        self.last_error = ""
        # Run of consecutive failures; resets on recovery. Drives log backoff.
        self.consecutive = 0


class SelfHealing:
    """Watchdog thread over registered components."""

    def __init__(self, store=None, interval: float = SELF_HEAL_INTERVAL) -> None:
        self._store = store
        self._interval = interval
        self._components: dict[str, _Component] = {}
        self._lock = threading.RLock()
        self._running = False
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="self-heal"
        )

    # ------------------------------------------------------------------
    # Registration / lifecycle
    # ------------------------------------------------------------------

    def register(self, name: str, check_fn: Callable[[], bool],
                 recover_fn: Optional[Callable[[], None]] = None) -> None:
        with self._lock:
            self._components[name] = _Component(name, check_fn, recover_fn)

    def start(self) -> None:
        self._running = True
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def status(self) -> dict:
        with self._lock:
            return {
                c.name: {
                    "ok":          c.ok,
                    "failures":    c.failures,
                    "recoveries":  c.recoveries,
                    "last_error":  c.last_error,
                    "last_check":  c.last_check,
                    # Live and never rate-limited, unlike the event log:
                    # backing off the LOGGING must not hide the STATE.
                    "consecutive": c.consecutive,
                    "recoverable": c.recover_fn is not None,
                }
                for c in self._components.values()
            }

    def all_ok(self) -> bool:
        with self._lock:
            return all(c.ok for c in self._components.values())

    # ------------------------------------------------------------------
    # Watchdog loop
    # ------------------------------------------------------------------

    def check_now(self) -> None:
        """Run one full check pass (also used by the loop and by tests)."""
        with self._lock:
            components = list(self._components.values())
        for comp in components:
            self._check_one(comp)

    def _check_one(self, comp: _Component) -> None:
        healthy = False
        error = ""
        try:
            healthy = bool(comp.check_fn())
        except BaseException as exc:              # a broken check is a failure,
            error = f"check raised: {exc}"        # not a crash - catch BaseException
        comp.last_check = time.time()             # (not just Exception) so a stray
                                                    # SystemExit/KeyboardInterrupt raised
                                                    # inside a check/recover callback can
                                                    # never silently kill the watchdog
                                                    # thread (see _loop below).

        if healthy:
            # A component coming BACK is information, and it used to be logged
            # nowhere at all -- the trail showed the failure and then silence,
            # which reads identically to "still broken, watchdog gave up".
            if not comp.ok:
                self._log(f"{comp.name} recovered after {comp.consecutive} "
                          f"failed check(s)")
            comp.ok = True
            comp.last_error = ""
            comp.consecutive = 0
            return

        comp.ok = False
        comp.failures += 1
        comp.consecutive += 1
        comp.last_error = error or "health check returned False"

        if comp.recover_fn is None:
            # Do not claim an action that cannot happen. This branch used to
            # log "attempting recovery" for every component, including the
            # ones registered with no recover_fn at all -- web_dashboard being
            # exactly that case. Announcing a recovery that no code will ever
            # perform is worse than silence: it makes an unattended failure
            # look like it is being handled.
            if _should_log_failure(comp.consecutive):
                self._log(f"{comp.name} unhealthy ({comp.last_error}) — "
                          f"no recovery action is registered for it "
                          f"(failure #{comp.consecutive})")
            return

        if _should_log_failure(comp.consecutive):
            self._log(f"{comp.name} unhealthy ({comp.last_error}) — "
                      f"attempting recovery (failure #{comp.consecutive})")
        try:
            comp.recover_fn()
            comp.recoveries += 1
            if _should_log_failure(comp.consecutive):
                self._log(f"{comp.name} recovery attempted")
        except BaseException as exc:
            comp.last_error = f"recovery raised: {exc}"
            if _should_log_failure(comp.consecutive):
                self._log(f"{comp.name} recovery failed: {exc}")

    def _loop(self) -> None:
        while self._running:
            time.sleep(self._interval)
            if not self._running:
                break
            try:
                self.check_now()
            except BaseException:
                pass    # the watchdog itself must never die - a check_fn/recover_fn
                         # is untrusted third-party-ish code (dns_server.start(), etc.)
                         # and _check_one already isolates ordinary exceptions, but this
                         # outer guard is the last line of defence for anything that
                         # slips past it (e.g. a bug in check_now()/_check_one() itself).

    def _log(self, message: str) -> None:
        if self._store is None:
            return
        try:
            from ..store import DnsEvent
            self._store.log(DnsEvent.now(
                domain       = "",
                decision     = "flagged",
                process_name = "valkyrie",
                process_pid  = 0,
                process_path = "",
                reason       = message,
                suspicion    = 0.0,
                raw_category = "self_heal",
            ))
        except Exception:
            pass
