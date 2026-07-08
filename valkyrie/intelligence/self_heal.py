"""SelfHealing — background watchdog that keeps Valkyrie's components
alive without ever crashing the system itself.

Components register a ``check_fn`` (returns True when healthy) and an
optional ``recover_fn``.  Every SELF_HEAL_INTERVAL seconds each check
runs inside its own try/except; on failure the recovery is attempted
(also isolated) and the incident is logged to the Store as a
``self_heal`` event.  One component failing — or one check raising —
never affects the others.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Optional

from ..config import SELF_HEAL_INTERVAL


class _Component:
    __slots__ = ("name", "check_fn", "recover_fn", "ok", "last_check",
                 "failures", "recoveries", "last_error")

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
                    "ok":         c.ok,
                    "failures":   c.failures,
                    "recoveries": c.recoveries,
                    "last_error": c.last_error,
                    "last_check": c.last_check,
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
            error = f"check raised: {exc}"        # not a crash — catch BaseException
        comp.last_check = time.time()             # (not just Exception) so a stray
                                                    # SystemExit/KeyboardInterrupt raised
                                                    # inside a check/recover callback can
                                                    # never silently kill the watchdog
                                                    # thread (see _loop below).

        if healthy:
            comp.ok = True
            comp.last_error = ""
            return

        comp.ok = False
        comp.failures += 1
        comp.last_error = error or "health check returned False"
        self._log(f"{comp.name} unhealthy ({comp.last_error}) — attempting recovery")

        if comp.recover_fn is None:
            return
        try:
            comp.recover_fn()
            comp.recoveries += 1
            self._log(f"{comp.name} recovery attempted")
        except BaseException as exc:
            comp.last_error = f"recovery raised: {exc}"
            self._log(f"{comp.name} recovery failed: {exc}")

    def _loop(self) -> None:
        while self._running:
            time.sleep(self._interval)
            if not self._running:
                break
            try:
                self.check_now()
            except BaseException:
                pass    # the watchdog itself must never die — a check_fn/recover_fn
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
