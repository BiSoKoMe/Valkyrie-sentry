"""Sensor tamper detection — notice when Valkyrie's OWN sensors go dark.

Nothing in this codebase previously watched for this. On 2026-08-04, on the
machine this module was written on, a mainstream consumer AV silently
removed SysmonDrv.sys from disk with no clean-uninstall trail — no Service
Control Manager removal event, no uninstall command in any shell history —
and Sysmon64 crashed 25 seconds after the next boot trying to reach its now-
missing driver. Nothing noticed. The engine kept running, reported healthy,
and quietly lost command-line, process-injection, and credential-dump
detection until a human went looking for an unrelated reason.

A detection sensor disappearing is itself an attack technique — T1562.001,
Impair Defenses: Disable or Modify Tools — whether the cause is malware
disabling Valkyrie on purpose or, as measured here, a THIRD PARTY security
product's self-defense module colliding with it by accident. Either way the
right response is the same: notice, and raise it as loudly as any other
detection, not silently degrade.

Scope, honestly: this watches Sysmon specifically (present / running /
collection actually live / the exact event types Valkyrie's detectors read
still configured), because Sysmon is the sensor this session found silently
dying. It is deliberately shaped so another sensor's health check could be
added the same way later — see `_CHECKS` — not because more are needed
today, but so "add a check" stays a one-function change rather than a new
watchdog class each time.

**Compensating control (valkyrie/control_taxonomy.py, IIBA §4.2.3).** Before
this pass, a Sysmon failure was detective-only: an incident was raised, and
detection quality silently fell back to whatever ran independently of
Sysmon (`process_telemetry.ProcessCollector`'s 2-second psutil poll — see
`docs/adr/0048-sysmon-dependency.md`). Nothing actively responded to the
loss. `SensorTamperMonitor` now accepts an optional `compensations` map so a
sensor's health transition can trigger a real substitute action — e.g.
tightening that poller's interval on the healthy→unhealthy transition, and
reverting it on recovery. This is honest about its limits: a userland poll
can partially cover process-creation visibility, but it cannot see the
ETW-only signals (process injection, LSASS access, image-load hashes) —
see `docs/adr/0048-sysmon-dependency.md` and `control_taxonomy.py` for what
is and is not compensated.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from .sysmon_manager import _EID_RULE_SECTION, SysmonEnvironment, probe_sysmon
from .telemetry import (
    ACT_FLAGGED, CAT_PROCESS, SEV_CRITICAL, SEV_INFO, TelemetryEvent,
)


@dataclass(frozen=True)
class SensorHealth:
    name: str
    healthy: bool
    detail: str


def _sysmon_health() -> SensorHealth:
    env: SysmonEnvironment = probe_sysmon()
    if not env.present:
        return SensorHealth("sysmon", False, env.detail or "Sysmon not running")
    if not env.collection_live:
        return SensorHealth("sysmon", False,
                            f"Sysmon running but not delivering events ({env.detail})")
    missing = set(_EID_RULE_SECTION) - set(env.configured_eids)
    if missing:
        names = sorted(_EID_RULE_SECTION[e] for e in missing)
        return SensorHealth("sysmon", False,
                            f"Sysmon running but no longer configured for {names}")
    return SensorHealth("sysmon", True, env.detail)


# One entry per watched sensor. Add here, not by writing a new monitor class.
_CHECKS: tuple = (_sysmon_health,)


class SensorTamperMonitor:
    """Periodically re-checks every registered sensor; raises a CRITICAL
    incident the moment a previously-healthy sensor goes unhealthy.

    Fires on the HEALTHY -> UNHEALTHY transition only. A host that never had
    Sysmon (or has it deliberately disabled) is a known, already-reported
    degraded mode (see sysmon_manager.SysmonInstallResult) — alerting on that
    forever would be noise, not signal. What must never be silent is a sensor
    that WAS working and then stopped, because that is the tamper signature.
    """

    def __init__(self, emit: Callable[[TelemetryEvent], None],
                 interval: float = 300.0,
                 compensations: Optional[dict] = None) -> None:
        """``compensations`` maps a sensor name (e.g. ``"sysmon"``) to a
        ``(activate, deactivate)`` pair of zero-arg callables — the real
        compensating-control action to run on that sensor's healthy→unhealthy
        transition, and the reverting action to run on recovery. Both are
        called defensively (a broken compensation must never take the
        monitor down, same discipline as a broken health check)."""
        self._emit = emit
        self._interval = max(30.0, float(interval))
        self._compensations = dict(compensations) if compensations else {}
        # name -> True/False/None(unknown yet)
        self._last: dict = {}
        # name -> the SAME poll's detail text (why it's healthy/unhealthy --
        # present vs. running vs. missing the specific EIDs Valkyrie reads).
        # Kept separate from `_last` rather than folded into it because
        # current_status()'s {name: bool} shape is an established contract
        # (server.py and tests read it directly) -- adding detail text here
        # is additive instead of a breaking reshape.
        self._last_detail: dict = {}
        # name -> True once that sensor's compensating action is active, so
        # a recovery only fires deactivate() when something was activated
        # (and so current_compensation() can report it without a live probe).
        self._compensated: dict = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def current_compensation(self) -> dict:
        """{sensor_name: bool} -- whether that sensor's compensating action
        is currently active. Empty for sensors with no registered
        compensation at all (distinct from False = registered-but-inactive)."""
        return dict(self._compensated)

    def current_status(self) -> dict:
        """The last-known health per sensor, from the most recent poll — not
        a fresh probe. Cheap on purpose: probe_sysmon() shells out to
        PowerShell several times, so a status API a dashboard might poll
        frequently reads this cache instead of paying that cost per request.
        Empty until start() has run once."""
        return dict(self._last)

    def current_detail(self) -> dict:
        """The last-known DETAIL TEXT per sensor -- e.g. "Sysmon running but
        not delivering events" vs. "no longer configured for ['LSASS access']"
        vs. "Sysmon not running". current_status() collapses this to a bool
        for the tamper-transition logic; a status UI showing WHY a sensor is
        degraded (present? running? missing an EID?) needs the prose this
        returns instead. Same cache-not-probe rule as current_status()."""
        return dict(self._last_detail)

    def poll_once(self) -> int:
        """Run every registered check once. Returns how many transitions
        (healthy -> unhealthy) were emitted this pass."""
        emitted = 0
        for check in _CHECKS:
            try:
                h = check()
            except Exception:
                continue   # a broken checker must never take the monitor down
            was = self._last.get(h.name)
            self._last[h.name] = h.healthy
            self._last_detail[h.name] = h.detail
            if was is True and not h.healthy:
                self._emit_tamper(h)
                self._activate_compensation(h)
                emitted += 1
            elif was is False and h.healthy:
                self._emit_recovery(h)
                self._deactivate_compensation(h)
        return emitted

    def _emit_tamper(self, h: SensorHealth) -> None:
        compensated = h.name in self._compensations
        ev = TelemetryEvent(
            category=CAT_PROCESS, activity="sensor_tamper",
            action=ACT_FLAGGED, severity=SEV_CRITICAL,
            source="sensor_tamper_monitor",
            reason=f"detection sensor '{h.name}' went from healthy to unhealthy: {h.detail}"
                  + (f" — compensating control activated for '{h.name}'" if compensated
                     else f" — NO compensating control registered for '{h.name}'"),
            labels=["sensor_tamper", f"{h.name}_degraded"]
                  + (["compensating_control_activated"] if compensated else []),
            fields={"technique": "T1562.001 — Impair Defenses: Disable or Modify Tools",
                   "sensor": h.name, "compensated": compensated},
        )
        try:
            self._emit(ev)
        except Exception:
            pass   # a bad emitter must never stop the monitor

    def _emit_recovery(self, h: SensorHealth) -> None:
        """Informational (not critical) -- recovery is good news, but IIBA
        §4.2.5's "leave no residual state" applies to the monitor's OWN
        compensating actions too: silently reverting a tightened poll
        interval with no record would be exactly the kind of unannounced
        state change this whole audit exists to stop."""
        ev = TelemetryEvent(
            category=CAT_PROCESS, activity="sensor_recovered",
            action=ACT_FLAGGED, severity=SEV_INFO,
            source="sensor_tamper_monitor",
            reason=f"detection sensor '{h.name}' recovered: {h.detail}",
            labels=["sensor_recovered", f"{h.name}_recovered"],
            fields={"sensor": h.name},
        )
        try:
            self._emit(ev)
        except Exception:
            pass

    def _activate_compensation(self, h: SensorHealth) -> None:
        pair = self._compensations.get(h.name)
        if pair is None:
            self._compensated[h.name] = False
            return
        activate, _deactivate = pair
        try:
            activate()
            self._compensated[h.name] = True
        except Exception:
            # A broken compensating action must not hide the tamper alert
            # that already fired above -- it is reported False, not silently
            # dropped.
            self._compensated[h.name] = False

    def _deactivate_compensation(self, h: SensorHealth) -> None:
        pair = self._compensations.get(h.name)
        if pair is None or not self._compensated.get(h.name):
            return
        _activate, deactivate = pair
        try:
            deactivate()
        except Exception:
            pass
        finally:
            self._compensated[h.name] = False

    # -- lifecycle ------------------------------------------------------------
    def start(self) -> None:
        if self._running:
            return
        # Baseline seeding runs INSIDE the monitor thread (see _loop), not here.
        # Each check() shells out (sc query, Get-Acl, driver probe); on a host
        # where spawning those is slow this seeding measured ~60s, and doing it
        # in start() blocked the whole agent — including the web server bind —
        # for that entire time. The "no false first-alert" guarantee is
        # preserved: the first real poll cannot fire before one _interval has
        # elapsed anyway, and _loop seeds the baseline before that first sleep.
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="sensor-tamper-monitor")
        self._thread.start()

    def _seed_baseline(self) -> None:
        """Record each sensor's CURRENT health as the starting point so a sensor
        already down at startup is a known-bad baseline, not a false transition
        alert on the first poll. Runs once, in-thread, before the poll loop."""
        for check in _CHECKS:
            try:
                h = check()
                self._last[h.name] = h.healthy
                self._last_detail[h.name] = h.detail
            except Exception:
                continue

    def stop(self) -> None:
        self._running = False

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _loop(self) -> None:
        # Seed the baseline first (was in start(); moved here so its slow
        # subprocess checks never block agent startup — see start()).
        try:
            self._seed_baseline()
        except Exception:
            pass
        while self._running:
            time.sleep(self._interval)
            if not self._running:
                break
            try:
                self.poll_once()
            except Exception:
                pass
