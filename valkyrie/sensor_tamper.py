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
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from .sysmon_manager import _EID_RULE_SECTION, SysmonEnvironment, probe_sysmon
from .telemetry import ACT_FLAGGED, CAT_PROCESS, SEV_CRITICAL, TelemetryEvent


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
                 interval: float = 300.0) -> None:
        self._emit = emit
        self._interval = max(30.0, float(interval))
        # name -> True/False/None(unknown yet)
        self._last: dict = {}
        # name -> the SAME poll's detail text (why it's healthy/unhealthy --
        # present vs. running vs. missing the specific EIDs Valkyrie reads).
        # Kept separate from `_last` rather than folded into it because
        # current_status()'s {name: bool} shape is an established contract
        # (server.py and tests read it directly) -- adding detail text here
        # is additive instead of a breaking reshape.
        self._last_detail: dict = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None

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
                emitted += 1
        return emitted

    def _emit_tamper(self, h: SensorHealth) -> None:
        ev = TelemetryEvent(
            category=CAT_PROCESS, activity="sensor_tamper",
            action=ACT_FLAGGED, severity=SEV_CRITICAL,
            source="sensor_tamper_monitor",
            reason=f"detection sensor '{h.name}' went from healthy to unhealthy: {h.detail}",
            labels=["sensor_tamper", f"{h.name}_degraded"],
            fields={"technique": "T1562.001 — Impair Defenses: Disable or Modify Tools",
                   "sensor": h.name},
        )
        try:
            self._emit(ev)
        except Exception:
            pass   # a bad emitter must never stop the monitor

    # -- lifecycle ------------------------------------------------------------
    def start(self) -> None:
        if self._running:
            return
        # Seed the baseline synchronously so a sensor that is ALREADY down at
        # startup is recorded as a known-bad starting point (no false
        # transition-alert on the very first poll) rather than as "unknown".
        for check in _CHECKS:
            try:
                h = check()
                self._last[h.name] = h.healthy
                self._last_detail[h.name] = h.detail
            except Exception:
                continue
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="sensor-tamper-monitor")
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _loop(self) -> None:
        while self._running:
            time.sleep(self._interval)
            if not self._running:
                break
            try:
                self.poll_once()
            except Exception:
                pass
