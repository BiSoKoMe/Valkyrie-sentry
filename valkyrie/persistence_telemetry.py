"""Persistence (ASEP) telemetry collector - endpoint visibility for the places
attackers establish persistence.

Auto-Start Extension Points (ASEPs) are where malware survives reboot: registry
Run keys, Windows services, Scheduled Tasks and Startup folders. This collector
snapshots those locations and emits a normalized ``TelemetryEvent`` (category
``persistence``) whenever a NEW entry appears - the highest-signal, lowest-noise
endpoint telemetry available without a kernel sensor.

Scope and honesty:
  * **Read-only pollers** over the registry (stdlib ``winreg``) and the
    filesystem - no ETW, no kernel, no external process, no console window. It
    detects persistence shortly after it is written (poll interval), not at the
    instant of the write. Real-time capture (ETW registry/file providers) is the
    documented next increment; it plugs into the same schema and pipeline.
  * The first poll establishes a silent baseline, so the hundreds of legitimate
    pre-existing ASEPs are not reported - only entries created *after* start.
  * Degrades gracefully to a no-op on non-Windows or when a key is unreadable;
    never raises into the caller.

Every event carries a MITRE-ish label (run key -> T1547, service -> T1543, task ->
T1053, startup folder -> T1547) that the EDR engine maps to a technique, and a
suspicious command line (encoded PowerShell, download cradle, temp path) escalates
the severity via the same heuristics the process collector uses.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Callable, Optional

from .telemetry import (
    ACT_FLAGGED, ACT_OBSERVED, CAT_PERSISTENCE,
    PERSIST_RUN_KEY, PERSIST_SCHEDULED_TASK, PERSIST_SERVICE, PERSIST_STARTUP_FOLDER,
    SEV_HIGH, SEV_INFO, SEV_MEDIUM, severity_rank, TelemetryEvent,
)
from .process_telemetry import classify_cmdline, _SUSPICIOUS_PATHS
from .trust import is_trusted_os_command

try:
    import winreg
    _WINREG = True
except ImportError:
    winreg = None  # type: ignore
    _WINREG = False


# Label + MITRE technique per ASEP class (technique mapping lives in the EDR
# engine's _TELEMETRY_TECHNIQUE; the label is the join key).
_ACTIVITY_LABEL = {
    PERSIST_RUN_KEY:        "persistence_run_key",
    PERSIST_SERVICE:        "persistence_service",
    PERSIST_SCHEDULED_TASK: "persistence_scheduled_task",
    PERSIST_STARTUP_FOLDER: "persistence_startup_folder",
}

def _enum_loaded_user_sids() -> list[str]:
    """SIDs of currently-LOADED user hives under HKEY_USERS - i.e. actual
    logged-on interactive users.

    Valkyrie ships as a Windows service with no configured logon account, so
    nssm runs it as LocalSystem. From that process, HKEY_CURRENT_USER is
    LocalSystem's OWN hive (effectively HKU\\.DEFAULT) - NOT the interactive
    desktop user's. A registry Run-key write via the interactive user's HKCU
    (by far the most common real-world persistence path, since it needs no
    admin rights) was therefore structurally invisible: the poller was reading
    the wrong hive, not failing to detect in time. HKEY_USERS instead lists
    every hive actually loaded (i.e. every logged-on user), so a service can
    read them directly - the same capability every real EDR/AV agent relies on.
    Mirrors _startup_dirs() below, which already solves the identical
    service-vs-interactive-user problem for the filesystem case by enumerating
    C:\\Users explicitly instead of trusting "current user" context.
    """
    if not _WINREG:
        return []
    # Real interactive-user SIDs look like S-1-5-21-...; skip the paired
    # "_Classes" hive (COM registration, not autostart) and well-known
    # non-interactive hives (.DEFAULT, LocalSystem/LocalService/NetworkService).
    return [s for s in _subkeys(winreg.HKEY_USERS, "")
            if s.startswith("S-1-5-21-") and not s.endswith("_Classes")]


# Registry Run/RunOnce/Winlogon ASEPs. (hive, subkey, human location).
def _run_key_specs() -> list:
    if not _WINREG:
        return []
    H = winreg
    specs = [
        (H.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\\...\\Run"),
        (H.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\...\\RunOnce"),
        (H.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\...\\Run (WOW64)"),
        (H.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU\\...\\Run"),
        (H.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\...\\RunOnce"),
        (H.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "HKLM\\...\\Winlogon"),
    ]
    # Per-user Run/RunOnce via HKEY_USERS\<SID> - see _enum_loaded_user_sids.
    # The static HKEY_CURRENT_USER entries above are kept too: harmless, and
    # meaningful in the (less common) case Valkyrie runs interactively rather
    # than as a service.
    for sid in _enum_loaded_user_sids():
        tag = sid[-4:]        # last 4 chars distinguish multiple logged-on users
        specs.append((H.HKEY_USERS, f"{sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      f"HKU\\...{tag}\\...\\Run"))
        specs.append((H.HKEY_USERS, f"{sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                      f"HKU\\...{tag}\\...\\RunOnce"))
    return specs

_SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
# How often the cooperative snapshot yields the GIL. Small enough that the web
# loop never starves (the 253s-freeze bug), large enough that the yields add
# negligible overhead to a normal, fast snapshot.
_YIELD_EVERY = 128
_TASKS_DIR = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Tasks")


def _exe_from_command(command: str) -> str:
    """Best-effort program name from a command string / ImagePath."""
    c = (command or "").strip()
    if not c:
        return ""
    if c.startswith('"'):
        end = c.find('"', 1)
        first = c[1:end] if end > 0 else c[1:]
    else:
        first = c.split(" ")[0]
    return os.path.basename(first.strip().strip('"'))


def _read_values(hive, subkey) -> dict:
    out: dict = {}
    if not _WINREG:
        return out
    try:
        with winreg.OpenKey(hive, subkey) as k:
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(k, i)
                except OSError:
                    break
                out[name] = str(data)
                i += 1
    except OSError:
        pass
    return out


def _subkeys(hive, subkey) -> list:
    out: list = []
    if not _WINREG:
        return out
    try:
        with winreg.OpenKey(hive, subkey) as k:
            i = 0
            while True:
                try:
                    out.append(winreg.EnumKey(k, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return out


def _startup_dirs() -> list[str]:
    dirs = []
    pd = os.environ.get("ProgramData")
    if pd:
        dirs.append(os.path.join(pd, r"Microsoft\Windows\Start Menu\Programs\StartUp"))
    users = os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "Users")
    skip = {"public", "default", "default user", "all users", "defaultuser0"}
    if os.path.isdir(users):
        for u in os.listdir(users):
            if u.lower() in skip:
                continue
            p = os.path.join(users, u, r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")
            if os.path.isdir(p):
                dirs.append(p)
    return dirs


def _persistence_severity(activity: str, command: str) -> tuple[str, list[str], str]:
    """New persistence is inherently notable (medium); a suspicious command line
    or temp-dir target escalates to high.

    OS self-maintenance - Windows Update (TrustedInstaller), Defender, Edge's
    updater, signed drivers - legitimately creates autostart entries constantly,
    and on real hardware that was the largest single source of persistence false
    positives. When the entry's target is a trusted OS binary, start at INFO so
    it is OBSERVED (logged, no alert) rather than flagged. Escalation below still
    applies, so a trusted binary abused into a genuinely suspicious command line
    or temp-dir target is NOT a blind spot."""
    label = _ACTIVITY_LABEL.get(activity, "persistence")
    labels = [label]
    trusted = is_trusted_os_command(command)
    severity = SEV_INFO if trusted else SEV_MEDIUM
    reasons = (["OS component autostart (trusted path)"] if trusted
               else ["new auto-start entry created"])
    if trusted:
        labels.append("trusted_os")
    csev, clabels, creason = classify_cmdline("", command)
    if severity_rank(csev) > severity_rank(severity):
        severity = csev
    if clabels:
        labels += clabels
        if creason:
            reasons.append(creason)
    low = (command or "").lower().replace("\\", "/")
    if any(frag in low for frag in _SUSPICIOUS_PATHS):
        labels.append("suspicious_path")
        reasons.append("auto-start runs from a temp/download directory")
        severity = SEV_HIGH
    return severity, labels, "; ".join(reasons)


class PersistenceCollector:
    """Polls ASEP locations and emits a TelemetryEvent per newly-created entry."""

    def __init__(self, emit: Callable[[TelemetryEvent], None], interval: float = 15.0,
                 snapshot_budget: float = 4.0) -> None:
        self._emit = emit
        self._interval = max(2.0, float(interval))
        self._last: Optional[dict] = None      # {activity: {identity: value}}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        # Wall-clock cap on a single snapshot so it can never freeze the process
        # the way the unbounded version froze the web loop for 253s (see
        # snapshot() docstring). Truncated sections are recorded here.
        self._snapshot_budget = max(1.0, float(snapshot_budget))
        self._truncated: list[str] = []
        # Seconds to wait before the first baseline snapshot, keeping the engine's
        # startup + readiness window clear of the heavy enumeration.
        self._startup_grace = 45.0

    def available(self) -> bool:
        return os.name == "nt" and _WINREG

    # -- snapshot -----------------------------------------------------------
    def snapshot(self) -> dict:
        """Return {activity: {identity: command}} across all ASEP classes.
        Never raises.

        COOPERATIVE + BOUNDED (2026-08-24). Measured on a CI runner, a naive
        snapshot held the thread for **253 seconds** enumerating the services
        registry and the Tasks tree - and because it never released the GIL, it
        froze the web server's asyncio loop for that whole time, so /api/health
        went deaf and every Tier B run failed at the readiness gate (confirmed by
        the [loop-stall]/[persist-poll] instrumentation; see
        valkyrie_startup_deafness). Two guarantees fix that here:

          1. GIL yield: every _YIELD_EVERY items we call time.sleep(0) so the
             event-loop thread (and everything else) gets to run. A snapshot can
             never again monopolise the interpreter.
          2. Time budget: the whole snapshot is capped at self._snapshot_budget
             seconds. A section that would run away is truncated and the fact is
             recorded (self._truncated). A partial persistence snapshot is
             vastly better than a multi-minute freeze - and a persistence
             monitor that takes minutes is useless anyway (it would report the
             change long after the attacker used it)."""
        snap = {PERSIST_RUN_KEY: {}, PERSIST_SERVICE: {},
                PERSIST_SCHEDULED_TASK: {}, PERSIST_STARTUP_FOLDER: {}}
        deadline = time.monotonic() + self._snapshot_budget
        truncated: list[str] = []
        n = 0

        def _tick() -> bool:
            """Yield the GIL periodically; return True when the budget is spent."""
            nonlocal n
            n += 1
            if n % _YIELD_EVERY == 0:
                time.sleep(0)                 # release the GIL to the web loop
            return time.monotonic() >= deadline

        try:
            # Run / RunOnce / Winlogon values (cheap; always completes).
            for hive, subkey, loc in _run_key_specs():
                for name, data in _read_values(hive, subkey).items():
                    snap[PERSIST_RUN_KEY][f"{loc}::{name}"] = data
                    _tick()
            # Services - enumerated INLINE (not via _subkeys) so the GIL yield
            # and the budget apply to the enumeration itself, which is a prime
            # suspect for the runaway. ImagePath is still read lazily on emit.
            if _WINREG:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _SERVICES_KEY) as k:
                        i = 0
                        while True:
                            try:
                                svc = winreg.EnumKey(k, i)
                            except OSError:
                                break
                            snap[PERSIST_SERVICE][svc] = ""
                            i += 1
                            if _tick():
                                truncated.append("services")
                                break
                except OSError:
                    pass
            # Scheduled tasks - file names under the Tasks tree (os.walk is
            # incremental, so the yield/budget bite per file).
            if time.monotonic() < deadline and os.path.isdir(_TASKS_DIR):
                stop = False
                for root, _dirs, files in os.walk(_TASKS_DIR):
                    for f in files:
                        full = os.path.join(root, f)
                        rel = os.path.relpath(full, _TASKS_DIR)
                        snap[PERSIST_SCHEDULED_TASK][rel] = ""
                        if _tick():
                            truncated.append("scheduled_tasks")
                            stop = True
                            break
                    if stop:
                        break
            # Startup folders - files (cheap).
            for d in _startup_dirs():
                try:
                    for f in os.listdir(d):
                        if f.lower() == "desktop.ini":
                            continue
                        snap[PERSIST_STARTUP_FOLDER][os.path.join(d, f)] = os.path.join(d, f)
                        _tick()
                except OSError:
                    continue
        except Exception:
            pass

        self._truncated = truncated
        return snap

    # -- emit helpers -------------------------------------------------------
    def _command_for(self, activity: str, identity: str, value: str) -> str:
        if activity == PERSIST_SERVICE:
            data = _read_values(winreg.HKEY_LOCAL_MACHINE, f"{_SERVICES_KEY}\\{identity}") \
                if _WINREG else {}
            return data.get("ImagePath", "")
        return value

    def _emit_new(self, activity: str, identity: str, value: str) -> None:
        command = self._command_for(activity, identity, value)
        severity, labels, reason = _persistence_severity(activity, command)
        action = ACT_FLAGGED if severity_rank(severity) >= severity_rank(SEV_MEDIUM) else ACT_OBSERVED
        ev = TelemetryEvent(
            category=CAT_PERSISTENCE, activity=activity, action=action,
            actor_name=_exe_from_command(command),
            actor_path=command,
            target={"location": identity, "command": command},
            severity=severity, reason=reason, source="persistence_collector",
            labels=labels, fields={"identity": identity},
        )
        try:
            self._emit(ev)
        except Exception:
            pass

    # -- poll ---------------------------------------------------------------
    def poll_once(self) -> int:
        new = self.snapshot()
        if self._last is None:
            self._last = new
            return 0
        count = 0
        for activity, entries in new.items():
            prev = self._last.get(activity, {})
            for identity, value in entries.items():
                if identity not in prev:
                    self._emit_new(activity, identity, value)
                    count += 1
        self._last = new
        return count

    # -- lifecycle ----------------------------------------------------------
    def start(self) -> None:
        if self._running or not self.available():
            return
        # The baseline snapshot is NOT taken here any more. On a slow host it can
        # hold the thread for many seconds, and start() runs on the engine's
        # startup path - blocking it (and, via the GIL, the web loop) exactly
        # when the readiness gate is trying to confirm the engine is alive. The
        # background thread takes the first (silent) baseline after a short grace
        # delay, so startup and the readiness window stay clear of it.
        self._last = None
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="persistence-collector")
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _loop(self) -> None:
        # Grace delay before the FIRST snapshot so the engine can finish starting
        # and the readiness gate can confirm it live during a persistence-quiet
        # window. Capped so it never delays real detection by much.
        grace = min(self._startup_grace, self._interval * 3)
        waited = 0.0
        while self._running and waited < grace:
            time.sleep(0.5)
            waited += 0.5
        if self._running and self._last is None:
            self._last = self.snapshot()     # silent baseline, on THIS thread
        while self._running:
            time.sleep(self._interval)
            if not self._running:
                break
            try:
                # Diagnostic timing (2026-08-24): a full snapshot enumerates every
                # HKLM service subkey + os.walk of the Tasks tree + registry run
                # keys - GIL-heavy Python work. The first poll lands at ~15s,
                # exactly when the uvicorn event loop goes deaf under Tier B
                # (valkyrie_startup_deafness). Log each poll's duration to stderr
                # so the CI transcript shows whether THIS is the loop-stall's GIL
                # hog. If a poll takes several seconds and the [loop-stall] line
                # fires at the same moment, the collector is confirmed as the
                # cause. Cheap; safe to leave on.
                _t0 = time.monotonic()
                self.poll_once()
                _dur = time.monotonic() - _t0
                if _dur > 1.0:
                    import sys as _sys
                    print(f"[persist-poll] {time.strftime('%H:%M:%S')} snapshot "
                          f"held the thread for {_dur:.1f}s", file=_sys.stderr,
                          flush=True)
            except Exception:
                pass
