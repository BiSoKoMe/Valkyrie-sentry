"""Persistence (ASEP) telemetry collector — endpoint visibility for the places
attackers establish persistence.

Auto-Start Extension Points (ASEPs) are where malware survives reboot: registry
Run keys, Windows services, Scheduled Tasks and Startup folders. This collector
snapshots those locations and emits a normalized ``TelemetryEvent`` (category
``persistence``) whenever a NEW entry appears — the highest-signal, lowest-noise
endpoint telemetry available without a kernel sensor.

Scope and honesty:
  * **Read-only pollers** over the registry (stdlib ``winreg``) and the
    filesystem — no ETW, no kernel, no external process, no console window. It
    detects persistence shortly after it is written (poll interval), not at the
    instant of the write. Real-time capture (ETW registry/file providers) is the
    documented next increment; it plugs into the same schema and pipeline.
  * The first poll establishes a silent baseline, so the hundreds of legitimate
    pre-existing ASEPs are not reported — only entries created *after* start.
  * Degrades gracefully to a no-op on non-Windows or when a key is unreadable;
    never raises into the caller.

Every event carries a MITRE-ish label (run key → T1547, service → T1543, task →
T1053, startup folder → T1547) that the EDR engine maps to a technique, and a
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

# Registry Run/RunOnce/Winlogon ASEPs. (hive, subkey, human location).
def _run_key_specs() -> list:
    if not _WINREG:
        return []
    H = winreg
    return [
        (H.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\\...\\Run"),
        (H.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\...\\RunOnce"),
        (H.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\...\\Run (WOW64)"),
        (H.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU\\...\\Run"),
        (H.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\...\\RunOnce"),
        (H.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "HKLM\\...\\Winlogon"),
    ]

_SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
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

    OS self-maintenance — Windows Update (TrustedInstaller), Defender, Edge's
    updater, signed drivers — legitimately creates autostart entries constantly,
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

    def __init__(self, emit: Callable[[TelemetryEvent], None], interval: float = 15.0) -> None:
        self._emit = emit
        self._interval = max(2.0, float(interval))
        self._last: Optional[dict] = None      # {activity: {identity: value}}
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def available(self) -> bool:
        return os.name == "nt" and _WINREG

    # -- snapshot -----------------------------------------------------------
    def snapshot(self) -> dict:
        """Return {activity: {identity: command}} across all ASEP classes.
        Never raises."""
        snap = {PERSIST_RUN_KEY: {}, PERSIST_SERVICE: {},
                PERSIST_SCHEDULED_TASK: {}, PERSIST_STARTUP_FOLDER: {}}
        try:
            # Run / RunOnce / Winlogon values.
            for hive, subkey, loc in _run_key_specs():
                for name, data in _read_values(hive, subkey).items():
                    snap[PERSIST_RUN_KEY][f"{loc}::{name}"] = data
            # Services — track names cheaply; ImagePath is read lazily on emit.
            for svc in _subkeys(winreg.HKEY_LOCAL_MACHINE, _SERVICES_KEY) if _WINREG else []:
                snap[PERSIST_SERVICE][svc] = ""
            # Scheduled tasks — file names under the Tasks tree.
            if os.path.isdir(_TASKS_DIR):
                for root, _dirs, files in os.walk(_TASKS_DIR):
                    for f in files:
                        full = os.path.join(root, f)
                        rel = os.path.relpath(full, _TASKS_DIR)
                        snap[PERSIST_SCHEDULED_TASK][rel] = ""
            # Startup folders — files.
            for d in _startup_dirs():
                try:
                    for f in os.listdir(d):
                        if f.lower() == "desktop.ini":
                            continue
                        snap[PERSIST_STARTUP_FOLDER][os.path.join(d, f)] = os.path.join(d, f)
                except OSError:
                    continue
        except Exception:
            pass
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
        self._last = self.snapshot()     # silent baseline
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="persistence-collector")
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
