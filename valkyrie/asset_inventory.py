"""Asset inventory — CIS Controls #1 (Enterprise Assets) & #2 (Software
Assets), applied to a single endpoint.

Clinton's *Cybersecurity for Business* (ch. 9) and the CIS Controls both
start from the same premise: you cannot protect what you don't know you
have. Before this module, Valkyrie could not answer three basic questions
about its own host: what software is installed, what is listening for
inbound connections, and what kernel drivers are loaded. Boot-time
autostart entries are the one asset class Valkyrie already tracked —
``persistence_telemetry.py`` owns that signal at its own (usually higher)
severity, and this module REUSES it (calling ``PersistenceCollector.
snapshot()`` for completeness of a full inventory report) rather than
re-detecting the same change twice.

**The delta IS the detector**, same idea as ``sensor_tamper.py``'s
healthy→unhealthy transition and ``process_telemetry.classify_discovery``'s
weak Discovery-tactic labels: a single snapshot is just a fact; a NEW
listener, a NEWLY installed unsigned binary, or a NEW kernel driver since
the last snapshot is the actual signal. Every change is reported at
``SEV_INFO`` and ``ACT_OBSERVED`` — never a standalone incident, always
correlation input — because on its own "a new program was installed" is
exactly as weak a signal as a single ``whoami`` call, and Windows Update /
ordinary app installs make this happen constantly. ``is_trusted_os_path``
(the same helper ``persistence_telemetry``'s own benign-OS-churn check
uses) labels — never suppresses — changes from a trusted Microsoft-owned
path, so correlation can weigh "new driver from System32" differently than
"new driver from a user-writable temp folder" without this module making
that judgement call itself.

**REMOVALS are never emitted.** Uninstalling software or a port going
quiet is the safe direction of change (same reasoning as
``release_isolation`` restoring connectivity in item 1's reversibility
audit) and would only add noise to a feed meant to surface new exposure.

Entirely read-only: every function here enumerates registry values / live
sockets and returns data. Nothing writes, deletes, starts, or stops
anything on the host.
"""

from __future__ import annotations

import os
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .persistence_telemetry import PersistenceCollector, _read_values, _subkeys
from .telemetry import ACT_OBSERVED, CAT_ASSET, SEV_INFO, TelemetryEvent
from .trust import is_trusted_os_path

try:
    import winreg
    _WINREG = True
except ImportError:                                     # non-Windows
    winreg = None                                        # type: ignore
    _WINREG = False

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False


# ---------------------------------------------------------------------------
# Read-only enumeration — one function per asset class
# ---------------------------------------------------------------------------

def _uninstall_key_specs() -> list[tuple]:
    if not _WINREG:
        return []
    return [
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]


def snapshot_software() -> dict:
    """{display_name: {"version", "publisher", "install_location"}}.

    Skips entries with no DisplayName (registry components/patches, not a
    user-facing "install") and KBxxxxxxx hotfix entries (Windows Update
    churn, not new software — the exact "benign control" CIS #2 and the
    task both call out as required). Never raises.
    """
    out: dict = {}
    for hive, base in _uninstall_key_specs():
        try:
            for sub in _subkeys(hive, base):
                if len(sub) >= 3 and sub[:2].upper() == "KB" and sub[2:].isdigit():
                    continue
                full = f"{base}\\{sub}"
                vals = _read_values(hive, full)
                name = (vals.get("DisplayName") or "").strip()
                if not name:
                    continue
                out[name] = {
                    "version": vals.get("DisplayVersion", ""),
                    "publisher": vals.get("Publisher", ""),
                    "install_location": vals.get("InstallLocation", ""),
                }
        except Exception:                                # noqa: BLE001
            continue
    return out


def snapshot_listening_ports() -> dict:
    """{"tcp:PORT" or "udp:PORT": {"pid", "process", "addr"}}.

    TCP sockets actually in LISTEN state, plus bound UDP sockets (UDP has
    no listen state, but a bound local address IS "accepting datagrams",
    the functional equivalent). Degrades to {} without psutil or without
    permission to enumerate (non-admin sees only this user's own sockets on
    Windows — a real, honest limitation, not hidden here).
    """
    out: dict = {}
    if not _PSUTIL:
        return out
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return out
    for c in conns:
        try:
            if not c.laddr:
                continue
            is_tcp = c.type == socket.SOCK_STREAM
            if is_tcp and c.status != psutil.CONN_LISTEN:
                continue
            proto = "tcp" if is_tcp else "udp"
            key = f"{proto}:{c.laddr.port}"
            pname = ""
            if c.pid:
                try:
                    pname = psutil.Process(c.pid).name()
                except Exception:
                    pname = ""
            out[key] = {"pid": c.pid or 0, "process": pname, "addr": c.laddr.ip}
        except Exception:
            continue
    return out


def snapshot_kernel_drivers() -> dict:
    """{driver_name: {"image_path", "start"}} — SYSTEM\\...\\Services entries
    whose Type marks them a kernel-mode (1) or file-system (2) driver, not
    an ordinary Win32 service. Read-only registry enumeration; never
    raises."""
    out: dict = {}
    if not _WINREG:
        return out
    services_key = r"SYSTEM\CurrentControlSet\Services"
    try:
        for name in _subkeys(winreg.HKEY_LOCAL_MACHINE, services_key):
            full = f"{services_key}\\{name}"
            vals = _read_values(winreg.HKEY_LOCAL_MACHINE, full)
            try:
                svc_type = int(vals.get("Type", "") or 0)
            except ValueError:
                continue
            if svc_type not in (1, 2):     # SERVICE_KERNEL_DRIVER, SERVICE_FILE_SYSTEM_DRIVER
                continue
            out[name] = {
                "image_path": vals.get("ImagePath", ""),
                "start": vals.get("Start", ""),
            }
    except Exception:                                     # noqa: BLE001
        pass
    return out


# ---------------------------------------------------------------------------
# Snapshot + diff
# ---------------------------------------------------------------------------

@dataclass
class AssetSnapshot:
    software: dict = field(default_factory=dict)
    listening_ports: dict = field(default_factory=dict)
    kernel_drivers: dict = field(default_factory=dict)
    # For a COMPLETE point-in-time inventory report only. NOT diffed by
    # AssetInventoryCollector -- persistence_telemetry.PersistenceCollector
    # already emits its own change telemetry for this at its own severity;
    # re-diffing it here would duplicate that detector, which the task
    # explicitly says not to do.
    boot_items: dict = field(default_factory=dict)
    taken_at: float = field(default_factory=time.time)

    def counts(self) -> dict:
        return {"software": len(self.software),
                "listening_ports": len(self.listening_ports),
                "kernel_drivers": len(self.kernel_drivers),
                "boot_items": sum(len(v) for v in self.boot_items.values())}


def take_snapshot(persistence_collector: Optional[PersistenceCollector] = None
                  ) -> AssetSnapshot:
    boot_items: dict = {}
    if persistence_collector is not None:
        try:
            boot_items = persistence_collector.snapshot()
        except Exception:                                 # noqa: BLE001
            boot_items = {}
    return AssetSnapshot(
        software=snapshot_software(),
        listening_ports=snapshot_listening_ports(),
        kernel_drivers=snapshot_kernel_drivers(),
        boot_items=boot_items,
    )


@dataclass
class AssetDelta:
    software_added: dict = field(default_factory=dict)
    software_removed: dict = field(default_factory=dict)
    ports_added: dict = field(default_factory=dict)
    ports_removed: dict = field(default_factory=dict)
    drivers_added: dict = field(default_factory=dict)
    drivers_removed: dict = field(default_factory=dict)

    def is_empty(self) -> bool:
        return not any([self.software_added, self.software_removed,
                       self.ports_added, self.ports_removed,
                       self.drivers_added, self.drivers_removed])


def _added(old: dict, new: dict) -> dict:
    return {k: v for k, v in new.items() if k not in old}


def _removed(old: dict, new: dict) -> dict:
    return {k: v for k, v in old.items() if k not in new}


def diff_snapshots(old: AssetSnapshot, new: AssetSnapshot) -> AssetDelta:
    return AssetDelta(
        software_added=_added(old.software, new.software),
        software_removed=_removed(old.software, new.software),
        ports_added=_added(old.listening_ports, new.listening_ports),
        ports_removed=_removed(old.listening_ports, new.listening_ports),
        drivers_added=_added(old.kernel_drivers, new.kernel_drivers),
        drivers_removed=_removed(old.kernel_drivers, new.kernel_drivers),
    )


# ---------------------------------------------------------------------------
# Collector — periodic snapshot + diff + emit-on-change
# ---------------------------------------------------------------------------

class AssetInventoryCollector:
    """Periodic snapshot+diff. Every ADDED item emits one INFO-severity
    TelemetryEvent (CAT_ASSET); removals are never emitted (safe direction
    of change, pure noise for a delta feed). First poll seeds the baseline
    silently — same contract as ProcessCollector.poll_once()."""

    def __init__(self, emit: Callable[[TelemetryEvent], None],
                 interval: float = 3600.0,
                 persistence_collector: Optional[PersistenceCollector] = None) -> None:
        self._emit = emit
        self._interval = max(60.0, float(interval))
        self._persistence_collector = persistence_collector
        self._last: Optional[AssetSnapshot] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def available(self) -> bool:
        return os.name == "nt" and (_WINREG or _PSUTIL)

    def current_snapshot(self) -> AssetSnapshot:
        return take_snapshot(self._persistence_collector)

    def poll_once(self) -> int:
        """Snapshot, diff against the last poll, emit one event per newly
        added item. Returns the count emitted. Never raises."""
        new = self.current_snapshot()
        if self._last is None:
            self._last = new
            return 0
        delta = diff_snapshots(self._last, new)
        self._last = new
        emitted = 0
        for name, meta in delta.software_added.items():
            self._emit_change("new_installed_software", name,
                              meta.get("install_location", ""),
                              {"version": meta.get("version", ""),
                               "publisher": meta.get("publisher", "")})
            emitted += 1
        for key, meta in delta.ports_added.items():
            self._emit_change("new_listening_port", key,
                              meta.get("process", ""),
                              {"pid": meta.get("pid", 0),
                               "addr": meta.get("addr", "")})
            emitted += 1
        for name, meta in delta.drivers_added.items():
            self._emit_change("new_kernel_driver", name,
                              meta.get("image_path", ""),
                              {"start": meta.get("start", "")})
            emitted += 1
        return emitted

    def _emit_change(self, activity: str, identity: str, path: str,
                     extra: dict) -> None:
        trusted = is_trusted_os_path(path) if path else False
        labels = ["asset_change", activity]
        if trusted:
            labels.append("trusted_os_path")
        ev = TelemetryEvent(
            category=CAT_ASSET, activity=activity, action=ACT_OBSERVED,
            actor_name=(os.path.basename(path.strip('"')) if path else identity),
            actor_path=path,
            target={"identity": identity, **extra},
            severity=SEV_INFO,
            reason=f"{activity.replace('_', ' ')}: {identity}",
            source="asset_inventory",
            labels=labels,
            fields={"identity": identity, "trusted_os_path": trusted, **extra},
        )
        try:
            self._emit(ev)
        except Exception:                                 # noqa: BLE001
            pass   # a bad emitter must never stop collection

    # -- lifecycle ------------------------------------------------------
    def start(self) -> None:
        if self._running or not self.available():
            return
        self._last = self.current_snapshot()   # seed baseline synchronously
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="asset-inventory")
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
            except Exception:                             # noqa: BLE001
                pass
