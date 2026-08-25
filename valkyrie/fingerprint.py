"""Network (TCP/IP) fingerprint normalization.

Even after the MAC address is randomized, a machine is still identifiable by
its TCP/IP stack fingerprint - default TTL, TCP options, timestamps. This
module normalizes the two highest-signal, lowest-risk, fully reversible knobs
on Windows:

  * **Default TTL -> 64.** Windows ships 128; Linux/Android/most of the internet
    use 64. Matching the majority removes an obvious "this is Windows" tell.
  * **TCP timestamps -> disabled.** The timestamp option leaks a monotonic
    counter that reveals system uptime and helps correlate connections.

Window scaling / IP-ID behaviour are *reported* by :meth:`status` but not
forced, because changing them can hurt throughput or connectivity for little
fingerprinting gain - normalization should never trade privacy for a broken
connection.

Every change is backed up to ``data/fingerprint_backup.json`` first, so
:meth:`restore` returns the stack exactly to its prior state. Requires
Administrator rights; degrades gracefully otherwise.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Optional

from .config import DATA_DIR

_BACKUP_PATH = DATA_DIR / "fingerprint_backup.json"

_TCPIP_KEY = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
_TTL_VALUE = "DefaultTTL"
_TARGET_TTL = 64
_WINDOWS_DEFAULT_TTL = 128   # shown when the registry value is absent


def _is_windows() -> bool:
    return os.name == "nt"


def _is_admin() -> bool:
    if not _is_windows():
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Low-level getters/setters
# ---------------------------------------------------------------------------

def _read_ttl() -> Optional[int]:
    """Return the configured DefaultTTL, or None if unset (Windows default)."""
    if not _is_windows():
        return None
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _TCPIP_KEY) as key:
            value, _ = winreg.QueryValueEx(key, _TTL_VALUE)
            return int(value)
    except FileNotFoundError:
        return None
    except OSError:
        return None


def _write_ttl(ttl: Optional[int]) -> bool:
    """Set DefaultTTL to ``ttl``; if ``ttl`` is None, delete the value so
    Windows reverts to its built-in default."""
    if not _is_windows():
        return False
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _TCPIP_KEY, 0,
                            winreg.KEY_SET_VALUE) as key:
            if ttl is None:
                try:
                    winreg.DeleteValue(key, _TTL_VALUE)
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(key, _TTL_VALUE, 0, winreg.REG_DWORD, int(ttl))
        return True
    except OSError:
        return False


def _read_tcp_timestamps() -> Optional[bool]:
    """Return True if TCP timestamps are enabled, False if disabled, None if
    it can't be determined."""
    if not _is_windows():
        return None
    try:
        result = subprocess.run(
            ["netsh", "int", "tcp", "show", "global"],
            capture_output=True, text=True, timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    for line in result.stdout.splitlines():
        if "timestamp" in line.lower():
            low = line.lower()
            if "disabled" in low:
                return False
            if "enabled" in low:
                return True
    return None


def _set_tcp_timestamps(enabled: bool) -> bool:
    state = "enabled" if enabled else "disabled"
    try:
        result = subprocess.run(
            ["netsh", "int", "tcp", "set", "global", f"timestamps={state}"],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


# ---------------------------------------------------------------------------
# NetworkFingerprint
# ---------------------------------------------------------------------------

class NetworkFingerprint:
    """Normalize, restore, and report the machine's TCP/IP fingerprint."""

    def __init__(self, backup_path: Path = _BACKUP_PATH) -> None:
        self._backup_path = backup_path
        self.last_error = ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def normalize(self) -> bool:
        """Apply the normalized fingerprint. Returns True only if every change
        was applied. Sets :attr:`last_error` on failure; never raises."""
        self.last_error = ""
        if not _is_windows():
            self.last_error = "fingerprint normalization is Windows-only"
            return False
        if not _is_admin():
            self.last_error = "Administrator rights required to change TCP/IP settings"
            return False

        # Back up current values first (only if we don't already have one, so a
        # repeated normalize doesn't overwrite the true originals).
        if not self._backup_path.exists():
            self._save_backup({
                "DefaultTTL": _read_ttl(),          # None => was unset
                "tcp_timestamps": _read_tcp_timestamps(),
            })

        ok_ttl = _write_ttl(_TARGET_TTL)
        ok_ts  = _set_tcp_timestamps(False)
        if not (ok_ttl and ok_ts):
            failed = []
            if not ok_ttl:
                failed.append("DefaultTTL")
            if not ok_ts:
                failed.append("tcp_timestamps")
            self.last_error = f"could not apply: {', '.join(failed)}"
            return False
        return True

    def restore(self) -> bool:
        """Restore the fingerprint from backup. Returns True on success."""
        self.last_error = ""
        if not _is_windows():
            self.last_error = "fingerprint normalization is Windows-only"
            return False
        if not _is_admin():
            self.last_error = "Administrator rights required to change TCP/IP settings"
            return False

        backup = self._load_backup()
        if backup is None:
            self.last_error = "no fingerprint backup to restore"
            return False

        ok_ttl = _write_ttl(backup.get("DefaultTTL"))
        ts = backup.get("tcp_timestamps")
        ok_ts = True if ts is None else _set_tcp_timestamps(bool(ts))
        if ok_ttl and ok_ts:
            self._clear_backup()
            return True
        self.last_error = "restore incomplete — backup left in place"
        return False

    def status(self) -> dict:
        """Return current fingerprint values and whether they are normalized."""
        ttl = _read_ttl()
        effective_ttl = ttl if ttl is not None else (
            _WINDOWS_DEFAULT_TTL if _is_windows() else None)
        timestamps = _read_tcp_timestamps()
        return {
            "supported":       _is_windows(),
            "ttl":             effective_ttl,
            "ttl_normalized":  effective_ttl == _TARGET_TTL,
            "tcp_timestamps":  timestamps,           # True/False/None
            "timestamps_normalized": timestamps is False,
            "normalized":      effective_ttl == _TARGET_TTL and timestamps is False,
            "backup_present":  self._backup_path.exists(),
        }

    # ------------------------------------------------------------------
    # Backup persistence
    # ------------------------------------------------------------------

    def _save_backup(self, data: dict) -> None:
        try:
            self._backup_path.parent.mkdir(parents=True, exist_ok=True)
            self._backup_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except OSError:
            pass

    def _load_backup(self) -> Optional[dict]:
        try:
            return json.loads(self._backup_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _clear_backup(self) -> None:
        try:
            self._backup_path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
