"""Windows telemetry killer — registry + service edits to cut OS-level
tracking at the source instead of only blocking it on the wire.

Every change is backed up to TELEMETRY_BACKUP_PATH before being applied so
restore() can put the machine back exactly as it was. Registry keys are
never deleted — only individual values are set (or, on restore, removed if
they did not exist beforehand).

Requires Administrator privileges; scan()/kill()/restore() degrade
gracefully (return {} / all-False) when not elevated rather than raising,
so a missing admin token never crashes the rest of Valkyrie.
"""

from __future__ import annotations

import ctypes
import json
import subprocess
from typing import Any, Optional

from .config import TELEMETRY_BACKUP_PATH, TELEMETRY_SERVICES_TO_DISABLE

try:
    import winreg
    _WINREG_OK = True
except ImportError:    # non-Windows
    _WINREG_OK = False


# ---------------------------------------------------------------------------
# Registry change spec
#
# Each entry: name -> (hive, subkey, value_name, value_type, killed_value)
# "killed_value" is what we set when disabling telemetry; the registry's
# value *before* our change is whatever scan()/kill() reads and backs up.
# ---------------------------------------------------------------------------

def _spec() -> dict[str, tuple]:
    if not _WINREG_OK:
        return {}
    HKLM = winreg.HKEY_LOCAL_MACHINE
    HKCU = winreg.HKEY_CURRENT_USER
    DWORD = winreg.REG_DWORD
    SZ    = winreg.REG_SZ
    return {
        "telemetry_level": (HKLM, r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
                             "AllowTelemetry", DWORD, 0),
        "telemetry_auth_proxy": (HKLM, r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
                                  "DisableEnterpriseAuthProxy", DWORD, 1),
        "advertising_id": (HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
                            "Enabled", DWORD, 0),
        "activity_feed": (HKLM, r"SOFTWARE\Policies\Microsoft\Windows\System",
                           "EnableActivityFeed", DWORD, 0),
        "activity_publish": (HKLM, r"SOFTWARE\Policies\Microsoft\Windows\System",
                              "PublishUserActivities", DWORD, 0),
        "activity_upload": (HKLM, r"SOFTWARE\Policies\Microsoft\Windows\System",
                             "UploadUserActivities", DWORD, 0),
        "location_consent": (HKLM,
                              r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location",
                              "Value", SZ, "Deny"),
        "cortana": (HKLM, r"SOFTWARE\Policies\Microsoft\Windows\Windows Search",
                    "AllowCortana", DWORD, 0),
        "cortana_web_search": (HKLM, r"SOFTWARE\Policies\Microsoft\Windows\Windows Search",
                                "DisableWebSearch", DWORD, 1),
        "cortana_connected_search": (HKLM, r"SOFTWARE\Policies\Microsoft\Windows\Windows Search",
                                      "ConnectedSearchUseWeb", DWORD, 0),
        "wifi_sense": (HKLM, r"SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config",
                        "AutoConnectAllowedOEM", DWORD, 0),
        "error_reporting": (HKLM, r"SOFTWARE\Microsoft\Windows\Windows Error Reporting",
                             "Disabled", DWORD, 1),
        "defender_spynet_reporting": (HKLM, r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet",
                                       "SpynetReporting", DWORD, 0),
        "defender_sample_submission": (HKLM, r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet",
                                        "SubmitSamplesConsent", DWORD, 2),
    }


def is_admin() -> bool:
    """True if the current process holds Administrator privileges."""
    return _is_admin()


def _is_admin() -> bool:
    if not _WINREG_OK:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _read_value(hive: int, subkey: str, name: str) -> Optional[Any]:
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value
    except FileNotFoundError:
        return None
    except OSError:
        return None


def _write_value(hive: int, subkey: str, name: str, vtype: int, value: Any) -> bool:
    try:
        with winreg.CreateKeyEx(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, vtype, value)
        return True
    except OSError:
        return False


def _delete_value(hive: int, subkey: str, name: str) -> bool:
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)
        return True
    except FileNotFoundError:
        return True   # already gone
    except OSError:
        return False


def _set_service_start(service: str, disabled: bool) -> bool:
    """sc config <service> start= disabled|demand, then stop it if disabling."""
    try:
        mode = "disabled" if disabled else "demand"
        subprocess.run(["sc", "config", service, "start=", mode],
                        capture_output=True, text=True, timeout=5)
        if disabled:
            subprocess.run(["sc", "stop", service], capture_output=True, text=True, timeout=5)
        return True
    except Exception:
        return False


def _service_start_mode(service: str) -> Optional[str]:
    try:
        result = subprocess.run(["sc", "qc", service], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            if "START_TYPE" in line.upper():
                return line.strip()
    except Exception:
        pass
    return None


class TelemetryKiller:
    """Scans, applies, and reverts Windows telemetry registry/service settings."""

    def __init__(self, backup_path=TELEMETRY_BACKUP_PATH) -> None:
        self._backup_path = backup_path

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------

    def scan(self) -> dict[str, dict]:
        """Return {setting_name: {"active": bool, "current": value}}.

        "active" means telemetry is currently ENABLED for that setting
        (i.e. it does NOT match the killed/disabled value).
        Returns {} if not running as admin or not on Windows.
        """
        if not _WINREG_OK or not _is_admin():
            return {}

        findings: dict[str, dict] = {}
        for name, (hive, subkey, value_name, _vtype, killed_value) in _spec().items():
            current = _read_value(hive, subkey, value_name)
            findings[name] = {
                "active": current != killed_value,
                "current": current,
            }
        for service in TELEMETRY_SERVICES_TO_DISABLE:
            mode = _service_start_mode(service)
            findings[f"service_{service}"] = {
                "active": mode is not None and "DISABLED" not in mode.upper(),
                "current": mode,
            }
        return findings

    # ------------------------------------------------------------------
    # Kill
    # ------------------------------------------------------------------

    def kill(self) -> dict[str, bool]:
        """Back up current values, then apply all telemetry-disabling
        registry/service changes. Returns {setting_name: success}."""
        if not _WINREG_OK or not _is_admin():
            return {}

        # NEVER overwrite an existing backup.
        #
        # kill() used to rebuild the backup from whatever the registry held at
        # the time and write it unconditionally. Running it a SECOND time
        # therefore read back the values kill() had already written and recorded
        # those as the "originals" — permanently destroying the user's real
        # Windows settings. restore() would then report success while handing
        # back the killed values, and the true originals were unrecoverable.
        #
        # This was trivially reachable: the Privacy page has a "Kill Telemetry"
        # button and POST /api/telemetry/kill is a plain endpoint. Nothing
        # stopped a second click, or a second launch calling it again.
        #
        # The FIRST backup is the only truthful one, so existing entries are
        # preserved and only settings not already recorded are added (which
        # also handles a build that adds new settings to _spec() later).
        existing = self._load_backup() or {}
        backup: dict[str, Any] = {
            "registry": dict(existing.get("registry", {})),
            "services": dict(existing.get("services", {})),
        }
        results: dict[str, bool] = {}

        for name, (hive, subkey, value_name, vtype, killed_value) in _spec().items():
            if name not in backup["registry"]:
                backup["registry"][name] = {
                    "hive": hive, "subkey": subkey, "value_name": value_name,
                    "vtype": vtype, "original": _read_value(hive, subkey, value_name),
                }
            results[name] = _write_value(hive, subkey, value_name, vtype, killed_value)

        for service in TELEMETRY_SERVICES_TO_DISABLE:
            if service not in backup["services"]:
                backup["services"][service] = _service_start_mode(service)
            results[f"service_{service}"] = _set_service_start(service, disabled=True)

        # Written BEFORE nothing else depends on it, but after the reads above so
        # a partially-failed kill still records what it saw.
        self._save_backup(backup)
        return results

    # ------------------------------------------------------------------
    # Restore
    # ------------------------------------------------------------------

    def restore(self) -> dict[str, bool]:
        """Restore every value/service to what scan() recorded before kill().
        Returns {setting_name: success}. No-op (returns {}) if no backup
        exists or not admin."""
        if not _WINREG_OK or not _is_admin():
            return {}

        backup = self._load_backup()
        if backup is None:
            return {}

        results: dict[str, bool] = {}
        for name, entry in backup.get("registry", {}).items():
            hive       = entry["hive"]
            subkey     = entry["subkey"]
            value_name = entry["value_name"]
            vtype      = entry["vtype"]
            original   = entry["original"]
            if original is None:
                results[name] = _delete_value(hive, subkey, value_name)
            else:
                results[name] = _write_value(hive, subkey, value_name, vtype, original)

        for service, original_mode in backup.get("services", {}).items():
            was_disabled = original_mode is not None and "DISABLED" in original_mode.upper()
            results[f"service_{service}"] = _set_service_start(service, disabled=was_disabled)

        # Clear the backup once everything has been put back. kill() now refuses
        # to overwrite an existing backup (so a second kill cannot destroy the
        # originals), which means a stale backup left here would make every
        # FUTURE kill/restore cycle restore to these same now-outdated values.
        # Only discard it if the restore actually succeeded everywhere —
        # a partial restore must keep the backup so the user can retry.
        if results and all(results.values()):
            try:
                self._backup_path.unlink()
            except OSError:
                pass

        return results

    # ------------------------------------------------------------------
    # Internal — backup persistence
    # ------------------------------------------------------------------

    def _save_backup(self, backup: dict) -> None:
        try:
            self._backup_path.parent.mkdir(parents=True, exist_ok=True)
            self._backup_path.write_text(json.dumps(backup, default=str), encoding="utf-8")
        except OSError:
            pass

    def _load_backup(self) -> Optional[dict]:
        if not self._backup_path.exists():
            return None
        try:
            raw = json.loads(self._backup_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

        # hive/vtype were serialised as ints via default=str only if non-native;
        # winreg HKEY/REG_* constants are plain ints already, so this round-trips.
        for entry in raw.get("registry", {}).values():
            entry["hive"]  = int(entry["hive"])
            entry["vtype"] = int(entry["vtype"])
        return raw
