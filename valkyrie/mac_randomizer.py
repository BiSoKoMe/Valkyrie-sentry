"""MAC address randomizer.

Generates realistic-looking random MAC addresses using known OUI prefixes,
applies them via OS-specific commands, and monitors for network reconnect
events to trigger auto-randomisation.

Platform support:
  Linux   — ip link set {iface} address {mac}
  Windows — registry NetworkAddress + netsh interface disable/enable
  macOS   — ifconfig {iface} ether {mac}
"""

from __future__ import annotations

import json
import os
import platform
import random
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

from .config import (
    MAC_AUTO_RANDOMIZE,
    MAC_BACKUP_PATH,
    MAC_NEVER_RANDOMIZE,
    REALISTIC_OUIS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$')


def _is_valid_mac(mac: str) -> bool:
    return bool(_MAC_RE.match(mac))


def _generate_mac() -> str:
    """Generate a locally-administered MAC from a realistic OUI."""
    oui    = random.choice(REALISTIC_OUIS)
    suffix = ":".join(f"{random.randint(0, 255):02X}" for _ in range(3))
    mac    = f"{oui}:{suffix}"
    # Set locally administered bit (bit 1 of first byte)
    parts        = mac.split(":")
    first        = int(parts[0], 16)
    first        = (first | 0x02) & 0xFE   # set LA bit, clear multicast bit
    parts[0]     = f"{first:02X}"
    return ":".join(parts)


def _platform() -> str:
    return platform.system().lower()


def _is_windows_admin() -> bool:
    """True if the current process has Administrator rights on Windows."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# MacRandomizer
# ---------------------------------------------------------------------------

class MacRandomizer:
    """Randomises MAC addresses per interface with backup/restore support."""

    def __init__(self, store=None) -> None:
        """Args:
            store: optional Store instance for logging MAC-change events.
        """
        self._store       = store
        self._lock        = threading.Lock()
        self.last_error   = ""
        self._backup: dict[str, str] = self._load_backup()
        self._monitor_thread: Optional[threading.Thread] = None
        self._monitor_stop  = threading.Event()
        self._last_stats: dict[str, bool] = {}   # iface → was_up

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def randomize(self, interface: Optional[str] = None) -> str:
        """Apply a new random MAC to *interface* (or all non-excluded ifaces).

        Returns the new MAC string (last interface changed), or empty string
        on failure. Sets self.last_error with a human-readable reason when
        every interface fails (e.g. missing admin rights on Windows).
        """
        self.last_error = ""
        if _platform() == "windows" and not _is_windows_admin():
            self.last_error = (
                "Administrator rights required — MAC randomisation writes to "
                "HKEY_LOCAL_MACHINE. Re-run as Administrator."
            )
            return ""

        ifaces = self._resolve_interfaces(interface)
        last   = ""
        for iface in ifaces:
            new_mac = _generate_mac()
            ok      = self._apply_mac(iface, new_mac)
            if ok:
                last = new_mac
                self._log(f"MAC randomised: {iface} → {new_mac}")
        if not last and ifaces and not self.last_error:
            self.last_error = "No interface could be changed (adapter not found or write failed)."
        return last

    def restore(self, interface: Optional[str] = None) -> str:
        """Restore the original MAC for *interface* from backup.

        Returns the restored MAC string, or empty string if no backup found.
        """
        ifaces  = self._resolve_interfaces(interface)
        last    = ""
        backup  = self._load_backup()
        for iface in ifaces:
            orig = backup.get(iface)
            if not orig:
                continue
            ok = self._apply_mac(iface, orig, is_restore=True)
            if ok:
                last = orig
                self._log(f"MAC restored: {iface} → {orig}")
        return last

    def get_current(self, interface: str) -> str:
        """Return the current MAC address of *interface*, or empty string."""
        try:
            return self._read_current_mac(interface)
        except Exception:
            return ""

    def get_original(self, interface: str) -> str:
        """Return the backed-up original MAC for *interface*, or empty string."""
        return self._load_backup().get(interface, "")

    def auto_randomize_on_connect(self) -> None:
        """Start a background thread that randomises MACs on reconnect events."""
        if self._monitor_thread and self._monitor_thread.is_alive():
            return
        self._monitor_stop.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="mac-monitor",
        )
        self._monitor_thread.start()

    def stop(self) -> None:
        """Stop the background monitor thread."""
        self._monitor_stop.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=10)

    def status(self) -> dict:
        """Return a dict mapping interface → {current, original, changed}."""
        try:
            import psutil
            ifaces = list(psutil.net_if_addrs().keys())
        except Exception:
            ifaces = []

        backup  = self._load_backup()
        result  = {}
        for iface in ifaces:
            if iface in MAC_NEVER_RANDOMIZE:
                continue
            current  = self.get_current(iface)
            original = backup.get(iface, "")
            changed  = bool(original) and current != original
            result[iface] = {
                "current":  current,
                "original": original,
                "changed":  changed,
            }
        return result

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _resolve_interfaces(self, interface: Optional[str]) -> list[str]:
        """Return list of target interfaces, filtering excluded ones."""
        if interface:
            if interface in MAC_NEVER_RANDOMIZE:
                return []
            return [interface]
        try:
            import psutil
            return [
                iface for iface in psutil.net_if_addrs().keys()
                if iface not in MAC_NEVER_RANDOMIZE
            ]
        except Exception:
            return []

    def _apply_mac(self, iface: str, new_mac: str, is_restore: bool = False) -> bool:
        """Change the MAC of *iface* to *new_mac*. Backups original first."""
        if iface in MAC_NEVER_RANDOMIZE:
            return False
        if not _is_valid_mac(new_mac):
            return False

        # Backup the current MAC before first change
        if not is_restore:
            backup = self._load_backup()
            if iface not in backup:
                current = self._read_current_mac(iface)
                if current:
                    backup[iface] = current
                    self._save_backup(backup)

        sys = _platform()
        try:
            if sys == "linux":
                return self._apply_linux(iface, new_mac)
            elif sys == "windows":
                return self._apply_windows(iface, new_mac)
            elif sys == "darwin":
                return self._apply_macos(iface, new_mac)
        except Exception:
            pass
        return False

    def _apply_linux(self, iface: str, mac: str) -> bool:
        subprocess.run(["ip", "link", "set", iface, "down"],  check=True, capture_output=True)
        subprocess.run(["ip", "link", "set", iface, "address", mac], check=True, capture_output=True)
        subprocess.run(["ip", "link", "set", iface, "up"],    check=True, capture_output=True)
        return True

    def _apply_windows(self, iface: str, mac: str) -> bool:
        import winreg

        # MAC in registry format: no colons, uppercase
        reg_mac = mac.replace(":", "").upper()
        net_class = "{4D36E972-E325-11CE-BFC1-08002BE10318}"
        base_path = (
            r"SYSTEM\CurrentControlSet\Control\Class"
            rf"\{net_class}"
        )

        # Find the adapter subkey matching this interface name
        adapter_key = self._find_windows_adapter_key(iface, base_path)
        if not adapter_key:
            return False

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, adapter_key,
                             0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "NetworkAddress", 0, winreg.REG_SZ, reg_mac)

        # Cycle the adapter so Windows actually loads the new NetworkAddress.
        # netsh matches the alias literally: it must be a bare "name=<alias>"
        # token — the previous f'"{iface}"' sent embedded quotes and matched
        # nothing. Check return codes AND read the live MAC back: a registry
        # write with no successful cycle otherwise looks identical to success.
        #
        # netsh can hang indefinitely on some virtual/VPN adapters instead of
        # erroring — a timeout turns that into a reported failure for this one
        # interface instead of freezing the whole randomize() call forever.
        try:
            dis = subprocess.run(
                ["netsh", "interface", "set", "interface",
                 f"name={iface}", "admin=disabled"],
                capture_output=True, text=True, timeout=15,
            )
        except subprocess.TimeoutExpired:
            # netsh may have taken effect despite timing out on us — best-effort
            # re-enable so we never strand the adapter disabled with no retry.
            try:
                subprocess.run(
                    ["netsh", "interface", "set", "interface",
                     f"name={iface}", "admin=enabled"],
                    capture_output=True, text=True, timeout=15,
                )
            except Exception:
                pass
            self.last_error = f"Adapter '{iface}' disable timed out after 15s"
            return False
        if dis.returncode != 0:
            self.last_error = (
                f"Adapter '{iface}' disable failed: "
                f"{(dis.stdout + dis.stderr).strip()}"
            )
            return False
        time.sleep(2)
        try:
            ena = subprocess.run(
                ["netsh", "interface", "set", "interface",
                 f"name={iface}", "admin=enabled"],
                capture_output=True, text=True, timeout=15,
            )
        except subprocess.TimeoutExpired:
            self.last_error = f"Adapter '{iface}' enable timed out after 15s"
            return False
        if ena.returncode != 0:
            self.last_error = (
                f"Adapter '{iface}' enable failed: "
                f"{(ena.stdout + ena.stderr).strip()}"
            )
            return False

        # Verify on the machine, not by assumption: the live MAC must now match
        # what we wrote. Give the driver a moment to re-init after enable.
        time.sleep(2)
        applied = self._read_current_mac(iface).replace(":", "").upper()
        if applied != reg_mac:
            self.last_error = (
                f"MAC write did not apply: registry={reg_mac} live={applied or '<unreadable>'}"
                " — adapter cycle did not take effect."
            )
            return False
        return True

    def _apply_macos(self, iface: str, mac: str) -> bool:
        subprocess.run(["sudo", "ifconfig", iface, "ether", mac],
                        check=True, capture_output=True)
        return True

    def _find_windows_adapter_key(self, iface_name: str, base_path: str) -> Optional[str]:
        """Locate the registry subkey for a Windows adapter by its interface alias.

        Matching against DriverDesc (e.g. "Realtek PCIe GbE Family Controller")
        never matches a real interface alias (e.g. "Ethernet", "Wi-Fi") — the
        two strings are unrelated. The correct lookup is two-step:
          1. Control\\Network\\{netclass}\\{adapterGUID}\\Connection -> "Name"
             gives the friendly alias exactly as shown by ipconfig/psutil.
          2. Control\\Class\\{netclass}\\NNNN -> "NetCfgInstanceId" == that GUID
             identifies the matching settings subkey (where NetworkAddress lives).
        """
        try:
            import winreg
            net_class = base_path.rsplit("\\", 1)[-1]
            conn_base = rf"SYSTEM\CurrentControlSet\Control\Network\{net_class}"

            # Step 1: find the adapter GUID whose Connection\Name matches iface_name
            target_guid: Optional[str] = None
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, conn_base) as conn_root:
                idx = 0
                while True:
                    try:
                        guid = winreg.EnumKey(conn_root, idx)
                        idx += 1
                    except OSError:
                        break
                    try:
                        conn_path = f"{conn_base}\\{guid}\\Connection"
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, conn_path) as ck:
                            name, _ = winreg.QueryValueEx(ck, "Name")
                            if name.lower() == iface_name.lower():
                                target_guid = guid
                                break
                    except OSError:
                        continue
            if not target_guid:
                return None

            # Step 2: find the Class subkey whose NetCfgInstanceId == target_guid
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_path) as base:
                idx = 0
                while True:
                    try:
                        sub = winreg.EnumKey(base, idx)
                        idx += 1
                    except OSError:
                        break
                    try:
                        full = f"{base_path}\\{sub}"
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, full) as k:
                            net_cfg_id, _ = winreg.QueryValueEx(k, "NetCfgInstanceId")
                            if net_cfg_id == target_guid:
                                return full
                    except OSError:
                        continue
        except Exception:
            pass
        return None

    def _read_current_mac(self, iface: str) -> str:
        """Read the current MAC of *iface* via psutil or /sys.

        psutil reports Windows MACs hyphen-separated ("AA-BB-CC-DD-EE-FF")
        and Linux/macOS colon-separated — normalise to colon format so the
        rest of the codebase (generation, backup, validation) sees one shape.
        """
        try:
            import psutil
            addrs = psutil.net_if_addrs().get(iface, [])
            link_family = psutil.AF_LINK if hasattr(psutil, "AF_LINK") else 17
            for addr in addrs:
                if addr.family == link_family:
                    raw = (addr.address or "").replace("-", ":")
                    if _is_valid_mac(raw):
                        return raw.upper()
        except Exception:
            pass

        # Linux fallback
        sys_path = Path(f"/sys/class/net/{iface}/address")
        if sys_path.exists():
            return sys_path.read_text().strip()

        return ""

    def _monitor_loop(self) -> None:
        """Poll interface up/down state; randomise MAC on reconnect."""
        try:
            import psutil
        except ImportError:
            return

        while not self._monitor_stop.is_set():
            try:
                stats = psutil.net_if_stats()
                for iface, info in stats.items():
                    if iface in MAC_NEVER_RANDOMIZE:
                        continue
                    was_up  = self._last_stats.get(iface, True)
                    is_up   = info.isup
                    # Detect down → up transition (reconnect)
                    if not was_up and is_up:
                        time.sleep(2)   # wait for link to stabilise
                        self.randomize(iface)
                    self._last_stats[iface] = is_up
            except Exception:
                pass
            self._monitor_stop.wait(5)

    def _load_backup(self) -> dict[str, str]:
        try:
            with open(MAC_BACKUP_PATH) as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_backup(self, backup: dict) -> None:
        try:
            MAC_BACKUP_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(MAC_BACKUP_PATH, "w") as f:
                json.dump(backup, f, indent=2)
        except Exception:
            pass

    def _log(self, msg: str) -> None:
        if self._store is None:
            return
        try:
            from .store import DnsEvent
            event = DnsEvent.now(
                domain       = "localhost",
                decision     = "allowed",
                process_name = "mac_randomizer",
                process_pid  = os.getpid(),
                process_path = "",
                reason       = msg,
                raw_category = "mac_change",
            )
            self._store.log(event)
        except Exception:
            pass
