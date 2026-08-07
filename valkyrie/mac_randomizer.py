"""MAC address randomizer — privacy-grade address randomisation.

Generates unlinkable MAC addresses and applies them via OS-specific commands,
monitoring for network reconnect events to trigger auto-randomisation.

Two things make this privacy-grade rather than a toy:

  * **CSPRNG, not a PRNG.** Every random byte comes from ``secrets`` (the OS
    cryptographic RNG), never ``random`` (a Mersenne Twister whose output
    stream is reconstructable from a few samples). For an *unlinkability*
    primitive a predictable generator is a real weakness, so it is not used.

  * **Per-network stable addresses** (the iOS "Private Wi-Fi Address" /
    Android persistent-randomised-MAC model). The address for a given network
    is derived deterministically from a per-install secret key + a stable
    network id via HMAC-SHA256: the SAME every time you rejoin that network
    (captive portals, DHCP leases and NAC keep working, and you don't stand out
    by changing address every reconnect) but UNLINKABLE across networks and
    unpredictable to anyone without the key. Falls back to a fresh CSPRNG random
    address when the network can't be identified.

Address style is spec-compliant locally-administered by default (LA bit set,
matching iOS/Android); an opt-in vendor-blend mode hides behind a real vendor
OUI. The old behaviour — a real vendor OUI *with* the LA bit set — is a
combination real hardware never has and is therefore itself a fingerprint; it
is not produced any more.

Platform support:
  Linux   — ip link set {iface} address {mac}
  Windows — registry NetworkAddress + netsh interface disable/enable
  macOS   — ifconfig {iface} ether {mac}
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

from .config import (
    MAC_AUTO_RANDOMIZE,
    MAC_BACKUP_PATH,
    MAC_KEY_PATH,
    MAC_NEVER_RANDOMIZE,
    MAC_PER_NETWORK,
    MAC_VENDOR_BLEND,
    REALISTIC_OUIS,
)


# ---------------------------------------------------------------------------
# Pure address construction (CSPRNG / HMAC) — unit-tested without any hardware
# ---------------------------------------------------------------------------

_MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$')
_IPV4_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')


def _is_valid_mac(mac: str) -> bool:
    return bool(_MAC_RE.match(mac))


def _RE_IPV4(s: str) -> bool:
    return bool(_IPV4_RE.match(s.strip()))


def _first_octet(mac: str) -> int:
    """First octet of *mac*, accepting either separator.

    `_MAC_RE` accepts BOTH ``:`` and ``-`` (Windows reports dashes — `ipconfig`,
    `getmac` and the registry all use them), so splitting on ``:`` alone raised
    ValueError on a MAC this module considers valid. Normalising here keeps the
    accepted-input set and the parsed-input set identical, which is the actual
    defect: a validator that accepts a format the parser cannot read.
    """
    return int(mac.replace("-", ":").split(":")[0], 16)


def is_unicast(mac: str) -> bool:
    """True if the address is unicast (bit 0 of the first octet is clear).
    A multicast source address is invalid on the wire — every address we emit
    must be unicast."""
    return (_first_octet(mac) & 0x01) == 0


def is_locally_administered(mac: str) -> bool:
    """True if the locally-administered bit (bit 1 of the first octet) is set."""
    return (_first_octet(mac) & 0x02) == 0x02


def _mac_from_bytes(b: bytes, vendor_oui: Optional[str]) -> str:
    """Assemble a valid unicast MAC string from 6+ bytes.

    vendor_oui set  → blend behind that real vendor prefix, universally
                      administered (LA bit CLEAR), just the multicast bit forced
                      clear so it is a legal unicast source address.
    vendor_oui None → spec-compliant locally-administered random (LA bit SET,
                      multicast bit clear) — the iOS/Android style.
    """
    if vendor_oui:
        oui_parts = [int(x, 16) for x in vendor_oui.split(":")]
        first = oui_parts[0] & 0xFE            # unicast; keep vendor's U/L bit
        octets = [first, oui_parts[1], oui_parts[2], b[0], b[1], b[2]]
    else:
        first = (b[0] | 0x02) & 0xFE           # LA set, multicast clear
        octets = [first, b[1], b[2], b[3], b[4], b[5]]
    return ":".join(f"{o:02X}" for o in octets)


def generate_mac(vendor_blend: bool = False) -> str:
    """A fresh random MAC drawn from the OS CSPRNG (``secrets``).

    Default is a spec-compliant locally-administered address; ``vendor_blend``
    hides behind a randomly-chosen realistic vendor OUI instead.
    """
    rnd = secrets.token_bytes(6)
    oui = secrets.choice(REALISTIC_OUIS) if vendor_blend else None
    return _mac_from_bytes(rnd, oui)


def mac_for_network(install_key: bytes, network_id: str,
                    vendor_blend: bool = False) -> str:
    """Deterministic per-network MAC — stable for a network, unlinkable across
    networks, unpredictable without ``install_key``.

    HMAC-SHA256(install_key, network_id) yields the address bytes, so the same
    (key, network) always maps to the same address (the iOS/Android private-
    address model) while different networks map to independent addresses no
    observer can correlate or precompute without the secret key.
    """
    digest = hmac.new(install_key, network_id.encode("utf-8", "replace"),
                      hashlib.sha256).digest()
    if vendor_blend:
        # Choose the vendor OUI deterministically from the digest too, so the
        # whole address is a stable function of (key, network).
        oui = REALISTIC_OUIS[digest[6] % len(REALISTIC_OUIS)]
        return _mac_from_bytes(digest[:6], oui)
    return _mac_from_bytes(digest[:6], None)


def _generate_mac() -> str:
    """Backward-compatible fresh-random generator (honours config style).

    Retained so existing callers keep working; new code should call
    ``generate_mac`` / ``mac_for_network`` directly.
    """
    return generate_mac(vendor_blend=MAC_VENDOR_BLEND)


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
        self._key         = self._load_or_create_key()
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
            new_mac, mode = self._next_mac(iface)
            ok      = self._apply_mac(iface, new_mac)
            if ok:
                last = new_mac
                self._log(f"MAC randomised ({mode}): {iface} → {new_mac}")
        if not last and ifaces and not self.last_error:
            self.last_error = "No interface could be changed (adapter not found or write failed)."
        return last

    def _next_mac(self, iface: str) -> tuple[str, str]:
        """Pick the address for *iface*: a per-network stable one when enabled
        and the network is identifiable, otherwise a fresh CSPRNG-random one.

        Returns (mac, mode) where mode is "per-network" or "random" for logging.
        """
        if MAC_PER_NETWORK:
            net_id = self.current_network_id(iface)
            if net_id:
                return (mac_for_network(self._key, f"{iface}\x1f{net_id}",
                                        vendor_blend=MAC_VENDOR_BLEND),
                        "per-network")
        return (generate_mac(vendor_blend=MAC_VENDOR_BLEND), "random")

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
            # Reversibility gap closed here: an explicit (non-timeout) enable
            # failure previously returned False and left the adapter DISABLED
            # with no further attempt — the exact "unreversible in practice"
            # residual state audited in item 1 (a network outage with no
            # automatic recovery). The timeout branch above already retries;
            # a clean non-zero return code deserves the same best-effort retry,
            # not less effort just because netsh answered instead of hanging.
            try:
                subprocess.run(
                    ["netsh", "interface", "set", "interface",
                     f"name={iface}", "admin=enabled"],
                    capture_output=True, text=True, timeout=15,
                )
            except Exception:
                pass   # best-effort only; the failure above is already recorded
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

    def _load_or_create_key(self) -> bytes:
        """Load the per-install HMAC key, creating it once on first use.

        The key is what makes per-network addresses both stable and
        unpredictable, so it is generated from the OS CSPRNG and restricted to
        privileged principals on every platform. If it cannot be persisted
        (read-only volume, permission error) we still return a live key so
        randomisation works this session — only cross-session stability is
        lost, never security.

        THIS KEY IS A SECRET, and it used to be protected only on POSIX
        (`if os.name == "posix": chmod 0600`), while the docstring claimed
        "where the platform supports it" — implying Windows could not. Windows
        supports ACLs perfectly well; the guard simply left the key readable
        by BUILTIN\\Users under %ProgramData%. That is a real privacy defeat
        rather than a permissions nit: every per-network address is
        HMAC(key, network_id), so anyone who reads this file can compute the
        address for EVERY network the machine joins — predicting them ahead of
        time and linking them all back to one person. That is precisely the
        cross-network unlinkability the feature exists to provide.
        """
        try:
            if MAC_KEY_PATH.exists():
                data = MAC_KEY_PATH.read_bytes()
                if len(data) >= 32:
                    # Heal an already-exposed key from an older build. The key
                    # stays valid (rotating it would change every per-network
                    # address); only its permissions are corrected.
                    self._protect_key()
                    return data
        except Exception:
            pass
        key = secrets.token_bytes(32)
        try:
            MAC_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
            MAC_KEY_PATH.write_bytes(key)
            self._protect_key()
        except Exception:
            pass
        return key

    def _protect_key(self) -> None:
        """Restrict the install key to privileged principals, on any platform."""
        try:
            from . import secure_file
            ok, detail = secure_file.harden(MAC_KEY_PATH)
            if not ok:
                self._log(f"MAC install key could not be protected: {detail}")
        except Exception as exc:      # noqa: BLE001 — never break randomisation
            self._log(f"MAC install key protection error: {exc}")

    def current_network_id(self, iface: str) -> str:
        """Best-effort stable identifier for the network *iface* is joined to.

        Prefers the Wi-Fi SSID (stable across reconnects to the same network);
        falls back to the default-gateway MAC (stable per LAN). Returns "" when
        the network can't be identified — the caller then uses a fresh random
        address instead of a per-network one, so an unknown network never
        produces a predictable address.
        """
        try:
            ssid = self._wifi_ssid(iface)
            if ssid:
                return f"ssid:{ssid}"
            gw = self._gateway_id()
            if gw:
                return f"gw:{gw}"
        except Exception:
            pass
        return ""

    def _wifi_ssid(self, iface: str) -> str:
        sys = _platform()
        try:
            if sys == "windows":
                out = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                                     capture_output=True, text=True, timeout=8).stdout
                # Parse the block for this interface; SSID line (not BSSID).
                cur_iface, ssid = "", ""
                for line in out.splitlines():
                    s = line.strip()
                    low = s.lower()
                    if low.startswith("name") and ":" in s:
                        cur_iface = s.split(":", 1)[1].strip()
                    elif low.startswith("ssid") and not low.startswith("bssid") and ":" in s:
                        val = s.split(":", 1)[1].strip()
                        if not iface or cur_iface.lower() == iface.lower():
                            ssid = val
                            if cur_iface.lower() == iface.lower():
                                break
                return ssid
            if sys == "linux":
                out = subprocess.run(["iwgetid", iface, "-r"],
                                     capture_output=True, text=True, timeout=8).stdout.strip()
                return out
            if sys == "darwin":
                out = subprocess.run(
                    ["/System/Library/PrivateFrameworks/Apple80211.framework/"
                     "Versions/Current/Resources/airport", "-I"],
                    capture_output=True, text=True, timeout=8).stdout
                for line in out.splitlines():
                    if " SSID:" in line:
                        return line.split(":", 1)[1].strip()
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        return ""

    def _gateway_id(self) -> str:
        """Default-gateway MAC as a per-LAN identifier (best effort)."""
        sys = _platform()
        try:
            if sys == "windows":
                # Default gateway IP → its ARP entry (MAC).
                route = subprocess.run(["ipconfig"], capture_output=True,
                                       text=True, timeout=8).stdout
                gw_ip = ""
                for line in route.splitlines():
                    if "Default Gateway" in line and ":" in line:
                        cand = line.split(":", 1)[1].strip()
                        if _RE_IPV4(cand):
                            gw_ip = cand
                if not gw_ip:
                    return ""
                arp = subprocess.run(["arp", "-a", gw_ip], capture_output=True,
                                     text=True, timeout=8).stdout
                m = re.search(r"([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}", arp)
                return m.group(0).replace("-", ":").upper() if m else ""
            if sys in ("linux", "darwin"):
                route = subprocess.run(["ip", "route"] if sys == "linux"
                                       else ["route", "-n", "get", "default"],
                                       capture_output=True, text=True, timeout=8).stdout
                m = re.search(r"(?:via|gateway:)\s+(\d{1,3}(?:\.\d{1,3}){3})", route)
                if not m:
                    return ""
                gw_ip = m.group(1)
                arp = subprocess.run(["arp", "-n", gw_ip], capture_output=True,
                                     text=True, timeout=8).stdout
                mm = re.search(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", arp)
                return mm.group(0).upper() if mm else ""
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        return ""

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
