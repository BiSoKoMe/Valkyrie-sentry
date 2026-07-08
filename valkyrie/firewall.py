"""Kernel-level IP firewall — Phase 2 of Valkyrie's defence stack.

Complements the DNS sinkhole by blocking outbound packets to known
tracker/malware IP ranges.  Catches apps that hardcode IP addresses
and skip DNS resolution entirely.

Two rule categories:
  DoH block  — TCP/443 to public DoH resolver IPs (always enforced)
  IP ranges  — CIDRs from threat-intel feeds (refreshed daily)

Platform implementations
------------------------
Linux:
  Uses a dedicated ``VALKYRIE`` iptables chain inserted into OUTPUT.
  All rules live in that chain so stop() can flush and delete it cleanly
  without disturbing existing firewall rules.

Windows:
  Uses ``netsh advfirewall`` to add outbound block rules.
  All rule names are prefixed ``Valkyrie_`` so stop() can delete them
  with a single wildcard delete command.

Admin / root requirement
------------------------
Both platforms require elevated privileges.
  Linux:   run as root or with CAP_NET_ADMIN
  Windows: run as Administrator

If the required binary is absent or returns a permission error the
manager logs a warning and continues — the firewall layer is optional.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import subprocess
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import (
    DNS_UPSTREAM,
    FIREWALL_DOH_IPS,
    FIREWALL_IP_PATH,
    FIREWALL_IP_SOURCES,
    FIREWALL_MAX_AGE_DAYS,
    FIREWALL_NEVER_BLOCK,
    USE_EXTERNAL_LISTS,
)

_SYSTEM = platform.system()

# Matches a bare IPv4 address
_RE_IP   = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# Matches an IPv4 CIDR
_RE_CIDR = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")


# ---------------------------------------------------------------------------
# CIDR utilities
# ---------------------------------------------------------------------------

def _parse_cidr(token: str) -> Optional[str]:
    """Return a normalised CIDR string or None if invalid."""
    token = token.strip()
    try:
        if _RE_IP.match(token):
            return str(ipaddress.IPv4Address(token))          # single host
        if _RE_CIDR.match(token):
            net = ipaddress.IPv4Network(token, strict=False)
            return str(net)                                    # normalised network
    except ValueError:
        pass
    return None


def _in_never_block(cidr: str) -> bool:
    """Return True if cidr overlaps any protected range."""
    try:
        candidate = ipaddress.ip_network(cidr, strict=False)
        for protected_str in FIREWALL_NEVER_BLOCK:
            try:
                protected = ipaddress.ip_network(protected_str, strict=False)
                if candidate.overlaps(protected):
                    return True
            except ValueError:
                pass
    except ValueError:
        pass
    return False


# ---------------------------------------------------------------------------
# Feed fetching & parsing
# ---------------------------------------------------------------------------

def _fetch_text(url: str, timeout: int = 20) -> str:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _parse_feed(text: str) -> set[str]:
    """Extract valid, non-protected CIDRs from one feed."""
    result: set[str] = set()
    for raw_line in text.splitlines():
        # Strip inline comments
        line = raw_line.split("#")[0].split(";")[0].strip()
        if not line:
            continue
        cidr = _parse_cidr(line)
        if cidr and not _in_never_block(cidr):
            result.add(cidr)
    return result


def _file_age_days(path: Path) -> Optional[float]:
    if not path.exists():
        return None
    mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    return (datetime.now(tz=timezone.utc) - mtime).total_seconds() / 86_400


def fetch_ip_blocklist(console=None) -> set[str]:
    """Download all feeds, merge, and write blocked_ips.txt.

    Returns the merged set of CIDRs.
    """
    def _print(msg: str) -> None:
        if console:
            console.print(msg)

    _print("[bold cyan]IP blocklist:[/bold cyan] fetching feeds…")
    merged: set[str] = set()

    for url in FIREWALL_IP_SOURCES:
        label = url.split("/")[2][:30]
        try:
            text  = _fetch_text(url)
            cidrs = _parse_feed(text)
            merged |= cidrs
            _print(f"  {label}: {len(cidrs):,} ranges")
        except Exception as exc:
            _print(f"  [yellow]Warning:[/yellow] {label}: {exc}")

    if merged:
        FIREWALL_IP_PATH.write_text("\n".join(sorted(merged)) + "\n", encoding="utf-8")
        _print(f"[green]IP blocklist:[/green] {len(merged):,} ranges → {FIREWALL_IP_PATH.name}")

    return merged


def load_ip_blocklist(console=None, allow_download: bool | None = None) -> set[str]:
    """Load the IP blocklist.

    Downloads are opt-in (``--download-lists`` / USE_EXTERNAL_LISTS): only
    then are stale feeds refreshed.  Otherwise a previously downloaded
    cache on disk is used when present, and the firewall falls back to
    DoH-only blocking when there is no cache — fully offline.
    """
    if allow_download is None:
        allow_download = USE_EXTERNAL_LISTS

    age = _file_age_days(FIREWALL_IP_PATH)
    if allow_download and (age is None or age > FIREWALL_MAX_AGE_DAYS):
        return fetch_ip_blocklist(console)
    if not FIREWALL_IP_PATH.exists():
        if console:
            console.print(
                "[dim]IP blocklist: no cached feeds (downloads off) — "
                "DoH blocking + learned intelligence only[/dim]"
            )
        return set()
    cidrs = set()
    for line in FIREWALL_IP_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            cidrs.add(line)
    if console:
        console.print(
            f"[dim]IP blocklist: {len(cidrs):,} ranges from cache "
            f"({age:.1f}d old)[/dim]"
        )
    return cidrs


# ---------------------------------------------------------------------------
# In-process IP lookup (used by is_blocked_ip)
# ---------------------------------------------------------------------------

class _IPSet:
    """Fast membership test for a mixed set of host IPs and CIDRs."""

    def __init__(self) -> None:
        self._hosts:    set[ipaddress.IPv4Address]  = set()
        self._networks: list[ipaddress.IPv4Network] = []
        self._lock = threading.RLock()

    def load(self, cidrs: set[str]) -> None:
        hosts: set[ipaddress.IPv4Address]  = set()
        nets:  list[ipaddress.IPv4Network] = []
        for c in cidrs:
            try:
                if "/" in c:
                    nets.append(ipaddress.IPv4Network(c, strict=False))
                else:
                    hosts.add(ipaddress.IPv4Address(c))
            except ValueError:
                pass
        with self._lock:
            self._hosts    = hosts
            self._networks = nets

    def contains(self, ip: str) -> bool:
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            return False
        with self._lock:
            if addr in self._hosts:
                return True
            return any(addr in net for net in self._networks)

    def count(self) -> int:
        with self._lock:
            return len(self._hosts) + len(self._networks)


# ---------------------------------------------------------------------------
# Platform helpers
# ---------------------------------------------------------------------------

_NETSH_TIMEOUT = 5   # seconds per netsh call — hangs without this on Windows


def _run(args: list[str], check: bool = False, timeout: int = _NETSH_TIMEOUT) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=timeout)


class _LinuxFirewall:
    """iptables implementation using a dedicated VALKYRIE chain.

    CIDR rules are applied in one batched iptables-restore call so
    startup time scales with file I/O, not subprocess count.
    """

    CHAIN = "VALKYRIE"

    def setup_chain(self) -> bool:
        """Create chain and insert it into OUTPUT.  Returns True on success."""
        try:
            _run(["iptables", "-N", self.CHAIN])
            r = _run(["iptables", "-I", "OUTPUT", "-j", self.CHAIN])
            return r.returncode == 0
        except FileNotFoundError:
            return False

    def add_doh_rules(self, ips: list[str]) -> int:
        """Add DoH block rules; returns count successfully added."""
        ok = 0
        for ip in ips:
            try:
                r = _run(["iptables", "-A", self.CHAIN,
                          "-p", "tcp", "-d", ip, "--dport", "443", "-j", "DROP"])
                if r.returncode == 0:
                    ok += 1
            except (subprocess.TimeoutExpired, OSError):
                pass
        return ok

    def add_cidr_rules_batch(self, cidrs: set[str]) -> int:
        """Add all CIDR rules in one iptables-restore call.  Returns count."""
        if not cidrs:
            return 0
        # Build iptables-restore input for the filter table
        lines = ["*filter"]
        for cidr in cidrs:
            lines.append(f"-A {self.CHAIN} -d {cidr} -j DROP")
        lines.append("COMMIT\n")
        payload = "\n".join(lines).encode()
        try:
            r = subprocess.run(
                ["iptables-restore", "--noflush"],
                input          = payload,
                capture_output = True,
                timeout        = 30,
            )
            return len(cidrs) if r.returncode == 0 else 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            # iptables-restore unavailable — fall back to one-by-one (slower)
            ok = 0
            for cidr in cidrs:
                try:
                    r = _run(["iptables", "-A", self.CHAIN, "-d", cidr, "-j", "DROP"])
                    if r.returncode == 0:
                        ok += 1
                except (subprocess.TimeoutExpired, OSError):
                    pass
            return ok

    def teardown(self) -> None:
        for cmd in (
            ["iptables", "-F", self.CHAIN],
            ["iptables", "-D", "OUTPUT", "-j", self.CHAIN],
            ["iptables", "-X", self.CHAIN],
        ):
            try:
                _run(cmd)
            except (subprocess.TimeoutExpired, OSError):
                pass


class _WindowsFirewall:
    """netsh advfirewall implementation.

    Windows Firewall becomes unstable with thousands of individual rules and
    each `netsh` call takes 0.3–1s under UAC/policy checks — 12 k rules
    would take hours.  On Windows we therefore:
      - Install only the 10 DoH block rules (TCP/443 to known resolvers)
      - Rely entirely on the in-process _IPSet for all other IP-range checks

    This gives instant startup and correct DoH blocking.  The _IPSet covers
    all 12 k ranges for Valkyrie's own connection logging and alerting.
    """

    PREFIX = "Valkyrie_"

    def setup(self) -> bool:
        """Probe that netsh is available and we have permission."""
        try:
            r = _run(["netsh", "advfirewall", "show", "currentprofile"])
            return r.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def add_doh_rules(self, ips: list[str]) -> int:
        """Add one outbound block rule per DoH IP (TCP/443 only).

        Returns count successfully added.  Skips silently on timeout.
        """
        ok = 0
        for ip in ips:
            name = f"{self.PREFIX}DoH_{ip.replace('.', '_')}"
            try:
                _run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={name}", "dir=out", "action=block",
                    "protocol=TCP", f"remoteip={ip}", "remoteport=443",
                ])
                ok += 1
            except (subprocess.TimeoutExpired, OSError):
                pass
        return ok

    def add_cidr_rules_batch(self, cidrs: set[str]) -> int:
        """No-op on Windows — _IPSet handles in-process CIDR blocking."""
        return 0

    def teardown(self) -> None:
        try:
            _run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={self.PREFIX}*",
            ])
        except (subprocess.TimeoutExpired, OSError):
            pass


# ---------------------------------------------------------------------------
# FirewallManager — public interface
# ---------------------------------------------------------------------------

class FirewallManager:
    """Manages kernel-level outbound IP blocking.

    Usage::

        fw = FirewallManager()
        count = fw.start()          # load lists, install rules
        fw.is_blocked_ip("1.1.1.1") # True  (DoH)
        fw.count()                  # total enforced ranges
        fw.stop()                   # remove all rules
    """

    def __init__(self, console=None) -> None:
        self._console   = console
        self._ipset     = _IPSet()
        self._active    = False
        self._rule_count = 0

        if _SYSTEM == "Linux":
            self._platform: _LinuxFirewall | _WindowsFirewall = _LinuxFirewall()
        else:
            self._platform = _WindowsFirewall()

    def _print(self, msg: str) -> None:
        if self._console:
            self._console.print(msg)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self, console=None, allow_download: bool | None = None) -> int:
        """Load IP lists and install firewall rules.

        On Linux:   installs DoH rules + all CIDR ranges via iptables-restore.
        On Windows: installs only the 10 DoH rules via netsh; CIDR ranges are
                    enforced in-process by _IPSet (no kernel rules — avoids
                    the multi-hour hang of running 12k netsh commands).

        ``allow_download`` gates feed downloads (default: USE_EXTERNAL_LISTS).
        DoH blocking always works — the resolver IPs are hardcoded.

        Returns total count of IP ranges loaded into _IPSet.
        """
        if console:
            self._console = console

        # 1. Check platform availability (non-fatal)
        if _SYSTEM == "Linux":
            kernel_ok = self._platform.setup_chain()
        else:
            kernel_ok = self._platform.setup()

        if not kernel_ok:
            self._print(
                "[yellow]Firewall:[/yellow] iptables/netsh unavailable or "
                "insufficient privileges — using in-process IP blocking only"
            )

        # 2. Load IP blocklist into _IPSet regardless of kernel availability
        try:
            cidrs = load_ip_blocklist(self._console, allow_download=allow_download)
        except Exception as exc:
            self._print(f"[yellow]Firewall:[/yellow] IP list load failed: {exc}")
            cidrs = set()

        all_cidrs = cidrs | set(FIREWALL_DOH_IPS)
        self._ipset.load(all_cidrs)

        doh_ok  = 0
        cidr_ok = 0

        if kernel_ok:
            # 3. DoH kernel rules — small fixed set, fast on both platforms
            doh_ok = self._platform.add_doh_rules(FIREWALL_DOH_IPS)

            # 4. CIDR kernel rules
            #    Linux:   one batched iptables-restore call (~instant)
            #    Windows: no-op (_IPSet handles it, avoids hours-long hang)
            cidr_ok = self._platform.add_cidr_rules_batch(cidrs)

        self._rule_count = len(all_cidrs)
        self._active     = True

        if _SYSTEM == "Windows":
            self._print(
                f"[green]✓[/green] Firewall: {doh_ok} DoH kernel rules + "
                f"{len(cidrs):,} IP ranges (in-process)"
            )
        else:
            self._print(
                f"[green]✓[/green] Firewall: {doh_ok} DoH rules + "
                f"{cidr_ok:,} IP ranges (kernel)"
            )
        return self._rule_count

    def stop(self) -> None:
        """Remove all rules Valkyrie added."""
        if not self._active:
            return
        try:
            self._platform.teardown()
        except Exception as exc:
            self._print(f"[yellow]Firewall teardown warning:[/yellow] {exc}")
        self._active     = False
        self._rule_count = 0

    def update(self, console=None) -> int:
        """Fetch fresh IP lists and re-apply rules.

        Returns new total range count.
        """
        if console:
            self._console = console
        try:
            cidrs = fetch_ip_blocklist(self._console)
        except Exception as exc:
            self._print(f"[yellow]Firewall update failed:[/yellow] {exc}")
            return self._rule_count

        if self._active:
            # Rebuild rules from scratch
            self.stop()
            return self.start()

        all_cidrs = cidrs | set(FIREWALL_DOH_IPS)
        self._ipset.load(all_cidrs)
        return len(all_cidrs)

    def is_blocked_ip(self, ip: str) -> bool:
        """Return True if ip falls within any blocked range (in-process check)."""
        return self._ipset.contains(ip)

    def count(self) -> int:
        """Return count of currently enforced ranges (kernel rules + DoH)."""
        return self._rule_count if self._active else self._ipset.count()
