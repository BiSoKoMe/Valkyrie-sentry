#!/usr/bin/env python3
"""
=============================================================================
  VALKYRIE V1
  Version: 0.4.0-alpha
=============================================================================

  Modes:
    python valkyrie.py scan              One-shot connection + Wi-Fi scan
    python valkyrie.py watch             Continuous connection monitor
                                         (+ active firewall mitigation on Windows)
    python valkyrie.py dns               DNS sinkhole (blocks tracker domains)
    python valkyrie.py monitor           24/7 tracking alerts (notify only, no block)
    python valkyrie.py alerts            Show tracking / data-theft alert log
    python valkyrie.py watch --dns       Monitor + DNS sinkhole together

  Active Mitigation (watch mode, Windows only):
    When an ESTABLISHED connection to a blocklisted host is detected, Valkyrie
    automatically injects a temporary outbound block rule via Windows Advanced
    Firewall using:
      netsh advfirewall firewall add rule name="Valkyrie_Block_..." ...
    All injected rules are removed automatically on Ctrl+C / clean exit.
    Requires Administrator privileges for firewall rule injection.

  REST API (localhost:8080):
    GET /alerts        Tracking alert history
    GET /mitigations   Firewall block events
    GET /stats         Event counts (includes firewall_blocks)
    GET /health        Health check

  Requirements:
    pip install -r requirements.txt
=============================================================================
"""

import argparse
import json
import os
import re
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import datetime
import platform
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional

try:
    import psutil
except ImportError:
    print("\n  [!] psutil not installed. Run:  pip install -r requirements.txt\n")
    sys.exit(1)

if sys.platform == "win32":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass

try:
    from dnslib import DNSRecord, QTYPE, RR, A
    from dnslib.server import DNSServer, BaseResolver
    HAS_DNSLIB = True
except ImportError:
    HAS_DNSLIB = False
    BaseResolver = object  # stub — allows module load without dnslib
    DNSServer = DNSRecord = QTYPE = RR = A = None

SCRIPT_DIR = Path(__file__).resolve().parent
BLOCKLIST_DIR = SCRIPT_DIR / "blocklists"
EVENT_DB_PATH = SCRIPT_DIR / "valkyrie_events.db"
DEFAULT_DNS_PORT = 5353
DEFAULT_DNS_UPSTREAM = "8.8.8.8"
WATCH_INTERVAL = 2.5
ALERT_COOLDOWN_SEC = 90

# ── Feature: Active Firewall Mitigation ──────────────────────────────────────
# Prefix for every firewall rule Valkyrie creates.  All rules are named
# "Valkyrie_Block_<ProcessName>_<IP>_<Port>" so they can be enumerated and
# bulk-deleted on clean shutdown without touching any pre-existing rules.
FW_RULE_PREFIX = "Valkyrie_Block_"

# ── Feature: Automated DNS Switcher ──────────────────────────────────────────
DNS_SWITCH_INTERFACE_WIN   = "Wi-Fi"   # Windows adapter name — edit if yours differs
DNS_SWITCH_INTERFACE_MAC   = "Wi-Fi"   # macOS service name — edit if yours differs

# ── Feature: REST API log server ─────────────────────────────────────────────
API_SERVER_HOST = "127.0.0.1"
API_SERVER_PORT = 8080

# ── Feature: Router/ARP mode — LAN device identification ─────────────────────
ARP_SCAN_INTERVAL = 30   # seconds between ARP table refreshes between refreshes



# ─────────────────────────────────────────────────────────────────────────────
# NEW FEATURE: ACTIVE FIREWALL MITIGATION
# ─────────────────────────────────────────────────────────────────────────────
# When watch mode detects a new ESTABLISHED connection to a blocklisted host,
# FirewallMitigator injects a temporary outbound block rule via the Windows
# Advanced Firewall (netsh advfirewall).  Each rule is named with the
# FW_RULE_PREFIX constant so all Valkyrie rules can be identified and bulk-
# removed on clean shutdown.
#
# On non-Windows platforms the class is a safe no-op — all public methods
# succeed silently — so the rest of the codebase requires no OS guards.
#
# Threading model: mitigate_threat() is always called from a daemon thread
# (threading.Thread) so the OS subprocess call never blocks the scan loop.
# ─────────────────────────────────────────────────────────────────────────────

class FirewallMitigator:
    """
    Manages temporary outbound block rules in the Windows Advanced Firewall.

    Usage (from watch loop):
        mitigator = FirewallMitigator(event_log)
        mitigator.mitigate_threat(process_name, remote_ip, remote_port)

    On program exit:
        mitigator.cleanup_all_rules()
    """

    def __init__(self, event_log: "EventLog"):
        self._event_log = event_log
        # Track rule names created this session so cleanup is O(n) not O(search)
        self._created_rules: list[str] = []
        self._lock = threading.Lock()
        self._is_windows = sys.platform == "win32"

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _sanitize(value: str) -> str:
        """Strip characters that could break the netsh rule name or command."""
        return re.sub(r"[^\w\-.]", "_", value)[:40]

    def _rule_name(self, process_name: str, remote_ip: str, remote_port: int) -> str:
        proc = self._sanitize(process_name)
        ip   = self._sanitize(remote_ip)
        return f"{FW_RULE_PREFIX}{proc}_{ip}_{remote_port}"

    def _run_netsh(self, args: list[str], timeout: int = 8) -> tuple[bool, str]:
        """Execute a netsh advfirewall subcommand. Returns (success, output)."""
        cmd = ["netsh", "advfirewall", "firewall"] + args
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                creationflags=subprocess.CREATE_NO_WINDOW if self._is_windows else 0,
            )
            ok = result.returncode == 0
            out = (result.stdout + result.stderr).strip()
            return ok, out
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            return False, str(exc)

    # ── Public API ────────────────────────────────────────────────────────────

    def mitigate_threat(self, process_name: str, remote_ip: str,
                        remote_port: int) -> bool:
        """
        Inject a temporary outbound firewall block for the given connection.

        Silently succeeds (returns True) on non-Windows platforms so callers
        require no platform guard.  Always call this from a background thread.

        Returns True if a rule was created (or already existed), False on error.
        """
        if not self._is_windows:
            return True  # safe no-op on macOS / Linux

        rule_name = self._rule_name(process_name, remote_ip, remote_port)

        # Deduplicate — don't add the same rule twice per session
        with self._lock:
            if rule_name in self._created_rules:
                return True

        # Build the netsh command that adds the block rule.
        # dir=out  → outbound traffic only (we never block inbound here)
        # protocol=TCP  → most tracker/telemetry traffic is TCP
        # enable=yes    → rule is active immediately
        add_args = [
            "add", "rule",
            f"name={rule_name}",
            "dir=out",
            "action=block",
            "protocol=TCP",
            f"remoteip={remote_ip}",
            f"remoteport={remote_port}",
            "enable=yes",
        ]

        ok, output = self._run_netsh(add_args)

        if ok:
            with self._lock:
                self._created_rules.append(rule_name)

            # Console feedback
            print(
                f"\n  {Color.RED}{Color.BOLD}[FIREWALL] ✓ BLOCKED{Color.RESET}  "
                f"{Color.MAGENTA}{process_name}{Color.RESET} → "
                f"{Color.CYAN}{remote_ip}:{remote_port}{Color.RESET}"
            )
            print(
                f"     {Color.DIM}Rule: {rule_name}{Color.RESET}\n"
            )

            # Persist to SQLite so the REST API / dashboard picks it up
            self._event_log.log(
                action="firewall_block",
                domain=remote_ip,
                process_name=process_name,
                remote_ip=remote_ip,
                category="ACTIVE-MITIGATION",
                severity=5,
                details=(
                    f"Outbound TCP block rule injected → "
                    f"{remote_ip}:{remote_port} (rule: {rule_name})"
                ),
            )
            return True

        else:
            # Rule creation failed — log the error but don't crash the scan loop
            print(
                f"\n  {Color.YELLOW}[FIREWALL] ✗ Could not block "
                f"{process_name} → {remote_ip}:{remote_port}{Color.RESET}"
            )
            print(
                f"     {Color.DIM}netsh error: {output}{Color.RESET}"
            )
            if "Access is denied" in output or "5)" in output:
                print(
                    f"     {Color.YELLOW}→ Run Valkyrie as Administrator "
                    f"to enable firewall mitigation.{Color.RESET}\n"
                )
            return False

    def cleanup_all_rules(self) -> int:
        """
        Delete every firewall rule created during this session.

        Called automatically on clean exit (Ctrl+C / SIGTERM).  Safe to call
        multiple times.  Returns the number of rules successfully removed.
        """
        if not self._is_windows:
            return 0

        with self._lock:
            rules_to_remove = list(self._created_rules)

        if not rules_to_remove:
            return 0

        print(
            f"\n  {Color.CYAN}[FIREWALL] Removing "
            f"{len(rules_to_remove)} Valkyrie block rule(s)...{Color.RESET}"
        )

        removed = 0
        for rule_name in rules_to_remove:
            ok, _ = self._run_netsh(["delete", "rule", f"name={rule_name}"])
            if ok:
                removed += 1
                print(f"     {Color.DIM}✓ Removed: {rule_name}{Color.RESET}")
            else:
                print(f"     {Color.YELLOW}✗ Could not remove: {rule_name}{Color.RESET}")

        with self._lock:
            self._created_rules.clear()

        if removed:
            print(
                f"  {Color.GREEN}[FIREWALL] ✓ {removed} rule(s) cleaned up. "
                f"Your firewall is back to its original state.{Color.RESET}\n"
            )
        else:
            print(
                f"  {Color.YELLOW}[FIREWALL] No rules could be removed. "
                f"Check Windows Firewall manually if needed.{Color.RESET}\n"
            )

        return removed


# ─────────────────────────────────────────────────────────────────────────────
# NEW FEATURE 1: AUTOMATED OS DNS SWITCHER
# ─────────────────────────────────────────────────────────────────────────────
# When Valkyrie starts dns or monitor mode it automatically points the OS DNS
# to 127.0.0.1 so every DNS query on the machine flows through the sinkhole.
# On clean exit (or Ctrl+C) it restores the original DNS servers automatically.
#
# Supports: Windows (netsh), macOS (networksetup), Linux (resolvectl / nmcli)
# Requires: Administrator / sudo to write DNS settings on Windows & Mac.
# ─────────────────────────────────────────────────────────────────────────────

class DNSSwitcher:
    """
    Automatically redirects OS-level DNS to 127.0.0.1 when Valkyrie's
    DNS sinkhole or monitor starts, and restores original settings on exit.

    Usage:
        switcher = DNSSwitcher()
        switcher.activate()    # point OS DNS → 127.0.0.1
        ...
        switcher.restore()     # put original DNS back

    The restore() call is registered as an atexit handler automatically,
    so it runs even if the process is killed via Ctrl+C as long as Python's
    signal handler fires normally.
    """

    def __init__(self,
                 win_interface: str = DNS_SWITCH_INTERFACE_WIN,
                 mac_interface: str = DNS_SWITCH_INTERFACE_MAC):
        self._win_iface = win_interface
        self._mac_iface = mac_interface
        self._original_dns: list[str] = []   # saved before we change anything
        self._active = False
        self._os = platform.system()

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _run(cmd: list[str], timeout: int = 6) -> tuple[bool, str]:
        """Run a command, return (success, output/error text)."""
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if r.returncode == 0:
                return True, r.stdout.strip()
            return False, r.stderr.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            return False, str(e)

    def _read_current_dns_windows(self) -> list[str]:
        """Return the current DNS server list for the Windows Wi-Fi adapter."""
        ok, out = self._run([
            "netsh", "interface", "ip", "show", "dns",
            f"name={self._win_iface}"
        ])
        if not ok:
            return []
        servers = []
        for line in out.splitlines():
            m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
            if m and m.group(1) != "127.0.0.1":
                servers.append(m.group(1))
        return servers or ["dhcp"]   # "dhcp" is our sentinel for auto-config

    def _read_current_dns_macos(self) -> list[str]:
        """Return the current DNS server list for the macOS Wi-Fi service."""
        ok, out = self._run(["networksetup", "-getdnsservers", self._mac_iface])
        if not ok or "There aren't any DNS Servers" in out:
            return ["empty"]   # sentinel: means "no manual DNS set"
        return [line.strip() for line in out.splitlines() if line.strip()]

    def _read_current_dns_linux(self) -> list[str]:
        """
        Read current DNS from resolvectl (systemd-resolved) or resolv.conf.
        Returns list of server IPs, or ["auto"] as a sentinel.
        """
        ok, out = self._run(["resolvectl", "status"])
        if ok:
            servers = []
            for line in out.splitlines():
                if "DNS Servers" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        servers += parts[1].strip().split()
            if servers:
                return [s for s in servers if s != "127.0.0.1"]
        # Fallback: parse /etc/resolv.conf
        try:
            text = Path("/etc/resolv.conf").read_text()
            return [
                line.split()[1] for line in text.splitlines()
                if line.startswith("nameserver") and "127.0.0.1" not in line
            ]
        except OSError:
            return ["auto"]

    # ── Public API ────────────────────────────────────────────────────────────

    def activate(self) -> bool:
        """
        Save current DNS and switch OS DNS to 127.0.0.1.
        Returns True if successfully switched, False if not (e.g. no admin rights).
        Registers restore() as an atexit handler.
        """
        if self._active:
            return True

        import atexit
        atexit.register(self.restore)

        print(f"  {Color.CYAN}[DNS-SWITCH] Reading current DNS settings...{Color.RESET}")

        if self._os == "Windows":
            self._original_dns = self._read_current_dns_windows()
            ok, err = self._run([
                "netsh", "interface", "ip", "set", "dns",
                f"name={self._win_iface}", "source=static", "address=127.0.0.1"
            ])
        elif self._os == "Darwin":
            self._original_dns = self._read_current_dns_macos()
            ok, err = self._run([
                "networksetup", "-setdnsservers", self._mac_iface, "127.0.0.1"
            ])
        elif self._os == "Linux":
            self._original_dns = self._read_current_dns_linux()
            # Try resolvectl first (systemd-resolved)
            ok, err = self._run(["resolvectl", "dns", "0", "127.0.0.1"])
            if not ok:
                # Fallback: use nmcli for NetworkManager systems
                ok, err = self._run([
                    "nmcli", "con", "mod",
                    self._mac_iface, "ipv4.dns", "127.0.0.1"
                ])
        else:
            print(f"  {Color.YELLOW}[DNS-SWITCH] Unsupported OS for automatic DNS switching.{Color.RESET}")
            print(f"  {Color.DIM}Point your DNS manually to 127.0.0.1{Color.RESET}")
            return False

        if ok:
            self._active = True
            orig_str = ", ".join(self._original_dns) or "DHCP/auto"
            print(f"  {Color.GREEN}[DNS-SWITCH] ✓ OS DNS → 127.0.0.1  (was: {orig_str}){Color.RESET}")
            print(f"  {Color.DIM}Will restore automatically on exit.{Color.RESET}\n")
            return True
        else:
            print(f"  {Color.RED}[DNS-SWITCH] ✗ Failed to set DNS: {err}{Color.RESET}")
            if self._os in ("Windows", "Darwin"):
                print(f"  {Color.YELLOW}  → Try running as Administrator / sudo{Color.RESET}")
            print(f"  {Color.DIM}  → Continuing without auto DNS switch. Set DNS to 127.0.0.1 manually.{Color.RESET}")
            return False

    def restore(self) -> bool:
        """
        Restore DNS to what it was before activate() was called.
        Safe to call multiple times — only acts if _active is True.
        """
        if not self._active:
            return True
        self._active = False

        print(f"{Color.CYAN}[DNS-SWITCH] Restoring original DNS settings...{Color.RESET}")

        if self._os == "Windows":
            if self._original_dns == ["dhcp"]:
                ok, err = self._run([
                    "netsh", "interface", "ip", "set", "dns",
                    f"name={self._win_iface}", "source=dhcp"
                ])
            else:
                ok, err = self._run([
                    "netsh", "interface", "ip", "set", "dns",
                    f"name={self._win_iface}", "source=static",
                    f"address={self._original_dns[0]}"
                ])
                for extra in self._original_dns[1:]:
                    self._run([
                        "netsh", "interface", "ip", "add", "dns",
                        f"name={self._win_iface}", f"address={extra}", "index=2"
                    ])

        elif self._os == "Darwin":
            if self._original_dns in (["empty"], []):
                ok, err = self._run([
                    "networksetup", "-setdnsservers", self._mac_iface, "Empty"
                ])
            else:
                ok, err = self._run([
                    "networksetup", "-setdnsservers",
                    self._mac_iface, *self._original_dns
                ])

        elif self._os == "Linux":
            if self._original_dns and self._original_dns != ["auto"]:
                ok, err = self._run(
                    ["resolvectl", "dns", "0", *self._original_dns]
                )
                if not ok:
                    ok, err = self._run([
                        "nmcli", "con", "mod",
                        self._mac_iface, "ipv4.dns", " ".join(self._original_dns)
                    ])
            else:
                ok, err = True, "auto"
        else:
            return False

        if ok:
            orig_str = ", ".join(self._original_dns) or "DHCP/auto"
            print(f"  {Color.GREEN}[DNS-SWITCH] ✓ DNS restored to: {orig_str}{Color.RESET}")
            return True
        else:
            print(f"  {Color.RED}[DNS-SWITCH] ✗ Restore failed: {err}{Color.RESET}")
            print(f"  {Color.YELLOW}  → Manually set your DNS back to automatic / your ISP's DNS{Color.RESET}")
            return False


# ─────────────────────────────────────────────────────────────────────────────
# NEW FEATURE 2: REST API LOG SERVER
# ─────────────────────────────────────────────────────────────────────────────
# Starts a lightweight HTTP server on localhost:8080 in a background thread.
# Exposes SQLite event data as JSON so a web dashboard or mobile app can
# consume it without reading the database file directly.
#
# Endpoints:
#   GET /alerts              → last 24h tracking alerts as JSON array
#   GET /alerts?hours=N      → last N hours
#   GET /alerts?limit=N      → cap at N records
#   GET /stats               → summary counts
#   GET /health              → {"status": "ok"}
# ─────────────────────────────────────────────────────────────────────────────

class _AlertAPIHandler(BaseHTTPRequestHandler):
    """
    Minimal HTTP request handler for the Valkyrie REST API.
    _event_log is injected at server creation time via server.event_log.
    """

    def log_message(self, format, *args):
        # Suppress the default Apache-style access log spam to keep the
        # Valkyrie console output clean.
        pass

    def _send_json(self, data: object, status: int = 200):
        """Serialize data to JSON and write the HTTP response."""
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Allow the future dashboard (running on any local port) to call this
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _parse_qs(self) -> dict[str, str]:
        """Parse ?key=value pairs from the request path."""
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        return {k: v[0] for k, v in qs.items()}

    def do_OPTIONS(self):
        """Handle preflight CORS requests from browser-based dashboards."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.end_headers()

    def do_GET(self):
        from urllib.parse import urlparse
        path = urlparse(self.path).path
        qs   = self._parse_qs()
        log: EventLog = self.server.event_log  # type: ignore[attr-defined]

        if path == "/health":
            self._send_json({"status": "ok", "ts": datetime.datetime.now().isoformat()})

        elif path == "/alerts":
            try:
                hours = int(qs.get("hours", 24))
                limit = int(qs.get("limit", 200))
            except ValueError:
                self._send_json({"error": "hours and limit must be integers"}, 400)
                return
            alerts = log.fetch_tracking_alerts(hours=hours, limit=limit)
            self._send_json({
                "count":   len(alerts),
                "hours":   hours,
                "alerts":  alerts,
            })

        elif path == "/stats":
            total     = log.recent_count()
            tracking  = log.recent_count("tracking_alert")
            blocked   = log.recent_count("blocked_dns")
            detected  = log.recent_count("detected")
            mitigated = log.recent_count("firewall_block")
            self._send_json({
                "total_events":        total,
                "active_connections":  total,
                "tracking_alerts":     tracking,
                "dns_blocked":         blocked,
                "dns_allowed":         max(0, total - blocked),
                "connections_flagged": detected,
                "firewall_blocks":     mitigated,
                "db_path":             str(log._db_path),
            })

        elif path == "/mitigations":
            try:
                hours = int(qs.get("hours", 24))
                limit = int(qs.get("limit", 200))
            except ValueError:
                self._send_json({"error": "hours and limit must be integers"}, 400)
                return
            events = log.fetch_mitigation_events(hours=hours, limit=limit)
            self._send_json({
                "count":      len(events),
                "hours":      hours,
                "mitigations": events,
            })

        elif path == "/dns-log":
            try:
                hours = int(qs.get("hours", 1))
                limit = int(qs.get("limit", 500))
            except ValueError:
                self._send_json({"error": "hours and limit must be integers"}, 400)
                return
            events = log.fetch_dns_log(hours=hours, limit=limit)
            self._send_json({"count": len(events), "events": events})

        else:
            self._send_json({"error": f"Unknown endpoint: {path}"}, 404)


class AlertAPIServer:
    """
    Wraps Python's built-in HTTPServer to serve Valkyrie log data as JSON.
    Runs in a daemon thread so it never blocks the main program.

    Usage:
        api = AlertAPIServer(event_log)
        api.start()          # non-blocking
        ...
        api.stop()
    """

    def __init__(self, event_log: "EventLog",
                 host: str = API_SERVER_HOST, port: int = API_SERVER_PORT):
        self._host = host
        self._port = port
        self._event_log = event_log
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self):
        """Start the API server in a background daemon thread."""
        try:
            self._server = HTTPServer((self._host, self._port), _AlertAPIHandler)
            # Inject event_log onto the server object so the handler can access it
            self._server.event_log = self._event_log  # type: ignore[attr-defined]
        except OSError as e:
            print(f"  {Color.YELLOW}[API] Could not start on "
                  f"{self._host}:{self._port} — {e}{Color.RESET}")
            print(f"  {Color.DIM}  → Another process may be using port {self._port}. "
                  f"Change API_SERVER_PORT in the script.{Color.RESET}")
            return

        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="valkyrie-api",
        )
        self._thread.start()
        print(f"  {Color.CYAN}[API] Log server running on "
              f"http://{self._host}:{self._port}{Color.RESET}")
        print(f"  {Color.DIM}  Endpoints: /alerts  /alerts?hours=N  /stats  /health{Color.RESET}")

    def stop(self):
        if self._server:
            self._server.shutdown()


# ─────────────────────────────────────────────────────────────────────────────
# NEW FEATURE 3: LAN DEVICE IDENTIFIER (ARP + DHCP LEASE READER)
# ─────────────────────────────────────────────────────────────────────────────
# Upgrades the scanner from a single-machine view to a full-network view.
# Instead of only seeing connections on the machine running the script,
# this module reads the OS ARP table and common DHCP lease files to build
# a map of every device on the LAN: IP → {hostname, MAC, vendor}.
#
# When a blocklist hit is detected via DNS, the sinkhole can use this map
# to say "it was the Samsung TV (192.168.1.42)" not just an IP address.
#
# In production (on real hardware): replace ARP table with pcap/dnslib
# DNS query source IP parsing so the hardware box sees true per-device traffic.
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class LANDevice:
    """A device discovered on the local network."""
    ip: str
    mac: str
    hostname: str = "unknown"
    vendor: str   = "unknown"   # OUI lookup — populated if oui.txt is available
    last_seen: str = ""


class LANMapper:
    """
    Builds and maintains a map of LAN devices using:
      1. OS ARP table    (arp -a / ip neigh)
      2. DHCP lease files (/var/lib/dhcp/dhcpd.leases, dnsmasq leases, etc.)
      3. OUI vendor lookup (optional — reads oui.txt if present next to script)

    This gives the DNS sinkhole the ability to log WHICH device made a
    blocked DNS query, not just that something on the network did.
    """

    # Common DHCP lease file locations (Linux / macOS / router-on-host setups)
    DHCP_LEASE_PATHS = [
        Path("/var/lib/dhcp/dhcpd.leases"),
        Path("/var/lib/dhcpd/dhcpd.leases"),
        Path("/var/lib/misc/dnsmasq.leases"),
        Path("/tmp/dnsmasq.leases"),
        Path("/var/run/dnsmasq/dnsmasq-dhcp.leases"),
    ]

    def __init__(self):
        self._devices: dict[str, LANDevice] = {}   # IP → LANDevice
        self._lock = threading.Lock()
        self._oui: dict[str, str] = {}             # first 6 hex chars → vendor name
        self._load_oui()

    def _load_oui(self):
        """
        Load IEEE OUI vendor table from oui.txt if present.
        Download from https://linuxnet.ca/ieee/oui.txt and place next to script.
        Without this file, vendor shows as "unknown".
        """
        oui_path = SCRIPT_DIR / "oui.txt"
        if not oui_path.is_file():
            return
        try:
            for line in oui_path.read_text(errors="ignore").splitlines():
                if "(hex)" in line:
                    parts = line.split("(hex)")
                    if len(parts) == 2:
                        prefix = parts[0].strip().replace("-", "").lower()
                        vendor = parts[1].strip()
                        self._oui[prefix] = vendor
        except OSError:
            pass

    def _vendor_from_mac(self, mac: str) -> str:
        """Look up manufacturer from the first 3 octets of a MAC address."""
        prefix = mac.replace(":", "").replace("-", "").lower()[:6]
        return self._oui.get(prefix, "unknown")

    # ── ARP table parsing ─────────────────────────────────────────────────────

    def _parse_arp_windows(self) -> list[LANDevice]:
        try:
            out = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=5
            ).stdout
        except OSError:
            return []
        devices = []
        for line in out.splitlines():
            m = re.match(
                r"\s+(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f-]{17})", line, re.I
            )
            if m:
                ip  = m.group(1)
                mac = m.group(2).replace("-", ":").lower()
                devices.append(LANDevice(
                    ip=ip, mac=mac,
                    vendor=self._vendor_from_mac(mac),
                    last_seen=datetime.datetime.now().isoformat(),
                ))
        return devices

    def _parse_arp_unix(self) -> list[LANDevice]:
        """Parse ARP table on Linux/macOS using `ip neigh` or `arp -a`."""
        devices = []

        # Try `ip neigh` first (Linux, most accurate)
        try:
            out = subprocess.run(
                ["ip", "neigh"], capture_output=True, text=True, timeout=5
            ).stdout
            for line in out.splitlines():
                # Format: 192.168.1.5 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
                m = re.match(
                    r"(\d{1,3}(?:\.\d{1,3}){3}).*?lladdr\s+([0-9a-f:]{17})",
                    line, re.I
                )
                if m:
                    ip  = m.group(1)
                    mac = m.group(2).lower()
                    devices.append(LANDevice(
                        ip=ip, mac=mac,
                        vendor=self._vendor_from_mac(mac),
                        last_seen=datetime.datetime.now().isoformat(),
                    ))
            if devices:
                return devices
        except OSError:
            pass

        # Fallback: `arp -a` (macOS + older Linux)
        try:
            out = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=5
            ).stdout
            for line in out.splitlines():
                # Format: hostname (192.168.1.5) at aa:bb:cc:dd:ee:ff [ether] on en0
                m = re.search(
                    r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9a-f:]{17})",
                    line, re.I
                )
                if m:
                    ip  = m.group(1)
                    mac = m.group(2).lower()
                    # Extract optional hostname before the parenthesis
                    hn_m = re.match(r"^(\S+)\s+\(", line)
                    hn = hn_m.group(1) if hn_m else "unknown"
                    devices.append(LANDevice(
                        ip=ip, mac=mac, hostname=hn,
                        vendor=self._vendor_from_mac(mac),
                        last_seen=datetime.datetime.now().isoformat(),
                    ))
        except OSError:
            pass

        return devices

    # ── DHCP lease parsing ────────────────────────────────────────────────────

    def _parse_dhcp_leases(self) -> list[LANDevice]:
        """
        Parse ISC dhcpd and dnsmasq lease files.
        dnsmasq format:  <expiry> <mac> <ip> <hostname> <client-id>
        ISC dhcpd format: multi-line lease blocks.
        """
        devices = []
        for lease_path in self.DHCP_LEASE_PATHS:
            if not lease_path.is_file():
                continue
            try:
                text = lease_path.read_text(errors="ignore")
            except OSError:
                continue

            # dnsmasq single-line format
            if "dnsmasq" in str(lease_path):
                for line in text.splitlines():
                    parts = line.split()
                    if len(parts) >= 4:
                        mac = parts[1]
                        ip  = parts[2]
                        hn  = parts[3] if parts[3] != "*" else "unknown"
                        devices.append(LANDevice(
                            ip=ip, mac=mac, hostname=hn,
                            vendor=self._vendor_from_mac(mac),
                            last_seen=datetime.datetime.now().isoformat(),
                        ))
                continue

            # ISC dhcpd multi-line blocks
            current: dict[str, str] = {}
            for line in text.splitlines():
                line = line.strip().rstrip(";")
                if line.startswith("lease "):
                    current = {"ip": line.split()[1]}
                elif "hardware ethernet" in line:
                    current["mac"] = line.split()[-1]
                elif "client-hostname" in line:
                    current["hostname"] = line.split()[-1].strip('"')
                elif line == "}" and "ip" in current and "mac" in current:
                    mac = current["mac"]
                    devices.append(LANDevice(
                        ip=current["ip"],
                        mac=mac,
                        hostname=current.get("hostname", "unknown"),
                        vendor=self._vendor_from_mac(mac),
                        last_seen=datetime.datetime.now().isoformat(),
                    ))
                    current = {}

        return devices

    # ── Public API ────────────────────────────────────────────────────────────

    def refresh(self):
        """
        Re-scan the ARP table and DHCP leases, update the internal device map.
        Thread-safe — can be called from a background thread.
        """
        fresh: dict[str, LANDevice] = {}

        arp_devices = (
            self._parse_arp_windows()
            if platform.system() == "Windows"
            else self._parse_arp_unix()
        )
        for dev in arp_devices:
            fresh[dev.ip] = dev

        # DHCP leases enrich ARP data with hostnames
        for dev in self._parse_dhcp_leases():
            if dev.ip in fresh:
                if fresh[dev.ip].hostname == "unknown":
                    fresh[dev.ip].hostname = dev.hostname
            else:
                fresh[dev.ip] = dev

        with self._lock:
            self._devices = fresh

    def lookup(self, ip: str) -> Optional[LANDevice]:
        """Return the LANDevice for a given IP, or None if not in the map."""
        with self._lock:
            return self._devices.get(ip)

    def all_devices(self) -> list[LANDevice]:
        """Return a snapshot of all discovered LAN devices."""
        with self._lock:
            return list(self._devices.values())

    def start_background_refresh(self, interval: int = ARP_SCAN_INTERVAL):
        """
        Kick off a daemon thread that refreshes the ARP/DHCP map every
        `interval` seconds so the device list stays current automatically.
        """
        def _loop():
            while True:
                try:
                    self.refresh()
                except Exception:
                    pass
                time.sleep(interval)

        t = threading.Thread(target=_loop, daemon=True, name="valkyrie-lan-mapper")
        t.start()
        self.refresh()   # do one immediate refresh before returning


# helper: format a LAN device for console output
def _format_lan_device(dev: Optional[LANDevice]) -> str:
    if not dev:
        return ""
    parts = [f"LAN: {dev.ip}"]
    if dev.hostname and dev.hostname != "unknown":
        parts.append(dev.hostname)
    if dev.vendor and dev.vendor != "unknown":
        parts.append(f"[{dev.vendor}]")
    return "  ".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1: ANSI COLORS
# ─────────────────────────────────────────────────────────────────────────────

class Color:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2: BLOCKLIST DATABASE
# ─────────────────────────────────────────────────────────────────────────────

class ThreatCategory(Enum):
    TELEMETRY      = "TELEMETRY"
    DATA_BROKER    = "DATA-BROKER"
    AD_TRACKER     = "AD-TRACKER"
    FINGERPRINTING = "FINGERPRINTING"
    CORPORATE_SPY  = "CORPORATE-SPY"
    MALWARE_C2     = "MALWARE-C2"


@dataclass
class BlocklistEntry:
    domain: str
    category: ThreatCategory
    description: str
    severity: int  # 1–5
    source: str = "curated"


class BlocklistDB:
    """Surveillance domain blocklist with file import support."""

    _CURATED = [
        BlocklistEntry("telemetry.microsoft.com",         ThreatCategory.TELEMETRY,      "Windows OS usage telemetry",               4),
        BlocklistEntry("vortex.data.microsoft.com",       ThreatCategory.TELEMETRY,      "Windows Vortex telemetry pipeline",        4),
        BlocklistEntry("settings-win.data.microsoft.com", ThreatCategory.TELEMETRY,      "Windows settings sync telemetry",          3),
        BlocklistEntry("metrics.apple.com",               ThreatCategory.TELEMETRY,      "Apple device metrics collection",          4),
        BlocklistEntry("xp.apple.com",                    ThreatCategory.TELEMETRY,      "Apple experience improvement program",     3),
        BlocklistEntry("app-measurement.com",             ThreatCategory.TELEMETRY,      "Google Firebase app analytics",            4),
        BlocklistEntry("clients4.google.com",             ThreatCategory.TELEMETRY,      "Google client telemetry reporting",        3),
        BlocklistEntry("data.mistat.xiaomi.com",          ThreatCategory.TELEMETRY,      "Xiaomi device telemetry",                  5),
        BlocklistEntry("tracking.tiktok.com",             ThreatCategory.TELEMETRY,      "TikTok background device tracking",        5),
        BlocklistEntry("log.byteoversea.com",             ThreatCategory.TELEMETRY,      "ByteDance overseas log aggregation",       5),
        BlocklistEntry("data.acxiom.com",                 ThreatCategory.DATA_BROKER,    "Acxiom consumer data platform",            5),
        BlocklistEntry("api.tapad.com",                   ThreatCategory.DATA_BROKER,    "Tapad cross-device tracking",              4),
        BlocklistEntry("sync.liveramp.com",               ThreatCategory.DATA_BROKER,    "LiveRamp identity resolution",             4),
        BlocklistEntry("pixel.lotame.com",                ThreatCategory.DATA_BROKER,    "Lotame DMP data collection pixel",         4),
        BlocklistEntry("sync.mathtag.com",                ThreatCategory.DATA_BROKER,    "MediaMath cookie sync",                    3),
        BlocklistEntry("doubleclick.net",                 ThreatCategory.AD_TRACKER,     "Google DoubleClick ad tracker",            4),
        BlocklistEntry("googlesyndication.com",           ThreatCategory.AD_TRACKER,     "Google AdSense tracker",                   3),
        BlocklistEntry("ads.facebook.com",                ThreatCategory.AD_TRACKER,     "Meta cross-site ad tracker",               4),
        BlocklistEntry("connect.facebook.net",            ThreatCategory.AD_TRACKER,     "Meta pixel social tracking SDK",           4),
        BlocklistEntry("advertising.com",                 ThreatCategory.AD_TRACKER,     "Yahoo advertising tracker",                3),
        BlocklistEntry("track.gainsight.com",             ThreatCategory.AD_TRACKER,     "Gainsight SaaS behavioral tracking",       3),
        BlocklistEntry("fingerprintjs.com",               ThreatCategory.FINGERPRINTING, "FingerprintJS device fingerprint SaaS",    5),
        BlocklistEntry("cdn.iovation.com",                ThreatCategory.FINGERPRINTING, "iovation device intelligence",             4),
        BlocklistEntry("h.clarity.ms",                    ThreatCategory.FINGERPRINTING, "Microsoft Clarity session recorder",       3),
        BlocklistEntry("api.amplitude.com",               ThreatCategory.CORPORATE_SPY,  "Amplitude product analytics",              3),
        BlocklistEntry("api.mixpanel.com",                ThreatCategory.CORPORATE_SPY,  "Mixpanel behavioral analytics",            3),
        BlocklistEntry("heapanalytics.com",               ThreatCategory.CORPORATE_SPY,  "Heap auto-capture analytics",              3),
        BlocklistEntry("hotjar.com",                      ThreatCategory.CORPORATE_SPY,  "Hotjar heatmap & session recording",       4),
        BlocklistEntry("fullstory.com",                   ThreatCategory.CORPORATE_SPY,  "FullStory session replay",                 4),
        BlocklistEntry("analytics.yahoo.com",             ThreatCategory.CORPORATE_SPY,  "Yahoo Analytics tracking",                 3),
        BlocklistEntry("update.mykings.pw",               ThreatCategory.MALWARE_C2,     "MyKings botnet C2",                        5),
        BlocklistEntry("dl.installcdn-pub.com",           ThreatCategory.MALWARE_C2,     "Malicious installer CDN",                  5),
    ]

    def __init__(self):
        self._index: dict[str, BlocklistEntry] = {
            e.domain: e for e in self._CURATED
        }
        self._imported_count = 0

    @staticmethod
    def _normalize(domain: str) -> str:
        return domain.lower().strip().rstrip(".")

    def _add_domain(self, domain: str, source: str) -> bool:
        domain = self._normalize(domain)
        if not domain or "." not in domain:
            return False
        if domain in self._index:
            return False
        self._index[domain] = BlocklistEntry(
            domain=domain,
            category=ThreatCategory.AD_TRACKER,
            description=f"Imported tracker domain ({source})",
            severity=3,
            source=source,
        )
        return True

    def load_from_directory(self, directory: Path) -> int:
        """Load all .txt / .hosts files from blocklists/. Returns new domain count."""
        if not directory.is_dir():
            return 0
        added = 0
        for path in sorted(directory.iterdir()):
            if not path.is_file():
                continue
            if path.suffix.lower() not in (".txt", ".hosts", ".list") and path.name != "hosts":
                continue
            added += self._import_file(path)
        self._imported_count += added
        return added

    def _import_file(self, path: Path) -> int:
        added = 0
        source = path.name
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2 and re.match(r"^[\d.:a-fA-F]+$", parts[0]):
                domain = parts[1]
            else:
                domain = parts[0]
            domain = domain.split("/")[0]
            if self._add_domain(domain, source):
                added += 1
        return added

    def lookup(self, domain: str) -> Optional[BlocklistEntry]:
        domain = self._normalize(domain)
        if not domain:
            return None
        if domain in self._index:
            return self._index[domain]
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self._index:
                return self._index[parent]
        return None

    @property
    def size(self) -> int:
        return len(self._index)

    @property
    def imported_count(self) -> int:
        return self._imported_count


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2b: ALERTS (tracking / data-collection notifications)
# ─────────────────────────────────────────────────────────────────────────────

class AlertState:
    """Dedupe alerts — same domain won't spam within cooldown window."""

    def __init__(self, cooldown_sec: float = ALERT_COOLDOWN_SEC):
        self._cooldown = cooldown_sec
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def should_alert(self, domain: str) -> bool:
        domain = domain.lower()
        now = time.time()
        with self._lock:
            last = self._last.get(domain, 0)
            if now - last < self._cooldown:
                return False
            self._last[domain] = now
            return True


class Notifier:
    """Desktop toast + console alert when trackers or data collectors are detected."""

    @staticmethod
    def tracking(domain: str, category: str, description: str, process_name: str = ""):
        title = "Valkyrie — Tracking Detected"
        proc = f" via {process_name}" if process_name else ""
        message = f"{domain}{proc}\n[{category}] {description}"

        print(f"\n  {Color.YELLOW}{Color.BOLD}⚡ TRACKING ALERT — {category}{Color.RESET}")
        print(f"     {Color.CYAN}{domain}{Color.RESET}{proc}")
        print(f"     {Color.DIM}{description}{Color.RESET}\n")

        if sys.platform == "win32":
            try:
                from winotify import Notification
                toast = Notification(
                    app_id="Valkyrie",
                    title=title,
                    msg=message,
                    duration="long",
                )
                toast.show()
                return
            except (ImportError, OSError):
                pass
            try:
                ps_msg = message.replace("'", "''").replace("\n", " | ")
                subprocess.run(
                    [
                        "powershell", "-Command",
                        f"Add-Type -AssemblyName System.Windows.Forms; "
                        f"[System.Windows.Forms.MessageBox]::Show('{ps_msg}','{title}')",
                    ],
                    capture_output=True,
                    timeout=2,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3: EVENT LOG (SQLite)
# ─────────────────────────────────────────────────────────────────────────────

class EventLog:
    """Local SQLite log for detected and blocked events."""

    def __init__(self, db_path: Path = EVENT_DB_PATH):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    action TEXT NOT NULL,
                    domain TEXT,
                    process_name TEXT,
                    remote_ip TEXT,
                    category TEXT,
                    severity INTEGER,
                    details TEXT
                )
            """)
            conn.commit()

    def log(self, action: str, domain: str = "", process_name: str = "",
            remote_ip: str = "", category: str = "", severity: int = 0,
            details: str = ""):
        ts = datetime.datetime.now().isoformat(timespec="seconds")
        with self._lock:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute(
                    "INSERT INTO events (ts, action, domain, process_name, remote_ip, "
                    "category, severity, details) VALUES (?,?,?,?,?,?,?,?)",
                    (ts, action, domain, process_name, remote_ip, category, severity, details),
                )
                conn.commit()

    def recent_count(self, action: Optional[str] = None) -> int:
        with sqlite3.connect(self._db_path) as conn:
            if action:
                row = conn.execute(
                    "SELECT COUNT(*) FROM events WHERE action = ?", (action,)
                ).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
            return row[0] if row else 0

    def fetch_tracking_alerts(self, hours: int = 24, limit: int = 100) -> list[dict]:
        cutoff = (datetime.datetime.now() - datetime.timedelta(hours=hours)).isoformat()
        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT ts, domain, process_name, category, severity, details "
                "FROM events WHERE action = 'tracking_alert' AND ts >= ? "
                "ORDER BY ts DESC LIMIT ?",
                (cutoff, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def fetch_mitigation_events(self, hours: int = 24, limit: int = 100) -> list[dict]:
        """Return firewall_block events logged by FirewallMitigator."""
        cutoff = (datetime.datetime.now() - datetime.timedelta(hours=hours)).isoformat()
        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT ts, domain, process_name, remote_ip, category, severity, details "
                "FROM events WHERE action = 'firewall_block' AND ts >= ? "
                "ORDER BY ts DESC LIMIT ?",
                (cutoff, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def fetch_dns_log(self, hours: int = 1, limit: int = 500) -> list[dict]:
        """Return all DNS events: dns_query (clean), blocked_dns, tracking_alert."""
        cutoff = (datetime.datetime.now() - datetime.timedelta(hours=hours)).isoformat()
        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT ts, action, domain, category, severity, details "
                "FROM events "
                "WHERE action IN ('dns_query', 'blocked_dns', 'tracking_alert') "
                "AND ts >= ? ORDER BY ts DESC LIMIT ?",
                (cutoff, limit),
            ).fetchall()
        return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4: DNS SINKHOLE
# ─────────────────────────────────────────────────────────────────────────────

class ValkyrieDNSResolver(BaseResolver):
    """dnslib resolver: blocklist hit → 0.0.0.0, else forward upstream."""

    def __init__(self, blocklist: BlocklistDB, upstream: str, event_log: EventLog):
        self._blocklist = blocklist
        self._upstream = upstream
        self._event_log = event_log
        self.blocked_total = 0
        self.allowed_total = 0
        self._query_state = AlertState(cooldown_sec=30)  # dedupe clean queries per 30s

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".")
        hit = self._blocklist.lookup(qname)

        if hit:
            self.blocked_total += 1
            self._event_log.log(
                action="blocked_dns",
                domain=qname,
                category=hit.category.value,
                severity=hit.severity,
                details=hit.description,
            )
            reply = request.reply()
            if request.q.qtype in (QTYPE.A, QTYPE.ANY):
                reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=300))
            return reply

        self.allowed_total += 1
        if qname and "." in qname and self._query_state.should_alert(qname):
            self._event_log.log(
                action="dns_query",
                domain=qname,
                category="ALLOWED",
                severity=0,
                details="Clean DNS query",
            )
        try:
            upstream_reply = request.send(self._upstream, 53, timeout=3)
            return DNSRecord.parse(upstream_reply)
        except (socket.timeout, OSError):
            reply = request.reply()
            reply.header.rcode = 2  # SERVFAIL
            return reply


class DNSSinkhole:
    """Local DNS proxy that blocks surveillance domains."""

    def __init__(self, blocklist: BlocklistDB, event_log: EventLog,
                 host: str = "127.0.0.1", port: int = DEFAULT_DNS_PORT,
                 upstream: str = DEFAULT_DNS_UPSTREAM):
        if not HAS_DNSLIB:
            raise RuntimeError("dnslib not installed. Run: pip install -r requirements.txt")
        self._resolver = ValkyrieDNSResolver(blocklist, upstream, event_log)
        self._server = DNSServer(self._resolver, port=port, address=host, tcp=False)
        self._thread: Optional[threading.Thread] = None
        self.host = host
        self.port = port
        self.upstream = upstream

    def start_background(self):
        self._thread = threading.Thread(target=self._server.start_thread, daemon=True)
        self._thread.start()
        time.sleep(0.3)

    def start_blocking(self):
        self._server.start()

    def stop(self):
        self._server.stop()

    @property
    def stats(self) -> tuple[int, int]:
        return self._resolver.blocked_total, self._resolver.allowed_total


class MonitorDNSResolver(BaseResolver):
    """DNS proxy: allows all queries, notifies on tracker/surveillance domains."""

    def __init__(self, blocklist: BlocklistDB, upstream: str, event_log: EventLog,
                 alert_state: AlertState):
        self._blocklist = blocklist
        self._upstream = upstream
        self._event_log = event_log
        self._alert_state = alert_state
        self.alert_total = 0
        self.query_total = 0
        self._query_state = AlertState(cooldown_sec=30)  # dedupe clean queries per 30s

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".")
        self.query_total += 1

        try:
            upstream_reply = request.send(self._upstream, 53, timeout=3)
            reply = DNSRecord.parse(upstream_reply)
        except (socket.timeout, OSError):
            reply = request.reply()
            reply.header.rcode = 2
            return reply

        hit = self._blocklist.lookup(qname)
        if hit and self._alert_state.should_alert(qname):
            self.alert_total += 1
            self._event_log.log(
                action="tracking_alert",
                domain=qname,
                category=hit.category.value,
                severity=hit.severity,
                details=hit.description,
            )
            Notifier.tracking(qname, hit.category.value, hit.description)
        elif not hit and qname and "." in qname and self._query_state.should_alert(qname):
            self._event_log.log(
                action="dns_query",
                domain=qname,
                category="ALLOWED",
                severity=0,
                details="Clean DNS query",
            )
        return reply


class DNSMonitor:
    """Local DNS proxy that alerts on trackers without blocking."""

    def __init__(self, blocklist: BlocklistDB, event_log: EventLog,
                 alert_state: AlertState, host: str = "127.0.0.1",
                 port: int = DEFAULT_DNS_PORT, upstream: str = DEFAULT_DNS_UPSTREAM):
        if not HAS_DNSLIB:
            raise RuntimeError("dnslib not installed. Run: pip install -r requirements.txt")
        self._resolver = MonitorDNSResolver(blocklist, upstream, event_log, alert_state)
        self._server = DNSServer(self._resolver, port=port, address=host, tcp=False)
        self._thread: Optional[threading.Thread] = None
        self.host = host
        self.port = port

    def start_background(self):
        self._thread = threading.Thread(target=self._server.start_thread, daemon=True)
        self._thread.start()
        time.sleep(0.3)

    def start_blocking(self):
        self._server.start()

    def stop(self):
        self._server.stop()

    @property
    def stats(self) -> tuple[int, int]:
        return self._resolver.alert_total, self._resolver.query_total


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5: LIVE CONNECTION SCANNER
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class LiveConnection:
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    status: str
    pid: Optional[int]
    process_name: str
    resolved_domain: str
    blocklist_hit: Optional[BlocklistEntry] = None
    is_encrypted: bool = False

    def key(self) -> tuple:
        return (self.remote_ip, self.remote_port, self.pid)


@dataclass
class AppReport:
    process_name: str
    connections: list[LiveConnection] = field(default_factory=list)

    def flagged(self) -> list[LiveConnection]:
        return [c for c in self.connections if c.blocklist_hit]

    def unencrypted(self) -> list[LiveConnection]:
        return [c for c in self.connections
                if not c.is_encrypted and not c.blocklist_hit
                and c.remote_port not in (53, 123)]

    def score(self) -> int:
        s = 100
        for c in self.flagged():
            s -= 8 + (c.blocklist_hit.severity if c.blocklist_hit else 0)
        for c in self.unencrypted():
            s -= 5
        return max(0, min(100, s))


class LiveScanner:
    ENCRYPTED_PORTS = {443, 8443, 853, 465, 993, 995, 8883}

    def __init__(self, blocklist: BlocklistDB):
        self._blocklist = blocklist
        self._dns_cache: dict[str, str] = {}

    def _resolve_ip(self, ip: str) -> str:
        if ip in self._dns_cache:
            return self._dns_cache[ip]
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            hostname = ip
        self._dns_cache[ip] = hostname
        return hostname

    def _get_process_name(self, pid: Optional[int]) -> str:
        if pid is None:
            return "unknown"
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return f"pid:{pid}"

    def scan(self) -> list[LiveConnection]:
        connections = []
        try:
            raw = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            print(f"  {Color.YELLOW}[!] Limited connection data — run as admin for full scan{Color.RESET}")
            raw = []

        for conn in raw:
            if not conn.raddr or not conn.raddr.ip:
                continue
            if conn.raddr.ip.startswith("127.") or conn.raddr.ip == "::1":
                continue

            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            resolved = self._resolve_ip(remote_ip)
            hit = self._blocklist.lookup(resolved)

            connections.append(LiveConnection(
                local_ip=conn.laddr.ip if conn.laddr else "?",
                local_port=conn.laddr.port if conn.laddr else 0,
                remote_ip=remote_ip,
                remote_port=remote_port,
                status=conn.status or "?",
                pid=conn.pid,
                process_name=self._get_process_name(conn.pid),
                resolved_domain=resolved,
                blocklist_hit=hit,
                is_encrypted=remote_port in self.ENCRYPTED_PORTS,
            ))
        return connections


def group_by_app(connections: list[LiveConnection]) -> list[AppReport]:
    groups: dict[str, list[LiveConnection]] = defaultdict(list)
    for c in connections:
        groups[c.process_name].append(c)
    reports = [AppReport(name, conns) for name, conns in groups.items()]
    reports.sort(key=lambda r: r.score())
    return reports


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6: WI-FI SIGNAL CHECKER
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class WiFiInfo:
    ssid: str = "Unknown"
    signal_dbm: Optional[int] = None
    signal_quality: str = "Unknown"
    security: str = "Unknown"
    frequency: str = "Unknown"
    interface: str = "Unknown"
    raw_output: str = ""


class WiFiChecker:

    @staticmethod
    def _run(cmd: list[str]) -> str:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
            return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return ""

    def _signal_quality_label(self, dbm: Optional[int]) -> str:
        if dbm is None:
            return "Unknown"
        if dbm >= -50:
            return f"{Color.GREEN}Excellent (-50 dBm+){Color.RESET}"
        if dbm >= -60:
            return f"{Color.GREEN}Good (-50 to -60 dBm){Color.RESET}"
        if dbm >= -70:
            return f"{Color.YELLOW}Fair (-60 to -70 dBm){Color.RESET}"
        if dbm >= -80:
            return f"{Color.YELLOW}Weak (-70 to -80 dBm){Color.RESET}"
        return f"{Color.RED}Very Weak (below -80 dBm){Color.RESET}"

    def _parse_dbm(self, text: str, patterns: list[str]) -> Optional[int]:
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                try:
                    return int(match.group(1))
                except (ValueError, IndexError):
                    continue
        return None

    def check_macos(self) -> WiFiInfo:
        info = WiFiInfo()
        airport_path = (
            "/System/Library/PrivateFrameworks/Apple80211.framework"
            "/Versions/Current/Resources/airport"
        )
        output = self._run([airport_path, "-I"]) or self._run(
            ["system_profiler", "SPAirPortDataType"]
        )
        info.raw_output = output
        if m := re.search(r"\s+SSID:\s+(.+)", output):
            info.ssid = m.group(1).strip()
        if m := re.search(r"agrCtlRSSI:\s+(-\d+)", output):
            info.signal_dbm = int(m.group(1))
        if m := re.search(r"link auth:\s+(.+)", output):
            info.security = m.group(1).strip()
        info.signal_quality = self._signal_quality_label(info.signal_dbm)
        return info

    def check_linux(self) -> WiFiInfo:
        info = WiFiInfo()
        output = self._run(["nmcli", "-t", "-f",
                            "ACTIVE,SSID,SIGNAL,SECURITY,FREQ,DEVICE",
                            "device", "wifi"])
        if output:
            for line in output.splitlines():
                parts = line.split(":")
                if len(parts) >= 6 and parts[0] == "yes":
                    info.ssid = parts[1]
                    info.frequency = parts[4]
                    info.security = parts[3] if parts[3] else "Open (none)"
                    info.interface = parts[5]
                    try:
                        info.signal_dbm = int((int(parts[2]) / 2) - 100)
                    except ValueError:
                        pass
                    info.signal_quality = self._signal_quality_label(info.signal_dbm)
                    info.raw_output = output
                    return info
        output = self._run(["iwconfig"])
        if output:
            info.raw_output = output
            if m := re.search(r'ESSID:"(.+?)"', output):
                info.ssid = m.group(1)
            info.signal_dbm = self._parse_dbm(output, [r"Signal level[=:](-?\d+)\s*dBm"])
            info.signal_quality = self._signal_quality_label(info.signal_dbm)
            if m := re.search(r"Frequency[=:](\S+\s*GHz)", output):
                info.frequency = m.group(1)
        return info

    def check_windows(self) -> WiFiInfo:
        info = WiFiInfo()
        output = self._run(["netsh", "wlan", "show", "interfaces"])
        info.raw_output = output
        if m := re.search(r"SSID\s+:\s+(.+)", output):
            info.ssid = m.group(1).strip()
        if m := re.search(r"Signal\s+:\s+(\d+)%", output):
            info.signal_dbm = int((int(m.group(1)) / 2) - 100)
        if m := re.search(r"Authentication\s+:\s+(.+)", output):
            info.security = m.group(1).strip()
        info.signal_quality = self._signal_quality_label(info.signal_dbm)
        return info

    def get_wifi_info(self) -> WiFiInfo:
        os_name = platform.system()
        if os_name == "Darwin":
            return self.check_macos()
        if os_name == "Linux":
            return self.check_linux()
        if os_name == "Windows":
            return self.check_windows()
        info = WiFiInfo()
        info.ssid = f"Unsupported OS: {os_name}"
        return info

    def security_rating(self, info: WiFiInfo) -> tuple[str, str]:
        sec = info.security.upper()
        if "WPA3" in sec:
            return "WPA3", f"{Color.GREEN}WPA3 — Excellent{Color.RESET}"
        if "WPA2" in sec and "ENTERPRISE" in sec:
            return "WPA2-Enterprise", f"{Color.GREEN}WPA2-Enterprise — Strong{Color.RESET}"
        if "WPA2" in sec:
            return "WPA2", f"{Color.YELLOW}WPA2 — Adequate{Color.RESET}"
        if "WPA" in sec:
            return "WPA", f"{Color.RED}WPA — Weak{Color.RESET}"
        if "WEP" in sec:
            return "WEP", f"{Color.RED}WEP — CRITICAL{Color.RESET}"
        if "OPEN" in sec or sec in ("", "NONE"):
            return "Open", f"{Color.RED}Open — CRITICAL{Color.RESET}"
        return info.security, f"{Color.CYAN}{info.security}{Color.RESET}"


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7: CONSOLE OUTPUT
# ─────────────────────────────────────────────────────────────────────────────

class Console:

    @staticmethod
    def banner():
        print(f"""
{Color.CYAN}{Color.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║        VALKYRIE V1    ║
╚══════════════════════════════════════════════════════════════════╝
{Color.RESET}  {Color.DIM}Time:     {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Color.RESET}
  {Color.DIM}Platform: {platform.system()} {platform.release()}{Color.RESET}
  {Color.DIM}Hostname: {socket.gethostname()}{Color.RESET}
""")

    @staticmethod
    def section(title: str):
        print(f"\n{Color.DIM}{'═' * 68}{Color.RESET}")
        print(f"  {Color.BOLD}{title}{Color.RESET}")
        print(f"{Color.DIM}{'═' * 68}{Color.RESET}\n")

    @staticmethod
    def print_blocklist_info(blocklist: BlocklistDB):
        print(f"  Blocklist domains : {Color.BOLD}{blocklist.size}{Color.RESET}")
        if blocklist.imported_count:
            print(f"  Imported from files: {blocklist.imported_count}")

    @staticmethod
    def print_wifi(info: WiFiInfo, checker: WiFiChecker):
        _, sec_label = checker.security_rating(info)
        dbm_str = f"{info.signal_dbm} dBm" if info.signal_dbm is not None else "N/A"
        print(f"  {'SSID':<18} {Color.BOLD}{info.ssid}{Color.RESET}")
        print(f"  {'Interface':<18} {info.interface or 'N/A'}")
        print(f"  {'Frequency':<18} {info.frequency or 'N/A'}")
        print(f"  {'Signal Strength':<18} {dbm_str}")
        print(f"  {'Signal Quality':<18} {info.signal_quality}")
        print(f"  {'Security':<18} {sec_label}")
        if info.signal_dbm is not None and info.signal_dbm < -75:
            print(f"\n  {Color.YELLOW}⚠  Weak signal — evil-twin risk. Move closer to router.{Color.RESET}")

    @staticmethod
    def print_connection(i: int, conn: LiveConnection):
        hit = conn.blocklist_hit
        enc = conn.is_encrypted
        port = conn.remote_port
        if hit:
            tag = f"{Color.YELLOW}{Color.BOLD}[TRACKER — {hit.category.value}  SEV:{hit.severity}]{Color.RESET}"
        elif not enc and port not in (53, 123):
            tag = f"{Color.RED}{Color.BOLD}[WARN — UNENCRYPTED]{Color.RESET}"
        else:
            tag = f"{Color.GREEN}{Color.BOLD}[OK]{Color.RESET}"

        domain_display = conn.resolved_domain
        if domain_display == conn.remote_ip:
            domain_display = f"{conn.remote_ip} {Color.DIM}(no PTR){Color.RESET}"

        print(f"  {Color.BOLD}#{i:<3}{Color.RESET} {tag}")
        print(f"       Remote  : {Color.CYAN}{domain_display}{Color.RESET}  [{conn.remote_ip}:{port}]")
        print(f"       Process : {Color.MAGENTA}{conn.process_name}{Color.RESET}  (PID {conn.pid or '?'})")
        if hit:
            print(f"       {Color.YELLOW}⚠  {hit.description}{Color.RESET}")
        print()

    @staticmethod
    def print_app_reports(reports: list[AppReport]):
        if not reports:
            return
        Console.section("PER-APP PRIVACY SCORES")
        for r in reports:
            score = r.score()
            color = Color.GREEN if score >= 80 else Color.YELLOW if score >= 50 else Color.RED
            flagged = len(r.flagged())
            print(f"  {Color.BOLD}{r.process_name:<24}{Color.RESET} "
                  f"score {color}{score}/100{Color.RESET}  "
                  f"({len(r.connections)} conn, {flagged} tracker hits)")
        print()

    @staticmethod
    def print_summary(connections: list[LiveConnection], wifi: WiFiInfo,
                      checker: WiFiChecker, event_log: Optional[EventLog] = None):
        total = len(connections)
        blocked = [c for c in connections if c.blocklist_hit]
        unenc = [c for c in connections if not c.is_encrypted
                 and not c.blocklist_hit and c.remote_port not in (53, 123)]
        clean = total - len(blocked) - len(unenc)
        _, sec = checker.security_rating(wifi)

        print(f"\n{Color.CYAN}{Color.BOLD}")
        print("  ╔══════════════════════════════════════════════════╗")
        print("  ║                 VALKYRIE SUMMARY                 ║")
        print("  ╚══════════════════════════════════════════════════╝")
        print(f"{Color.RESET}")
        print(f"    Active external connections : {total}")
        print(f"    {Color.GREEN}Encrypted & clean          : {clean}{Color.RESET}")
        print(f"    {Color.YELLOW}Surveillance domains found : {len(blocked)}{Color.RESET}")
        print(f"    {Color.RED}Unencrypted connections    : {len(unenc)}{Color.RESET}")
        print(f"    Wi-Fi security             : {sec}")
        if event_log:
            print(f"    Events logged              : {event_log.recent_count()}")

        if blocked:
            print(f"\n    {Color.YELLOW}{Color.BOLD}Tracker connections:{Color.RESET}")
            for c in blocked:
                print(f"      ⚠  {c.resolved_domain}  [{c.blocklist_hit.category.value}]"
                      f"  via {c.process_name}")
        if unenc:
            print(f"\n    {Color.RED}{Color.BOLD}Unencrypted:{Color.RESET}")
            for c in unenc:
                print(f"      ✗  {c.resolved_domain}:{c.remote_port}  via {c.process_name}")
        if not blocked and not unenc:
            print(f"\n    {Color.GREEN}✓  No trackers or unencrypted connections detected.{Color.RESET}")
        print()

    @staticmethod
    def print_dns_setup(host: str, port: int):
        print(f"\n  {Color.CYAN}{Color.BOLD}DNS sinkhole active on {host}:{port}{Color.RESET}")
        print(f"  {Color.DIM}Point your system DNS to {host} (port {port} if configuring manually).{Color.RESET}")
        if platform.system() == "Windows":
            print(f"""
  {Color.DIM}Windows setup (Settings → Network → your adapter → DNS):
    Preferred DNS: 127.0.0.1
  Or PowerShell (admin):
    Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses "127.0.0.1"
  {Color.YELLOW}Note: Windows DNS client uses port 53 by default.
  Run with --dns-port 53 as Administrator, or use a port-forward tool.{Color.RESET}
""")
        print(f"  {Color.DIM}Upstream resolver: queries not on blocklist go to {DEFAULT_DNS_UPSTREAM}{Color.RESET}\n")

    @staticmethod
    def alert_new_tracker(conn: LiveConnection):
        hit = conn.blocklist_hit
        if not hit:
            return
        print(f"\n  {Color.YELLOW}{Color.BOLD}⚡ NEW TRACKER CONNECTION{Color.RESET}")
        print(f"     {Color.CYAN}{conn.resolved_domain}{Color.RESET} via "
              f"{Color.MAGENTA}{conn.process_name}{Color.RESET}")
        print(f"     {Color.DIM}{hit.description} [{hit.category.value}]{Color.RESET}\n")

    @staticmethod
    def print_monitor_setup(host: str, port: int, tracker_count: int):
        print(f"\n  {Color.YELLOW}{Color.BOLD}TRACKING MONITOR active on {host}:{port}{Color.RESET}")
        print(f"  {Color.DIM}Watching {tracker_count} surveillance/tracker domains.")
        print(f"  Alerts only — nothing blocked. Sites still load.{Color.RESET}")
        print(f"  {Color.DIM}Set system DNS to 127.0.0.1 for best detection.{Color.RESET}")
        if platform.system() == "Windows":
            print(f"""
  {Color.DIM}Windows: Settings → Network → Wi-Fi → DNS → Manual → 127.0.0.1
  Or (admin): Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses "127.0.0.1"
  For system DNS: python valkyrie.py monitor --dns-port 53  (Administrator){Color.RESET}
""")
        print(f"  {Color.DIM}Leave this window open for 24/7 monitoring. Ctrl+C to stop.{Color.RESET}\n")

    @staticmethod
    def print_tracking_alerts(alerts: list[dict]):
        if not alerts:
            print(f"  {Color.GREEN}No tracking alerts in this period.{Color.RESET}\n")
            return
        print(f"  {Color.BOLD}{'Time':<20} {'Category':<16} {'Domain':<32} Process{Color.RESET}")
        print(f"  {Color.DIM}{'-' * 90}{Color.RESET}")
        for d in alerts:
            cat = d.get("category") or "?"
            domain = d.get("domain") or "?"
            proc = d.get("process_name") or "—"
            ts = (d.get("ts") or "")[:19]
            print(f"  {ts:<20} {Color.YELLOW}{cat:<16}{Color.RESET} {domain:<32} {proc}")
        print()


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 8: COMMANDS
# ─────────────────────────────────────────────────────────────────────────────

def init_blocklist() -> BlocklistDB:
    bl = BlocklistDB()
    bl.load_from_directory(BLOCKLIST_DIR)
    return bl


DEFAULT_BLOCKLIST_URLS = [
    ("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "stevenblack-hosts.txt"),
    ("https://raw.githubusercontent.com/oisd/domain-list/main/hosts", "oisd-hosts.txt"),
]


def run_update(blocklist_dir: Path = BLOCKLIST_DIR):
    console = Console()
    console.banner()
    console.section("BLOCKLIST AUTO-UPDATE")
    print(f"  Downloading remote blocklists into {blocklist_dir}\n")

    blocklist_dir.mkdir(parents=True, exist_ok=True)
    updated = 0
    failed = []

    for url, filename in DEFAULT_BLOCKLIST_URLS:
        dest = blocklist_dir / filename
        print(f"  {Color.CYAN}Downloading{Color.RESET} {url}")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "valkyrie-blocklist-updater/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
            dest.write_bytes(data)
            print(f"  {Color.GREEN}✓ Saved{Color.RESET} {len(data):,} bytes → {dest.name}\n")
            updated += 1
        except Exception as exc:
            print(f"  {Color.RED}✗ Failed{Color.RESET} {url}\n     {Color.DIM}{exc}{Color.RESET}\n")
            failed.append((url, str(exc)))

    if updated:
        print(f"  {Color.GREEN}Updated {updated} blocklist(s).{Color.RESET}")
        print(f"  {Color.DIM}Reload with: python valkyrie.py scan{Color.RESET}\n")
    if failed:
        print(f"  {Color.YELLOW}Failed: {len(failed)}{Color.RESET}")
        for url, err in failed:
            print(f"    {Color.DIM}{url} — {err}{Color.RESET}")
        print()


def _alert_tracking(domain: str, hit: BlocklistEntry, event_log: EventLog,
                    alert_state: AlertState, process_name: str = ""):
    if not alert_state.should_alert(domain):
        return
    event_log.log(
        action="tracking_alert",
        domain=domain,
        process_name=process_name,
        category=hit.category.value,
        severity=hit.severity,
        details=hit.description,
    )
    Notifier.tracking(domain, hit.category.value, hit.description, process_name)


def log_connection_hits(connections: list[LiveConnection], event_log: EventLog,
                        action: str = "detected"):
    for c in connections:
        if c.blocklist_hit:
            hit = c.blocklist_hit
            event_log.log(
                action=action,
                domain=c.resolved_domain,
                process_name=c.process_name,
                remote_ip=c.remote_ip,
                category=hit.category.value,
                severity=hit.severity,
                details=hit.description,
            )


def run_scan(blocklist: BlocklistDB, event_log: EventLog, api_bind: str = "127.0.0.1"):
    console = Console()
    console.banner()
    console.print_blocklist_info(blocklist)

    scanner  = LiveScanner(blocklist)
    wifi_chk = WiFiChecker()

    api = AlertAPIServer(event_log, host=api_bind)
    if api_bind != "127.0.0.1":
        print(f"  {Color.YELLOW}[API] Dashboard accessible on http://{api_bind}:8080 (no auth){Color.RESET}")
    api.start()

    # ── Feature 3: Discover LAN devices via ARP + DHCP leases ───────────────
    lan = LANMapper()
    lan.refresh()
    lan_devices = lan.all_devices()
    if lan_devices:
        console.section("LAN DEVICE MAP  (ARP + DHCP)")
        print(f"  Found {Color.BOLD}{len(lan_devices)}{Color.RESET} devices on the local network:\n")
        for dev in sorted(lan_devices, key=lambda d: d.ip):
            vendor = f"  [{dev.vendor}]" if dev.vendor != "unknown" else ""
            hn     = dev.hostname if dev.hostname != "unknown" else ""
            print(f"    {Color.CYAN}{dev.ip:<18}{Color.RESET}"
                  f"{Color.MAGENTA}{dev.mac}{Color.RESET}"
                  f"  {hn}{Color.DIM}{vendor}{Color.RESET}")
        print()

    console.section("WI-FI SIGNAL & SECURITY CHECK")
    wifi_info = wifi_chk.get_wifi_info()
    console.print_wifi(wifi_info, wifi_chk)

    console.section("LIVE CONNECTION SCAN")
    connections = scanner.scan()
    log_connection_hits(connections, event_log)

    if not connections:
        print(f"  {Color.DIM}No external connections. Open a browser and try again.{Color.RESET}\n")
    else:
        print(f"  Found {Color.BOLD}{len(connections)}{Color.RESET} connections:\n")
        for i, conn in enumerate(connections, 1):
            console.print_connection(i, conn)

    console.print_app_reports(group_by_app(connections))
    console.print_summary(connections, wifi_info, wifi_chk, event_log)


def run_watch(blocklist: BlocklistDB, event_log: EventLog,
              with_dns: bool = False, dns_port: int = DEFAULT_DNS_PORT,
              api_bind: str = "127.0.0.1"):
    console = Console()
    console.banner()
    console.print_blocklist_info(blocklist)

    scanner  = LiveScanner(blocklist)
    wifi_chk = WiFiChecker()
    wifi_info = wifi_chk.get_wifi_info()

    console.section("WI-FI CHECK")
    console.print_wifi(wifi_info, wifi_chk)

    sinkhole: Optional[DNSSinkhole] = None
    if with_dns:
        if not HAS_DNSLIB:
            print(f"  {Color.RED}[!] dnslib required for DNS mode. pip install -r requirements.txt{Color.RESET}")
            sys.exit(1)
        sinkhole = DNSSinkhole(blocklist, event_log, port=dns_port)
        sinkhole.start_background()
        console.print_dns_setup("127.0.0.1", dns_port)

    # ── Active Mitigation: inject firewall rules for detected tracker IPs ────
    mitigator = FirewallMitigator(event_log)
    if sys.platform == "win32":
        print(
            f"  {Color.RED}{Color.BOLD}[FIREWALL] Active mitigation ENABLED{Color.RESET}  "
            f"{Color.DIM}(Windows Advanced Firewall — requires Administrator){Color.RESET}\n"
        )
    else:
        print(
            f"  {Color.DIM}[FIREWALL] Active mitigation is Windows-only. "
            f"Running in alert-only mode on this OS.{Color.RESET}\n"
        )

    # Set of connection keys that have already had a firewall rule requested
    # this session — prevents spawning duplicate mitigation threads for the
    # same (ip, port, pid) tuple on every poll tick.
    mitigated: set[tuple] = set()

    api = AlertAPIServer(event_log, host=api_bind)
    if api_bind != "127.0.0.1":
        print(f"  {Color.YELLOW}[API] Dashboard accessible on http://{api_bind}:8080 (no auth){Color.RESET}")
    api.start()

    console.section("REAL-TIME WATCH")
    print(f"  {Color.DIM}Polling every {WATCH_INTERVAL}s — Ctrl+C to stop{Color.RESET}\n")

    seen: set[tuple] = set()
    tick = 0
    running = True

    def _stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _stop)

    try:
        while running:
            connections = scanner.scan()

            for conn in connections:
                key = conn.key()  # (remote_ip, remote_port, pid)

                # ── First-seen: log to SQLite + console ─────────────────────
                if key not in seen:
                    seen.add(key)
                    if conn.blocklist_hit:
                        event_log.log(
                            action="detected",
                            domain=conn.resolved_domain,
                            process_name=conn.process_name,
                            remote_ip=conn.remote_ip,
                            category=conn.blocklist_hit.category.value,
                            severity=conn.blocklist_hit.severity,
                            details=conn.blocklist_hit.description,
                        )
                        console.alert_new_tracker(conn)

                # ── Active mitigation: fire a background thread for every
                #    ESTABLISHED blocklist-hit not yet mitigated this session.
                #    Threading is mandatory so the subprocess call does not
                #    stall the scan loop waiting for netsh to return.
                if (
                    conn.blocklist_hit
                    and conn.status == "ESTABLISHED"
                    and key not in mitigated
                ):
                    mitigated.add(key)
                    t = threading.Thread(
                        target=mitigator.mitigate_threat,
                        args=(conn.process_name, conn.remote_ip, conn.remote_port),
                        daemon=True,
                        name=f"valkyrie-fw-{conn.remote_ip}",
                    )
                    t.start()

            tick += 1
            if tick % 12 == 0:
                blocked = sum(1 for c in connections if c.blocklist_hit)
                fw_count = len(mitigated)
                dns_stats = ""
                if sinkhole:
                    b, a = sinkhole.stats
                    dns_stats = f"  |  DNS blocked: {b}  allowed: {a}"
                print(
                    f"  {Color.DIM}[{datetime.datetime.now().strftime('%H:%M:%S')}] "
                    f"{len(connections)} connections  "
                    f"{Color.YELLOW}{blocked} trackers{Color.RESET}"
                    f"{dns_stats}"
                    f"  |  {Color.RED}FW rules: {fw_count}{Color.RESET}"
                    f"{Color.RESET}"
                )

            time.sleep(WATCH_INTERVAL)

    except KeyboardInterrupt:
        # Ctrl+C lands here when signal handler has not yet set running=False
        running = False

    finally:
        # ── Graceful cleanup: remove all dynamic firewall rules ──────────────
        print(f"\n  {Color.CYAN}[WATCH] Shutting down — cleaning up firewall rules...{Color.RESET}")
        mitigator.cleanup_all_rules()

        if sinkhole:
            sinkhole.stop()

        api.stop()
        print(f"  {Color.DIM}Watch stopped. Events saved to {EVENT_DB_PATH}{Color.RESET}\n")


def run_dns(blocklist: BlocklistDB, event_log: EventLog, port: int = DEFAULT_DNS_PORT,
             api_bind: str = "127.0.0.1"):
    if not HAS_DNSLIB:
        print(f"\n  {Color.RED}[!] dnslib not installed. Run: pip install -r requirements.txt\n")
        sys.exit(1)

    console = Console()
    console.banner()
    console.print_blocklist_info(blocklist)

    # ── Feature 1: Auto-switch OS DNS to 127.0.0.1 ──────────────────────────
    dns_switcher = DNSSwitcher()
    dns_switcher.activate()

    # ── Feature 2: Start REST API so dashboards can read blocked DNS events ──
    api = AlertAPIServer(event_log, host=api_bind)
    if api_bind != "127.0.0.1":
        print(f"  {Color.YELLOW}[API] Dashboard accessible on http://{api_bind}:8080 (no auth){Color.RESET}")
    api.start()

    # ── Feature 3: Start background LAN mapper ───────────────────────────────
    lan = LANMapper()
    lan.start_background_refresh()

    console.section("DNS SINKHOLE")
    sinkhole = DNSSinkhole(blocklist, event_log, port=port)
    console.print_dns_setup("127.0.0.1", port)
    print(f"  {Color.DIM}Blocking tracker DNS queries. Ctrl+C to stop.{Color.RESET}\n")

    def _stop(*_):
        sinkhole.stop()
        dns_switcher.restore()       # Feature 1: restore DNS before exit
        api.stop()                   # Feature 2: shut down API server
        print(f"\n  {Color.DIM}DNS sinkhole stopped. Events saved to {EVENT_DB_PATH}{Color.RESET}\n")
        sys.exit(0)

    signal.signal(signal.SIGINT, _stop)
    sinkhole.start_blocking()


def run_monitor(blocklist: BlocklistDB, event_log: EventLog,
                dns_port: int = DEFAULT_DNS_PORT, api_bind: str = "127.0.0.1"):
    if not HAS_DNSLIB:
        print(f"\n  {Color.RED}[!] dnslib not installed. Run: pip install -r requirements.txt\n")
        sys.exit(1)

    console = Console()
    console.banner()
    console.print_blocklist_info(blocklist)
    print(f"  {Color.DIM}Mode: notify on trackers/data collection — does NOT block{Color.RESET}")

    # ── Feature 1: Auto-switch OS DNS to 127.0.0.1 ──────────────────────────
    dns_switcher = DNSSwitcher()
    dns_switcher.activate()

    # ── Feature 2: REST API so a dashboard can poll /alerts in real time ─────
    api = AlertAPIServer(event_log, host=api_bind)
    if api_bind != "127.0.0.1":
        print(f"  {Color.YELLOW}[API] Dashboard accessible on http://{api_bind}:8080 (no auth){Color.RESET}")
    api.start()

    # ── Feature 3: LAN mapper — identify which device triggered each alert ───
    lan = LANMapper()
    lan.start_background_refresh()

    alert_state = AlertState()
    scanner = LiveScanner(blocklist)

    dns_monitor = DNSMonitor(blocklist, event_log, alert_state, port=dns_port)
    dns_monitor.start_background()
    console.print_monitor_setup("127.0.0.1", dns_port, blocklist.size)

    console.section("24/7 TRACKING MONITOR")
    print(f"  {Color.DIM}DNS + connection check every {WATCH_INTERVAL}s{Color.RESET}\n")

    seen_conn: set[tuple] = set()
    tick = 0
    running = True

    def _stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _stop)

    try:
        while running:
            connections = scanner.scan()
            for conn in connections:
                if not conn.blocklist_hit:
                    continue
                key = conn.key()
                if key in seen_conn:
                    continue
                seen_conn.add(key)
                _alert_tracking(
                    conn.resolved_domain, conn.blocklist_hit, event_log, alert_state,
                    conn.process_name,
                )

            tick += 1
            if tick % 12 == 0:
                alerts, queries = dns_monitor.stats
                logged = event_log.recent_count("tracking_alert")
                print(f"  {Color.DIM}[{datetime.datetime.now().strftime('%H:%M:%S')}] "
                      f"DNS queries: {queries}  "
                      f"{Color.YELLOW}tracking alerts: {alerts}{Color.RESET}  "
                      f"logged: {logged}{Color.RESET}")

            time.sleep(WATCH_INTERVAL)
    finally:
        dns_monitor.stop()
        dns_switcher.restore()   # Feature 1: put OS DNS back to original
        api.stop()               # Feature 2: shut down API server cleanly
        print(f"\n  {Color.DIM}Monitor stopped. Log: {EVENT_DB_PATH}  "
              f"View with: python valkyrie.py alerts{Color.RESET}\n")


def run_alerts(event_log: EventLog, hours: int = 24):
    console = Console()
    console.banner()
    console.section(f"TRACKING ALERT LOG  (last {hours}h)")
    alerts = event_log.fetch_tracking_alerts(hours=hours)
    print(f"  {Color.BOLD}{len(alerts)}{Color.RESET} alert(s)\n")
    console.print_tracking_alerts(alerts)
    print(f"  {Color.DIM}Full log: {EVENT_DB_PATH}{Color.RESET}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Valkyrie — local privacy scanner and DNS sinkhole",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python valkyrie.py scan
  python valkyrie.py watch
  python valkyrie.py dns
  python valkyrie.py monitor
  python valkyrie.py alerts
  python valkyrie.py monitor --dns-port 53
  python valkyrie.py alerts --hours 168
        """,
    )
    sub = parser.add_subparsers(dest="command", required=False)

    sub.add_parser("scan", help="One-shot connection + Wi-Fi scan")

    watch_p = sub.add_parser("watch", help="Continuous connection monitor")
    watch_p.add_argument("--dns", action="store_true",
                         help="Also run DNS sinkhole in background")
    watch_p.add_argument("--dns-port", type=int, default=DEFAULT_DNS_PORT,
                         help=f"DNS listen port (default {DEFAULT_DNS_PORT})")
    watch_p.add_argument("--api-bind", default="127.0.0.1",
                         help="Bind REST API to address (default 127.0.0.1, use 0.0.0.0 for LAN)")

    dns_p = sub.add_parser("dns", help="Run DNS sinkhole only")
    dns_p.add_argument("--dns-port", type=int, default=DEFAULT_DNS_PORT,
                        help=f"DNS listen port (default {DEFAULT_DNS_PORT})")
    dns_p.add_argument("--api-bind", default="127.0.0.1",
                        help="Bind REST API to address (default 127.0.0.1, use 0.0.0.0 for LAN)")

    mon_p = sub.add_parser("monitor",
                           help="24/7 tracking/data-collection alerts (no blocking)")
    mon_p.add_argument("--dns-port", type=int, default=DEFAULT_DNS_PORT,
                        help=f"DNS listen port (default {DEFAULT_DNS_PORT})")
    mon_p.add_argument("--api-bind", default="127.0.0.1",
                        help="Bind REST API to address (default 127.0.0.1, use 0.0.0.0 for LAN)")

    alert_p = sub.add_parser("alerts", help="Show tracking alert history")
    alert_p.add_argument("--hours", type=int, default=24,
                         help="How many hours back to show (default 24)")

    update_p = sub.add_parser("update", help="Download remote blocklists into blocklists/")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    command = args.command or "scan"

    blocklist = init_blocklist()
    event_log = EventLog()
    api_bind = getattr(args, "api_bind", "127.0.0.1")

    if command == "scan":
        run_scan(blocklist, event_log, api_bind=api_bind)
    elif command == "watch":
        run_watch(blocklist, event_log,
                  with_dns=getattr(args, "dns", False),
                  dns_port=getattr(args, "dns_port", DEFAULT_DNS_PORT),
                  api_bind=api_bind)
    elif command == "dns":
        run_dns(blocklist, event_log, port=getattr(args, "dns_port", DEFAULT_DNS_PORT),
                api_bind=api_bind)
    elif command == "monitor":
        run_monitor(blocklist, event_log,
                    dns_port=getattr(args, "dns_port", DEFAULT_DNS_PORT),
                    api_bind=api_bind)
    elif command == "alerts":
        run_alerts(event_log, hours=getattr(args, "hours", 24))
    elif command == "update":
        run_update()


if __name__ == "__main__":
    main()