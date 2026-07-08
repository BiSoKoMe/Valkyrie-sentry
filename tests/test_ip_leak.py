"""IP-leak test — prove Valkyrie's firewall drops connections that skip
DNS entirely and dial a known-bad IP directly.

Two enforcement layers are exercised:

  1. Kernel drop (Linux iptables VALKYRIE chain / Windows netsh):
     a real outbound socket to a target IP is DROPped before it completes.
     We use a *reachable* control IP as a documented stand-in for a
     Firehol/Spamhaus-listed tracker IP — the enforcement path is
     identical regardless of which CIDR is loaded, and using a reachable
     IP is the only way to prove the DROP *caused* the failure (an
     unroutable TEST-NET address would fail with or without the rule).

  2. In-process _IPSet: membership for a documented RFC5737 TEST-NET-3
     range (203.0.113.0/24 — reserved for documentation, never routable)
     standing in for a threat-feed CIDR, plus the hardcoded DoH resolver
     IPs Valkyrie blocks by default (the real-world "app hardcodes a DoH
     server IP to bypass our DNS" case).

Run as root on Linux for the kernel-drop portion:
    sudo python3 test_ip_leak.py
"""

from __future__ import annotations

import platform
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.firewall import FirewallManager, _IPSet, _LinuxFirewall
from valkyrie.config import FIREWALL_DOH_IPS

_PASS = 0
_FAIL = 0
_SKIP = 0

# RFC5737 documentation range — safe, reserved, never routable.
TEST_FEED_CIDR = "203.0.113.0/24"
TEST_FEED_IP   = "203.0.113.66"     # "known-bad" tracker IP (documentation range)
SAFE_IP        = "198.51.100.7"     # different RFC5737 range — must NOT be blocked


def check(label: str, cond: bool, detail: str = "") -> None:
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  PASS  {label}")
    else:
        _FAIL += 1
        print(f"  FAIL  {label}  {detail}")


def skip(label: str, why: str) -> None:
    global _SKIP
    _SKIP += 1
    print(f"  SKIP  {label}  ({why})")


# ---------------------------------------------------------------------------
# 1. In-process IP set — the layer that flags/logs every blocked-range hit
# ---------------------------------------------------------------------------

def test_ipset() -> None:
    print("\n[1] In-process IP blocking (_IPSet)")
    ipset = _IPSet()
    ipset.load({TEST_FEED_CIDR} | set(FIREWALL_DOH_IPS))

    check("known-bad feed IP is blocked (by CIDR, no DNS involved)",
          ipset.contains(TEST_FEED_IP))
    check("unrelated IP is NOT blocked",
          not ipset.contains(SAFE_IP))
    check("hardcoded DoH resolver IP 1.1.1.1 is blocked",
          ipset.contains("1.1.1.1"))
    check("hardcoded DoH resolver IP 8.8.8.8 is blocked",
          ipset.contains("8.8.8.8"))
    check("loopback is never blocked",
          not ipset.contains("127.0.0.1"))


# ---------------------------------------------------------------------------
# 2. Kernel drop — a real connection to a bad IP is dropped before it lands
# ---------------------------------------------------------------------------

def _tcp_reachable(ip: str, port: int, timeout: float = 3.0) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def test_kernel_drop() -> None:
    print("\n[2] Kernel-level DROP of a direct-to-IP connection")
    if platform.system() != "Linux":
        skip("kernel drop", "Linux-only test")
        return
    import os
    if os.geteuid() != 0:
        skip("kernel drop", "needs root for iptables")
        return

    # Find a genuinely reachable control target so the DROP is provable.
    candidates = [("1.1.1.1", 443), ("8.8.8.8", 443), ("9.9.9.9", 443)]
    target = None
    for ip, port in candidates:
        if _tcp_reachable(ip, port, timeout=3.0):
            target = (ip, port)
            break
    if target is None:
        skip("kernel drop", "no reachable control target in this environment")
        return
    ip, port = target
    print(f"       control target (reachable stand-in for a listed tracker IP): {ip}:{port}")

    fw = _LinuxFirewall()
    if not fw.setup_chain():
        skip("kernel drop", "could not create VALKYRIE iptables chain")
        return
    try:
        # Baseline: reachable BEFORE the rule
        check("baseline: target reachable before firewall rule",
              _tcp_reachable(ip, port))

        # Install the Valkyrie DROP rule for that IP (as if it were on the feed)
        added = fw.add_cidr_rules_batch({f"{ip}/32"})
        check("firewall installed a DROP rule", added >= 1)
        time.sleep(0.3)

        # Now the SAME direct-to-IP connection must be dropped
        dropped = not _tcp_reachable(ip, port, timeout=4.0)
        check("direct-to-IP connection is DROPPED after rule (no DNS involved)",
              dropped, "connection still completed — firewall did not drop it")
    finally:
        fw.teardown()

    # Restored after teardown
    check("target reachable again after teardown (rule cleanly removed)",
          _tcp_reachable(ip, port))


# ---------------------------------------------------------------------------
# 3. Full FirewallManager wiring — DoH IPs enforced on start()
# ---------------------------------------------------------------------------

def test_manager() -> None:
    print("\n[3] FirewallManager — DoH resolver IPs blocked (offline, no feeds)")
    fw = FirewallManager()
    # allow_download=False → no network; DoH IPs are hardcoded and always loaded
    count = fw.start(allow_download=False)
    try:
        check("DoH resolver 1.1.1.1 blocked (bypass-via-hardcoded-IP caught)",
              fw.is_blocked_ip("1.1.1.1"))
        check("DoH resolver 9.9.9.9 blocked",
              fw.is_blocked_ip("9.9.9.9"))
        check("ordinary site IP not blocked",
              not fw.is_blocked_ip(SAFE_IP))
        print(f"       {count:,} range(s) enforced (seed/DoH, no external feeds)")
    finally:
        fw.stop()


def main() -> int:
    print("Valkyrie IP-leak / firewall test")
    print(f"(platform: {platform.system()})")
    test_ipset()
    test_kernel_drop()
    test_manager()
    print(f"\n{'='*52}")
    print(f"  {_PASS} passed, {_FAIL} failed, {_SKIP} skipped")
    print(f"{'='*52}")
    return 1 if _FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
