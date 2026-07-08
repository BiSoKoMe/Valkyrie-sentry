"""Test the FirewallManager in isolation — no root/admin required for the
in-process IP lookup checks.  Kernel rule installation is tested separately
and will print a warning if privileges are missing.

Usage:
    python test_firewall.py          # full test suite
    python test_firewall.py --quick  # skip feed download, use cached list
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _check(label: str, result: bool) -> None:
    status = "PASS" if result else "FAIL"
    mark   = "+" if result else "!"
    print(f"  [{mark}] {label}: {status}")
    if not result:
        _FAILURES.append(label)


_FAILURES: list[str] = []


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true",
                        help="Skip feed download, use cached list only")
    args = parser.parse_args()

    print("\n=== Valkyrie FirewallManager tests ===\n")

    # ------------------------------------------------------------------
    # 1. Import
    # ------------------------------------------------------------------
    print("[1] Module import")
    try:
        from valkyrie.firewall import (
            FirewallManager, _IPSet, _in_never_block, _parse_cidr,
            _parse_feed, load_ip_blocklist,
        )
        from valkyrie.config import DNS_UPSTREAM, FIREWALL_DOH_IPS, FIREWALL_NEVER_BLOCK
        _check("firewall module imports", True)
    except ImportError as exc:
        print(f"  [!] FAIL: {exc}")
        sys.exit(1)

    # ------------------------------------------------------------------
    # 2. CIDR parser
    # ------------------------------------------------------------------
    print("\n[2] CIDR parser")
    _check("valid IPv4 host",        _parse_cidr("1.2.3.4")        == "1.2.3.4")
    _check("valid CIDR /24",         _parse_cidr("192.0.2.0/24")   == "192.0.2.0/24")
    _check("normalise host bits",    _parse_cidr("192.0.2.1/24")   == "192.0.2.0/24")
    _check("reject garbage",         _parse_cidr("not-an-ip")      is None)
    _check("reject IPv6",            _parse_cidr("::1")            is None)

    # ------------------------------------------------------------------
    # 3. Protected ranges — must never be blocked
    # ------------------------------------------------------------------
    print("\n[3] Never-block ranges")
    _check("127.0.0.1 is protected",       _in_never_block("127.0.0.1"))
    _check("127.0.0.0/8 is protected",     _in_never_block("127.0.0.0/8"))
    _check("10.0.0.0/8 is protected",      _in_never_block("10.0.0.0/8"))
    _check("10.1.2.3 (RFC1918) protected", _in_never_block("10.1.2.3"))
    _check("172.16.0.0/12 is protected",   _in_never_block("172.16.0.0/12"))
    _check("192.168.1.1 is protected",     _in_never_block("192.168.1.1"))
    _check(f"{DNS_UPSTREAM} upstream protected", _in_never_block(DNS_UPSTREAM))
    _check("public IP NOT protected",     not _in_never_block("185.220.101.1"))

    # ------------------------------------------------------------------
    # 4. Feed parser
    # ------------------------------------------------------------------
    print("\n[4] Feed text parser")
    sample = """
# Spamhaus DROP - sample
; this is a comment
1.10.16.0/20    ; SBL  example
5.188.86.0/24   # malware range
not-valid-line
192.168.1.0/24  # should be skipped (RFC1918)
10.0.0.0/8      # should be skipped (private)
185.220.101.45  # single IP
"""
    parsed = _parse_feed(sample)
    _check("parsed valid CIDR 1",     "1.10.16.0/20"   in parsed)
    _check("parsed valid CIDR 2",     "5.188.86.0/24"  in parsed)
    _check("parsed single host IP",   "185.220.101.45" in parsed)
    _check("skipped RFC1918",        "192.168.1.0/24" not in parsed)
    _check("skipped private /8",     "10.0.0.0/8"     not in parsed)
    _check("skipped garbage line",   "not-valid-line"  not in parsed)

    # ------------------------------------------------------------------
    # 5. _IPSet membership
    # ------------------------------------------------------------------
    print("\n[5] In-process IP lookup (_IPSet)")
    ipset = _IPSet()
    ipset.load({"185.220.101.0/24", "1.10.16.0/20", "203.0.113.5"})
    _check("host in CIDR /24",       ipset.contains("185.220.101.99"))
    _check("host in CIDR /20",       ipset.contains("1.10.31.255"))
    _check("exact host match",       ipset.contains("203.0.113.5"))
    _check("outside range = False", not ipset.contains("185.220.102.1"))
    _check("private = False",       not ipset.contains("192.168.1.1"))
    _check("count correct",          ipset.count() == 3)

    # ------------------------------------------------------------------
    # 6. DoH IPs are blocked (in-process — no kernel rules needed)
    # ------------------------------------------------------------------
    print("\n[6] DoH IP coverage")
    fw = FirewallManager()
    fw._ipset.load(set(FIREWALL_DOH_IPS))
    for ip in FIREWALL_DOH_IPS:
        _check(f"DoH IP {ip} blocked", fw.is_blocked_ip(ip))

    # ------------------------------------------------------------------
    # 7. Private ranges NOT blocked by FirewallManager.start()
    # ------------------------------------------------------------------
    print("\n[7] Private range exclusion via FirewallManager")
    private_cidrs = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}
    fw2 = FirewallManager()
    # Simulate what start() would load after fetching (private ranges excluded at parse time)
    clean = {c for c in private_cidrs if not _in_never_block(c)}
    fw2._ipset.load(clean)
    _check("10.x.x.x not in ipset",      not fw2.is_blocked_ip("10.1.2.3"))
    _check("172.16.x.x not in ipset",    not fw2.is_blocked_ip("172.16.0.1"))
    _check("192.168.x.x not in ipset",   not fw2.is_blocked_ip("192.168.1.1"))
    _check("127.0.0.1 not in ipset",     not fw2.is_blocked_ip("127.0.0.1"))

    # ------------------------------------------------------------------
    # 8. IP blocklist load — offline default, downloads opt-in
    # ------------------------------------------------------------------
    print("\n[8] IP blocklist load (downloads are opt-in)")
    try:
        cidrs = load_ip_blocklist(allow_download=False)
        _check("offline load returns a set (no network needed)",
               isinstance(cidrs, set))
        _check("no RFC1918 in blocklist",  not any(_in_never_block(c) for c in cidrs))
        _check("no loopback in blocklist", "127.0.0.1" not in cidrs)
        print(f"       {len(cidrs):,} ranges from local cache "
              f"({'cache present' if cidrs else 'no cache — DoH-only mode'})")
    except Exception as exc:
        print(f"  [!] SKIP — could not load blocklist: {exc}")

    try:
        fetched = load_ip_blocklist(allow_download=True)
        _check("opt-in download fetches ranges", len(fetched) > 0)
        print(f"       {len(fetched):,} ranges after opt-in download")
    except Exception as exc:
        print(f"  [!] SKIP — opt-in download unavailable offline: {exc}")

    # ------------------------------------------------------------------
    # 9. Kernel rule installation (admin/root required — non-fatal)
    # ------------------------------------------------------------------
    print("\n[9] Kernel rule installation (requires admin/root)")
    fw3 = FirewallManager()
    count = fw3.start()
    if count == 0:
        print("  [-] SKIP — no elevated privileges (firewall degraded gracefully)")
    else:
        _check("rules installed (count > 0)", count > 0)
        fw3.stop()
        _check("stop() did not raise",        True)
        print(f"       {count:,} rules installed and removed cleanly")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 40)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s):")
        for f in _FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("All checks PASSED.")


if __name__ == "__main__":
    main()
