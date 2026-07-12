#!/usr/bin/env python3
"""Reserved / bogon ranges must never reach the firewall enforcement set.

Threat-intel feeds occasionally list reserved, documentation, or bogon ranges
(RFC 5737 test-nets are common offenders). Firewalling those is pointless at
best and breaks core networking at worst (link-local, CGNAT, multicast). This
test pins the two layers of protection:

  1. FIREWALL_NEVER_BLOCK / _in_never_block covers every special-use range.
  2. load_ip_blocklist() strips protected ranges even from a stale on-disk cache
     that was written before the never-block set was expanded.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def main() -> int:
    from valkyrie.firewall import _in_never_block, load_ip_blocklist
    import valkyrie.firewall as fwmod

    print("\n=== bogon / reserved never-block tests ===\n")

    print("[1] Special-use ranges are all protected")
    protected_samples = {
        "0.0.0.0":          "this-network (0.0.0.0/8)",
        "100.64.10.1":      "CGNAT (100.64.0.0/10)",
        "192.0.2.5":        "TEST-NET-1 (RFC 5737)",
        "198.18.0.1":       "benchmarking (RFC 2544)",
        "198.51.100.7":     "TEST-NET-2 (RFC 5737)",
        "203.0.113.5":      "TEST-NET-3 (RFC 5737)",
        "169.254.1.1":      "link-local (RFC 3927)",
        "224.0.0.251":      "mDNS multicast",
        "255.255.255.255":  "broadcast (240.0.0.0/4)",
    }
    for ip, why in protected_samples.items():
        _check(f"{ip} protected — {why}", _in_never_block(ip))

    print("\n[2] Genuine public IPs are NOT protected")
    for ip in ("185.220.101.1", "45.83.64.1", "8.8.8.8"):
        _check(f"{ip} not protected", not _in_never_block(ip))

    print("\n[3] load_ip_blocklist() strips bogons from a stale cache")
    # Point the loader at a temp cache file poisoned with a documentation range,
    # exactly the situation a feed error produced before this fix.
    with tempfile.TemporaryDirectory() as td:
        cache = Path(td) / "blocked_ips.txt"
        cache.write_text(
            "185.220.101.0/24\n"    # a real bad range — must survive
            "198.51.100.0/24\n"     # TEST-NET-2 bogon — must be dropped
            "203.0.113.0/24\n"      # TEST-NET-3 bogon — must be dropped
            "100.64.0.0/10\n",      # CGNAT — must be dropped
            encoding="utf-8",
        )
        orig = fwmod.FIREWALL_IP_PATH
        try:
            fwmod.FIREWALL_IP_PATH = cache
            loaded = load_ip_blocklist(allow_download=False)
        finally:
            fwmod.FIREWALL_IP_PATH = orig
        _check("real bad range kept", "185.220.101.0/24" in loaded)
        _check("TEST-NET-2 dropped from cache", "198.51.100.0/24" not in loaded)
        _check("TEST-NET-3 dropped from cache", "203.0.113.0/24" not in loaded)
        _check("CGNAT dropped from cache", "100.64.0.0/10" not in loaded)

    print("\n" + "=" * 44)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
