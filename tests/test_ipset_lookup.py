#!/usr/bin/env python3
"""Differential + edge-case tests for _IPSet's fast CIDR membership.

_IPSet.contains is a hot path (every allowed DNS answer IP is screened against
it). ADR-0004 replaced the O(n) linear network scan with prefix-length bucketing.
This test pins the property that matters: the fast implementation returns exactly
what a brute-force `addr in network` reference returns, across randomized inputs
and hand-picked boundary cases. If a future change breaks equivalence, this fails.
"""

from __future__ import annotations

import ipaddress
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def _reference(cidrs: set[str]):
    """Brute-force membership oracle mirroring the old linear implementation."""
    nets = [ipaddress.IPv4Network(c, strict=False) for c in cidrs if "/" in c]
    hosts = {c for c in cidrs if "/" not in c}

    def contains(ip: str) -> bool:
        try:
            a = ipaddress.IPv4Address(ip)
        except ValueError:
            return False
        if str(a) in hosts:
            return True
        return any(a in n for n in nets)

    return contains


def main() -> int:
    from valkyrie.firewall import _IPSet

    print("\n=== _IPSet fast-lookup equivalence ===\n")

    print("[1] Hand-picked boundary cases")
    s = _IPSet()
    s.load({"10.0.0.0/8", "185.220.101.0/24", "1.10.16.0/20",
            "203.0.113.5", "255.255.255.255"})
    cases = {
        "185.220.101.0":   True,    # network address
        "185.220.101.255": True,    # broadcast of the /24
        "185.220.102.0":   False,   # just outside the /24
        "1.10.16.0":       True,    # /20 low
        "1.10.31.255":     True,    # /20 high boundary
        "1.10.32.0":       False,   # /20 just past the top
        "203.0.113.5":     True,    # exact host
        "203.0.113.6":     False,   # neighbor host, not loaded
        "255.255.255.255": True,    # exact host /32-style
        "10.255.255.255":  True,    # inside the /8
        "11.0.0.1":        False,   # just outside the /8
        "not-an-ip":       False,   # malformed -> False, never raises
    }
    for ip, want in cases.items():
        _check(f"contains({ip!r}) == {want}", s.contains(ip) is want)
    _check("count() == 5", s.count() == 5)

    print("\n[2] Randomized differential vs brute-force reference")
    random.seed(1337)
    mismatches = 0
    for trial in range(5):
        cidrs: set[str] = set()
        # mixed prefix lengths + some exact hosts
        while len(cidrs) < 500:
            plen = random.choice([8, 12, 16, 20, 22, 24, 28, 32])
            base = random.randint(1, 223)
            net = ipaddress.ip_network(
                f"{base}.{random.randint(0,255)}.{random.randint(0,255)}.0/{plen}",
                strict=False)
            cidrs.add(str(net))
        for _ in range(50):
            cidrs.add(f"{random.randint(1,223)}.{random.randint(0,255)}."
                      f"{random.randint(0,255)}.{random.randint(0,255)}")
        fast = _IPSet(); fast.load(cidrs)
        ref = _reference(cidrs)
        for _ in range(4000):
            ip = f"{random.randint(1,223)}.{random.randint(0,255)}." \
                 f"{random.randint(0,255)}.{random.randint(0,255)}"
            if fast.contains(ip) != ref(ip):
                mismatches += 1
    _check(f"0 mismatches across 20000 randomized probes (got {mismatches})",
           mismatches == 0)

    print("\n[3] Empty set is well-behaved")
    empty = _IPSet()
    _check("empty.contains() is False", not empty.contains("8.8.8.8"))
    _check("empty.count() == 0", empty.count() == 0)

    print("\n" + "=" * 48)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
