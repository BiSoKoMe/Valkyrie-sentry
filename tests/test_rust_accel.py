#!/usr/bin/env python3
"""Native accelerator equivalence + wiring (ADR-0010).

The optional Rust extension `valkyrie_accel.IpSet` is a drop-in for the
pure-Python `firewall._PyIPSet`. This test proves they return identical results
across randomized inputs and boundary cases, and that firewall selects the Rust
backend when it is installed. It SKIPS cleanly when the extension is not built,
so the pure-Python CI job (which does not compile Rust) stays green and still
proves the fallback path works.
"""

from __future__ import annotations

import ipaddress
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import skip_file

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def main() -> int:
    try:
        import valkyrie_accel
    except Exception as exc:   # noqa: BLE001
        print("      Build it with: cd rust/valkyrie_accel && maturin build --release")
        print("      The pure-Python fallback is exercised by test_ipset_lookup.py.")
        return skip_file("native accelerator (Rust)", f"not built ({exc})")

    from valkyrie.firewall import _PyIPSet
    from valkyrie import firewall

    print("\n=== native accelerator (Rust) ===\n")

    print("[1] firewall wires the Rust backend when present")
    _check("backend reported 'rust'", firewall._IPSET_BACKEND == "rust")
    _check("_IPSet is the native class",
           firewall._IPSet is valkyrie_accel.IpSet)

    print("\n[2] Rust ↔ Python differential (randomized)")
    random.seed(20260712)
    mism = 0
    for _ in range(5):
        cidrs: set[str] = set()
        while len(cidrs) < 400:
            plen = random.choice([8, 12, 16, 20, 22, 24, 28, 32])
            net = ipaddress.ip_network(
                f"{random.randint(1,223)}.{random.randint(0,255)}."
                f"{random.randint(0,255)}.0/{plen}", strict=False)
            cidrs.add(str(net))
        for _ in range(40):
            cidrs.add(f"{random.randint(1,223)}.{random.randint(0,255)}."
                      f"{random.randint(0,255)}.{random.randint(0,255)}")
        rust = valkyrie_accel.IpSet(); rust.load(cidrs)
        py = _PyIPSet(); py.load(cidrs)
        _check_count = (rust.count() == py.count())
        if not _check_count:
            mism += 1
        for _ in range(4000):
            ip = f"{random.randint(1,223)}.{random.randint(0,255)}." \
                 f"{random.randint(0,255)}.{random.randint(0,255)}"
            if rust.contains(ip) != py.contains(ip):
                mism += 1
    _check(f"0 Rust/Python disagreements across 20000 probes + counts (got {mism})",
           mism == 0)

    print("\n[3] Boundary + malformed inputs match Python")
    for spec in ({"10.0.0.0/8", "203.0.113.5", "0.0.0.0/1", "255.255.255.255"},):
        rust = valkyrie_accel.IpSet(); rust.load(spec)
        py = _PyIPSet(); py.load(spec)
        for ip in ("10.255.255.255", "11.0.0.1", "203.0.113.5", "203.0.113.6",
                   "127.0.0.1", "128.0.0.1", "255.255.255.255", "bad", "::1"):
            _check(f"contains({ip!r}) agrees", rust.contains(ip) == py.contains(ip))
        _check("count() agrees", rust.count() == py.count())

    print("\n[4] Throughput (informational)")
    random.seed(1)
    cidrs = set()
    while len(cidrs) < 12000:
        cidrs.add(f"{random.randint(1,223)}.{random.randint(0,255)}."
                  f"{random.randint(0,255)}.0/24")
    rust = valkyrie_accel.IpSet(); rust.load(cidrs)
    py = _PyIPSet(); py.load(cidrs)
    ips = [f"{random.randint(1,223)}.{random.randint(0,255)}."
           f"{random.randint(0,255)}.{random.randint(0,255)}" for _ in range(50000)]
    t = time.perf_counter(); [rust.contains(ip) for ip in ips]; rt = time.perf_counter() - t
    t = time.perf_counter(); [py.contains(ip) for ip in ips]; pt = time.perf_counter() - t
    print(f"      rust:   {rt/50000*1e6:5.2f} us/lookup")
    print(f"      python: {pt/50000*1e6:5.2f} us/lookup   (speedup x{pt/rt:.1f})")

    print("\n" + "=" * 52)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
