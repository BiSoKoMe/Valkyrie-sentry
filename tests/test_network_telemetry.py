#!/usr/bin/env python3
"""Network connection telemetry — classification + diff/emit (ADR-0014).

The high-value signal is an outbound connection to a threat-intel IP — the
hard-coded-IP-C2 case DNS never sees. This pins that behavior and the collector's
baseline-then-emit / flagged-only semantics with injected snapshots.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def main() -> int:
    from valkyrie.network_telemetry import (
        classify_connection, diff_snapshots, ConnInfo, NetworkCollector)
    from valkyrie import telemetry as T

    print("\n=== network telemetry ===\n")

    print("[1] classify_connection")
    sev, labels, reason = classify_connection("185.220.101.5", 443, blocked=True)
    _check("blocked -> high", sev == T.SEV_HIGH)
    _check("blocked -> threat_intel_ip label", labels == ["threat_intel_ip"])
    sev, labels, _ = classify_connection("93.184.216.34", 443, blocked=False)
    _check("clean -> info, no labels", sev == T.SEV_INFO and labels == [])

    print("\n[2] ConnInfo.to_event")
    ev = ConnInfo(pid=99, name="mal.exe", raddr_ip="185.220.101.5",
                  raddr_port=443).to_event(blocked=True)
    _check("category network", ev.category == T.CAT_NETWORK)
    _check("activity connect", ev.activity == "connect")
    _check("blocked -> flagged", ev.action == T.ACT_FLAGGED)
    _check("target carries ip/port",
           ev.target["ip"] == "185.220.101.5" and ev.target["port"] == 443)

    print("\n[3] diff_snapshots")
    a = ConnInfo(1, "a", "1.1.1.1", 80)
    b = ConnInfo(2, "b", "2.2.2.2", 443)
    old = {a.key(): a}
    new = {a.key(): a, b.key(): b}
    _check("only b is new", [c.pid for c in diff_snapshots(old, new)] == [2])

    print("\n[4] Collector emits only flagged connections by default")
    bad = ConnInfo(10, "mal", "185.220.101.5", 443)
    good = ConnInfo(11, "chrome", "93.184.216.34", 443)
    rep = lambda ip: ip == "185.220.101.5"   # only the bad IP is "blocked"
    emitted: list = []
    col = NetworkCollector(emit=emitted.append, ip_reputation=rep)
    seq = iter([{}, {bad.key(): bad, good.key(): good}])
    col.snapshot = lambda: next(seq)          # type: ignore[assignment]
    col.poll_once()                            # baseline (empty)
    n = col.poll_once()                        # bad + good appear
    _check("only the threat-intel connection emitted", n == 1 and len(emitted) == 1)
    _check("emitted event targets the bad IP",
           emitted and emitted[0].target["ip"] == "185.220.101.5")

    print("\n[5] emit_all=True surfaces every new connection")
    emitted2: list = []
    col2 = NetworkCollector(emit=emitted2.append, ip_reputation=rep, emit_all=True)
    seq2 = iter([{}, {bad.key(): bad, good.key(): good}])
    col2.snapshot = lambda: next(seq2)        # type: ignore[assignment]
    col2.poll_once(); col2.poll_once()
    _check("both connections emitted with emit_all", len(emitted2) == 2)

    print("\n[6] A raising emitter never breaks collection")
    col3 = NetworkCollector(emit=lambda e: (_ for _ in ()).throw(RuntimeError("x")),
                            ip_reputation=rep)
    seq3 = iter([{}, {bad.key(): bad}])
    col3.snapshot = lambda: next(seq3)        # type: ignore[assignment]
    col3.poll_once()
    try:
        col3.poll_once()
        _check("poll_once swallows emitter exceptions", True)
    except Exception:
        _check("poll_once swallows emitter exceptions", False)

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
