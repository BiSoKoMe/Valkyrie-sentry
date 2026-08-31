#!/usr/bin/env python3
"""Network connection telemetry - classification + diff/emit (ADR-0014).

The high-value signal is an outbound connection to a threat-intel IP - the
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

    print("\n[7] pid_for_local_port() - Nyx causality attribution lookup (ADR 0057)")
    import valkyrie.network_telemetry as NT

    class _FakeAddr:
        def __init__(self, ip, port):
            self.ip = ip
            self.port = port

    class _FakeConn:
        def __init__(self, laddr, pid, status="ESTABLISHED"):
            self.laddr = laddr
            self.pid = pid
            self.status = status
            self.raddr = None

    class _FakeProcess:
        def __init__(self, pid):
            self._pid = pid

        def name(self):
            return "chrome.exe" if self._pid == 4242 else ""

        def exe(self):
            return r"C:\chrome.exe" if self._pid == 4242 else ""

    class _FakePsutil:
        @staticmethod
        def net_connections(kind="inet"):
            return [_FakeConn(_FakeAddr("127.0.0.1", 55000), 4242)]

        @staticmethod
        def Process(pid):
            return _FakeProcess(pid)

    real_flag = NT._PSUTIL
    real_psutil = NT.psutil if real_flag else None
    NT.psutil = _FakePsutil()
    NT._PSUTIL = True
    try:
        result = NT.pid_for_local_port(55000)
        _check("resolves (pid, name, path) for a matching local port",
               result == (4242, "chrome.exe", r"C:\chrome.exe"))
        _check("no match for an unrelated port returns None",
               NT.pid_for_local_port(9999) is None)
        _check("a falsy port is rejected without calling psutil",
               NT.pid_for_local_port(0) is None)
    finally:
        NT._PSUTIL = real_flag
        if real_psutil is not None:
            NT.psutil = real_psutil

    print("\n[8] pid_for_local_port() degrades cleanly without psutil")
    NT._PSUTIL = False
    try:
        _check("no psutil available -> None, never raises",
               NT.pid_for_local_port(55000) is None)
    finally:
        NT._PSUTIL = real_flag

    print("\n[9] snapshot() reuses a cached exe() path across polls for the "
          "same (pid, create_time) - Beta 0.5 audit found NetworkCollector "
          "had the same wasted-syscall shape as ProcessCollector's pr.exe() "
          "bug (docs/BETA_0_5_TELEMETRY_RELIABILITY.md)")

    class _FakeAddr2:
        def __init__(self, ip, port):
            self.ip = ip
            self.port = port

    class _FakeConn2:
        def __init__(self, raddr, pid, status="ESTABLISHED"):
            self.raddr = raddr
            self.pid = pid
            self.status = status

    class _FakeProcess2:
        def __init__(self, pid, create_time, path=r"C:\tools\curl.exe"):
            self._pid = pid
            self._create_time = create_time
            self._path = path
            self.exe_calls = 0

        def name(self):
            return "curl.exe"

        def create_time(self):
            return self._create_time

        def exe(self):
            self.exe_calls += 1
            return self._path

    _current9 = [_FakeProcess2(7777, 5000.0)]

    class _FakePsutil2:
        @staticmethod
        def net_connections(kind="inet"):
            return [_FakeConn2(_FakeAddr2("8.8.8.8", 443), 7777)]

        @staticmethod
        def Process(pid):
            return _current9[0]

    real_flag9 = NT._PSUTIL
    real_psutil9 = NT.psutil if real_flag9 else None
    NT.psutil = _FakePsutil2()
    NT._PSUTIL = True
    try:
        col9 = NetworkCollector(emit=lambda e: None, ip_reputation=lambda ip: False)
        col9.snapshot()
        _check("first snapshot resolves exe() once", _current9[0].exe_calls == 1)
        col9.snapshot()
        _check("second snapshot for the SAME (pid, create_time) does not "
               "call exe() again", _current9[0].exe_calls == 1)

        print("  [9b] pid reuse with a DIFFERENT create_time is inspected fresh")
        _current9[0] = _FakeProcess2(7777, 9999.0)
        col9.snapshot()
        _check("a new create_time under the same pid re-resolves exe()",
               _current9[0].exe_calls == 1)
    finally:
        NT._PSUTIL = real_flag9
        if real_psutil9 is not None:
            NT.psutil = real_psutil9

    print("\n[10] poll_once() emit_budget defers a not-yet-scored connection "
          "to the next poll instead of losing it (same pattern as "
          "ProcessCollector/PersistenceCollector's emit_budget fix)")
    import time as _time

    c1 = ConnInfo(21, "a.exe", "1.1.1.1", 80)
    c2 = ConnInfo(22, "b.exe", "185.220.101.5", 443)   # the threat-intel IP
    rep10 = lambda ip: ip == "185.220.101.5"
    emitted10: list = []
    col10 = NetworkCollector(emit=emitted10.append, ip_reputation=rep10, emit_budget=1.0)
    seq10 = iter([{}, {c1.key(): c1, c2.key(): c2}])
    col10.snapshot = lambda: next(seq10)   # type: ignore[assignment]
    col10.poll_once()   # baseline (empty)

    real_monotonic = _time.monotonic
    _budget_returns = iter([0.0, 0.5])   # deadline=1.0; c1 checked at 0.5 (ok); c2's check exhausts the iterator
    _time.monotonic = lambda: next(_budget_returns, 999.0)
    try:
        n10 = col10.poll_once()
    finally:
        _time.monotonic = real_monotonic
    _check("budget-limited cycle does not score/emit the connection past "
           "the deadline", n10 == 0)
    _check("status reports the diff_score_emit stage as truncated",
           "diff_score_emit" in col10.status()["truncated"])

    seq10b = iter([{c1.key(): c1, c2.key(): c2}])
    col10.snapshot = lambda: next(seq10b)   # type: ignore[assignment]
    n10b = col10.poll_once()   # real time now - budget is not a constraint
    _check("the deferred connection is rediscovered and scored on the next poll",
           n10b == 1 and len(emitted10) == 1)
    _check("emitted event is the deferred (threat-intel) connection",
           emitted10 and emitted10[0].target["ip"] == "185.220.101.5")
    _check("truncated clears once a cycle completes within budget",
           col10.status()["truncated"] == [])

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
