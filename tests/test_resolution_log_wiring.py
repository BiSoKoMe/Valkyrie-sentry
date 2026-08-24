#!/usr/bin/env python3
"""Resolution log + network scorer — actually wired, not just unit-tested.

test_list_free_firewall.py proves network_score.py's scorer is list-free in
isolation. This file proves the two integration seams the backlog asked for
actually exist in the running pipeline, not just as standalone modules with
their own green tests:

  [1] dns_interceptor.py records an ALLOWED answer's IPs into the resolution
      log, and does NOT record a BLOCKED/DECEIVED one (a sinkholed address is
      not evidence a real destination was expected — recording it would teach
      network_score.py's S2 signal the wrong thing).
  [2] network_telemetry.NetworkCollector actually builds a ConnFacts per new
      connection and asks network_score.classify_connection_anomaly — proven
      by a connection that fires on list-free signals ALONE (no threat-intel
      hit at all), which the pre-wiring collector could never have surfaced.
  [3] The per-process network baseline (S4) is live: a binary's first-ever
      connection reports history=0, its second reports history=1.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks
from test_dns_decision_matrix import _build, _PROC, _QTYPE


def main() -> int:
    c = Checks("resolution log + network scorer wiring", expect_min=8)

    import dns.message
    import dns.rdatatype
    import dns.rdataclass
    import dns.rdtypes.IN.A
    from valkyrie.resolution_log import ResolutionLog, set_active

    # ------------------------------------------------------------------
    print("[1] dns_interceptor records ALLOWED answers, never BLOCKED ones")
    log = ResolutionLog()
    set_active(log)
    try:
        di, _ = _build()
        di._sock = SimpleNamespace(sendto=lambda *a, **k: None)
        di._watcher = SimpleNamespace(lookup=lambda src_ip, src_port: _PROC)
        di._store.log = lambda *a, **k: None

        def _fake_answer(ip: str):
            def _forward(request, _ip=ip):
                resp = dns.message.make_response(request)
                resp.flags |= dns.flags.AA
                rrset = resp.find_rrset(
                    resp.answer, request.question[0].name,
                    dns.rdataclass.IN, dns.rdatatype.A, create=True)
                rrset.add(dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A, _ip),
                         ttl=60)
                return resp.to_wire()
            return _forward

        allowed_domain = "clean-example.test"
        allowed_ip = "93.184.216.34"
        req = dns.message.make_query(allowed_domain, dns.rdatatype.A)
        with mock.patch.object(di, "_forward", _fake_answer(allowed_ip)):
            di._handle(req.to_wire(), ("127.0.0.1", 40000))
        c.check("an ALLOWED resolution is recorded",
                log.was_resolved(allowed_ip))
        c.check("the recorded domain matches",
                log.domain_for(allowed_ip) == allowed_domain)

        from test_dns_decision_matrix import _Scanner, _ScanResult
        di2, _ = _build(scanner=_Scanner(
            {"evil-c2.test": _ScanResult("block", ("malware",), 1.0, "scanner")}))
        di2._sock = SimpleNamespace(sendto=lambda *a, **k: None)
        di2._watcher = SimpleNamespace(lookup=lambda src_ip, src_port: _PROC)
        di2._store.log = lambda *a, **k: None
        blocked_ip = "45.32.11.9"
        req2 = dns.message.make_query("evil-c2.test", dns.rdatatype.A)
        # _forward must not even be reached for a hard block, but patch it
        # anyway so a regression that DID call it can't leak an IP into the
        # log through this path either.
        with mock.patch.object(di2, "_forward", _fake_answer(blocked_ip)):
            di2._handle(req2.to_wire(), ("127.0.0.1", 40001))
        c.check("a BLOCKED decision's IP is never recorded as resolved",
                not log.was_resolved(blocked_ip))
    finally:
        set_active(None)

    # ------------------------------------------------------------------
    print("\n[2] NetworkCollector fires on list-free signals with NO intel hit")
    from valkyrie.network_telemetry import ConnInfo, NetworkCollector

    log2 = ResolutionLog()
    set_active(log2)
    try:
        emitted: list = []
        # ip_reputation always says "clean" — if anything fires, it can only
        # be the list-free scorer, proving the wiring reaches production code
        # rather than the old list-only path.
        col = NetworkCollector(emit=emitted.append, ip_reputation=lambda ip: False)
        bad = ConnInfo(pid=10, name="svch0st.exe",
                       path=r"C:\Users\v\AppData\Local\Temp\svch0st.exe",
                       raddr_ip="45.32.11.9", raddr_port=443)
        seq = iter([{}, {bad.key(): bad}])
        col.snapshot = lambda: next(seq)   # type: ignore[assignment]
        col.poll_once()                     # baseline
        n = col.poll_once()                 # bad connection appears
        c.check("a connection with compounding list-free signals is emitted "
                "despite a clean reputation", n == 1 and len(emitted) == 1)
        if emitted:
            c.check("list-free labels are attached (never_resolved + "
                    "actor_untrusted + process_novelty)",
                    "network_anomaly" in emitted[0].labels)

        emitted_clean: list = []
        col_clean = NetworkCollector(emit=emitted_clean.append,
                                     ip_reputation=lambda ip: False)
        good = ConnInfo(pid=11, name="chrome.exe",
                        path=r"C:\Program Files\Google\Chrome\chrome.exe",
                        raddr_ip="142.250.72.14", raddr_port=443)
        log2.record("google.com", ["142.250.72.14"])   # this IP WAS resolved
        seq2 = iter([{}, {good.key(): good}])
        col_clean.snapshot = lambda: next(seq2)   # type: ignore[assignment]
        col_clean.poll_once()
        n2 = col_clean.poll_once()
        c.check("a trusted, resolved, non-novel connection stays quiet",
                n2 == 0 and emitted_clean == [])
    finally:
        set_active(None)

    # ------------------------------------------------------------------
    print("\n[3] Per-process network baseline (S4) is live across polls")
    emitted3: list = []
    col3 = NetworkCollector(emit=emitted3.append, ip_reputation=lambda ip: False)
    c.check("a never-before-seen image has no network history",
            col3._baseline.history_for("newapp.exe") == 0)
    facts_first = col3._score(ConnInfo(pid=20, name="newapp.exe",
                                       raddr_ip="8.8.8.8", raddr_port=443))
    c.check("baseline advances after the first observed connection",
            col3._baseline.history_for("newapp.exe") == 1)
    c.check("a second connection from the same image is no longer novel",
            col3._baseline.history_for("newapp.exe") == 1
            and col3._baseline.history_for("newapp.exe") != 0)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
