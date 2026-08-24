"""Tier 3.13 — the component that says "you are protected" must not lie.

`self_test.py` was 0% covered, 140 statements, and it is the module whose entire
job is telling the user whether protection is working. TEST_PLAN puts it first
in tier 3 for a reason: if this can report healthy while protection is down,
every other guarantee in the product is void, because the user's only signal
that Valkyrie has stopped working is this module saying so.

The failure being tested for is specific and asymmetric. A heartbeat that cries
wolf is annoying. A heartbeat that stays green while the DNS sinkhole is dead
means the user browses all day believing they are protected — the module's own
docstring names this: *"the worst failure mode is not a crash; it is silently
not protecting while the UI still says ACTIVE."*

So the tests are weighted toward proving the **green** state is earned:

  * a dead sinkhole must eventually flip the state to unhealthy
  * recovery must flip it back, or the signal is useless after one blip
  * `preflight` must mark genuinely broken things as critical, and must not
    mark working things critical (a preflight that always fails gets ignored)
  * the single-packet-loss tolerance must not become unlimited tolerance

`_probe_dns` is patched rather than bound to a real socket: the property under
test is the state machine's response to probe outcomes, and a test that needs a
live resolver would be skipped in CI, which is how this module reached 0%.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks
import valkyrie.self_test as st
from valkyrie.config import HEALTH_PROBE_DOMAIN


def main() -> int:
    c = Checks("self test", expect_min=20)

    # ── 1. Heartbeat: green must be earned ──────────────────────────────────
    print("[1] heartbeat state machine")
    original = st._probe_dns
    try:
        probe_result = {"ok": True}
        # Stub must match the real _probe_dns signature, which now takes a qname
        # (the heartbeat probes a reserved local health name).
        st._probe_dns = lambda host, port, timeout=1.0, qname="": probe_result["ok"]

        transitions: list[bool] = []
        # startup_grace=0 so these pin the pure failure-counting STATE MACHINE;
        # the startup-grace behaviour is covered separately in [1c] below.
        hb = st.HeartbeatMonitor("127.0.0.1", 5399, interval=999,
                                 on_change=transitions.append, startup_grace=0)

        c.check("starts optimistic (before any probe)", hb.is_healthy())

        probe_result["ok"] = True
        hb.check_once()
        c.check("a successful probe keeps it healthy", hb.is_healthy())

        # One failure must NOT flip it — a single dropped UDP packet is noise.
        probe_result["ok"] = False
        hb.check_once()
        c.check("ONE failed probe does not raise a false alarm", hb.is_healthy())
        c.check("but the failure is counted", hb.status()["fail_count"] == 1)

        # Two consecutive failures must flip it. This is the check that stops
        # the UI claiming ACTIVE while the sinkhole is dead.
        hb.check_once()
        c.check("TWO consecutive failures flip it to unhealthy",
                not hb.is_healthy())
        c.check("the transition fired a change callback", transitions == [False])

        # Tolerance must not be unlimited: sustained failure stays unhealthy.
        for _ in range(20):
            hb.check_once()
        c.check("sustained failure stays unhealthy (tolerance is not unlimited)",
                not hb.is_healthy())
        c.check("fail_count keeps climbing, it is not clamped at 2",
                hb.status()["fail_count"] > 2)

        # Recovery must work, or the signal is useless after the first blip.
        probe_result["ok"] = True
        hb.check_once()
        c.check("recovery flips it back to healthy", hb.is_healthy())
        c.check("recovery fired a second transition", transitions == [False, True])
        c.check("fail_count resets on recovery", hb.status()["fail_count"] == 0)

        # A transition must fire only on CHANGE, not on every probe, or the
        # dashboard would flap and operators would learn to ignore it.
        before = len(transitions)
        for _ in range(5):
            hb.check_once()
        c.check("no callback while state is unchanged",
                len(transitions) == before)

        # status() must be self-consistent and complete.
        s = hb.status()
        c.check("status reports the port it is actually probing",
                s["dns_port"] == 5399)
        c.check("status carries a last_ok timestamp once healthy",
                s["last_ok"] > 0)
        c.check("status healthy agrees with is_healthy()",
                s["healthy"] == hb.is_healthy())

        # A probe that raises must not take the monitor down, and must not be
        # silently treated as success.
        def _boom(host, port, timeout=1.0, qname=""):
            raise OSError("network unreachable")

        st._probe_dns = _boom
        crashed = False
        try:
            for _ in range(3):
                hb.check_once()
        except Exception:                              # noqa: BLE001
            crashed = True
        c.check("a probe that raises does not crash the monitor", not crashed)
        if not crashed:
            c.check("a raising probe is NOT counted as healthy", not hb.is_healthy())
        else:
            c.check("a raising probe is NOT counted as healthy "
                    "(monitor crashed instead)", False)

        # ── Staleness: a monitor that stopped monitoring is not healthy ─────
        # A dead heartbeat thread does not announce itself. Without a staleness
        # guard the signal freezes at its last value, and 'healthy' is the most
        # likely value to freeze at since it is the initial state.
        print("\n[1b] a stopped monitor must not keep reporting green")
        st._probe_dns = lambda host, port, timeout=1.0, qname="": True
        hb2 = st.HeartbeatMonitor("127.0.0.1", 5399, interval=1.0, startup_grace=0)
        hb2.check_once()
        c.check("healthy right after a good probe", hb2.is_healthy())
        # Simulate the thread having died some time ago.
        import time as _t
        with hb2._lock:
            hb2._last_check = _t.time() - (1.0 * hb2._STALE_INTERVALS + 5)
        c.check("a stale last_check is NOT reported as healthy",
                not hb2.is_healthy())
        c.check("status() marks it stale explicitly", hb2.status()["stale"])
        c.check("status() healthy agrees with is_healthy() when stale",
                hb2.status()["healthy"] is False)
        # A fresh probe must clear staleness — the guard must not be one-way.
        hb2.check_once()
        c.check("a fresh probe clears the stale state", hb2.is_healthy())
        c.check("status() no longer marks it stale", not hb2.status()["stale"])
        # Never-probed is not stale: start() has simply not run yet.
        hb3 = st.HeartbeatMonitor("127.0.0.1", 5399, interval=1.0)
        c.check("a monitor that has never probed is not called stale",
                not hb3.status()["stale"])

        # ── [1c] Startup grace: a cold boot must not cry wolf ───────────────
        # The heartbeat fires seconds after start(), sometimes BEFORE the DNS
        # listener has finished binding. During the grace window a failing probe
        # means "still starting," not "protection down" — no false
        # PROTECTION-FAILED. After the first success, normal rules resume.
        print("\n[1c] startup grace suppresses the cold-boot false alarm")
        st._probe_dns = lambda host, port, timeout=1.0, qname="": False   # not up yet
        transitions_g: list[bool] = []
        hbg = st.HeartbeatMonitor("127.0.0.1", 5399, interval=999,
                                  on_change=transitions_g.append, startup_grace=30.0)
        hbg.start(); hbg.stop()             # sets _started_at; we drive probes below
        for _ in range(5):
            hbg.check_once()
        c.check("failures during startup grace do NOT flip to unhealthy",
                hbg.is_healthy())
        c.check("failures during startup grace are NOT counted",
                hbg.status()["fail_count"] == 0)
        c.check("no false PROTECTION-FAILED transition during grace",
                transitions_g == [])
        st._probe_dns = lambda host, port, timeout=1.0, qname="": True
        hbg.check_once()
        c.check("first success within grace keeps it healthy", hbg.is_healthy())
        st._probe_dns = lambda host, port, timeout=1.0, qname="": False
        hbg.check_once(); hbg.check_once()
        c.check("after the first success, real failures DO flip it",
                not hbg.is_healthy())
    finally:
        st._probe_dns = original

    # ── 1d. Wire-level probe fast path answers WITHOUT a worker thread ──────
    # Regression for a live bug: the heartbeat still false-failed under a burst
    # of real DNS queries (not just at cold boot) because each query spawns its
    # own worker thread, and Python's GIL can delay a freshly-spawned heartbeat-
    # reply thread past its 1s probe budget purely from scheduling contention.
    # The fix recognises the reserved health-probe name directly off the wire in
    # the serve loop and answers INLINE, before any thread is spawned. This pins
    # two things: the wire-format encoding used by the probe (self_test) and the
    # one used by the recogniser (dns_interceptor) must agree, and the live
    # answer must come back correct even while a burst of worker threads runs.
    print("\n[1d] health-probe answered inline, never queued behind worker threads")
    import socket as _socket
    import threading as _threading
    import valkyrie.dns_interceptor as _di

    probe_wire = st._encode_qname(HEALTH_PROBE_DOMAIN)
    header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    full_packet = header + probe_wire + b"\x00\x01\x00\x01"
    c.check("interceptor's wire recogniser agrees with the probe's own encoding",
            _di._is_health_probe_wire(full_packet))
    c.check("a normal domain's packet is NOT recognised as the health probe",
            not _di._is_health_probe_wire(
                header + st._encode_qname("example.com") + b"\x00\x01\x00\x01"))

    # Drive it through a REAL interceptor instance on a live loopback socket,
    # with a burst of worker threads (simulating real query load) already
    # occupying the GIL, and confirm the probe still answers fast.
    interceptor = _di.DNSInterceptor(
        store=None, blocklist=None, behavioral=None, rules=None,
        process_watcher=None, host="127.0.0.1", port=0)
    interceptor._sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    interceptor._sock.bind(("127.0.0.1", 0))
    interceptor._sock.settimeout(0.5)
    bound_port = interceptor._sock.getsockname()[1]
    interceptor._running = True
    loop_thread = _threading.Thread(target=interceptor._serve_loop, daemon=True)
    loop_thread.start()

    # Saturate the GIL with busy worker threads for the probe window, the same
    # shape as a real query burst (CPU-bound work, no real query dispatch needed
    # for this check — only the health-probe's OWN latency is under test).
    stop_noise = _threading.Event()
    def _spin():
        while not stop_noise.is_set():
            sum(i * i for i in range(2000))
    noise_threads = [_threading.Thread(target=_spin, daemon=True) for _ in range(12)]
    for t in noise_threads:
        t.start()
    try:
        client = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        client.settimeout(1.0)
        import time as _t
        t0 = _t.monotonic()
        client.sendto(full_packet, ("127.0.0.1", bound_port))
        try:
            reply, _addr = client.recvfrom(4096)
            elapsed = _t.monotonic() - t0
            c.check(f"health probe answered under GIL contention ({elapsed*1000:.0f}ms)",
                    len(reply) > 0)
        except _socket.timeout:
            c.check("health probe answered under GIL contention", False)
        client.close()
    finally:
        stop_noise.set()
        for t in noise_threads:
            t.join(timeout=2)
        interceptor._running = False
        interceptor._sock.close()
        loop_thread.join(timeout=2)

    # ── 2. preflight: critical means critical ───────────────────────────────
    print("\n[2] preflight checks")
    checks = st.preflight(port=5399, want_dns=True, want_unbound=False,
                          want_tls=False)
    c.check("preflight returns results rather than raising", isinstance(checks, list))
    c.check("preflight actually ran checks (not an empty list)", len(checks) > 0)
    c.check("every result is a Check with a name",
            all(isinstance(x, st.Check) and x.name for x in checks))
    c.check("every failing check explains itself",
            all(x.detail for x in checks if not x.ok))

    crit = st.critical_failures(checks)
    c.check("critical_failures returns only failed criticals",
            all(x.critical and not x.ok for x in crit))
    c.check("critical_failures is a subset of all checks",
            all(x in checks for x in crit))

    # A preflight where everything is critical would be ignored in practice;
    # one where nothing is critical cannot block a broken start. Both extremes
    # are defects, so assert the classification actually discriminates.
    criticals = [x for x in checks if x.critical]
    c.check(f"some checks are critical ({len(criticals)}/{len(checks)})",
            len(criticals) > 0)
    c.check(f"not every check is critical ({len(criticals)}/{len(checks)})",
            len(criticals) < len(checks))

    # TLS requested but no CA present must be reported, not silently passed.
    tls_checks = st.preflight(port=5399, want_dns=False, want_unbound=False,
                              want_tls=True)
    names = " ".join(x.name.lower() for x in tls_checks)
    c.check("requesting TLS adds a CA-related check", "ca" in names or "tls" in names)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
