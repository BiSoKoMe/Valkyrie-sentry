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


def main() -> int:
    c = Checks("self test", expect_min=20)

    # ── 1. Heartbeat: green must be earned ──────────────────────────────────
    print("[1] heartbeat state machine")
    original = st._probe_dns
    try:
        probe_result = {"ok": True}
        st._probe_dns = lambda host, port, timeout=1.0: probe_result["ok"]

        transitions: list[bool] = []
        hb = st.HeartbeatMonitor("127.0.0.1", 5399, interval=999,
                                 on_change=transitions.append)

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
        def _boom(host, port, timeout=1.0):
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
        st._probe_dns = lambda host, port, timeout=1.0: True
        hb2 = st.HeartbeatMonitor("127.0.0.1", 5399, interval=1.0)
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
    finally:
        st._probe_dns = original

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
