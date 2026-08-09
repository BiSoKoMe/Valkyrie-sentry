#!/usr/bin/env python3
"""Authority + lease sweeper, actually wired (coverage_state.py, engine.py).

The autonomy machinery was built across six commits and then sat inert:
authorize() and sweep_expired_leases() had no production callers, only tests.
This pins the wiring itself.

Two properties dominate, and both are about not making things worse:

  * the coverage oracle must NEVER block the detection path. check_all() costs
    ~3.3s measured; running it per detection would be far worse than the API
    bug it was modelled on, because it would sit in the path that has to react
    to an attack. Cold reads answer immediately with STATE_UNKNOWN.

  * an unmeasured control must yield LESS authority, never more. Unknown is
    the conservative answer, so the first detection after startup is judged
    pessimistically rather than optimistically.

No engine boots here, nothing enforces, no host state is touched.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402


def _wait_for(pred, timeout_s: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.02)
    return pred()


def main() -> int:
    c = Checks("authority + sweeper wiring", expect_min=14)

    from valkyrie.edr import coverage_state as CS, sensor_deps as SD

    # ------------------------------------------------------------------ [1]
    print("\n[1] a COLD provider answers instantly and conservatively")
    slow_calls = {"n": 0}

    class _SlowCtx:
        pass

    def slow_factory():
        slow_calls["n"] += 1
        return _SlowCtx()

    p = CS.CoverageStateProvider(slow_factory)
    t0 = time.perf_counter()
    state = p.state_of("firewall")
    dt_ms = (time.perf_counter() - t0) * 1000
    c.check(f"a cold read returned in {dt_ms:.1f}ms — check_all() costs ~3.3s "
            f"and must never run inside the detection path", dt_ms < 50)
    c.check("and the cold answer is UNKNOWN, which sensor_deps treats as dark "
            "— an unmeasured control must yield LESS authority, never more",
            state == SD.STATE_UNKNOWN)

    # ------------------------------------------------------------------ [2]
    print("\n[2] the refresh happens off the hot path and then serves real data")
    ok = _wait_for(lambda: p.snapshot()["measured"])
    c.check("a background refresh populated the snapshot", ok)
    if ok:
        snap = p.snapshot()
        c.check(f"it measured all {snap['total']} controls", snap["total"] > 0)
        c.check("with no failures", snap["failures"] == 0)
        t0 = time.perf_counter()
        p.state_of("firewall")
        warm_ms = (time.perf_counter() - t0) * 1000
        c.check(f"a warm read is still immediate ({warm_ms:.1f}ms)",
                warm_ms < 50)
    else:
        c.fail("refresh did not complete", "background thread never landed")

    # ------------------------------------------------------------------ [3]
    print("\n[3] a FAILING refresh never raises into the detection path")
    def bad_factory():
        raise RuntimeError("context construction exploded")

    bad = CS.CoverageStateProvider(bad_factory)
    got = bad.state_of("firewall")
    c.check("the read still returns rather than propagating", got == SD.STATE_UNKNOWN)
    _wait_for(lambda: bad.snapshot()["failures"] > 0)
    c.check("and the failure is counted, not swallowed silently",
            bad.snapshot()["failures"] > 0)
    c.check("with the reason retained",
            "exploded" in (bad.snapshot()["last_error"] or ""))

    # ------------------------------------------------------------------ [4]
    print("\n[4] not installing a provider is a NO-OP, never an implicit pass")
    CS.install(None)
    c.check("sensor_state() is None when nothing is installed — authorize() "
            "treats a missing gate as skipped, so an engine that never "
            "installs one behaves exactly as before",
            CS.sensor_state() is None)
    CS.install(p)
    c.check("and is a callable once installed", callable(CS.sensor_state()))
    CS.install(None)

    # ------------------------------------------------------------------ [5]
    print("\n[5] authorize() consumes the provider and the cascade budget")
    from valkyrie.edr import authority as A, cascade as CA
    from valkyrie.decision import Signal, decide

    sig = Signal(category="attack_sequence", source="attack_sequence",
                 severity="critical", process_name="evil.exe",
                 entity="evil.example", distinct_tactics=3)
    base = decide(sig)

    dark = lambda name: SD.STATE_ABSENT            # noqa: E731
    au_dark = A.authorize(sig, base, target="evil.example", sensor_state=dark,
                          budget_permits=CA.CascadeBudget().permits)
    c.check("dark sensors limit the action", "coverage" in au_dark.limited_by)

    live = lambda name: SD.STATE_EFFECTIVE         # noqa: E731
    au_live = A.authorize(sig, base, target="evil.example", sensor_state=live,
                          budget_permits=CA.CascadeBudget().permits)
    c.check("live sensors do not", "coverage" not in au_live.limited_by)
    c.check("so the SAME signal reaches a stronger action when the sensors "
            "backing it are actually running — which is the whole point of "
            "the coverage gate",
            A._ACTION_ORDER.index(au_live.action)
            >= A._ACTION_ORDER.index(au_dark.action))

    # ------------------------------------------------------------------ [6]
    print("\n[6] the engine exposes the sweeper as a schedulable facade")
    from valkyrie.edr.engine import EdrEngine
    c.check("EdrEngine.sweep_expired_leases exists for the periodic loop to "
            "call — without a scheduled sweep a 'time-boxed' block is a "
            "permanent one", hasattr(EdrEngine, "sweep_expired_leases"))
    c.check("and _authorize is the single place the four gates are composed",
            hasattr(EdrEngine, "_authorize"))

    # ------------------------------------------------------------------ [7]
    print("\n[7] the sweep interval is configured and sane")
    from valkyrie.config import LEASE_SWEEP_INTERVAL
    from valkyrie.edr.leases import DEFAULT_TTL_S
    c.check(f"sweep interval ({LEASE_SWEEP_INTERVAL}s) is well below the "
            f"default lease TTL ({DEFAULT_TTL_S}s), so an expiry is lifted "
            f"promptly rather than lingering most of another TTL",
            0 < LEASE_SWEEP_INTERVAL < DEFAULT_TTL_S / 4)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
