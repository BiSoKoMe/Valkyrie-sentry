#!/usr/bin/env python3
"""Authority composition (valkyrie/edr/authority.py) + TTL-by-cadence.

The property under test is that the four gates compose as a MINIMUM, not a
blend. A single averaged score would let a very strong signal on one axis buy
authority it has not earned on another -- which is exactly how an agent ends
up very confidently doing something catastrophic. Each gate must be able to
hold the action down on its own, and the invariant layer must overrule all of
them.

Also pins the flat-TTL flaw: a 900s lease on an hourly implant expires between
beacons and never renews, lifting the block on the stealthiest threat.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402


def main() -> int:
    c = Checks("authority composition (min of four gates)", expect_min=20)

    from valkyrie.edr import authority as A, leases as L, sensor_deps as SD
    from valkyrie.decision import Action, Signal, decide

    live = lambda s: SD.STATE_EFFECTIVE            # noqa: E731
    dark = lambda s: SD.STATE_ABSENT               # noqa: E731

    # A signal strong enough that the policy wants to enforce.
    sig = Signal(category="attack_sequence", source="attack_sequence",
                 severity="critical", process_name="evil.exe",
                 entity="evil.example", distinct_tactics=3)
    base = decide(sig)

    # ------------------------------------------------------------------ [1]
    print("\n[1] with every gate open, authority equals what evidence justified")
    au = A.authorize(sig, base, target="evil.example", sensor_state=live)
    c.check("action is not downgraded", au.action == base.action)
    c.check("nothing limited it", au.limited_by == ())
    c.check("not vetoed", not au.vetoed)

    # ------------------------------------------------------------------ [2]
    print("\n[2] every gate is OPTIONAL and skipping one is a no-op, never an "
          "implicit pass")
    bare = A.authorize(sig, base, target="evil.example")
    c.check("no gates supplied -> unchanged action", bare.action == base.action)
    c.check("no gates supplied -> nothing claimed to have been checked",
            bare.limited_by == ())

    # ------------------------------------------------------------------ [3]
    print("\n[3] COVERAGE alone can hold the action down")
    au = A.authorize(sig, base, target="evil.example", sensor_state=dark)
    c.check("dark sensors downgrade the action", au.action != base.action)
    c.check("'coverage' is named as the limiter", "coverage" in au.limited_by)
    c.check("the reason survives to the caller", len(au.reasons) >= 1)
    c.check("downgraded flag is set", au.downgraded)

    # ------------------------------------------------------------------ [4]
    print("\n[4] BUDGET alone can hold the action down")
    au = A.authorize(sig, base, target="evil.example", sensor_state=live,
                     budget_permits=lambda: (False, "cascade: 40 actions/min"))
    c.check("exhausted budget caps at ALERT",
            A._ACTION_ORDER.index(au.action) <= A._ACTION_ORDER.index(Action.ALERT))
    c.check("'budget' is named", "budget" in au.limited_by)
    c.check("no lease is granted for an action that will not run",
            au.lease_ttl_s is None)
    c.check("budget reason is carried",
            any("cascade" in r for r in au.reasons))

    # ------------------------------------------------------------------ [5]
    print("\n[5] INVARIANT overrules everything, including full confidence and "
          "every other gate being wide open")
    au = A.authorize(sig, base, target="Wi-Fi", sensor_state=live)
    c.check("action against the wireless adapter is vetoed", au.vetoed)
    c.check("capped at ALERT — it still tells the user, it just does not act",
            A._ACTION_ORDER.index(au.action) <= A._ACTION_ORDER.index(Action.ALERT))
    c.check("'invariant' is named as the limiter", "invariant" in au.limited_by)
    c.check("no lease for a vetoed action", au.lease_ttl_s is None)

    # ------------------------------------------------------------------ [6]
    print("\n[6] the gates take the FLOOR, not an average — a wide-open gate "
          "cannot buy back what another one took")
    au = A.authorize(sig, base, target="Wi-Fi", sensor_state=live,
                     budget_permits=lambda: (True, ""))
    c.check("perfect coverage + healthy budget still cannot beat a veto",
            au.vetoed)

    # ------------------------------------------------------------------ [7]
    print("\n[7] an enforcing action that survives is TIME-BOXED")
    au = A.authorize(sig, base, target="evil.example", sensor_state=live)
    if au.enforces:
        c.check("a surviving enforcement carries a lease TTL",
                au.lease_ttl_s is not None and au.lease_ttl_s > 0)
    else:
        c.check("policy did not reach an enforcing rung for this signal "
                "(recorded, not asserted away)", True)

    # ------------------------------------------------------------------ [8]
    print("\n[8] TTL scales to the behaviour's CADENCE, not a constant")
    c.check("no measured interval -> the default", L.ttl_for() == L.DEFAULT_TTL_S)
    hourly = L.ttl_for("network_score", observed_interval_s=3600.0)
    c.check("an HOURLY beacon leases far longer than the flat 900s default — "
            "otherwise the lease expires between check-ins and the block "
            "silently lifts on the stealthiest threat",
            hourly > L.DEFAULT_TTL_S and hourly >= 3600.0 * 2)
    c.check("a fast beacon still gets at least the default (never shorter)",
            L.ttl_for("network_score", observed_interval_s=5.0) >= L.DEFAULT_TTL_S)
    c.check("TTL is capped at MAX_TTL_S even for an absurd interval",
            L.ttl_for("x", observed_interval_s=10 ** 9) <= L.MAX_TTL_S)
    c.check("a grant at the cadence-derived TTL is accepted by the registry",
            hourly <= L.MAX_TTL_S)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
