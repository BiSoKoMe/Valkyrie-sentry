#!/usr/bin/env python3
"""Cascade budget — shape, not volume (valkyrie/edr/cascade.py).

The property being pinned: a real intrusion and a runaway loop can produce the
SAME number of actions, so counting cannot separate them. Blocking fifty
distinct C2 domains must stay allowed while fifty repeats against one target
must trip. Every check below therefore compares two series of equal or near
equal length and asserts they are judged differently.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402


def main() -> int:
    c = Checks("cascade budget (shape, not volume)", expect_min=14)

    from valkyrie.edr import cascade as C

    T0 = 1_000_000.0

    # ------------------------------------------------------------------ [1]
    print("\n[1] quiet and small samples are always permitted")
    b = C.CascadeBudget()
    ok, _ = b.permits(now=T0)
    c.check("an empty budget permits", ok)
    for i in range(C.MIN_SAMPLE - 1):
        b.record("block_domain", f"d{i}.example", "network_score", now=T0 + i)
    ok, _ = b.permits(now=T0 + 10)
    c.check(f"below MIN_SAMPLE ({C.MIN_SAMPLE}) never trips — three actions can "
            f"look infinitely accelerated, and refusing then would disable the "
            f"agent exactly when an incident starts", ok)

    # ------------------------------------------------------------------ [2]
    print("\n[2] a REAL campaign: many actions, all distinct targets -> ALLOWED")
    b = C.CascadeBudget()
    for i in range(40):
        b.record("block_domain", f"c2-{i}.example", "network_score", now=T0 + i * 30)
    ok, why = b.permits(now=T0 + 40 * 30)
    c.check(f"40 blocks against 40 distinct C2 domains is permitted "
            f"(reason if not: {why!r}) — fanning out is what a real "
            f"intrusion looks like", ok)
    c.check("all 40 are still inside the window", len(b) == 40)

    # ------------------------------------------------------------------ [3]
    print("\n[3] a LOOP: same count, one target -> REFUSED")
    b = C.CascadeBudget()
    for i in range(40):
        b.record("block_domain", "same.example", "reconnaissance-burst",
                 now=T0 + i * 30)
    ok, why = b.permits(now=T0 + 40 * 30)
    c.check("the SAME 40 actions against ONE target is refused — identical "
            "volume, opposite verdict, which is the whole point", not ok)
    c.check("the reason identifies it as a loop and names the target",
            "loop" in why.lower() and "same.example" in why)

    # ------------------------------------------------------------------ [4]
    print("\n[4] the measured real artifact: reconnaissance-burst completing "
          "repeatedly instead of escalating one incident")
    b = C.CascadeBudget()
    for i in range(C.MAX_PER_TARGET + 2):
        b.record("block_domain", "host-recon", "reconnaissance-burst",
                 now=T0 + i * 60)
    for i in range(4):
        b.record("block_domain", f"other{i}.example", "network_score",
                 now=T0 + 500 + i * 60)
    ok, why = b.permits(now=T0 + 900)
    c.check(f"exceeding MAX_PER_TARGET ({C.MAX_PER_TARGET}) trips even with "
            f"other distinct activity present — repeating a block that is not "
            f"holding is never the right answer", not ok)

    # ------------------------------------------------------------------ [5]
    print("\n[5] MONOTONY: many actions grinding over few targets")
    b = C.CascadeBudget()
    # 3 targets, under the per-target cap each, but heavily repetitive overall.
    for i in range(15):
        b.record("block_domain", f"t{i % 3}.example", "x", now=T0 + i * 10)
    ok, why = b.permits(now=T0 + 200)
    c.check("grinding over a handful of targets trips monotony or repetition",
            not ok)

    # ------------------------------------------------------------------ [6]
    print("\n[6] ACCELERATION trips BEFORE the absolute ceiling")
    b = C.CascadeBudget()
    # Slow prior phase spread over most of the window...
    for i in range(8):
        b.record("block_domain", f"slow{i}.example", "x", now=T0 + i * 300)
    # ...then a burst of distinct targets inside the last quarter.
    burst_start = T0 + C.WINDOW_S * 0.80
    for i in range(30):
        b.record("block_domain", f"fast{i}.example", "x", now=burst_start + i)
    ok, why = b.permits(now=T0 + C.WINDOW_S * 0.99)
    c.check(f"a sharp rate increase trips while total ({len(b)}) is still "
            f"below MAX_TOTAL ({C.MAX_TOTAL}) — watching the derivative is "
            f"what catches a runaway early", not ok and len(b) < C.MAX_TOTAL)
    c.check("the reason names acceleration and shows both rates",
            "accelerat" in why.lower() and "/min" in why)

    # ------------------------------------------------------------------ [7]
    print("\n[7] the window drains — a trip is temporary, not a latch")
    b = C.CascadeBudget()
    for i in range(40):
        b.record("block_domain", "same.example", "x", now=T0 + i)
    c.check("tripped while the burst is inside the window",
            not b.permits(now=T0 + 60)[0])
    ok, _ = b.permits(now=T0 + C.WINDOW_S + 120)
    c.check("permits again once the window has drained — enforcement pauses, "
            "it does not latch off until a human intervenes", ok)
    c.check("drained events are actually evicted", len(b) == 0)

    # ------------------------------------------------------------------ [8]
    print("\n[8] absolute ceiling is a backstop even for perfect shape")
    b = C.CascadeBudget()
    for i in range(C.MAX_TOTAL + 5):
        b.record("block_domain", f"unique{i}.example", "x", now=T0 + i)
    ok, why = b.permits(now=T0 + C.MAX_TOTAL + 10)
    c.check("all-distinct targets still stop at MAX_TOTAL — a shape detector "
            "with a bug must not authorise unlimited action", not ok)
    c.check("reason names the ceiling", "ceiling" in why.lower())

    # ------------------------------------------------------------------ [9]
    print("\n[9] shape matches authority.authorize's budget_permits contract")
    b = C.CascadeBudget()
    res = b.permits(now=T0)
    c.check("returns a (bool, str) tuple",
            isinstance(res, tuple) and len(res) == 2
            and isinstance(res[0], bool) and isinstance(res[1], str))

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
