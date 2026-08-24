#!/usr/bin/env python3
"""Progressive-overload ratchet (redteam/evaluation/ratchet.py).

The properties that make it a ratchet rather than a wandering number:

  * it only ever moves UP - the best rate and the ever-resisted set grow, never
    shrink;
  * a technique that was ONCE resisted and now evades is a REGRESSION and a
    hard failure, even if the aggregate rate is unchanged;
  * a technique evading that never resisted is HEADROOM, not a failure - the
    next plate to lift;
  * a regression leaves the persisted ledger untouched (via ok=False), so the
    high-water mark keeps reflecting the last good state.

Pure functions over dicts, so this runs fully offline.
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent.parent / "tests"))

from harness import Checks  # noqa: E402
import ratchet as R         # noqa: E402


def _summary(**transforms) -> dict:
    """Build an evasion-result-shaped dict. Each kwarg is
    name=(rate, resisted_ids, evaded_ids)."""
    t = {}
    for name, (rate, resisted, evaded) in transforms.items():
        t[name] = {"resistance_rate": rate,
                   "resisted_ids": list(resisted),
                   "evaded_ids": list(evaded)}
    return {"transforms": t}


def main() -> int:
    c = Checks("evasion ratchet (progressive overload)", expect_min=20)

    # ------------------------------------------------------------------ [1]
    print("\n[1] first run seeds the ledger; everything resisted is a gain")
    run1 = _summary(comma_delimit=(0.8, ["a", "b", "c", "d"], ["e"]))
    led, rep = R.update_ledger(None, run1)
    c.check("ratchet holds on a first run", rep.ok)
    c.check("resisted techniques count as gains",
            set(rep.gains[0].newly_resisted) == {"a", "b", "c", "d"})
    c.check("the evading one is surfaced as headroom",
            rep.headroom and rep.headroom[0].headroom == ("e",))
    c.check("best rate recorded", led["transforms"]["comma_delimit"]["best_rate"] == 0.8)
    c.check("ever-resisted set recorded",
            set(led["transforms"]["comma_delimit"]["ever_resisted"]) == {"a", "b", "c", "d"})

    # ------------------------------------------------------------------ [2]
    print("\n[2] closing headroom ratchets UP and is a gain, not noise")
    run2 = _summary(comma_delimit=(1.0, ["a", "b", "c", "d", "e"], []))
    led, rep = R.update_ledger(led, run2)
    c.check("ratchet still holds", rep.ok)
    c.check("the once-evading technique is now a gain",
            rep.gains and "e" in rep.gains[0].newly_resisted)
    c.check("best rate ratcheted to 1.0", led["transforms"]["comma_delimit"]["best_rate"] == 1.0)
    c.check("no headroom remains", not rep.headroom)

    # ------------------------------------------------------------------ [3]
    print("\n[3] THE RATCHET: a once-resisted technique that now evades is a "
          "HARD regression, even at the same aggregate count")
    # 'e' evades again; 'f' newly resists - count unchanged (5 resisted), but
    # 'e' regressed. A rate-only check would miss this entirely.
    run3 = _summary(comma_delimit=(1.0, ["a", "b", "c", "d", "f"], ["e"]))
    led_after, rep = R.update_ledger(led, run3)
    c.check("a regression breaks the ratchet", not rep.ok)
    c.check("the regressed technique is named",
            rep.regressions and "e" in rep.regressions[0].regressed)
    c.check("this is caught despite the aggregate rate being identical",
            rep.regressions[0].run_rate == 1.0)

    # ------------------------------------------------------------------ [4]
    print("\n[4] a rate drop below the high-water mark is also a regression")
    run4 = _summary(comma_delimit=(0.6, ["a", "b", "c"], ["d", "e"]))
    _, rep = R.update_ledger(led, run4)
    c.check("rate falling below best is a regression", not rep.ok)
    c.check("rate_regressed flag set",
            any(d.rate_regressed for d in rep.regressions))
    c.check("regressed techniques (d, e were once resisted) are named",
            set(rep.regressions[0].regressed) == {"d", "e"})

    # ------------------------------------------------------------------ [5]
    print("\n[5] the ledger only moves up: best_rate never falls")
    # feed a worse run; the RETURNED ledger's best_rate must still be the max.
    led2, _ = R.update_ledger(led, run4)
    c.check("best_rate held at the high-water mark despite a worse run",
            led2["transforms"]["comma_delimit"]["best_rate"] == 1.0)
    c.check("ever-resisted set never shrinks",
            {"a", "b", "c", "d", "e", "f"}.issubset(
                set(led2["transforms"]["comma_delimit"]["ever_resisted"])) is False
            and {"a", "b", "c", "d", "e"}.issubset(
                set(led2["transforms"]["comma_delimit"]["ever_resisted"])))

    # ------------------------------------------------------------------ [6]
    print("\n[6] a transform absent from a run is carried forward, not lost")
    multi = _summary(comma_delimit=(1.0, ["a"], []), caret=(1.0, ["x"], []))
    led3, _ = R.update_ledger(None, multi)
    only_one = _summary(comma_delimit=(1.0, ["a"], []))
    led4, rep = R.update_ledger(led3, only_one)
    c.check("the unexercised transform survives in the ledger",
            "caret" in led4["transforms"])
    c.check("an unexercised transform is not reported as a regression", rep.ok)

    # ------------------------------------------------------------------ [7]
    print("\n[7] a steady state with no change reports HELD and no gains")
    steady = _summary(comma_delimit=(1.0, ["a", "b", "c", "d", "e", "f"], []))
    ledS, _ = R.update_ledger(led, steady)   # absorb everything first
    _, rep = R.update_ledger(ledS, steady)
    c.check("no-change run holds", rep.ok)
    c.check("no-change run reports no gains", not rep.gains)
    c.check("no-change run reports no headroom", not rep.headroom)

    # ------------------------------------------------------------------ [8]
    print("\n[8] accepts a full result file OR just the transforms block")
    full = {"tier": "evasion", "generated_at": "x",
            "transforms": {"t": {"resistance_rate": 1.0,
                                 "resisted_ids": ["a"], "evaded_ids": []}}}
    _, rep_full = R.update_ledger(None, full)
    _, rep_block = R.update_ledger(None, full["transforms"])
    c.check("both input shapes produce the same verdict",
            rep_full.ok == rep_block.ok and
            len(rep_full.deltas) == len(rep_block.deltas))

    # ------------------------------------------------------------------ [9]
    print("\n[9] render never raises and states the status")
    txt = R.render(rep)
    c.check("render mentions HELD or BROKEN",
            ("HELD" in txt) or ("BROKEN" in txt))
    _, badrep = R.update_ledger(led, run3)
    c.check("render of a broken ratchet says BROKEN",
            "BROKEN" in R.render(badrep))

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
