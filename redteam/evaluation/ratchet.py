"""Progressive-overload ratchet for the evasion tier.

THE IDEA (why this is the gym, not just another test)
------------------------------------------------------
Writing more detection rules against a scale pinned at 100% teaches nothing -
that was the finding of 2026-08-23: Tier A 36/40, live-safe 11/12 and the
evasion tier all sat maxed, so effort produced no measurable movement. The fix
was heavier plates (new transforms with real headroom). This file is the other
half: a ratchet, so the gains can only go ONE WAY.

A ratchet stores, per obfuscation transform, the BEST resistance ever recorded
and the exact set of techniques that have EVER been resisted under it. On each
run it compares the fresh evasion result against that high-water mark and
classifies every change:

  * GAIN       - resistance rose, or a technique that used to evade now
                 resists. The ledger ratchets UP to the new high-water mark.
  * REGRESSION - a technique that was ONCE resisted now evades, or a
                 transform's rate fell below its recorded best AGAINST THE SAME
                 applicable population. This is a HARD FAILURE (non-zero exit):
                 the whole point of a ratchet is that you cannot silently slide
                 back down. A real regression must be fixed or the ledger
                 deliberately reset with a recorded reason.

                 Growing the catalog with new, not-yet-resisted techniques
                 lowers the aggregate rate on its own (a bigger denominator)
                 without any previously-resisted technique regressing. That is
                 not penalized: a rate drop only counts as a regression when
                 the applicable population did not grow. The per-technique
                 check (a once-resisted id now evading) still fires regardless
                 of population size, since that is never an artifact of scale.
  * HEADROOM   - techniques that evade right now and never resisted. Not a
                 failure - it is the NEXT plate to lift, surfaced so the loop
                 always has a target.

This is deliberately asymmetric: gains are absorbed automatically, losses stop
the line. That asymmetry is what makes a loop around it "progressive overload"
rather than a number that wanders.

PURITY
------
Everything here is a pure function over dicts. `update_ledger` takes the old
ledger and a run summary and returns (new_ledger, report); it performs no I/O.
The thin `load`/`save`/`main` wrapper at the bottom is the only part that
touches disk, so the ratchet logic itself is exhaustively testable offline -
which matters, because this is the component that decides whether a change is
allowed to count as progress.

HONEST SCOPE
------------
The evasion tier is OFFLINE: obfuscated command lines scored through the real
classifiers on synthetic input (Tier A class). Resistance here means "the
normalizer + rules fold this obfuscation back to something a rule matches," NOT
"a live attack was blocked end to end." A rising ratchet is real evidence the
classifier's evasion resistance is improving and not regressing; it is not a
detection-rate claim. Live detection is still the Tier B question.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

LEDGER_SCHEMA = "valkyrie-evasion-ratchet/1"

# Floating-point rates are compared with a small tolerance so re-serialisation
# jitter never reads as a regression.
_EPS = 1e-9


@dataclass
class TransformDelta:
    """What changed for one transform between the ledger and a fresh run."""
    transform:        str
    best_rate:        float          # high-water mark AFTER this run
    prev_best_rate:   Optional[float]
    run_rate:         float
    newly_resisted:   tuple = ()     # techniques resisted now, never before
    regressed:        tuple = ()     # techniques once resisted, now evading
    headroom:         tuple = ()     # evading now, never resisted
    rate_regressed:   bool = False   # run_rate fell below recorded best
    population_grew:  bool = False   # new techniques entered the applicable set

    @property
    def is_regression(self) -> bool:
        return bool(self.regressed) or self.rate_regressed

    @property
    def is_gain(self) -> bool:
        return bool(self.newly_resisted) or (
            self.prev_best_rate is not None
            and self.run_rate > self.prev_best_rate + _EPS)

    def to_dict(self) -> dict:
        return {
            "transform": self.transform,
            "best_rate": self.best_rate,
            "prev_best_rate": self.prev_best_rate,
            "run_rate": self.run_rate,
            "newly_resisted": list(self.newly_resisted),
            "regressed": list(self.regressed),
            "headroom": list(self.headroom),
            "rate_regressed": self.rate_regressed,
            "is_regression": self.is_regression,
            "is_gain": self.is_gain,
        }


@dataclass
class RatchetReport:
    deltas: list = field(default_factory=list)   # list[TransformDelta]

    @property
    def regressions(self) -> list:
        return [d for d in self.deltas if d.is_regression]

    @property
    def gains(self) -> list:
        return [d for d in self.deltas if d.is_gain]

    @property
    def headroom(self) -> list:
        return [d for d in self.deltas if d.headroom]

    @property
    def ok(self) -> bool:
        """True when nothing regressed - the ratchet held."""
        return not self.regressions

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "regressions": [d.to_dict() for d in self.regressions],
            "gains": [d.to_dict() for d in self.gains],
            "headroom": [d.to_dict() for d in self.headroom],
            "all": [d.to_dict() for d in self.deltas],
        }


def new_ledger() -> dict:
    """An empty high-water-mark ledger."""
    return {"schema": LEDGER_SCHEMA, "transforms": {}}


def _run_transforms(run_summary: dict) -> dict:
    """Pull the per-transform block out of an evasion result JSON.

    Accepts either a full result file ({..., 'transforms': {...}}) or the
    transforms block itself, so callers need not care which they hold.
    """
    if "transforms" in run_summary and isinstance(run_summary["transforms"], dict):
        return run_summary["transforms"]
    return run_summary


def update_ledger(ledger: Optional[dict], run_summary: dict) -> tuple:
    """Fold a fresh evasion run into the ledger. Pure - returns a NEW ledger.

    Returns ``(new_ledger, RatchetReport)``. The ledger is never mutated in
    place, so a caller can inspect the report and decide whether to persist the
    new ledger (e.g. refuse to save on a regression that turns out to be a real
    bug, so the high-water mark still reflects the last good state).
    """
    old = ledger or new_ledger()
    old_transforms = old.get("transforms", {})
    fresh = _run_transforms(run_summary)

    new_transforms: dict = {}
    deltas: list = []

    for name, summ in fresh.items():
        run_rate = float(summ.get("resistance_rate") or 0.0)
        resisted_now = set(summ.get("resisted_ids") or [])
        evaded_now = set(summ.get("evaded_ids") or [])

        prev = old_transforms.get(name)
        prev_best_rate = None
        ever_resisted: set = set()
        prev_applicable: set = set()
        if prev is not None:
            prev_best_rate = prev.get("best_rate")
            ever_resisted = set(prev.get("ever_resisted") or [])
            prev_applicable = set(prev.get("applicable_ids") or [])

        # Regression: a technique that was EVER resisted now evades. This is
        # never an artifact of the catalog growing, so it fires regardless.
        regressed = tuple(sorted(ever_resisted & evaded_now))
        # Gain: resisted now, never in the ledger before.
        newly = tuple(sorted(resisted_now - ever_resisted))
        # Headroom: evading now and never resisted - the next plate to lift.
        headroom = tuple(sorted(evaded_now - ever_resisted))

        applicable_now = resisted_now | evaded_now
        merged_applicable = prev_applicable | applicable_now
        # New techniques entering the population drag the aggregate rate down
        # on their own - that is not a regression, it is more plates on the
        # bar. Only compare rates when the population did not grow.
        population_grew = bool(applicable_now - prev_applicable)
        rate_regressed = (prev_best_rate is not None
                          and run_rate < prev_best_rate - _EPS
                          and not population_grew)

        # The ledger only ever ratchets UP.
        best_rate = run_rate if prev_best_rate is None else max(prev_best_rate, run_rate)
        merged_resisted = sorted(ever_resisted | resisted_now)

        new_transforms[name] = {
            "best_rate": best_rate,
            "ever_resisted": merged_resisted,
            "applicable_ids": sorted(merged_applicable),
            "last_run_rate": run_rate,
        }
        deltas.append(TransformDelta(
            transform=name, best_rate=best_rate, prev_best_rate=prev_best_rate,
            run_rate=run_rate, newly_resisted=newly, regressed=regressed,
            headroom=headroom, rate_regressed=rate_regressed,
            population_grew=population_grew,
        ))

    # Transforms that were in the ledger but absent from this run are carried
    # forward untouched - a transform temporarily not exercised is not a loss.
    for name, prev in old_transforms.items():
        if name not in new_transforms:
            new_transforms[name] = prev

    return ({"schema": LEDGER_SCHEMA, "transforms": new_transforms},
            RatchetReport(deltas=deltas))


def render(report: RatchetReport) -> str:
    """One-screen human summary of a ratchet run."""
    lines = []
    status = "HELD" if report.ok else "BROKEN"
    lines.append(f"Ratchet: {status}")
    if report.gains:
        lines.append("\nGains (ratcheted up):")
        for d in report.gains:
            bits = []
            if d.newly_resisted:
                bits.append(f"+{len(d.newly_resisted)} newly resisted "
                            f"({', '.join(d.newly_resisted)})")
            if d.prev_best_rate is not None and d.run_rate > d.prev_best_rate + _EPS:
                bits.append(f"rate {100*d.prev_best_rate:.1f}% -> {100*d.run_rate:.1f}%")
            lines.append(f"  {d.transform}: {'; '.join(bits)}")
    if report.regressions:
        lines.append("\nREGRESSIONS (ratchet broken - fix or reset):")
        for d in report.regressions:
            if d.regressed:
                lines.append(f"  {d.transform}: {len(d.regressed)} technique(s) "
                             f"stopped resisting: {', '.join(d.regressed)}")
            if d.rate_regressed:
                lines.append(f"  {d.transform}: rate fell "
                             f"{100*(d.prev_best_rate or 0):.1f}% -> {100*d.run_rate:.1f}%")
    if report.headroom:
        lines.append("\nHeadroom (the next plates to lift):")
        for d in report.headroom:
            lines.append(f"  {d.transform}: {len(d.headroom)} evading "
                         f"({', '.join(d.headroom)})")
    grown = [d for d in report.deltas
             if d.population_grew and not d.is_regression
             and d.prev_best_rate is not None and d.run_rate < d.prev_best_rate - _EPS]
    if grown:
        lines.append("\nRate dip from a growing catalog (not a regression - "
                      "no previously-resisted technique evaded):")
        for d in grown:
            lines.append(f"  {d.transform}: rate {100*d.prev_best_rate:.1f}% -> "
                         f"{100*d.run_rate:.1f}% (new techniques added to scope)")
    if report.ok and not report.gains and not report.headroom and not grown:
        lines.append("\nNo change - every transform at its recorded best.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Thin I/O wrapper (the only part that touches disk)
# ---------------------------------------------------------------------------

def main() -> int:
    import argparse
    import glob
    import io
    import json
    import os
    from pathlib import Path

    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--result", help="evasion result JSON (default: newest in results/)")
    ap.add_argument("--ledger", default=str(here / "evasion_ratchet.json"))
    ap.add_argument("--no-save", action="store_true",
                    help="report only; never write the ledger")
    args = ap.parse_args()

    result_path = args.result
    if not result_path:
        candidates = sorted(glob.glob(str(here / "results" / "*__evasion.json")))
        if not candidates:
            print("no evasion result files found - run evasion_harness.py first")
            return 2
        result_path = candidates[-1]

    run_summary = json.load(io.open(result_path, encoding="utf-8"))
    ledger = None
    if os.path.exists(args.ledger):
        ledger = json.load(io.open(args.ledger, encoding="utf-8"))

    new_led, report = update_ledger(ledger, run_summary)
    print(f"result: {os.path.basename(result_path)}")
    print(render(report))

    if report.ok and not args.no_save:
        io.open(args.ledger, "w", encoding="utf-8").write(
            json.dumps(new_led, indent=2))
        print(f"\nledger updated: {args.ledger}")
    elif not report.ok:
        print("\nledger NOT updated - a regression must be resolved first.")

    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
