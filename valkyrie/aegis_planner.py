"""Aegis 3 -- the privacy planner. Mechanism-independent; no mitigation
implemented here, real or synthetic-as-if-real.

Aegis 2's exposure graph answers "which observations, combined, support this
inference, and what is the smallest set of them whose removal breaks it."
That is a diagnosis, not a decision. This module adds exactly one thing on
top: given a synthetic CATALOG of candidate mechanisms -- each declaring
only which exposure categories it can weaken, and an abstract cost, nothing
about padding, jitter, or relaying -- find the cheapest mechanism set that
breaks every inference hypothesis a policy cares about.

## Why mechanisms stay declarative

    PRIVACY REASONING                    MECHANISM CATALOG
    "break these inference-      -->     mechanism X affects TIMING
     enabling relationships"             mechanism Y affects VOLUME
                                         mechanism Z affects TIMING+VOLUME

The planner never learns "timing leak -> jitter" as a rule. It only ever
asks: does some COMBINATION of declared `affected_categories` cover every
observation in some minimal cut for this hypothesis? Aegis 1A and 1B failed
by solving one field at a time; a planner that reasoned the same way would
reproduce that mistake one level up. Solving the SET-COVER problem instead
-- across every currently-alerting hypothesis at once, not one at a time --
is what a single mechanism affecting two categories, or two cheap mechanisms
together beating one expensive one, actually requires.

## Exhaustive search, on purpose

The mechanism catalogs and cut counts this stage reasons about are small
(single digits). Brute-forcing every mechanism subset is deterministic,
trivially verifiable, and correct by construction -- the honest choice while
the vocabulary stays this size, over a heuristic that could hide a cheaper
plan or, worse, a real UNSAT behind an approximate "good enough."

## UNSAT is a first-class result

If no subset of the catalog can realize even one minimal cut for some
target hypothesis, the planner returns `satisfiable=False` and names exactly
which hypothesis and which exposure remains open -- never a plan that
silently leaves an inference path intact.
"""

from __future__ import annotations

import itertools
from dataclasses import asdict, dataclass

from .aegis_exposure import (
    INFERENCE_HYPOTHESES,
    ExposureObservation,
    Scenario,
    enumerate_minimal_cuts,
    evaluate_pair,
)


@dataclass(frozen=True)
class Mechanism:
    """A synthetic candidate actuator. Declares ONLY which exposure
    categories it can weaken/remove and an abstract cost -- no networking
    detail, no name tied to a real technique. `scope_observation_points`,
    when given, restricts the mechanism to specific observation points
    (e.g. a mechanism deployable only at ENTRY); `None` means it applies
    wherever that category appears.
    """
    name: str
    affected_categories: frozenset[str]
    cost: float
    scope_observation_points: frozenset[str] | None = None

    def covers(self, observation: ExposureObservation) -> bool:
        if observation.category not in self.affected_categories:
            return False
        if (self.scope_observation_points is not None
                and observation.observation_point not in self.scope_observation_points):
            return False
        return True

    def to_dict(self) -> dict:
        d = asdict(self)
        d["affected_categories"] = sorted(self.affected_categories)
        d["scope_observation_points"] = (
            sorted(self.scope_observation_points)
            if self.scope_observation_points is not None else None)
        return d


@dataclass(frozen=True)
class HypothesisPlan:
    hypothesis: str
    status: str   # "already_safe" | "planned" | "unreachable_within_search_bound" | "unsatisfiable"
    minimal_cuts_considered: int
    satisfied_cut: tuple | None            # the cut (as dicts) this plan realizes, if any
    covering_mechanisms: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "hypothesis": self.hypothesis, "status": self.status,
            "minimal_cuts_considered": self.minimal_cuts_considered,
            "satisfied_cut": ([o.to_dict() if isinstance(o, ExposureObservation) else o
                              for o in self.satisfied_cut]
                             if self.satisfied_cut is not None else None),
            "covering_mechanisms": list(self.covering_mechanisms),
        }


@dataclass(frozen=True)
class PlanResult:
    satisfiable: bool
    chosen_mechanisms: tuple[str, ...]
    total_cost: float
    hypothesis_plans: tuple[HypothesisPlan, ...]
    remaining_exposure: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "satisfiable": self.satisfiable,
            "chosen_mechanisms": list(self.chosen_mechanisms),
            "total_cost": self.total_cost,
            "hypothesis_plans": [p.to_dict() for p in self.hypothesis_plans],
            "remaining_exposure": list(self.remaining_exposure),
        }


def _subset_realizes_a_cut(subset: tuple[Mechanism, ...],
                           cuts: tuple[tuple[ExposureObservation, ...], ...]) -> tuple | None:
    """The first cut (of possibly several redundant ones) this mechanism
    subset fully covers -- every observation in it neutralized by at least
    one mechanism in `subset` -- or None if it covers none of them."""
    for cut in cuts:
        if all(any(m.covers(obs) for m in subset) for obs in cut):
            return cut
    return None


def plan(scenario: Scenario, flow_a: str, flow_b: str, targets: tuple[str, ...],
        catalog: tuple[Mechanism, ...], max_cut_size: int = 3) -> PlanResult:
    """Find the cheapest mechanism subset that breaks every hypothesis in
    `targets` that is currently established for (flow_a, flow_b).

    Every target is solved TOGETHER, not independently: one chosen subset
    must realize some minimal cut for EACH active target simultaneously,
    so a mechanism that happens to help two hypotheses at once is credited
    once, not twice, and a plan that fixes hypothesis 1 while leaving
    hypothesis 2 open is never reported as a success.
    """
    for t in targets:
        if t not in INFERENCE_HYPOTHESES:
            raise ValueError(f"unknown inference hypothesis: {t!r}")

    baseline = evaluate_pair(scenario, flow_a, flow_b)
    cuts_by_target: dict[str, tuple] = {}
    plans: list[HypothesisPlan] = []
    active: list[str] = []

    for t in targets:
        if baseline["decisions"][t]["action"] != "alert":
            plans.append(HypothesisPlan(t, "already_safe", 0, None, ()))
            continue
        cuts = enumerate_minimal_cuts(scenario, flow_a, flow_b, t, max_cut_size)
        if not cuts:
            plans.append(HypothesisPlan(t, "unreachable_within_search_bound", 0, None, ()))
            continue
        cuts_by_target[t] = cuts
        active.append(t)

    if not active:
        return PlanResult(True, (), 0.0, tuple(plans), ())

    catalog_list = list(catalog)
    best_subset: tuple[Mechanism, ...] | None = None
    best_cost = None
    best_realized: dict[str, tuple] = {}

    for size in range(len(catalog_list) + 1):
        for subset in itertools.combinations(catalog_list, size):
            realized: dict[str, tuple] = {}
            ok = True
            for t in active:
                cut = _subset_realizes_a_cut(subset, cuts_by_target[t])
                if cut is None:
                    ok = False
                    break
                realized[t] = cut
            if not ok:
                continue
            cost = sum(m.cost for m in subset)
            if best_cost is None or cost < best_cost:
                best_cost, best_subset, best_realized = cost, subset, realized

    if best_subset is None:
        # UNSAT: name exactly what remains exposed for every active target,
        # not just report failure.
        remaining = []
        for t in active:
            categories = sorted({obs.category for cut in cuts_by_target[t] for obs in cut})
            remaining.append(f"{t}: no mechanism combination in the catalog covers any of its "
                            f"minimal cuts (categories involved: {', '.join(categories)})")
        for p in plans:
            if p.status == "unreachable_within_search_bound":
                remaining.append(f"{p.hypothesis}: established, but no cut found within "
                                f"max_cut_size={max_cut_size}")
        return PlanResult(False, (), 0.0, tuple(plans) + tuple(
            HypothesisPlan(t, "unsatisfiable", len(cuts_by_target[t]), None, ()) for t in active
        ), tuple(remaining))

    for t in active:
        cut = best_realized[t]
        covering = tuple(sorted({m.name for m in best_subset if any(m.covers(o) for o in cut)}))
        plans.append(HypothesisPlan(t, "planned", len(cuts_by_target[t]), cut, covering))

    return PlanResult(True, tuple(sorted(m.name for m in best_subset)), best_cost,
                      tuple(plans), ())
