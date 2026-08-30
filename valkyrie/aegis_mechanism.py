"""Aegis 4 -- mechanism characterization. Consumed by, but not part of, the
Aegis 3 planner.

Aegis 1A already proved why this stage has to exist: "bucketing reduces
volume exposure" is a true sentence that would have made a terrible catalog
entry, because it says nothing about the sequence fingerprint the same
mechanism created. This module's whole job is to keep that distinction
structural rather than a thing someone has to remember to check: a
`MechanismProfile` records `intended_effect` (free text, never consumed by
any reasoning code) separately from `measured_effects` (the only thing
`verify()` or a planner is allowed to act on), and it records new signals
(replacement fingerprints) as first-class effects, not a footnote.

## What this module refuses to do

It does not let a caller construct a `Mechanism` (the Aegis 3 planner's
catalog entry) directly from `intended_effect`. The only path from a
`MechanismProfile` to something the planner can consume is
`naive_catalog_entry()` -- and that function exists to be compared against
reality, not trusted. `verify()` is the actual product of this module: does
trusting the naive, intent-only view of a mechanism agree with what
re-evaluating the exposure graph on the mechanism's MEASURED post-state
actually shows?
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .aegis_exposure import ExposureObservation, Scenario, evaluate_pair
from .aegis_planner import Mechanism, plan


@dataclass(frozen=True)
class ExposureEffect:
    """One measured before/after change to a canonical exposure category, at
    one observation point, attributed to one mechanism. `is_new_signal=True`
    means this category was NOT present before the mechanism ran -- Aegis
    1A's bucket-tier SEQUENCE fingerprint is the motivating example."""
    category: str
    observation_point: str
    baseline_precision: float
    measured_precision: float
    is_new_signal: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class MechanismProfile:
    """The result of characterizing ONE real mechanism from measurement,
    never from intuition. `intended_effect` is kept purely as a human-
    readable record of what the mechanism was supposed to do -- no
    reasoning code in this module or in valkyrie.aegis_planner ever reads
    it."""
    name: str
    intended_effect: str
    measured_effects: tuple[ExposureEffect, ...]
    bandwidth_overhead_pct: float
    latency_overhead_ms: dict
    compatibility_note: str
    repeatability_note: str
    evidence_class: str
    source_experiment: str

    def to_dict(self) -> dict:
        return {
            "name": self.name, "intended_effect": self.intended_effect,
            "measured_effects": [e.to_dict() for e in self.measured_effects],
            "bandwidth_overhead_pct": self.bandwidth_overhead_pct,
            "latency_overhead_ms": self.latency_overhead_ms,
            "compatibility_note": self.compatibility_note,
            "repeatability_note": self.repeatability_note,
            "evidence_class": self.evidence_class,
            "source_experiment": self.source_experiment,
        }

    def weakened_categories(self, threshold: float = 0.15) -> frozenset[str]:
        """Categories a NAIVE catalog entry would claim this mechanism
        removes -- measured precision dropped by more than `threshold` and
        it isn't itself a new signal. This is deliberately the SAME
        oversimplified view an unmeasured "affects VOLUME" declaration
        would produce; it exists to be checked against reality, not to be
        the mechanism's real capability."""
        return frozenset(
            e.category for e in self.measured_effects
            if not e.is_new_signal and e.baseline_precision - e.measured_precision > threshold
        )

    def new_signal_categories(self) -> frozenset[str]:
        return frozenset(e.category for e in self.measured_effects if e.is_new_signal)

    def apply_to(self, scenario: Scenario, flow_id: str) -> Scenario:
        """The scenario as it actually looks AFTER this mechanism runs,
        built only from `measured_effects` -- existing observations at
        `flow_id` get their measured precision, and any new-signal category
        is added as a fresh, full-fidelity observation at the SAME point it
        was measured at. Never derived from `intended_effect`."""
        by_category = {(e.category, e.observation_point): e for e in self.measured_effects}
        updated: list[ExposureObservation] = []
        seen_points: set[str] = set()
        for obs in scenario:
            if obs.flow_id != flow_id:
                updated.append(obs)
                continue
            seen_points.add(obs.observation_point)
            effect = by_category.get((obs.category, obs.observation_point))
            if effect is None:
                updated.append(obs)
            elif not effect.is_new_signal:
                updated.append(ExposureObservation(
                    obs.observation_point, obs.category, obs.flow_id,
                    precision=effect.measured_precision))
            # is_new_signal effects for an EXISTING category/point combination
            # would be a contradiction in terms; new signals are added below.
        for e in self.measured_effects:
            if e.is_new_signal:
                updated.append(ExposureObservation(
                    e.observation_point, e.category, flow_id,
                    precision=e.measured_precision))
        return tuple(updated)


def naive_catalog_entry(profile: MechanismProfile, cost: float) -> Mechanism:
    """The Aegis 3 Mechanism a planner would see if nobody had measured
    anything -- built ONLY from `weakened_categories()`, the naive/intended
    view. Exists to be verified against `apply_to()`'s measured reality,
    never to be handed to a real planning decision on its own."""
    return Mechanism(profile.name, profile.weakened_categories(), cost=cost)


def verify(profile: MechanismProfile, scenario: Scenario, flow_a: str, flow_b: str,
          target: str, cost: float = 1.0) -> dict:
    """Does trusting `profile`'s naive/intended view (via a one-mechanism
    Aegis 3 catalog) agree with re-evaluating the exposure graph on the
    mechanism's MEASURED post-state? If the naive view believes `target` is
    solved but the measured post-state still shows it established, that is
    reported as a mismatch -- the planner must not count the inference as
    solved just because a mechanism's intent said it should be.
    """
    baseline_decision = evaluate_pair(scenario, flow_a, flow_b)["decisions"][target]

    naive_mechanism = naive_catalog_entry(profile, cost)
    naive_plan = plan(scenario, flow_a, flow_b, (target,), (naive_mechanism,))
    naive_believes_solved = naive_plan.satisfiable

    measured_scenario = profile.apply_to(scenario, flow_a)
    if flow_b != flow_a:
        measured_scenario = profile.apply_to(measured_scenario, flow_b)
    measured_decision = evaluate_pair(measured_scenario, flow_a, flow_b)["decisions"][target]
    measured_still_established = measured_decision["action"] == "alert"

    return {
        "mechanism": profile.name,
        "target": target,
        "baseline_decision": baseline_decision,
        "naive_planner_believes_solved": naive_believes_solved,
        "measured_still_established": measured_still_established,
        "measured_decision": measured_decision,
        "mismatch": naive_believes_solved and measured_still_established,
        "weakened_categories_naively_claimed": sorted(profile.weakened_categories()),
        "new_signal_categories_measured": sorted(profile.new_signal_categories()),
    }
