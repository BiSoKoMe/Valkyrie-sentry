"""Aegis 2 -- the exposure graph. Measurement/reasoning only; no mitigation.

Aegis 1A (size bucketing) and Aegis 1B (identity/destination separation)
were both killed, for what looked like two different reasons, until they
were looked at together:

    Aegis 1A: hide size precision -> other features compensate, and the
              transformed sequence becomes a NEW fingerprint.
    Aegis 1B: separate identity/destination -> destination alone still
              links sessions, and timing/size re-link the separated views.

Neither failure was about a field. Both were about which COMBINATIONS of
visible information let an observer join evidence into an inference. That is
this module's actual subject: not "is X exposed" but "which exposed pieces,
together, support which conclusion, and which contradict it."

## Deliberate reuse, not a parallel implementation

`valkyrie.edr.hypothesis` (EvidenceFact, HypothesisSpec, evaluate_hypotheses)
is already a fully generic evidence-fusion engine: facts name the
hypotheses they support or contradict, weights fuse by noisy-OR, and a
decision requires a minimum support count plus a margin over the runner-up
-- exactly the "don't just accumulate suspicious points" property this
reasoning needs. Reusing it here (rather than writing Aegis's own scoring
system) is "apply the principle, not copy the implementation" taken
literally: it IS the same implementation, because the principle -- evidence
for and against a bounded hypothesis, never a lone accumulating score -- is
not EDR-specific.

## The vocabulary

Exposure categories (what is observable, never itself "dangerous"):
    IDENTITY, DESTINATION, VOLUME, TIMING, SEQUENCE, FREQUENCY, SESSION,
    DIRECTION

Inference hypotheses (what an observer might conclude by joining exposure):
    ACTIVITY_CLASSIFICATION, FLOW_LINKAGE, CROSS_SESSION_LINKABILITY,
    USER_LINKABILITY, DESTINATION_DISCLOSURE

USER_LINKABILITY is compositional: it is supported directly when IDENTITY
and DESTINATION are observable at the SAME point, or indirectly when
IDENTITY is observable at one point, DESTINATION at another, and
FLOW_LINKAGE independently joins those two points -- exactly Aegis 1B's
"separated but re-linked" failure, produced here as a consequence of the
representation rather than encoded as a special case.

## The one rule this module must satisfy

Nothing in `_derive_facts` or `evaluate_pair` may branch on which experiment
produced a scenario. A scenario is only ever a tuple of `ExposureObservation`
values in the vocabulary above; the SAME derivation and evaluation code must
explain Aegis 1A, Aegis 1B, and any future scenario. `redteam/evaluation/
aegis_2_exposure_graph.py` is where 1A/1B get translated into that
vocabulary and replayed -- that translation is necessarily scenario-specific
(someone has to describe what each experiment exposed), but this module
never is.
"""

from __future__ import annotations

import itertools
from dataclasses import asdict, dataclass

from .edr.hypothesis import EvidenceFact, HypothesisDecision, HypothesisSpec, evaluate_hypotheses

EXPOSURE_CATEGORIES = frozenset({
    "IDENTITY", "DESTINATION", "VOLUME", "TIMING", "SEQUENCE", "FREQUENCY",
    "SESSION", "DIRECTION",
})

INFERENCE_HYPOTHESES = frozenset({
    "ACTIVITY_CLASSIFICATION", "FLOW_LINKAGE", "CROSS_SESSION_LINKABILITY",
    "USER_LINKABILITY", "DESTINATION_DISCLOSURE",
})

# Categories that can support recognizing WHAT is happening in one flow,
# independent of any other flow.
_ACTIVITY_BEARING_CATEGORIES = ("VOLUME", "SEQUENCE", "TIMING", "FREQUENCY")
# Categories that can support correlating separate OBSERVATION POINTS as
# holding the same underlying flow.
_CORRELATABLE_CATEGORIES = ("TIMING", "VOLUME", "SEQUENCE")

_SPECS = {
    hyp: HypothesisSpec(hyp, hyp.replace("_", " ").title(), decision_threshold=0.5, minimum_support=1)
    for hyp in INFERENCE_HYPOTHESES
}


@dataclass(frozen=True)
class ExposureObservation:
    """One canonical exposure category, visible at one observation point,
    about one flow. This is the raw input layer -- analogous to a raw
    detector label before behavior_ontology.canonicalize() -- not evidence
    for any hypothesis yet. `precision` in [0, 1]: 1.0 is full precision
    (e.g. an exact byte count); a degraded value (e.g. a size bucket, or
    jittered timing) is still an observation of that category, just a
    weaker one -- Aegis 1A's finding that bucketing didn't remove the VOLUME
    category, only its precision, is represented exactly this way, not as a
    special case.
    """
    observation_point: str
    category: str
    flow_id: str
    precision: float = 1.0

    def __post_init__(self) -> None:
        if self.category not in EXPOSURE_CATEGORIES:
            raise ValueError(f"unknown exposure category: {self.category!r}")
        if not 0.0 <= float(self.precision) <= 1.0:
            raise ValueError("precision must be between 0 and 1")

    def to_dict(self) -> dict:
        return asdict(self)


Scenario = tuple[ExposureObservation, ...]


def _by(scenario: Scenario, flow_id: str) -> list[ExposureObservation]:
    return [o for o in scenario if o.flow_id == flow_id]


def _best(observations: list[ExposureObservation]) -> ExposureObservation | None:
    return max(observations, key=lambda o: o.precision) if observations else None


def _derive_facts(scenario: Scenario, flow_a: str, flow_b: str) -> tuple[EvidenceFact, ...]:
    """The generic rulebook. Every fact here is produced from the abstract
    (category, observation_point, precision) shape of the scenario -- never
    from knowing which experiment the scenario came from."""
    facts: list[EvidenceFact] = []
    obs_a = _by(scenario, flow_a)
    obs_b = _by(scenario, flow_b) if flow_b != flow_a else []
    points_a = {o.observation_point for o in obs_a}
    points_b = {o.observation_point for o in obs_b}

    # DESTINATION_DISCLOSURE: destination visible anywhere for flow_a.
    dest = _best([o for o in obs_a if o.category == "DESTINATION"])
    if dest is not None:
        facts.append(EvidenceFact(
            f"{flow_a}:destination_visible", "destination_visible", dest.precision,
            supports=("DESTINATION_DISCLOSURE",),
            provenance=(f"{dest.observation_point}:DESTINATION",),
            explanation="destination is observable at at least one point"))

    # ACTIVITY_CLASSIFICATION: any activity-bearing category, at any point,
    # for flow_a. A degraded-precision observation still counts, at reduced
    # weight -- this is exactly how Aegis 1A's bucketing (VOLUME precision
    # reduced) and its own bucket SEQUENCE (a new, full-precision
    # observation) both enter as ordinary facts, with no bucketing-specific
    # code anywhere in this function.
    for category in _ACTIVITY_BEARING_CATEGORIES:
        match = _best([o for o in obs_a if o.category == category])
        if match is not None:
            facts.append(EvidenceFact(
                f"{flow_a}:{category.lower()}_available", f"{category.lower()}_available",
                round(match.precision * 0.6, 4),
                supports=("ACTIVITY_CLASSIFICATION",),
                provenance=(f"{match.observation_point}:{category}",),
                explanation=f"{category.lower()} is observable and activity-bearing"))

    if flow_b and flow_b != flow_a:
        # CROSS_SESSION_LINKABILITY: a point that sees DESTINATION for BOTH
        # flow_a and flow_b can compare them directly -- the mechanism
        # behind Aegis 0/1B's destination-overlap finding, produced here
        # without ever mentioning "overlap" as a bucketing/separation-
        # specific concept.
        for point in points_a & points_b:
            a_dest = _best([o for o in obs_a if o.observation_point == point and o.category == "DESTINATION"])
            b_dest = _best([o for o in obs_b if o.observation_point == point and o.category == "DESTINATION"])
            if a_dest is not None and b_dest is not None:
                strength = min(a_dest.precision, b_dest.precision)
                facts.append(EvidenceFact(
                    f"{flow_a}|{flow_b}:{point}:destination_comparable",
                    "destination_comparable", round(strength * 0.9, 4),
                    supports=("CROSS_SESSION_LINKABILITY",),
                    provenance=(f"{point}:DESTINATION for both flows",),
                    explanation="one point can see destination for both flows and compare them"))

        # FLOW_LINKAGE: a correlatable category present at TWO DIFFERENT
        # observation points, one holding flow_a and the other flow_b --
        # the mechanism behind Aegis 1B's re-linking finding. A precision
        # reduction on that category (e.g. real jitter/overhead) becomes
        # CONTRADICTING evidence, not a separate mechanism.
        if points_a and points_b and points_a != points_b:
            for category in _CORRELATABLE_CATEGORIES:
                a_match = _best([o for o in obs_a if o.category == category])
                b_match = _best([o for o in obs_b if o.category == category])
                if a_match is not None and b_match is not None:
                    strength = min(a_match.precision, b_match.precision)
                    facts.append(EvidenceFact(
                        f"{flow_a}|{flow_b}:{category.lower()}_correlatable",
                        f"{category.lower()}_correlatable", round(strength * 0.85, 4),
                        supports=("FLOW_LINKAGE",),
                        provenance=(f"{category} at {a_match.observation_point} and "
                                   f"{b_match.observation_point}",),
                        explanation=f"{category.lower()} is comparable across both "
                                   f"observation points"))
                    if strength < 0.6:
                        facts.append(EvidenceFact(
                            f"{flow_a}|{flow_b}:{category.lower()}_degraded",
                            f"{category.lower()}_degraded", round(1.0 - strength, 4),
                            contradicts=("FLOW_LINKAGE",),
                            provenance=(f"{category} precision reduced between points",),
                            explanation=f"{category.lower()} precision loss weakens "
                                       f"cross-point correlation"))

    return tuple(facts)


def evaluate_pair(scenario: Scenario, flow_a: str, flow_b: str | None = None) -> dict:
    """Evaluate all 5 canonical inference hypotheses for one flow (or one
    flow pair, for the pairwise hypotheses) given a scenario.

    USER_LINKABILITY is evaluated in a second pass: it is supported directly
    when IDENTITY and DESTINATION are both observable at the SAME point, and
    -- composed from the FLOW_LINKAGE decision already reached in the first
    pass -- indirectly when IDENTITY is observable at one point, DESTINATION
    at another, and FLOW_LINKAGE independently joins those points. That
    composition is what lets this module explain Aegis 1B's "separated but
    re-linked" result without a special case: USER_LINKABILITY simply
    consumes FLOW_LINKAGE's own decision as ordinary evidence.
    """
    flow_b = flow_b or flow_a
    base_facts = _derive_facts(scenario, flow_a, flow_b)

    decisions: dict[str, HypothesisDecision] = {}
    for hyp in ("DESTINATION_DISCLOSURE", "ACTIVITY_CLASSIFICATION",
               "CROSS_SESSION_LINKABILITY", "FLOW_LINKAGE"):
        relevant = tuple(f for f in base_facts if hyp in f.supports or hyp in f.contradicts)
        decisions[hyp] = evaluate_hypotheses([_SPECS[hyp]], relevant, alert_hypotheses={hyp})

    obs_pair = _by(scenario, flow_a) + _by(scenario, flow_b)
    identity = _best([o for o in obs_pair if o.category == "IDENTITY"])
    destination = _best([o for o in obs_pair if o.category == "DESTINATION"])
    user_facts: list[EvidenceFact] = []
    if identity is not None and destination is not None:
        if identity.observation_point == destination.observation_point:
            strength = min(identity.precision, destination.precision)
            user_facts.append(EvidenceFact(
                f"{flow_a}|{flow_b}:identity_destination_colocated",
                "identity_destination_colocated", round(strength * 0.95, 4),
                supports=("USER_LINKABILITY",),
                provenance=(f"{identity.observation_point}: IDENTITY + DESTINATION together",),
                explanation="identity and destination are visible to the SAME "
                           "observation point"))
        elif decisions["FLOW_LINKAGE"].alerts:
            user_facts.append(EvidenceFact(
                f"{flow_a}|{flow_b}:flow_linkage_bridges_identity_and_destination",
                "flow_linkage_bridges_identity_and_destination",
                decisions["FLOW_LINKAGE"].confidence,
                supports=("USER_LINKABILITY",),
                provenance=("derived from an independently established FLOW_LINKAGE "
                           "decision",),
                explanation="identity and destination sit at different points, but "
                           "flow linkage independently joins those points"))
    decisions["USER_LINKABILITY"] = evaluate_hypotheses(
        [_SPECS["USER_LINKABILITY"]], tuple(user_facts), alert_hypotheses={"USER_LINKABILITY"})

    return {
        "flow_a": flow_a, "flow_b": flow_b,
        "facts": [asdict(f) for f in base_facts + tuple(user_facts)],
        "decisions": {hyp: dec.to_dict() for hyp, dec in decisions.items()},
    }


def exposure_cut(scenario: Scenario, flow_a: str, flow_b: str, target: str,
                 max_cut_size: int = 3) -> dict:
    """The smallest set of ExposureObservations whose removal flips `target`
    from established to not-established for (flow_a, flow_b). Reasoning
    only: this identifies where a future mitigation would need to act,
    without proposing or implementing one.

    Brute-force over increasing subset sizes -- the scenarios this module
    reasons about are small (a handful of observations per flow pair), so an
    exhaustive search is the honest choice over a heuristic one.
    """
    if target not in INFERENCE_HYPOTHESES:
        raise ValueError(f"unknown inference hypothesis: {target!r}")

    baseline = evaluate_pair(scenario, flow_a, flow_b)
    if baseline["decisions"][target]["action"] != "alert":
        return {"target": target, "already_not_established": True, "cut": None}

    relevant = [o for o in scenario if o.flow_id in (flow_a, flow_b)]
    for size in range(1, min(max_cut_size, len(relevant)) + 1):
        for combo in itertools.combinations(relevant, size):
            reduced = tuple(o for o in scenario if o not in combo)
            result = evaluate_pair(reduced, flow_a, flow_b)
            if result["decisions"][target]["action"] != "alert":
                return {
                    "target": target,
                    "already_not_established": False,
                    "cut_size": size,
                    "cut": [o.to_dict() for o in combo],
                    "remaining_action": result["decisions"][target]["action"],
                }
    return {"target": target, "already_not_established": False, "cut": None,
           "note": f"no cut of size <= {max_cut_size} found -- either the "
                   "hypothesis is overdetermined by more paths than searched, "
                   "or it does not depend on the observations checked"}


def enumerate_minimal_cuts(scenario: Scenario, flow_a: str, flow_b: str, target: str,
                          max_cut_size: int = 3) -> tuple[tuple[ExposureObservation, ...], ...]:
    """Every MINIMAL cut for `target` up to `max_cut_size` -- a cut whose
    removal flips `target` from established to not-established, where no
    strict subset of it is itself already a cut. Aegis 3's planner needs
    every distinct cut (redundant inference paths mean there can be more
    than one), not just the first one found -- `exposure_cut` above answers
    "is there a small cut" for a human reading one hypothesis at a time;
    this answers "what are ALL the ways to break it," which a set-cover-style
    planner needs to reason about mechanism coverage.

    Returns an empty tuple both when `target` is already not established
    (nothing to cut) and when it IS established but no cut was found within
    `max_cut_size` -- callers that need to distinguish those two cases
    should check the target's own decision via `evaluate_pair` first.
    """
    if target not in INFERENCE_HYPOTHESES:
        raise ValueError(f"unknown inference hypothesis: {target!r}")

    baseline = evaluate_pair(scenario, flow_a, flow_b)
    if baseline["decisions"][target]["action"] != "alert":
        return ()

    relevant = [o for o in scenario if o.flow_id in (flow_a, flow_b)]
    found: list[tuple[ExposureObservation, ...]] = []
    for size in range(1, min(max_cut_size, len(relevant)) + 1):
        for combo in itertools.combinations(relevant, size):
            combo_set = set(combo)
            if any(set(existing) <= combo_set for existing in found):
                continue   # a smaller already-found cut makes this one non-minimal
            reduced = tuple(o for o in scenario if o not in combo)
            result = evaluate_pair(reduced, flow_a, flow_b)
            if result["decisions"][target]["action"] != "alert":
                found.append(combo)
    return tuple(found)
