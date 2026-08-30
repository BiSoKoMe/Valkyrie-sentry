"""Deterministic evidence fusion for competing security hypotheses.

This module is deliberately smaller than a detection engine.  Sensors and
behaviour extractors decide which facts exist; this layer decides which of a
bounded set of explanations those facts support or contradict.  It performs no
I/O, reads no clock, retains no raw telemetry, and cannot execute a response.

The important property is that evidence can reduce confidence.  A pipeline
that only accumulates suspicious points eventually convicts normal installers,
administration, and developer tools.  Here each fact names the hypotheses it
supports and contradicts, and every decision carries the resulting ledger.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass
from math import prod

MAX_EVIDENCE_FACTS = 64


@dataclass(frozen=True)
class EvidenceFact:
    """One reusable behavioural fact with traceable provenance.

    ``weight`` is evidential strength in ``[0, 1]``.  It is not an alert score.
    Independent facts are fused with a noisy-OR, so repeated weak observations
    have diminishing returns and duplicate fact ids have no effect.
    """

    fact_id: str
    behavior: str
    weight: float
    supports: tuple[str, ...] = ()
    contradicts: tuple[str, ...] = ()
    provenance: tuple[str, ...] = ()
    explanation: str = ""
    blocks_decision: bool = False

    def __post_init__(self) -> None:
        if not self.fact_id or not self.behavior:
            raise ValueError("evidence facts require fact_id and behavior")
        if not 0.0 <= float(self.weight) <= 1.0:
            raise ValueError("evidence weight must be between 0 and 1")


@dataclass(frozen=True)
class HypothesisSpec:
    hypothesis_id: str
    description: str
    decision_threshold: float = 0.70
    minimum_support: int = 2


@dataclass(frozen=True)
class HypothesisAssessment:
    hypothesis_id: str
    description: str
    support_strength: float
    contradiction_strength: float
    confidence: float
    supporting: tuple[EvidenceFact, ...] = ()
    contradicting: tuple[EvidenceFact, ...] = ()

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class HypothesisDecision:
    selected: str
    action: str
    confidence: float
    margin: float
    assessments: tuple[HypothesisAssessment, ...]
    blockers: tuple[EvidenceFact, ...] = ()
    reason: str = ""

    @property
    def alerts(self) -> bool:
        return self.action == "alert"

    def to_dict(self) -> dict:
        return asdict(self)


def _strength(facts: Iterable[EvidenceFact]) -> float:
    """Fuse independent evidence with diminishing returns."""
    weights = [max(0.0, min(1.0, float(f.weight))) for f in facts]
    return 0.0 if not weights else 1.0 - prod(1.0 - weight for weight in weights)


def evaluate_hypotheses(
    specs: Iterable[HypothesisSpec],
    facts: Iterable[EvidenceFact],
    *,
    alert_hypotheses: frozenset[str] = frozenset(),
    minimum_margin: float = 0.10,
) -> HypothesisDecision:
    """Evaluate competing explanations and return an auditable decision.

    Duplicate facts are collapsed by ``fact_id`` and input is bounded.  A
    blocking fact represents missing authority or incomplete observation.  It
    never becomes evidence for a benign explanation; it forces ``observe``.
    """
    spec_list = tuple(specs)
    if not spec_list:
        raise ValueError("at least one hypothesis is required")

    unique: dict[str, EvidenceFact] = {}
    for fact in facts:
        unique.setdefault(fact.fact_id, fact)
        if len(unique) >= MAX_EVIDENCE_FACTS:
            break
    fact_list = tuple(unique.values())
    blockers = tuple(f for f in fact_list if f.blocks_decision)

    assessments: list[HypothesisAssessment] = []
    for spec in spec_list:
        supporting = tuple(f for f in fact_list
                           if spec.hypothesis_id in f.supports)
        contradicting = tuple(f for f in fact_list
                              if spec.hypothesis_id in f.contradicts)
        support = _strength(supporting)
        contradiction = _strength(contradicting)
        confidence = support * (1.0 - contradiction)
        assessments.append(HypothesisAssessment(
            hypothesis_id=spec.hypothesis_id,
            description=spec.description,
            support_strength=round(support, 4),
            contradiction_strength=round(contradiction, 4),
            confidence=round(confidence, 4),
            supporting=supporting,
            contradicting=contradicting,
        ))

    ranked = sorted(assessments, key=lambda item: item.confidence, reverse=True)
    winner = ranked[0]
    # Hypotheses compete across decision classes, not merely by name. Two
    # attack explanations can both be true (for example persistence_attempt
    # and suspicious_execution_chain). Treating them as mutually exclusive
    # lets one malicious hypothesis suppress another through the margin gate.
    # Compare an alert winner with the strongest non-alert explanation, and a
    # benign winner with the strongest alert explanation.
    winner_alerts = winner.hypothesis_id in alert_hypotheses
    competitors = [
        item for item in ranked[1:]
        if (item.hypothesis_id in alert_hypotheses) != winner_alerts
    ]
    runner_up = max((item.confidence for item in competitors), default=0.0)
    margin = max(0.0, winner.confidence - runner_up)
    winner_spec = next(spec for spec in spec_list
                       if spec.hypothesis_id == winner.hypothesis_id)

    action = "observe"
    if blockers:
        reason = "decision withheld because required evidence is unavailable"
    elif len(winner.supporting) < winner_spec.minimum_support:
        reason = (f"{winner.hypothesis_id} has only {len(winner.supporting)} "
                  f"supporting fact(s); {winner_spec.minimum_support} required")
    elif winner.confidence < winner_spec.decision_threshold:
        reason = (f"{winner.hypothesis_id} confidence {winner.confidence:.2f} "
                  f"is below {winner_spec.decision_threshold:.2f}")
    elif margin < minimum_margin:
        reason = (f"competing explanations are too close: margin "
                  f"{margin:.2f} < {minimum_margin:.2f}")
    elif winner.hypothesis_id in alert_hypotheses:
        action = "alert"
        reason = (f"{winner.hypothesis_id} is best supported at "
                  f"{winner.confidence:.2f} with margin {margin:.2f}")
    else:
        reason = (f"benign explanation {winner.hypothesis_id} is best "
                  f"supported; no security alert originated")

    return HypothesisDecision(
        selected=winner.hypothesis_id,
        action=action,
        confidence=winner.confidence,
        margin=round(margin, 4),
        assessments=tuple(assessments),
        blockers=blockers,
        reason=reason,
    )
