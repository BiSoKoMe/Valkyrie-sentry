"""Layer-by-layer diagnosis for defensive evaluation runs.

One detection percentage cannot distinguish a blind sensor from a broken
normalizer or a reasoning miss.  ``PipelineTrace`` keeps those outcomes
separate and refuses to infer an unobserved stage from a later result.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass
from enum import Enum


class Stage(str, Enum):
    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


_ORDER = (
    "execution",
    "telemetry",
    "normalization",
    "causal_link",
    "behavior",
    "hypothesis",
    "decision",
    "prevention",
    "benign_control",
)


@dataclass(frozen=True)
class PipelineTrace:
    test_id: str
    cohort: str = "development"  # development | held_out | benign
    execution: Stage = Stage.UNKNOWN
    telemetry: Stage = Stage.UNKNOWN
    normalization: Stage = Stage.UNKNOWN
    causal_link: Stage = Stage.UNKNOWN
    behavior: Stage = Stage.UNKNOWN
    hypothesis: Stage = Stage.UNKNOWN
    decision: Stage = Stage.UNKNOWN
    prevention: Stage = Stage.NOT_APPLICABLE
    benign_control: Stage = Stage.NOT_APPLICABLE
    evidence_ids: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    def first_failure(self) -> str:
        """Return the earliest proven pipeline failure, never a guess."""
        for name in _ORDER:
            if getattr(self, name) == Stage.NO:
                return name
        return ""

    def first_unknown(self) -> str:
        for name in _ORDER:
            if getattr(self, name) == Stage.UNKNOWN:
                return name
        return ""

    @property
    def supports_detection_claim(self) -> bool:
        required = (self.execution, self.telemetry, self.normalization,
                    self.causal_link, self.behavior, self.hypothesis,
                    self.decision)
        return all(stage == Stage.YES for stage in required)

    def to_dict(self) -> dict:
        data = asdict(self)
        for name in _ORDER:
            data[name] = getattr(self, name).value
        data["first_failure"] = self.first_failure()
        data["first_unknown"] = self.first_unknown()
        data["supports_detection_claim"] = self.supports_detection_claim
        return data


def quality_matrix(traces: Iterable[PipelineTrace]) -> dict:
    """Aggregate only measured YES/NO stages; UNKNOWN never enters a rate."""
    trace_list = tuple(traces)
    stages: dict[str, dict] = {}
    for name in _ORDER:
        measured = [getattr(trace, name) for trace in trace_list
                    if getattr(trace, name) in (Stage.YES, Stage.NO)]
        passed = sum(stage == Stage.YES for stage in measured)
        stages[name] = {
            "passed": passed,
            "measured": len(measured),
            "rate": (passed / len(measured)) if measured else None,
        }
    cohorts = {
        cohort: sum(trace.cohort == cohort for trace in trace_list)
        for cohort in ("development", "held_out", "benign")
    }
    failures: dict[str, int] = {}
    for trace in trace_list:
        failure = trace.first_failure()
        if failure:
            failures[failure] = failures.get(failure, 0) + 1
    return {"total": len(trace_list), "cohorts": cohorts,
            "stages": stages, "first_failures": failures}
