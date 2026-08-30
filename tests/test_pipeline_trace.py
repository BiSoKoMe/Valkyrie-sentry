import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam.evaluation.pipeline_trace import (
    PipelineTrace,
    Stage,
    quality_matrix,
)


def test_pipeline_names_the_earliest_proven_failure():
    trace = PipelineTrace(
        test_id="atomic-T1033",
        execution=Stage.YES,
        telemetry=Stage.NO,
        normalization=Stage.UNKNOWN,
        decision=Stage.NO,
    )
    assert trace.first_failure() == "telemetry"
    assert trace.first_unknown() == "normalization"
    assert not trace.supports_detection_claim


def test_detection_claim_requires_every_reasoning_link():
    complete = PipelineTrace(
        test_id="held-out-variant",
        cohort="held_out",
        execution=Stage.YES,
        telemetry=Stage.YES,
        normalization=Stage.YES,
        causal_link=Stage.YES,
        behavior=Stage.YES,
        hypothesis=Stage.YES,
        decision=Stage.YES,
    )
    missing_graph = PipelineTrace(
        test_id="broken-graph",
        execution=Stage.YES,
        telemetry=Stage.YES,
        normalization=Stage.YES,
        causal_link=Stage.UNKNOWN,
        behavior=Stage.YES,
        hypothesis=Stage.YES,
        decision=Stage.YES,
    )
    assert complete.supports_detection_claim
    assert not missing_graph.supports_detection_claim


def test_unknown_stages_never_inflate_quality_rates():
    traces = [
        PipelineTrace("a", telemetry=Stage.YES, normalization=Stage.YES),
        PipelineTrace("b", cohort="held_out", telemetry=Stage.NO,
                      normalization=Stage.UNKNOWN),
        PipelineTrace("c", cohort="benign", telemetry=Stage.UNKNOWN,
                      normalization=Stage.UNKNOWN),
    ]
    matrix = quality_matrix(traces)
    assert matrix["stages"]["telemetry"] == {
        "passed": 1, "measured": 2, "rate": 0.5}
    assert matrix["stages"]["normalization"] == {
        "passed": 1, "measured": 1, "rate": 1.0}
    assert matrix["cohorts"] == {
        "development": 1, "held_out": 1, "benign": 1}


if __name__ == "__main__":
    test_pipeline_names_the_earliest_proven_failure()
    test_detection_claim_requires_every_reasoning_link()
    test_unknown_stages_never_inflate_quality_rates()
    print("3 passed")
