"""Frozen synthetic cohorts for v2 generalization and ablation mechanics."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam.evaluation.generalization import (
    Ablation,
    build_frozen_scenarios,
    run_ablation,
)

frozen_scenarios = build_frozen_scenarios


def test_frozen_corpus_has_distinct_development_heldout_and_benign_cohorts():
    scenarios = frozen_scenarios()
    assert len(scenarios) == 30
    assert len({scenario.scenario_id for scenario in scenarios}) == 30
    assert sum(s.cohort == "development" for s in scenarios) == 6
    assert sum(s.cohort == "held_out" for s in scenarios) == 12
    assert sum(s.cohort == "benign" for s in scenarios) == 12


def test_ablation_reports_every_mode_without_claiming_independence():
    report = run_ablation(frozen_scenarios())
    assert set(report["modes"]) == {mode.value for mode in Ablation}
    assert not report["independent"]
    assert report["evidence_class"] == "synthetic mechanism evaluation"
    assert len(report["manifest_sha256"]) == 64
    for result in report["modes"].values():
        assert result["total"] == 30
        assert result["latency_ms"]["p99"] >= 0


def test_full_pipeline_recognizes_locked_variants_and_allows_benign_twins():
    report = run_ablation(frozen_scenarios())
    full = report["modes"][Ablation.FULL.value]
    assert full["recall"] == 1.0
    assert full["specificity"] == 1.0
    assert full["false_positive_rate"] == 0.0
    assert full["latency_ms"]["p99"] < 10.0


def test_ablation_does_not_fabricate_a_causal_gain():
    report = run_ablation(frozen_scenarios())
    context = report["modes"][Ablation.BEHAVIOR_CONTEXT.value]
    full = report["modes"][Ablation.FULL.value]
    # This corpus currently shows no recall gain from adding graph context.
    # Pin that honest result until an independent corpus demonstrates one.
    assert full["recall"] == context["recall"]


if __name__ == "__main__":
    test_frozen_corpus_has_distinct_development_heldout_and_benign_cohorts()
    test_ablation_reports_every_mode_without_claiming_independence()
    test_full_pipeline_recognizes_locked_variants_and_allows_benign_twins()
    test_ablation_does_not_fabricate_a_causal_gain()
    print("4 passed")
