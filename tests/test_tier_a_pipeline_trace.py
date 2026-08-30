"""Tier A catalog -> Detection Architecture v2, stage by stage.

Unlike test_generalization_ablation.py (a committed synthetic corpus written
to exercise v2), this drives the REAL 90-technique redteam catalog through
the real v2 pipeline, using pipeline_trace.py's stage vocabulary so one
number can never hide which stage broke. See
redteam/evaluation/tier_a_pipeline_trace.py for what this can and cannot
claim.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam.evaluation.tier_a_pipeline_trace import SUPPORTED_PROBES, run


def test_covers_the_majority_of_the_catalog_and_names_the_rest():
    report = run()
    assert report["total_catalog"] >= 80
    assert report["covered"] >= 60
    assert report["covered"] + len(report["probe_unsupported"]) == report["total_catalog"]
    for entry in report["probe_unsupported"]:
        assert entry["probe"] not in SUPPORTED_PROBES


def test_telemetry_and_normalization_are_never_the_failure_here():
    # Every covered technique gets a real canonical event built from its real
    # classifier's real input -- these two stages should never be the reason
    # a technique fails in this harness.
    report = run()
    stages = report["quality_matrix"]["stages"]
    assert stages["telemetry"]["rate"] == 1.0
    assert stages["normalization"]["rate"] == 1.0


def test_vocabulary_gap_is_named_not_averaged_away():
    # The real finding this module exists to surface: legacy classifiers fire
    # with their own label vocabulary, and detection_v2's BehaviorEngine does
    # not recognise most of it yet. That must show up as a specific,
    # inspectable list, not vanish into an aggregate percentage.
    report = run()
    gap = report["vocabulary_gap"]
    assert gap["count"] > 0
    assert set(gap["catalog_ids"]) <= {
        e["catalog_id"] for e in report_traces_catalog_ids(report)
    }


def report_traces_catalog_ids(report):
    return [{"catalog_id": t["catalog_id"]} for t in report["traces"]]


def test_hypothesis_scarcity_is_explained_not_hidden():
    # detection_v2 requires >=2 supporting facts before an attack hypothesis
    # qualifies (see detection_v2._HYPOTHESES); every technique here is one
    # isolated event with no causal chain. A near-zero decision rate is
    # therefore expected -- this pins that it stays explained in the report's
    # own limitations rather than silently reading as "v2 barely works".
    report = run()
    assert report["quality_matrix"]["stages"]["decision"]["rate"] < 0.2
    assert any("hypothesis" in note.lower() and ">=2" in note
              for note in report["limitations"])


def test_evidence_class_is_distinct_from_the_synthetic_corpus():
    report = run()
    assert report["evidence_class"] != "synthetic mechanism evaluation"
    assert not report["independent"]
    assert report["limitations"]


if __name__ == "__main__":
    test_covers_the_majority_of_the_catalog_and_names_the_rest()
    test_telemetry_and_normalization_are_never_the_failure_here()
    test_vocabulary_gap_is_named_not_averaged_away()
    test_hypothesis_scarcity_is_explained_not_hidden()
    test_evidence_class_is_distinct_from_the_synthetic_corpus()
    print("5 passed")
