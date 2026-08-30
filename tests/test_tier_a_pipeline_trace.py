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


def test_vocabulary_gap_is_now_closed_by_the_canonicalization_boundary():
    # Regression pin: before behavior_ontology.py existed, this was 39 (of 50
    # real rule-fires producing zero v2 evidence). It must stay reportable as
    # a specific, inspectable list -- never silently averaged away -- even
    # though the count itself is now 0.
    report = run()
    gap = report["vocabulary_gap"]
    assert gap["count"] == 0
    assert gap["catalog_ids"] == []
    assert "catalog_ids" in gap and "meaning" in gap


def test_pipeline_report_names_every_requested_stage():
    # The exact reporting shape asked for: real rules fired, source behaviors
    # emitted, successfully canonicalized, unmapped, canonical evidence
    # reaching v2, graph linkage, hypotheses formed, final verdicts.
    report = run()
    pipeline = report["pipeline"]
    for key in ("real_rules_fired", "source_behaviors_emitted",
               "successfully_canonicalized_behaviors", "unmapped_behaviors",
               "canonical_evidence_reaching_v2", "graph_linkage_success",
               "hypotheses_formed", "final_verdicts_alerted"):
        assert key in pipeline
    assert pipeline["unmapped_behaviors"] == 0
    assert pipeline["successfully_canonicalized_behaviors"] > pipeline["real_rules_fired"]


def test_formerly_gapped_techniques_now_reach_canonical_evidence():
    # Regression pin on the specific techniques test_tier_a_pipeline_trace's
    # earlier run named as gapped: their real classifier's real labels must
    # now canonicalize into a v2 fact.
    report = run()
    by_id = {t["catalog_id"]: t for t in report["traces"]}
    for catalog_id in ("exec-mshta-remote", "exec-regsvr32-squiblydoo",
                      "persist-wmi-subscription", "evasion-defender-disable"):
        trace = by_id[catalog_id]
        assert trace["v2_facts"], f"{catalog_id} still reaches no v2 evidence"
        assert not trace["unmapped_labels"]


def test_a_multi_label_technique_clears_the_evidence_threshold_honestly():
    # exec-mshta-remote's real classifier returns TWO distinct labels for one
    # command line (mshta_exec + clickfix_paste_exec), canonicalizing into two
    # DIFFERENT behaviors (lolbin_proxy_execution + obfuscated_execution) from
    # a single isolated event -- clearing detection_v2's >=2-supporting-fact
    # bar without a causal chain, and without touching any threshold.
    report = run()
    trace = next(t for t in report["traces"] if t["catalog_id"] == "exec-mshta-remote")
    assert len(set(trace["v2_facts"])) >= 2
    assert trace["decision"] == "yes"


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
    test_vocabulary_gap_is_now_closed_by_the_canonicalization_boundary()
    test_pipeline_report_names_every_requested_stage()
    test_formerly_gapped_techniques_now_reach_canonical_evidence()
    test_a_multi_label_technique_clears_the_evidence_threshold_honestly()
    test_hypothesis_scarcity_is_explained_not_hidden()
    test_evidence_class_is_distinct_from_the_synthetic_corpus()
    print("8 passed")
