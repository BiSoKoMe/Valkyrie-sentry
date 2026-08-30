"""Aegis 2 replay: does the SAME generic exposure-graph code explain both
Aegis 1A and Aegis 1B's real findings, and does it generalize to a held-out
topology it was never designed around?
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam.evaluation.aegis_2_exposure_graph import run


def test_aegis_1a_activity_classification_survives_bucketing():
    report = run()
    a = report["aegis_1a"]
    assert a["control"]["action"] == "alert"
    assert a["bucketed"]["action"] == "alert"
    # The real finding: bucketing did not meaningfully weaken this hypothesis.
    assert a["bucketed"]["confidence"] >= a["control"]["confidence"] - 0.05


def test_aegis_1a_bucketed_evidence_includes_the_new_sequence_fact():
    report = run()
    facts = report["aegis_1a"]["bucketed"]["assessments"][0]["supporting"]
    behaviors = {f["behavior"] for f in facts}
    assert "sequence_available" in behaviors


def test_aegis_1b_exit_alone_matches_control_cross_session_linkability():
    report = run()
    b = report["aegis_1b"]
    assert b["control_cross_session_linkability"]["action"] == "alert"
    assert b["exit_alone_cross_session_linkability"]["action"] == "alert"
    assert b["exit_alone_cross_session_linkability"]["confidence"] == \
        b["control_cross_session_linkability"]["confidence"]


def test_aegis_1b_flow_linkage_and_composed_user_linkability_both_fire():
    report = run()
    b = report["aegis_1b"]
    assert b["entry_exit_flow_linkage"]["action"] == "alert"
    assert b["entry_exit_user_linkability"]["action"] == "alert"


def test_held_out_topology_correctly_shows_no_flow_linkage():
    # ENTRY exposes only TIMING, EXIT exposes only VOLUME/FREQUENCY -- no
    # shared correlatable category, so the same generic rule that fired for
    # Aegis 1B must correctly NOT fire here.
    report = run()
    h = report["held_out_three_point_relay"]
    assert h["entry_exit_flow_linkage"]["action"] != "alert"
    assert h["entry_exit_user_linkability"]["action"] != "alert"
    # But destination is still disclosed at EXIT regardless of linkage.
    assert h["exit_destination_disclosure"]["action"] == "alert"


def test_session_category_gap_is_named_not_hidden():
    report = run()
    assert "session_category_gap" in report["held_out_three_point_relay"]


def test_exposure_cut_examples_are_present_and_actually_flip_the_decision():
    report = run()
    cuts = report["exposure_cut_examples"]
    for cut in cuts.values():
        assert cut["cut"] is not None
        assert cut["remaining_action"] != "alert"


def test_success_criterion_is_stated_as_reasoning_not_accuracy():
    report = run()
    assert "generalizes" in report["success_criterion"]
    assert "explains" in report["success_criterion"]
    assert report["evidence_class"].startswith("reasoning/measurement replay")
