"""valkyrie/aegis_exposure.py -- the generic exposure-graph reasoning engine,
tested on its own terms (not through any specific replayed experiment).
Reuses valkyrie.edr.hypothesis's evidence-fusion machinery directly, so
these tests focus on Aegis-specific behavior: the exposure vocabulary,
fact derivation, the USER_LINKABILITY composition, and exposure_cut.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from valkyrie.aegis_exposure import (
    EXPOSURE_CATEGORIES,
    INFERENCE_HYPOTHESES,
    ExposureObservation,
    evaluate_pair,
    exposure_cut,
)


def test_unknown_category_is_rejected():
    with pytest.raises(ValueError):
        ExposureObservation("SINGLE", "NOT_A_REAL_CATEGORY", "f1")


def test_precision_out_of_range_is_rejected():
    with pytest.raises(ValueError):
        ExposureObservation("SINGLE", "TIMING", "f1", precision=1.5)


def test_no_observations_means_nothing_is_inferable():
    result = evaluate_pair((), "f1")
    for hyp in INFERENCE_HYPOTHESES:
        assert result["decisions"][hyp]["action"] != "alert"


def test_destination_alone_discloses_but_does_not_imply_user_linkability():
    scenario = (ExposureObservation("SINGLE", "DESTINATION", "f1"),)
    result = evaluate_pair(scenario, "f1")
    assert result["decisions"]["DESTINATION_DISCLOSURE"]["action"] == "alert"
    assert result["decisions"]["USER_LINKABILITY"]["action"] != "alert"


def test_identity_and_destination_at_the_same_point_gives_direct_user_linkability():
    scenario = (
        ExposureObservation("SINGLE", "IDENTITY", "f1"),
        ExposureObservation("SINGLE", "DESTINATION", "f1"),
    )
    result = evaluate_pair(scenario, "f1")
    assert result["decisions"]["USER_LINKABILITY"]["action"] == "alert"
    fact_ids = {f["fact_id"] for f in result["facts"]}
    assert any("colocated" in fid for fid in fact_ids)


def test_identity_and_destination_at_different_points_need_flow_linkage():
    # Split, with NOTHING correlatable shared between the two points --
    # neither direct co-location nor an established FLOW_LINKAGE exists.
    scenario = (
        ExposureObservation("ENTRY", "IDENTITY", "f_entry"),
        ExposureObservation("EXIT", "DESTINATION", "f_exit"),
    )
    result = evaluate_pair(scenario, "f_entry", "f_exit")
    assert result["decisions"]["FLOW_LINKAGE"]["action"] != "alert"
    assert result["decisions"]["USER_LINKABILITY"]["action"] != "alert"


def test_correlatable_category_at_both_points_establishes_flow_linkage():
    scenario = (
        ExposureObservation("ENTRY", "IDENTITY", "f_entry"),
        ExposureObservation("ENTRY", "TIMING", "f_entry"),
        ExposureObservation("EXIT", "DESTINATION", "f_exit"),
        ExposureObservation("EXIT", "TIMING", "f_exit"),
    )
    result = evaluate_pair(scenario, "f_entry", "f_exit")
    assert result["decisions"]["FLOW_LINKAGE"]["action"] == "alert"
    # And USER_LINKABILITY is now composed from that -- the exact mechanism
    # that explains Aegis 1B's "separated but re-linked" result.
    assert result["decisions"]["USER_LINKABILITY"]["action"] == "alert"
    provenance = result["decisions"]["USER_LINKABILITY"]["assessments"][0]["supporting"][0]["provenance"]
    assert any("FLOW_LINKAGE" in p for p in provenance)


def test_heavily_degraded_correlatable_precision_contradicts_flow_linkage():
    scenario = (
        ExposureObservation("ENTRY", "TIMING", "f_entry", precision=1.0),
        ExposureObservation("EXIT", "TIMING", "f_exit", precision=0.05),
    )
    result = evaluate_pair(scenario, "f_entry", "f_exit")
    facts = result["facts"]
    assert any(f["behavior"] == "timing_degraded" and "FLOW_LINKAGE" in f["contradicts"]
              for f in facts)


def test_exposure_cut_finds_a_minimal_removal_that_flips_the_decision():
    scenario = (ExposureObservation("SINGLE", "DESTINATION", "f1"),)
    cut = exposure_cut(scenario, "f1", "f1", "DESTINATION_DISCLOSURE")
    assert cut["cut_size"] == 1
    assert cut["remaining_action"] != "alert"


def test_exposure_cut_reports_already_not_established_when_nothing_to_cut():
    cut = exposure_cut((), "f1", "f1", "ACTIVITY_CLASSIFICATION")
    assert cut["already_not_established"] is True
    assert cut["cut"] is None


def test_unknown_hypothesis_target_is_rejected():
    with pytest.raises(ValueError):
        exposure_cut((), "f1", "f1", "NOT_A_REAL_HYPOTHESIS")


def test_canonical_vocabularies_match_the_spec():
    assert EXPOSURE_CATEGORIES == {
        "IDENTITY", "DESTINATION", "VOLUME", "TIMING", "SEQUENCE",
        "FREQUENCY", "SESSION", "DIRECTION"}
    assert INFERENCE_HYPOTHESES == {
        "ACTIVITY_CLASSIFICATION", "FLOW_LINKAGE", "CROSS_SESSION_LINKABILITY",
        "USER_LINKABILITY", "DESTINATION_DISCLOSURE"}
