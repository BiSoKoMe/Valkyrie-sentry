"""Aegis 3 replay: all five required planner cases, run through the actual
redteam harness (not re-derived here) to confirm the full explanation
contract -- hypothesis -> supporting paths -> minimal cuts -> candidate
mechanisms -> chosen plan -> cost -> remaining inference paths -- survives
end to end.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam.evaluation.aegis_3_planner import run


def test_case_1_matches_the_hand_worked_example():
    report = run()
    plan = report["case_1_aegis_1b_topology"]["plan"]
    assert plan["satisfiable"]
    assert set(plan["chosen_mechanisms"]) == {"M1_timing", "M2_volume"}
    assert plan["total_cost"] == 5


def test_case_2_solves_both_hypotheses_not_just_one():
    report = run()
    plan = report["case_2_multiple_simultaneous_hypotheses"]["plan"]
    assert plan["satisfiable"]
    statuses = {p["hypothesis"]: p["status"] for p in plan["hypothesis_plans"]}
    assert statuses == {"FLOW_LINKAGE": "planned", "ACTIVITY_CLASSIFICATION": "planned"}


def test_case_3_picks_the_cheap_side_of_the_redundant_paths():
    report = run()
    plan = report["case_3_redundant_paths"]["plan"]
    assert plan["satisfiable"]
    assert set(plan["chosen_mechanisms"]) == {"M_exit_timing", "M_exit_volume"}
    assert plan["total_cost"] == 2


def test_case_4_held_out_topology_and_catalog_solves_correctly():
    report = run()
    plan = report["case_4_held_out_topology_and_catalog"]["plan"]
    assert plan["satisfiable"]
    statuses = {p["hypothesis"]: p["status"] for p in plan["hypothesis_plans"]}
    assert statuses == {"USER_LINKABILITY": "planned", "DESTINATION_DISCLOSURE": "planned"}


def test_case_5_is_unsat_not_a_false_sense_of_protection():
    report = run()
    plan = report["case_5_unsat"]["plan"]
    assert not plan["satisfiable"]
    assert plan["chosen_mechanisms"] == []
    assert plan["total_cost"] == 0.0
    assert plan["remaining_exposure"]


def test_every_case_preserves_the_full_explanation_contract():
    report = run()
    for key in ("case_1_aegis_1b_topology", "case_2_multiple_simultaneous_hypotheses",
               "case_3_redundant_paths", "case_4_held_out_topology_and_catalog",
               "case_5_unsat"):
        case = report[key]
        assert "supporting_paths" in case      # hypothesis -> supporting paths
        assert "candidate_mechanisms" in case  # candidate mechanisms
        assert "plan" in case                  # chosen plan + cost + remaining paths
        assert "total_cost" in case["plan"]
        assert "remaining_exposure" in case["plan"]
        for hp in case["plan"]["hypothesis_plans"]:
            assert "hypothesis" in hp and "status" in hp  # explains each hypothesis's own outcome


def test_no_real_mitigation_language_anywhere_in_the_mechanism_catalogs():
    # The stage's own constraint: mechanisms must stay declarative, never
    # named after a real production privacy technique.
    report = run()
    banned = {"padding", "jitter", "relay", "vpn", "onion", "mix network"}
    for key in ("case_1_aegis_1b_topology", "case_2_multiple_simultaneous_hypotheses",
               "case_3_redundant_paths", "case_4_held_out_topology_and_catalog",
               "case_5_unsat"):
        for mech in report[key]["candidate_mechanisms"]:
            name = mech["name"].lower()
            assert not any(word in name for word in banned)
