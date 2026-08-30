"""valkyrie/aegis_planner.py -- the privacy planner tested on its own terms:
set-cover correctness, UNSAT as a first-class result, and multi-hypothesis
solving where one cut does not automatically solve another.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.aegis_exposure import ExposureObservation
from valkyrie.aegis_planner import Mechanism, plan


def test_already_safe_hypothesis_needs_no_mechanism():
    result = plan((), "f1", "f1", ("ACTIVITY_CLASSIFICATION",), ())
    assert result.satisfiable
    assert result.chosen_mechanisms == ()
    assert result.hypothesis_plans[0].status == "already_safe"


def test_worked_example_picks_the_two_cheap_mechanisms_over_the_expensive_combined_one():
    # The exact catalog shape from the research plan: M1 (timing, cost 2),
    # M2 (volume, cost 3), M3 (both, cost 8), M4 (destination, cost 4).
    # M1+M2 (cost 5) must beat M3 alone (cost 8).
    scenario = (
        ExposureObservation("ENTRY", "TIMING", "f_entry"),
        ExposureObservation("ENTRY", "VOLUME", "f_entry"),
        ExposureObservation("EXIT", "DESTINATION", "f_exit"),
        ExposureObservation("EXIT", "TIMING", "f_exit", precision=0.85),
        ExposureObservation("EXIT", "VOLUME", "f_exit", precision=0.85),
    )
    catalog = (
        Mechanism("M1", frozenset({"TIMING"}), cost=2),
        Mechanism("M2", frozenset({"VOLUME"}), cost=3),
        Mechanism("M3", frozenset({"TIMING", "VOLUME"}), cost=8),
        Mechanism("M4", frozenset({"DESTINATION"}), cost=4),
    )
    result = plan(scenario, "f_entry", "f_exit", ("FLOW_LINKAGE",), catalog)
    assert result.satisfiable
    assert set(result.chosen_mechanisms) == {"M1", "M2"}
    assert result.total_cost == 5


def test_neither_mechanism_alone_suffices():
    scenario = (
        ExposureObservation("ENTRY", "TIMING", "f_entry"),
        ExposureObservation("ENTRY", "VOLUME", "f_entry"),
        ExposureObservation("EXIT", "TIMING", "f_exit"),
        ExposureObservation("EXIT", "VOLUME", "f_exit"),
    )
    for lone in (
        (Mechanism("M1", frozenset({"TIMING"}), cost=2),),
        (Mechanism("M2", frozenset({"VOLUME"}), cost=3),),
    ):
        result = plan(scenario, "f_entry", "f_exit", ("FLOW_LINKAGE",), lone)
        assert not result.satisfiable


def test_two_hypotheses_that_do_not_share_a_solution_both_get_solved():
    # ACTIVITY_CLASSIFICATION here requires ALL of EXIT's timing/volume/
    # sequence removed (any one alone still clears the alert threshold), a
    # strictly larger requirement than FLOW_LINKAGE's own cut -- solving
    # FLOW_LINKAGE cheaply at ENTRY would leave ACTIVITY_CLASSIFICATION
    # fully untouched. The optimal joint plan (cost 12) instead cuts
    # FLOW_LINKAGE via EXIT's timing+volume, which is also 2/3 of what
    # ACTIVITY_CLASSIFICATION needs -- cheaper than solving them apart (14).
    scenario = (
        ExposureObservation("ENTRY", "TIMING", "f_entry"),
        ExposureObservation("ENTRY", "VOLUME", "f_entry"),
        ExposureObservation("EXIT", "TIMING", "f_exit"),
        ExposureObservation("EXIT", "VOLUME", "f_exit"),
        ExposureObservation("EXIT", "SEQUENCE", "f_exit"),
    )
    catalog = (
        Mechanism("M_entry_timing", frozenset({"TIMING"}), cost=1,
                 scope_observation_points=frozenset({"ENTRY"})),
        Mechanism("M_entry_volume", frozenset({"VOLUME"}), cost=1,
                 scope_observation_points=frozenset({"ENTRY"})),
        Mechanism("M_exit_timing", frozenset({"TIMING"}), cost=5,
                 scope_observation_points=frozenset({"EXIT"})),
        Mechanism("M_exit_volume", frozenset({"VOLUME"}), cost=5,
                 scope_observation_points=frozenset({"EXIT"})),
        Mechanism("M_exit_sequence", frozenset({"SEQUENCE"}), cost=2,
                 scope_observation_points=frozenset({"EXIT"})),
    )
    result = plan(scenario, "f_exit", "f_entry",
                 ("FLOW_LINKAGE", "ACTIVITY_CLASSIFICATION"), catalog)
    assert result.satisfiable
    assert result.total_cost == 12
    statuses = {p.hypothesis: p.status for p in result.hypothesis_plans}
    assert statuses == {"FLOW_LINKAGE": "planned", "ACTIVITY_CLASSIFICATION": "planned"}


def test_redundant_paths_choose_the_cheapest_realization():
    scenario = (
        ExposureObservation("ENTRY", "TIMING", "f_entry"),
        ExposureObservation("ENTRY", "VOLUME", "f_entry"),
        ExposureObservation("EXIT", "TIMING", "f_exit"),
        ExposureObservation("EXIT", "VOLUME", "f_exit"),
    )
    catalog = (
        Mechanism("M_entry_timing", frozenset({"TIMING"}), cost=9,
                 scope_observation_points=frozenset({"ENTRY"})),
        Mechanism("M_entry_volume", frozenset({"VOLUME"}), cost=9,
                 scope_observation_points=frozenset({"ENTRY"})),
        Mechanism("M_exit_timing", frozenset({"TIMING"}), cost=1,
                 scope_observation_points=frozenset({"EXIT"})),
        Mechanism("M_exit_volume", frozenset({"VOLUME"}), cost=1,
                 scope_observation_points=frozenset({"EXIT"})),
    )
    result = plan(scenario, "f_entry", "f_exit", ("FLOW_LINKAGE",), catalog)
    assert result.satisfiable
    assert set(result.chosen_mechanisms) == {"M_exit_timing", "M_exit_volume"}
    assert result.total_cost == 2


def test_unsat_when_no_mechanism_covers_the_required_category():
    scenario = (ExposureObservation("SINGLE", "DESTINATION", "f1"),)
    catalog = (
        Mechanism("M_timing_only", frozenset({"TIMING"}), cost=1),
        Mechanism("M_volume_only", frozenset({"VOLUME"}), cost=1),
    )
    result = plan(scenario, "f1", "f1", ("DESTINATION_DISCLOSURE",), catalog)
    assert not result.satisfiable
    assert result.chosen_mechanisms == ()
    assert result.total_cost == 0.0
    assert any("DESTINATION_DISCLOSURE" in r for r in result.remaining_exposure)
    assert result.hypothesis_plans[0].status == "unsatisfiable"


def test_unsat_never_reports_a_cost_or_chosen_mechanism():
    # A defensive invariant: UNSAT must never look like a cheap success.
    scenario = (ExposureObservation("SINGLE", "DESTINATION", "f1"),)
    result = plan(scenario, "f1", "f1", ("DESTINATION_DISCLOSURE",), ())
    assert not result.satisfiable
    assert result.total_cost == 0.0
    assert result.chosen_mechanisms == ()


def test_unknown_hypothesis_is_rejected():
    import pytest
    with pytest.raises(ValueError):
        plan((), "f1", "f1", ("NOT_A_REAL_HYPOTHESIS",), ())
