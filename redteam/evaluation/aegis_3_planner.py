"""Aegis 3 planner, exercised against five required cases. No real network
transformation is added anywhere in this file -- every Mechanism here is
synthetic, declared only by which exposure categories it affects and an
abstract cost.

Explanation contract preserved per case:
    hypothesis -> supporting paths -> minimal cuts -> candidate mechanisms
    -> chosen plan -> cost -> remaining inference paths
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))

from valkyrie.aegis_exposure import ExposureObservation, evaluate_pair  # noqa: E402
from valkyrie.aegis_planner import Mechanism, plan  # noqa: E402


def _report_case(name: str, scenario, flow_a: str, flow_b: str, targets: tuple[str, ...],
                 catalog: tuple[Mechanism, ...]) -> dict:
    supporting_paths = {
        t: evaluate_pair(scenario, flow_a, flow_b)["decisions"][t]
        for t in targets
    }
    result = plan(scenario, flow_a, flow_b, targets, catalog)
    return {
        "case": name,
        "targets": list(targets),
        "supporting_paths": supporting_paths,
        "candidate_mechanisms": [m.to_dict() for m in catalog],
        "plan": result.to_dict(),
    }


# ---------------------------------------------------------------------------
# Case 1: Aegis 1B topology -- timing and volume EACH independently support
# FLOW_LINKAGE, so both relationships must be disrupted.
# ---------------------------------------------------------------------------
def case_1_aegis_1b_topology() -> dict:
    scenario = (
        ExposureObservation("ENTRY", "IDENTITY", "f_entry", precision=1.0),
        ExposureObservation("ENTRY", "TIMING", "f_entry", precision=1.0),
        ExposureObservation("ENTRY", "VOLUME", "f_entry", precision=1.0),
        ExposureObservation("EXIT", "DESTINATION", "f_exit", precision=1.0),
        ExposureObservation("EXIT", "TIMING", "f_exit", precision=0.85),
        ExposureObservation("EXIT", "VOLUME", "f_exit", precision=0.85),
    )
    catalog = (
        Mechanism("M1_timing", frozenset({"TIMING"}), cost=2),
        Mechanism("M2_volume", frozenset({"VOLUME"}), cost=3),
        Mechanism("M3_both", frozenset({"TIMING", "VOLUME"}), cost=8),
        Mechanism("M4_destination", frozenset({"DESTINATION"}), cost=4),
    )
    return _report_case("aegis_1b_topology", scenario, "f_entry", "f_exit",
                        ("FLOW_LINKAGE",), catalog)


# ---------------------------------------------------------------------------
# Case 2: multiple simultaneous hypotheses that do NOT share a solution.
# FLOW_LINKAGE needs the ENTRY<->EXIT timing/volume correlation broken.
# ACTIVITY_CLASSIFICATION is evaluated for f_exit alone (its own TIMING,
# VOLUME, and SEQUENCE at EXIT each independently clear the alert threshold
# at weight 0.6 -- removing any two of the three still leaves the survivor
# above threshold), so it needs ALL THREE of EXIT's own observations
# neutralized, a strictly larger, only-partially-overlapping requirement.
# A plan that only solves FLOW_LINKAGE (e.g. cheaply, at ENTRY) leaves
# ACTIVITY_CLASSIFICATION fully intact -- the planner must solve both.
# ---------------------------------------------------------------------------
def case_2_multiple_simultaneous_hypotheses() -> dict:
    scenario = (
        ExposureObservation("ENTRY", "TIMING", "f_entry", precision=1.0),
        ExposureObservation("ENTRY", "VOLUME", "f_entry", precision=1.0),
        ExposureObservation("EXIT", "TIMING", "f_exit", precision=1.0),
        ExposureObservation("EXIT", "VOLUME", "f_exit", precision=1.0),
        ExposureObservation("EXIT", "SEQUENCE", "f_exit", precision=1.0),
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
    # flow_a=f_exit so ACTIVITY_CLASSIFICATION (which only reads flow_a's own
    # observations) is evaluated against EXIT's data; FLOW_LINKAGE is
    # symmetric in (flow_a, flow_b) so the order doesn't affect it.
    return _report_case("multiple_simultaneous_hypotheses", scenario, "f_exit", "f_entry",
                        ("FLOW_LINKAGE", "ACTIVITY_CLASSIFICATION"), catalog)


# ---------------------------------------------------------------------------
# Case 3: redundant inference paths. FLOW_LINKAGE has 4 equivalent minimal
# cuts here (either endpoint of TIMING or VOLUME suffices) -- the planner
# must find the CHEAPEST one, not just any one.
# ---------------------------------------------------------------------------
def case_3_redundant_paths() -> dict:
    scenario = (
        ExposureObservation("ENTRY", "TIMING", "f_entry", precision=1.0),
        ExposureObservation("ENTRY", "VOLUME", "f_entry", precision=1.0),
        ExposureObservation("EXIT", "TIMING", "f_exit", precision=1.0),
        ExposureObservation("EXIT", "VOLUME", "f_exit", precision=1.0),
    )
    catalog = (
        # Expensive if scoped at ENTRY; cheap at EXIT -- the planner must
        # notice EXIT-scoped mechanisms are the cheaper way to realize one
        # of the four redundant cuts, not just the first one it finds.
        Mechanism("M_entry_timing", frozenset({"TIMING"}), cost=9,
                 scope_observation_points=frozenset({"ENTRY"})),
        Mechanism("M_entry_volume", frozenset({"VOLUME"}), cost=9,
                 scope_observation_points=frozenset({"ENTRY"})),
        Mechanism("M_exit_timing", frozenset({"TIMING"}), cost=1,
                 scope_observation_points=frozenset({"EXIT"})),
        Mechanism("M_exit_volume", frozenset({"VOLUME"}), cost=1,
                 scope_observation_points=frozenset({"EXIT"})),
    )
    return _report_case("redundant_paths", scenario, "f_entry", "f_exit",
                        ("FLOW_LINKAGE",), catalog)


# ---------------------------------------------------------------------------
# Case 4: held-out topology AND mechanism catalog, both written after the
# planner logic above was frozen. A single observer sees identity+
# destination+frequency for one flow (never exercised together by cases
# 1-3) -- tests USER_LINKABILITY (direct co-location) and
# DESTINATION_DISCLOSURE together.
# ---------------------------------------------------------------------------
def case_4_held_out() -> dict:
    scenario = (
        ExposureObservation("SINGLE", "IDENTITY", "f1", precision=1.0),
        ExposureObservation("SINGLE", "DESTINATION", "f1", precision=1.0),
        ExposureObservation("SINGLE", "FREQUENCY", "f1", precision=1.0),
    )
    catalog = (
        Mechanism("M_identity", frozenset({"IDENTITY"}), cost=5),
        Mechanism("M_destination", frozenset({"DESTINATION"}), cost=6),
        Mechanism("M_frequency", frozenset({"FREQUENCY"}), cost=1),
    )
    return _report_case("held_out_topology_and_catalog", scenario, "f1", "f1",
                        ("USER_LINKABILITY", "DESTINATION_DISCLOSURE"), catalog)


# ---------------------------------------------------------------------------
# Case 5: impossible case. DESTINATION_DISCLOSURE requires cutting the
# DESTINATION observation, but no mechanism in this catalog affects
# DESTINATION at all -- must return UNSAT, not a false sense of protection.
# ---------------------------------------------------------------------------
def case_5_unsat() -> dict:
    scenario = (ExposureObservation("SINGLE", "DESTINATION", "f1", precision=1.0),)
    catalog = (
        Mechanism("M_timing_only", frozenset({"TIMING"}), cost=1),
        Mechanism("M_volume_only", frozenset({"VOLUME"}), cost=1),
    )
    return _report_case("impossible_no_covering_mechanism", scenario, "f1", "f1",
                        ("DESTINATION_DISCLOSURE",), catalog)


def run() -> dict:
    return {
        "evidence_class": "planner correctness demonstration -- synthetic mechanisms, "
                          "no real privacy transformation",
        "success_criterion": "the planner selects actions from graph structure and "
                            "declared mechanism effects alone, never from hard-coded "
                            "knowledge of a specific experiment or privacy feature",
        "case_1_aegis_1b_topology": case_1_aegis_1b_topology(),
        "case_2_multiple_simultaneous_hypotheses": case_2_multiple_simultaneous_hypotheses(),
        "case_3_redundant_paths": case_3_redundant_paths(),
        "case_4_held_out_topology_and_catalog": case_4_held_out(),
        "case_5_unsat": case_5_unsat(),
        "limitations": [
            "Mechanism costs and affected_categories are synthetic and hand-chosen "
            "for each case, not derived from any real privacy technique.",
            "This does not measure observer accuracy (that lives in Aegis 1A/1B); it "
            "verifies the planner finds a correct, cheapest, feasible mechanism set "
            "given a declared catalog and the exposure graph's own cut structure.",
            "max_cut_size (default 3, inherited from valkyrie.aegis_exposure) bounds "
            "the search for minimal cuts; a hypothesis whose only cuts are larger "
            "than this bound is reported as unreachable_within_search_bound, not "
            "silently treated as unsatisfiable for a different reason.",
        ],
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2, default=str))
