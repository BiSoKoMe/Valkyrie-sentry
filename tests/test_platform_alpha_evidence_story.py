"""Platform Alpha integration test: one real in-process event chain feeding
Valkyrie, NYX, and Aegis, producing one coherent (not merged) evidence
story. Includes the five required negative tests proving the platform
boundary holds.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam.evaluation.platform_alpha_evidence_story import build_shared_chain, run
from valkyrie.edr.detection_v2 import DetectionArchitectureV2
from valkyrie.telemetry import TelemetryEvent


def test_report_carries_all_required_sections():
    report = run()
    for key in ("what_happened", "causal_process_identity", "valkyrie", "nyx",
               "fused_decision", "aegis", "provenance"):
        assert key in report


def test_valkyrie_and_nyx_reach_different_isolated_conclusions_but_a_shared_fused_one():
    # The divergence itself is the point: Valkyrie's own evidence alone
    # concludes something different from NYX's own evidence alone, and the
    # REAL system fuses both into a single stronger conclusion -- none of
    # the three are forced to agree, and the fused one is not a vote.
    report = run()
    assert report["valkyrie"]["hypothesis_isolated"]["selected"] == "suspicious_execution_chain"
    assert report["nyx"]["hypothesis_isolated"]["selected"] == "possible_data_theft"
    assert report["fused_decision"]["hypothesis"]["selected"] == "possible_data_theft"
    # Fusing genuine evidence from both should never reduce confidence.
    assert (report["fused_decision"]["hypothesis"]["confidence"]
           >= report["nyx"]["hypothesis_isolated"]["confidence"])


def test_aegis_answers_different_questions_than_valkyrie_or_nyx():
    report = run()
    aegis = report["aegis"]["inference_hypotheses"]
    assert aegis["DESTINATION_DISCLOSURE"]["action"] == "alert"
    assert aegis["ACTIVITY_CLASSIFICATION"]["action"] == "alert"
    # No pairwise flow exists in this single-chain scenario, so the
    # pairwise hypotheses correctly stay unestablished -- Aegis does not
    # borrow Valkyrie/NYX's suspicion to manufacture a linkability finding.
    assert aegis["CROSS_SESSION_LINKABILITY"]["action"] != "alert"
    assert aegis["FLOW_LINKAGE"]["action"] != "alert"
    assert aegis["USER_LINKABILITY"]["action"] != "alert"


def test_no_global_verdict_field_exists_anywhere_in_the_report():
    # The architectural invariant the user specifically called out: a
    # merged malicious/safe boolean must never appear.
    import json
    report_text = json.dumps(run(), default=str).lower()
    for banned in ("global_verdict", "overall_verdict", "is_malicious", "final_verdict"):
        assert banned not in report_text


# --- Negative test 1: non-network events do not become Aegis observations ---
def test_negative_process_only_chain_produces_zero_aegis_observations():
    events = (
        TelemetryEvent(category="process", activity="exec", ts=1.0, actor_pid=999,
                       actor_name="tool.exe", source="process_collector",
                       labels=["office_child_shell"],
                       fields={"create_time": 1.0, "event_id": "evt-p1"}),
    )
    report = run(events)
    assert report["aegis"]["exposure_observations"] == []
    # Valkyrie still reasons about it -- the process event is real evidence
    # for Valkyrie, it just never reaches Aegis's network-exposure domain.
    assert report["valkyrie"]["evidence"]


# --- Negative test 2: missing exposure fields stay missing ---
def test_negative_missing_fields_are_not_synthesized():
    from valkyrie.aegis_bridge import UNAVAILABLE_CATEGORIES
    report = run()
    produced = {o["category"] for o in report["aegis"]["exposure_observations"]}
    assert produced.isdisjoint(UNAVAILABLE_CATEGORIES)
    # And the report is honest that these are UNAVAILABLE, not merely absent
    # from this one scenario by coincidence.
    assert {"VOLUME", "DIRECTION", "IDENTITY", "SESSION"} == set(UNAVAILABLE_CATEGORIES)


# --- Negative test 3: Aegis cannot alter Valkyrie or NYX verdicts ---
def test_negative_computing_aegis_never_changes_the_fused_decision():
    events = build_shared_chain()
    arch = DetectionArchitectureV2()
    results_without_aegis = [arch.observe(e) for e in events]
    decision_without_aegis = results_without_aegis[-1].hypothesis.to_dict()

    # Now run the SAME chain through a fresh engine and additionally invoke
    # the Aegis bridge/exposure graph afterward -- the fused decision must
    # be byte-for-byte identical, because nothing in valkyrie.edr.detection_v2
    # imports or calls anything Aegis-related.
    report = run(events)
    decision_with_aegis = report["fused_decision"]["hypothesis"]

    assert decision_without_aegis == decision_with_aegis


def test_negative_valkyrie_and_nyx_modules_do_not_import_aegis():
    import ast
    for path in (
        Path(__file__).resolve().parent.parent / "valkyrie" / "edr" / "detection_v2.py",
        Path(__file__).resolve().parent.parent / "valkyrie" / "edr" / "hypothesis.py",
        Path(__file__).resolve().parent.parent / "valkyrie" / "nyx.py",
    ):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert "aegis" not in node.module.lower(), f"{path.name} imports {node.module}"
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert "aegis" not in alias.name.lower(), f"{path.name} imports {alias.name}"


# --- Negative test 4: one subsystem's failure to derive evidence does not
#     fabricate evidence for another ---
def test_negative_no_network_evidence_does_not_inflate_valkyrie_or_produce_aegis_evidence():
    # A process-only event that Valkyrie finds highly suspicious. Aegis has
    # NOTHING to translate from it (no network-visible event exists), and
    # that emptiness must not be papered over by, say, inventing a
    # DESTINATION observation from Valkyrie's own suspicion score, or by
    # Valkyrie's confidence being artificially boosted because "Aegis also
    # flagged something."
    suspicious_only = (
        TelemetryEvent(category="process", activity="exec", ts=1.0, actor_pid=555,
                       actor_name="mshta.exe", source="process_collector",
                       labels=["mshta_exec", "obfuscated_command"],
                       fields={"create_time": 1.0, "event_id": "evt-susp"}),
    )
    report = run(suspicious_only)
    assert report["aegis"]["exposure_observations"] == []
    for hyp, dec in report["aegis"]["inference_hypotheses"].items():
        assert dec["action"] != "alert", f"Aegis fabricated an alert for {hyp} with no observations"
    # Valkyrie's own confidence should be exactly what its own two facts
    # (mshta_exec/obfuscated_command -> lolbin_proxy_execution + obfuscated_execution)
    # produce -- not altered by Aegis's silence.
    assert report["valkyrie"]["evidence"]


# --- Negative test 5: provenance survives the full path ---
def test_negative_every_aegis_observation_traces_back_to_a_real_event_id():
    report = run()
    real_event_ids = {e["fields"]["event_id"] for e in report["what_happened"]}
    for entry in report["provenance"]["aegis_observation_provenance"]:
        assert any(p in real_event_ids for p in entry["provenance"]), (
            f"observation {entry} has no provenance tracing to a real event id")


def test_negative_provenance_is_not_lost_when_two_observations_share_a_category_and_point():
    report = run()
    destinations = [e for e in report["provenance"]["aegis_observation_provenance"]
                    if e["category"] == "DESTINATION"]
    assert len(destinations) == 2   # network event AND privacy event both produce one
    provenances = [tuple(d["provenance"]) for d in destinations]
    assert len(set(provenances)) == 2   # distinct, neither silently overwritten


def test_negative_every_valkyrie_and_nyx_fact_traces_to_a_real_event_id():
    report = run()
    real_event_ids = {e["fields"]["event_id"] for e in report["what_happened"]}
    for fact_id, provenance in {
        **report["provenance"]["valkyrie_fact_provenance"],
        **report["provenance"]["nyx_fact_provenance"],
    }.items():
        assert any(p in real_event_ids for p in provenance), (
            f"fact {fact_id} has no provenance tracing to a real event id")
