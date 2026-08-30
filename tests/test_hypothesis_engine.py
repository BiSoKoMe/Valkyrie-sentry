"""Detection Architecture v2: evidence ledger and competing hypotheses."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.edr.causal_detect import (
    MIN_OBSERVATIONS,
    MIN_SESSIONS,
    CausalBaseline,
    evaluate_causal_hypotheses,
    score_subgraph,
)
from valkyrie.edr.hypothesis import (
    EvidenceFact,
    HypothesisSpec,
    evaluate_hypotheses,
)


def _node(key, pid, name, parent_key="", path=""):
    return {"key": key, "pid": pid, "name": name, "parent_key": parent_key,
            "path": path, "inferred": False, "terminator": False,
            "cmdline": "", "create_time": 1.0, "first_seen": 1.0,
            "last_seen": 2.0, "ppid": 0, "artifact_count": 0}


def _art(kind, summary, process, pid=200):
    return {"kind": kind, "summary": summary, "process": process,
            "pid": pid, "ts": 1.0, "data": {}}


def _chain(owner="winword.exe", shell="powershell.exe", *, truncated=False):
    root = _node("100/1", 100, owner, path=rf"c:\program files\{owner}")
    child = _node("200/1", 200, shell, parent_key="100/1")
    return {"found": True, "cgo": root, "chain": [root], "target": child,
            "tree": [child], "artifacts": [
                _art("registry", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", shell),
                _art("dns", "held-out.example", shell),
            ], "depth": 2, "inferred_nodes": 0,
            "truncated": truncated, "evicted": 0}


def _mature():
    baseline = CausalBaseline()
    baseline.observations = MIN_OBSERVATIONS
    baseline.sessions = MIN_SESSIONS
    return baseline


def test_generic_engine_deduplicates_and_records_contradiction():
    specs = (HypothesisSpec("attack", "attack", 0.60, 2),
             HypothesisSpec("benign", "benign", 0.60, 1))
    facts = [
        EvidenceFact("a", "unusual_parent", 0.7, supports=("attack",)),
        EvidenceFact("a", "duplicate", 1.0, supports=("attack",)),
        EvidenceFact("b", "sensitive_change", 0.7, supports=("attack",)),
        EvidenceFact("c", "known_admin", 0.6, supports=("benign",),
                     contradicts=("attack",)),
    ]
    decision = evaluate_hypotheses(
        specs, facts, alert_hypotheses=frozenset({"attack"}))
    attack = next(a for a in decision.assessments if a.hypothesis_id == "attack")
    assert len(attack.supporting) == 2
    assert len(attack.contradicting) == 1
    assert attack.contradiction_strength > 0


def test_two_attack_explanations_do_not_suppress_each_other():
    specs = (
        HypothesisSpec("execution", "execution", 0.60, 1),
        HypothesisSpec("persistence", "persistence", 0.60, 1),
        HypothesisSpec("benign", "benign", 0.60, 1),
    )
    facts = [
        EvidenceFact("e", "unexpected_chain", 0.80, supports=("execution",)),
        EvidenceFact("p", "autostart_change", 0.78, supports=("persistence",)),
    ]
    decision = evaluate_hypotheses(
        specs, facts,
        alert_hypotheses=frozenset({"execution", "persistence"}),
    )
    assert decision.alerts
    assert decision.margin >= 0.78


def test_rare_chain_selects_attack_with_auditable_ledger():
    baseline = _mature()
    finding = score_subgraph(_chain(), baseline)
    decision = evaluate_causal_hypotheses(_chain(), baseline, finding)
    assert finding.fires
    assert decision.alerts
    assert decision.selected == "malicious_execution"
    attack = next(a for a in decision.assessments
                  if a.hypothesis_id == "malicious_execution")
    assert {f.behavior for f in attack.supporting} >= {
        "full-intrusion-shape", "rare_on_this_host"}
    assert all(f.provenance for f in attack.supporting)


def test_benign_twin_selects_routine_activity():
    baseline = _mature()
    for _ in range(30):
        baseline.add_edge("winword.exe", "powershell.exe")
        baseline.add_artifact("powershell.exe", "registry")
        baseline.add_artifact("powershell.exe", "dns")
    finding = score_subgraph(_chain(), baseline)
    decision = evaluate_causal_hypotheses(_chain(), baseline, finding)
    assert not finding.fires
    assert not decision.alerts
    assert decision.selected == "routine_activity"
    attack = next(a for a in decision.assessments
                  if a.hypothesis_id == "malicious_execution")
    assert any(f.behavior == "routine_on_this_host"
               for f in attack.contradicting)


def test_trusted_maintenance_competes_with_attack_shape():
    baseline = _mature()
    chain = _chain(owner="msiexec.exe")
    decision = evaluate_causal_hypotheses(chain, baseline)
    assert not decision.alerts
    assert decision.selected == "trusted_maintenance"
    attack = next(a for a in decision.assessments
                  if a.hypothesis_id == "malicious_execution")
    assert any(f.behavior == "trusted_maintenance_lineage"
               for f in attack.contradicting)


def test_incomplete_graph_blocks_even_a_strong_chain():
    baseline = _mature()
    decision = evaluate_causal_hypotheses(_chain(truncated=True), baseline)
    assert not decision.alerts
    assert decision.blockers
    assert decision.blockers[0].behavior == "incomplete_provenance"


def test_held_out_script_host_reuses_existing_behavior_primitives():
    baseline = _mature()
    held_out = _chain(shell="wscript.exe")
    decision = evaluate_causal_hypotheses(held_out, baseline)
    assert decision.alerts
    assert decision.selected == "malicious_execution"


def test_engine_retains_hypothesis_ledger_on_originated_detection(tmp_path: Path):
    from valkyrie.edr import EdrEngine
    from valkyrie.store import Store

    engine = EdrEngine(Store(db_path=tmp_path / "state.db"))
    engine.start()
    engine._causal_baseline = _mature()
    graph = engine._causality
    graph.observe_process(100, "winword.exe", create_time=1.0,
                          path=r"c:\program files\office\winword.exe")
    graph.observe_process(200, "wscript.exe", ppid=100, create_time=2.0,
                          parent_name="winword.exe")
    graph.attribute(200, "registry", "run key", create_time=2.0,
                    data={"subject": r"HKCU\...\Run"})
    graph.attribute(200, "dns", "held-out.example", create_time=2.0,
                    data={"subject": "held-out.example"})

    engine._causal_check(200, "dns", create_time=2.0,
                         event_id="hypothesis-integration")

    detections = [d for d in engine._edr.list_detections()
                  if d.source == "edr.causal"]
    assert len(detections) == 1
    ledger = detections[0].details["hypothesis"]
    assert ledger["selected"] == "malicious_execution"
    assert ledger["action"] == "alert"
    assert ledger["assessments"]


if __name__ == "__main__":
    test_generic_engine_deduplicates_and_records_contradiction()
    test_two_attack_explanations_do_not_suppress_each_other()
    test_rare_chain_selects_attack_with_auditable_ledger()
    test_benign_twin_selects_routine_activity()
    test_trusted_maintenance_competes_with_attack_shape()
    test_incomplete_graph_blocks_even_a_strong_chain()
    test_held_out_script_host_reuses_existing_behavior_primitives()
    with tempfile.TemporaryDirectory(prefix="valkyrie_hypothesis_") as tmp:
        test_engine_retains_hypothesis_ledger_on_originated_detection(Path(tmp))
    print("8 passed")
