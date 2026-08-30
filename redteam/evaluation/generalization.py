"""Locked-cohort and ablation evaluation for Detection Architecture v2.

This is a mechanism harness, not independent efficacy evidence.  Scenarios are
synthetic and committed with the detector, so their results must never be
described as unseen real-world attacks.  Its job is to make generalization and
benign controls first-class and to prevent one aggregate percentage from
hiding the pipeline stage that failed.
"""

from __future__ import annotations

import hashlib
import json
import statistics
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Iterable

from valkyrie.edr.detection_v2 import DetectionArchitectureV2
from valkyrie.telemetry import TelemetryEvent, severity_rank

from .pipeline_trace import PipelineTrace, Stage, quality_matrix


class Ablation(str, Enum):
    RULE_BASELINE = "rule_baseline"
    BEHAVIOR_ONLY = "behavior_only"
    BEHAVIOR_CONTEXT = "behavior_context"
    FULL = "full"


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    cohort: str
    malicious: bool
    family: str
    events: tuple[TelemetryEvent, ...]
    causal_subgraph: dict | None = None

    def manifest_record(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "cohort": self.cohort,
            "malicious": self.malicious,
            "family": self.family,
            "events": [event.to_dict() for event in self.events],
            "causal_subgraph": self.causal_subgraph,
        }


@dataclass(frozen=True)
class ScenarioResult:
    scenario_id: str
    cohort: str
    malicious: bool
    predicted_malicious: bool
    correct: bool
    selected_hypothesis: str
    confidence: float
    latency_ms: float
    trace: PipelineTrace


def _process(pid: int, label: str, *, trusted: bool = False) -> TelemetryEvent:
    labels = [label]
    if trusted:
        labels.append("expected_maintenance")
    return TelemetryEvent(
        category="process", activity="exec", ts=float(pid), actor_pid=pid,
        actor_name="variant-host.exe", source="process_collector", labels=labels,
        fields={"create_time": float(pid), "event_id": f"p-{pid}"},
    )


def _network(pid: int) -> TelemetryEvent:
    return TelemetryEvent(
        category="network", activity="connect", ts=float(pid) + 0.1,
        actor_pid=pid, actor_name="variant-host.exe", source="network_collector",
        target={"ip": f"203.0.113.{pid % 200 + 1}"},
        fields={"event_id": f"n-{pid}"},
    )


def _persistence(pid: int) -> TelemetryEvent:
    return TelemetryEvent(
        category="persistence", activity="registry_run_key", ts=float(pid) + 0.2,
        actor_pid=pid, actor_name="variant-host.exe", source="persistence_collector",
        target={"location": rf"HKCU\Software\Run\v{pid}"},
        fields={"event_id": f"r-{pid}"},
    )


def _privacy(pid: int, authorized: bool) -> TelemetryEvent:
    return TelemetryEvent(
        category="privacy", activity="outbound_observation", ts=float(pid) + 0.3,
        actor_pid=pid, actor_name="variant-host.exe", source="nyx.tls",
        target={"domain": f"collector-{pid}.example"},
        labels=["nyx_leak"] + (["trusted_gesture"] if authorized else []),
        fields={"event_id": f"x-{pid}", "privacy_category": "identifier",
                "destination_host": f"collector-{pid}.example",
                "authorized": authorized, "body": f"sentinel-{pid}"},
    )


def _graph(pid: int) -> dict:
    root = {"key": "10/1", "pid": 10, "name": "document.exe",
            "parent_key": "", "inferred": False}
    child = {"key": f"{pid}/{pid}", "pid": pid, "name": "variant-host.exe",
             "parent_key": "10/1", "inferred": False}
    return {"found": True, "cgo": root, "chain": [root], "tree": [child],
            "artifacts": [], "truncated": False, "evicted": 0,
            "inferred_nodes": 0}


def build_frozen_scenarios() -> tuple[Scenario, ...]:
    """Return 30 committed mechanism cases across three explicit cohorts."""
    scenarios = []
    for index, family in enumerate(("execution", "persistence", "disclosure") * 2):
        pid = 100 + index
        events = [_process(pid, "office_child_shell"), _network(pid)]
        if family == "persistence":
            events.append(_persistence(pid))
        if family == "disclosure":
            events.append(_privacy(pid, False))
        scenarios.append(Scenario(f"dev-{family}-{index}", "development", True,
                                  family, tuple(events), _graph(pid)))

    variant_labels = ("lolbin", "encoded_powershell", "download_cradle", "dynamic_exec")
    for index in range(12):
        pid = 200 + index
        family = ("execution", "persistence", "disclosure")[index % 3]
        events = [_process(pid, variant_labels[index % len(variant_labels)]), _network(pid)]
        if family == "persistence":
            events.append(_persistence(pid))
        if family == "disclosure":
            events.append(_privacy(pid, False))
        scenarios.append(Scenario(f"held-{family}-{index}", "held_out", True,
                                  family, tuple(events), _graph(pid)))

    for index in range(12):
        pid = 300 + index
        family = ("developer", "maintenance", "authorized_disclosure")[index % 3]
        if family == "developer":
            events = (_process(pid, "user_initiated"), _network(pid))
        elif family == "maintenance":
            events = (_process(pid, "signed", trusted=True), _persistence(pid))
        else:
            events = (_process(pid, "user_initiated"), _network(pid), _privacy(pid, True))
        scenarios.append(Scenario(f"benign-{family}-{index}", "benign", False,
                                  family, tuple(events), _graph(pid)))
    return tuple(scenarios)


def manifest_hash(scenarios: Iterable[Scenario]) -> str:
    payload = [scenario.manifest_record() for scenario in scenarios]
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _rule_baseline(scenario: Scenario) -> tuple[bool, str, float, float, tuple[str, ...]]:
    predicted = any(
        str(event.action).lower() == "flagged"
        or severity_rank(str(event.severity)) >= severity_rank("medium")
        for event in scenario.events
    )
    return predicted, "legacy_rule_output", float(predicted), 0.0, ()


def run_scenario(scenario: Scenario, mode: Ablation) -> ScenarioResult:
    if mode == Ablation.RULE_BASELINE:
        predicted, selected, confidence, latency, evidence = _rule_baseline(scenario)
        trace = PipelineTrace(
            test_id=scenario.scenario_id, cohort=scenario.cohort,
            execution=Stage.YES, telemetry=Stage.YES,
            normalization=Stage.NOT_APPLICABLE, causal_link=Stage.NOT_APPLICABLE,
            behavior=Stage.NOT_APPLICABLE, hypothesis=Stage.NOT_APPLICABLE,
            decision=Stage.YES if predicted == scenario.malicious else Stage.NO,
            benign_control=(Stage.YES if not scenario.malicious and not predicted
                            else Stage.NO if not scenario.malicious else Stage.NOT_APPLICABLE),
            evidence_ids=evidence,
        )
        return ScenarioResult(scenario.scenario_id, scenario.cohort,
                              scenario.malicious, predicted,
                              predicted == scenario.malicious, selected,
                              confidence, latency, trace)

    architecture = DetectionArchitectureV2()
    last = None
    all_facts = []
    total_latency = 0.0
    for event in scenario.events:
        if mode == Ablation.BEHAVIOR_ONLY:
            # Remove cross-event state by using a fresh fabric for each event.
            architecture = DetectionArchitectureV2()
        subgraph = scenario.causal_subgraph if mode == Ablation.FULL else None
        last = architecture.observe(event, causal_subgraph=subgraph)
        all_facts.extend(last.facts)
        total_latency += last.fast_path_ms
    assert last is not None
    predicted = last.hypothesis.alerts
    correct = predicted == scenario.malicious
    causal_stage = (Stage.YES if scenario.causal_subgraph and mode == Ablation.FULL
                    else Stage.NOT_APPLICABLE)
    trace = PipelineTrace(
        test_id=scenario.scenario_id, cohort=scenario.cohort,
        execution=Stage.YES, telemetry=Stage.YES, normalization=Stage.YES,
        causal_link=causal_stage,
        behavior=Stage.YES if all_facts else Stage.NO,
        hypothesis=Stage.YES,
        decision=Stage.YES if correct else Stage.NO,
        prevention=Stage.NOT_APPLICABLE,
        benign_control=(Stage.YES if not scenario.malicious and not predicted
                        else Stage.NO if not scenario.malicious else Stage.NOT_APPLICABLE),
        evidence_ids=tuple(fact.fact_id for fact in all_facts),
    )
    return ScenarioResult(
        scenario.scenario_id, scenario.cohort, scenario.malicious,
        predicted, correct, last.hypothesis.selected,
        last.hypothesis.confidence, total_latency, trace,
    )


def run_ablation(scenarios: Iterable[Scenario]) -> dict:
    scenario_list = tuple(scenarios)
    modes = {}
    for mode in Ablation:
        results = [run_scenario(scenario, mode) for scenario in scenario_list]
        malicious = [result for result in results if result.malicious]
        benign = [result for result in results if not result.malicious]
        true_positive = sum(result.predicted_malicious for result in malicious)
        true_negative = sum(not result.predicted_malicious for result in benign)
        latencies = sorted(result.latency_ms for result in results)

        def percentile(p: float) -> float:
            if not latencies:
                return 0.0
            index = min(len(latencies) - 1, int((len(latencies) - 1) * p))
            return latencies[index]

        modes[mode.value] = {
            "total": len(results),
            "malicious": len(malicious),
            "benign": len(benign),
            "recall": true_positive / len(malicious) if malicious else None,
            "specificity": true_negative / len(benign) if benign else None,
            "false_positive_rate": (len(benign) - true_negative) / len(benign) if benign else None,
            "latency_ms": {
                "p50": statistics.median(latencies) if latencies else 0.0,
                "p95": percentile(0.95),
                "p99": percentile(0.99),
            },
            "quality_matrix": quality_matrix(result.trace for result in results),
            "results": [
                {**asdict(result), "trace": result.trace.to_dict()}
                for result in results
            ],
        }
    return {
        "evidence_class": "synthetic mechanism evaluation",
        "independent": False,
        "manifest_sha256": manifest_hash(scenario_list),
        "cohorts": {
            name: sum(scenario.cohort == name for scenario in scenario_list)
            for name in ("development", "held_out", "benign")
        },
        "modes": modes,
        "limitations": [
            "Scenarios are synthetic and committed with the detector.",
            "Held-out means a frozen evaluation cohort, not independent real-world novelty.",
            "Prevention is not measured because Detection Architecture v2 is shadow-only.",
        ],
    }
