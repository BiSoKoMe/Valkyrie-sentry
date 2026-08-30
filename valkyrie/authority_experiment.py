"""Reproducible evidence experiment for the browser causal-authority gate.

The experiment drives the real ``BrowserContextCollector`` and
``CausalAuthorityEngine`` with a fixed synthetic corpus.  It measures only the
in-process submit observation to deterministic verdict path.  It does not
exercise Chromium, native messaging, network I/O, or response enforcement.
"""

from __future__ import annotations

import json
import os
import platform
import statistics
import subprocess
import sys
import time
import uuid
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .browser_context import BrowserContextCollector
from .causal_authority import CausalAuthorityEngine


SCHEMA_VERSION = "1.0"
DEFAULT_AUTHORIZED = 500
DEFAULT_UNAUTHORIZED = 100
MAX_P99_MS = 10.0
PRIVACY_SENTINEL = "valkyrie-raw-sentinel-7f3c9a21"


class _Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _TelemetryRecorder:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def ingest_telemetry(self, event: object) -> None:
        self.events.append(event.to_dict())


@dataclass(frozen=True)
class _TrialSpec:
    scenario: str
    expected: str


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(len(ordered) * fraction) - 1))
    return ordered[index]


def _revision() -> str:
    if os.environ.get("GITHUB_SHA"):
        return os.environ["GITHUB_SHA"]
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], check=True, capture_output=True,
            text=True, timeout=5,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _event(number: int, *, event_type: str, interaction_id: str,
           source: str, destination: str, tab_id: int, frame_id: int,
           labels: list[str], user_initiated: bool) -> dict[str, Any]:
    return {
        "version": 1,
        "event_id": str(uuid.UUID(int=number + 1)),
        "event_type": event_type,
        "url": f"{source}/account?raw={PRIVACY_SENTINEL}",
        "destination_origin": f"{destination}/submit?raw={PRIVACY_SENTINEL}",
        "tab_id": tab_id,
        "frame_id": frame_id,
        "user_initiated": user_initiated,
        "gesture": "pointer" if event_type == "user_gesture" else "submit",
        "consent_state": "unknown",
        "browser": "chromium",
        "interaction_id": interaction_id,
        "intended_action": "form_submit" if event_type == "user_gesture" else "",
        "data_labels": labels + [PRIVACY_SENTINEL],
        "raw_form_value": PRIVACY_SENTINEL,
        "page_text": PRIVACY_SENTINEL,
        "cookie": PRIVACY_SENTINEL,
    }


def _corpus(authorized: int, unauthorized: int) -> list[_TrialSpec]:
    specs = [_TrialSpec("matching_grant", "allow") for _ in range(authorized)]
    scenarios = (
        "no_grant", "replay", "destination_changed", "source_changed",
        "tab_changed", "frame_changed", "labels_escalated", "expired",
    )
    specs.extend(
        _TrialSpec(scenarios[index % len(scenarios)], "refuse")
        for index in range(unauthorized)
    )
    return specs


def run_experiment(*, authorized: int = DEFAULT_AUTHORIZED,
                   unauthorized: int = DEFAULT_UNAUTHORIZED,
                   max_p99_ms: float = MAX_P99_MS) -> dict[str, Any]:
    """Run the fixed corpus and return a machine-readable evidence record."""
    if authorized < 1 or unauthorized < 1:
        raise ValueError("authorized and unauthorized counts must be positive")

    clock = _Clock()
    recorder = _TelemetryRecorder()
    engine = CausalAuthorityEngine(clock=clock)
    collector = BrowserContextCollector(
        recorder, token="e" * 32, authority=engine,
    )
    records: list[dict[str, Any]] = []
    scenario_counts: Counter[str] = Counter()

    for index, spec in enumerate(_corpus(authorized, unauthorized)):
        interaction = str(uuid.UUID(int=10_000 + index))
        source = f"https://source{index % 7}.example"
        destination = f"https://destination{index % 11}.example"
        tab_id = 1 + index % 13
        frame_id = index % 3
        grant_labels = ["ordinary", "email"] if index % 2 else ["ordinary"]

        gesture = _event(
            index * 3, event_type="user_gesture", interaction_id=interaction,
            source=source, destination=destination, tab_id=tab_id,
            frame_id=frame_id, labels=grant_labels, user_initiated=True,
        )
        submit = _event(
            index * 3 + 1, event_type="form_submit", interaction_id=interaction,
            source=source, destination=destination, tab_id=tab_id,
            frame_id=frame_id, labels=grant_labels, user_initiated=True,
        )

        if spec.scenario != "no_grant":
            issued = collector.ingest(gesture)
            if issued.get("event", {}).get("authority", {}).get("disposition") != "issued":
                raise RuntimeError(f"failed to issue grant for trial {index}")

        if spec.scenario == "replay":
            first = collector.ingest(dict(submit))
            if first["event"]["authority"]["disposition"] != "allow":
                raise RuntimeError(f"replay precursor was not allowed for trial {index}")
            submit["event_id"] = str(uuid.UUID(int=index * 3 + 3))
        elif spec.scenario == "destination_changed":
            submit["destination_origin"] = "https://changed.example/path"
        elif spec.scenario == "source_changed":
            submit["url"] = "https://changed-source.example/path"
        elif spec.scenario == "tab_changed":
            submit["tab_id"] = tab_id + 1000
        elif spec.scenario == "frame_changed":
            submit["frame_id"] = frame_id + 1000
        elif spec.scenario == "labels_escalated":
            submit["data_labels"] = grant_labels + ["payment", PRIVACY_SENTINEL]
        elif spec.scenario == "expired":
            clock.advance(2.1)

        started = time.perf_counter_ns()
        result = collector.ingest(submit)
        latency_ms = (time.perf_counter_ns() - started) / 1_000_000
        actual = result.get("event", {}).get("authority", {}).get("disposition", "invalid")
        reason = result.get("event", {}).get("authority", {}).get("reason", "")
        records.append({
            "trial": index + 1,
            "scenario": spec.scenario,
            "expected": spec.expected,
            "actual": actual,
            "correct": actual == spec.expected,
            "decision_latency_ms": round(latency_ms, 6),
            "reason": reason,
            "enforced": bool(
                result.get("event", {}).get("authority", {}).get("enforced", False)
            ),
            "attribution": "browser_semantic_no_process_pid",
        })
        scenario_counts[spec.scenario] += 1

    latencies = [record["decision_latency_ms"] for record in records]
    false_allows = sum(
        record["expected"] == "refuse" and record["actual"] == "allow"
        for record in records
    )
    false_refusals = sum(
        record["expected"] == "allow" and record["actual"] == "refuse"
        for record in records
    )
    incorrect = sum(not record["correct"] for record in records)
    retained_state = json.dumps({
        "records": records,
        "telemetry": recorder.events,
        "collector": collector.status(),
    }, sort_keys=True)
    privacy_leaks = retained_state.count(PRIVACY_SENTINEL)
    p99_ms = _percentile(latencies, 0.99)

    criteria = {
        "all_decisions_correct": incorrect == 0,
        "zero_false_allows": false_allows == 0,
        "zero_false_refusals": false_refusals == 0,
        "zero_raw_sentinel_leaks": privacy_leaks == 0,
        "in_process_p99_within_budget": p99_ms <= max_p99_ms,
        "responses_remained_observation_only": not any(
            record["enforced"] for record in records
        ),
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "experiment": "causal_authority_synthetic_corpus",
        "hypothesis": (
            "A fresh one-shot grant scoped to origin, destination, tab, frame, "
            "action, and data labels can distinguish the fixed authorized and "
            "unauthorized corpus locally without retaining raw values."
        ),
        "scope": (
            "In-process BrowserContextCollector submit observation through "
            "CausalAuthorityEngine verdict and normalized telemetry creation."
        ),
        "environment": {
            "os": platform.platform(),
            "python": platform.python_version(),
            "source_revision": _revision(),
            "github_run_id": os.environ.get("GITHUB_RUN_ID", ""),
        },
        "corpus": {
            "authorized": authorized,
            "unauthorized": unauthorized,
            "total": len(records),
            "scenario_counts": dict(sorted(scenario_counts.items())),
        },
        "thresholds": {
            "required_decision_accuracy": 1.0,
            "maximum_false_allows": 0,
            "maximum_false_refusals": 0,
            "maximum_raw_sentinel_leaks": 0,
            "maximum_in_process_p99_ms": max_p99_ms,
        },
        "metrics": {
            "correct": len(records) - incorrect,
            "incorrect": incorrect,
            "decision_accuracy": (len(records) - incorrect) / len(records),
            "false_allows": false_allows,
            "false_refusals": false_refusals,
            "raw_sentinel_leaks": privacy_leaks,
            "telemetry_events": len(recorder.events),
            "latency_ms": {
                "mean": statistics.fmean(latencies),
                "p50": _percentile(latencies, 0.50),
                "p95": _percentile(latencies, 0.95),
                "p99": p99_ms,
                "max": max(latencies),
            },
        },
        "criteria": criteria,
        "passed": all(criteria.values()),
        "records": records,
        "refused_claims": [
            "No real browser or native-messaging latency was measured.",
            "No network request was blocked or rewritten.",
            "No Windows PID was attributed from browser context.",
            "No malware efficacy or production false-positive rate was measured.",
            "No kernel driver was loaded or validated.",
        ],
    }


def render_markdown(evidence: dict[str, Any]) -> str:
    metrics = evidence["metrics"]
    latency = metrics["latency_ms"]
    lines = [
        "# Causal Authority Experiment Report",
        "",
        f"**Result:** {'PASS' if evidence['passed'] else 'FAIL'}",
        "",
        "## Question",
        "",
        evidence["hypothesis"],
        "",
        "## Fixed corpus and thresholds",
        "",
        f"- Authorized consequences: {evidence['corpus']['authorized']}",
        f"- Unauthorized consequences: {evidence['corpus']['unauthorized']}",
        "- Required decision accuracy: 100%",
        "- Allowed false allows and false refusals: 0",
        "- Allowed raw sentinel leaks: 0",
        f"- In-process p99 budget: {evidence['thresholds']['maximum_in_process_p99_ms']:.3f} ms",
        "",
        "## Results",
        "",
        f"- Correct decisions: {metrics['correct']}/{evidence['corpus']['total']}",
        f"- False allows: {metrics['false_allows']}",
        f"- False refusals: {metrics['false_refusals']}",
        f"- Raw sentinel leaks: {metrics['raw_sentinel_leaks']}",
        f"- In-process latency p50/p95/p99: {latency['p50']:.4f} / {latency['p95']:.4f} / {latency['p99']:.4f} ms",
        "",
        "## What this refuses to claim",
        "",
    ]
    lines.extend(f"- {claim}" for claim in evidence["refused_claims"])
    lines.extend([
        "",
        "The JSON evidence artifact contains every trial, its expected and actual",
        "verdict, the refusal reason, the measured in-process decision latency,",
        "and the source revision used for the run.",
        "",
    ])
    return "\n".join(lines)


def write_evidence(evidence: dict[str, Any], *, json_path: Path,
                   report_path: Path | None = None) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    if report_path is not None:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(render_markdown(evidence), encoding="utf-8")
