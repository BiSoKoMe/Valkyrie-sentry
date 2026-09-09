#!/usr/bin/env python3
"""Run and document the deterministic v2 synthetic ablation experiment."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from redteam.evaluation.generalization import (  # noqa: E402
    Ablation,
    build_frozen_scenarios,
    run_ablation,
)

JSON_PATH = ROOT / "redteam" / "evaluation" / "results" / "detection_v2_latest.json"
REPORT_PATH = ROOT / "docs" / "DETECTION_V2_EXPERIMENT.md"


def _percent(value) -> str:
    return "N/A" if value is None else f"{100.0 * value:.1f}%"


def render(report: dict) -> str:
    lines = [
        "# Detection Architecture v2 Experiment",
        "",
        "**Evidence class:** synthetic mechanism evaluation.  ",
        "**Independent:** no.  ",
        f"**Frozen manifest SHA-256:** `{report['manifest_sha256']}`",
        "",
        "## Research question",
        "",
        "Can canonical events, shared behavioral evidence, contradictory evidence, "
        "and competing hypotheses recognize committed behavioral variants while "
        "allowing superficially similar benign activity?",
        "",
        "## Cohorts",
        "",
        f"- Development: {report['cohorts']['development']}",
        f"- Frozen held-out variants: {report['cohorts']['held_out']}",
        f"- Benign twins: {report['cohorts']['benign']}",
        "",
        "## Ablation results",
        "",
        "| Mode | Recall | Specificity | False-positive rate | p99 fast-path latency |",
        "|---|---:|---:|---:|---:|",
    ]
    for mode in Ablation:
        result = report["modes"][mode.value]
        lines.append(
            f"| {mode.value} | {_percent(result['recall'])} | "
            f"{_percent(result['specificity'])} | "
            f"{_percent(result['false_positive_rate'])} | "
            f"{result['latency_ms']['p99']:.4f} ms |"
        )
    lines.extend([
        "",
        "## Result",
        "",
        "The frozen synthetic corpus verifies the v2 mechanism and its privacy "
        "boundary. It does not establish real-world efficacy. In the current "
        "corpus, graph context does not improve recall over cross-event behavioral "
        "context. That means the causal contribution remains unproven rather than "
        "being credited because the architecture sounds sophisticated.",
        "",
        "## Limitations",
        "",
    ])
    lines.extend(f"- {item}" for item in report["limitations"])
    lines.extend([
        "- The corpus was authored in the same repository as the detector.",
        "- The v2 path is shadow-only and cannot execute prevention.",
        "- Independent Atomic and real-browser results must be reported separately.",
        "",
        "## Next falsifiable hypothesis",
        "",
        "On an independently executed Atomic cohort with stage-level telemetry, "
        "causal context should improve held-out behavioral recognition without "
        "increasing benign false positives or pushing fast-path p99 above 10 ms.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    report = run_ablation(build_frozen_scenarios())
    JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
    JSON_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    REPORT_PATH.write_text(render(report), encoding="utf-8")
    print(json.dumps({
        "json": str(JSON_PATH),
        "report": str(REPORT_PATH),
        "manifest_sha256": report["manifest_sha256"],
        "full": report["modes"][Ablation.FULL.value],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
