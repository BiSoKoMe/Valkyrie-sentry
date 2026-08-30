#!/usr/bin/env python3
"""Synthetic benchmark for the in-memory causal-authority reflex only.

This does not measure extension, native messaging, HTTP, browser, or network
latency. It isolates the deterministic issue-and-verify operation so later
implementations can be compared without changing the semantics.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.causal_authority import CausalAuthorityEngine, EgressRequest


def percentile(samples: list[float], fraction: float) -> float:
    ordered = sorted(samples)
    return ordered[max(0, min(len(ordered) - 1, int(len(ordered) * fraction) - 1))]


def run(iterations: int) -> dict[str, float | int]:
    engine = CausalAuthorityEngine()
    samples: list[float] = []
    for _ in range(iterations):
        interaction = str(uuid.uuid4())
        start = time.perf_counter_ns()
        engine.issue(
            interaction_id=interaction,
            source_origin="https://source.example",
            destination_origin="https://destination.example",
            tab_id=1, frame_id=0, action="form_submit",
            data_labels=("ordinary", "email"),
        )
        verdict = engine.verify_and_consume(EgressRequest(
            request_id=str(uuid.uuid4()), interaction_id=interaction,
            source_origin="https://source.example",
            destination_origin="https://destination.example",
            tab_id=1, frame_id=0, action="form_submit",
            data_labels=frozenset({"ordinary", "email"}),
        ))
        if not verdict.allowed:
            raise RuntimeError(verdict.reason)
        samples.append((time.perf_counter_ns() - start) / 1_000_000)
    return {
        "iterations": iterations,
        "mean_ms": statistics.fmean(samples),
        "p50_ms": percentile(samples, 0.50),
        "p95_ms": percentile(samples, 0.95),
        "p99_ms": percentile(samples, 0.99),
        "max_ms": max(samples),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=20_000)
    parser.add_argument("--require-p99-ms", type=float, default=0.0)
    args = parser.parse_args()
    result = run(max(1, args.iterations))
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.require_p99_ms and result["p99_ms"] > args.require_p99_ms:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
