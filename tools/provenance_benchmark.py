#!/usr/bin/env python3
"""Measure local provenance-ingest cost under a reproducible synthetic burst.

This is a mechanism benchmark, not a security-efficacy test. It measures the
time from calling ``EdrEngine.ingest_telemetry`` to return for normalized DNS
artifacts after a real in-memory Store/EDR/causality pipeline has been built.
It deliberately reports host/configuration and percentile values instead of
claiming a universal "real-time" number.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path

# A directly executed repository tool has ``tools/`` as sys.path[0], not the
# repository root. Keep its import behavior identical to the test scripts.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.edr.engine import EdrEngine
from valkyrie.store import Store
from valkyrie.telemetry import CAT_DNS, CAT_PROCESS, TelemetryEvent


def _percentile(values: list[float], p: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    return ordered[min(len(ordered) - 1, round((len(ordered) - 1) * p))]


def run(events: int = 1_000) -> dict:
    events = max(1, int(events))
    with tempfile.TemporaryDirectory(prefix="valkyrie-provenance-") as directory:
        store = Store(db_path=Path(directory) / "benchmark.db")
        store.start()
        engine = EdrEngine(store)
        engine.start()
        try:
            engine.ingest_telemetry(TelemetryEvent(
                category=CAT_PROCESS, activity="exec", ts=time.time(), actor_pid=4100,
                actor_name="chrome.exe", source="process_collector"))
            engine.ingest_telemetry(TelemetryEvent(
                category=CAT_PROCESS, activity="exec", ts=time.time(), actor_pid=4101,
                actor_name="helper.exe", source="process_collector", fields={"ppid": 4100}))
            latencies = []
            started = time.perf_counter()
            for number in range(events):
                before = time.perf_counter()
                engine.ingest_telemetry(TelemetryEvent(
                    category=CAT_DNS, activity="query", ts=time.time(), actor_pid=4101,
                    actor_name="helper.exe", target={"domain": f"burst-{number}.example"},
                    source="provenance_benchmark"))
                latencies.append((time.perf_counter() - before) * 1_000)
            elapsed = time.perf_counter() - started
            return {
                "scope": "synthetic local ingest; not DNS hot-path or live efficacy",
                "host": {"platform": platform.platform(), "python": platform.python_version()},
                "events": events,
                "elapsed_seconds": elapsed,
                "throughput_events_per_second": events / elapsed if elapsed else 0.0,
                "ingest_latency_ms": {
                    "p50": _percentile(latencies, 0.50),
                    "p95": _percentile(latencies, 0.95),
                    "p99": _percentile(latencies, 0.99),
                    "mean": statistics.mean(latencies),
                },
                "graph": engine.causality_stats(),
            }
        finally:
            engine.stop()
            store.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=1_000)
    parser.add_argument("--output", type=Path,
                        help="optional JSON path; omitted means stdout only")
    args = parser.parse_args()
    result = run(args.events)
    text = json.dumps(result, indent=2, sort_keys=True)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
