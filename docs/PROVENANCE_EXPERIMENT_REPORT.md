# Provenance Experiment Report — Local Mechanism Run

## Status: MEASURED (synthetic mechanism only)

Run: `python tools/provenance_benchmark.py --events 1000`

| Metric | Result |
|---|---:|
| Events | 1,000 DNS artifacts |
| Throughput | 5,697.04 events/s |
| Ingest p50 | 0.1740 ms |
| Ingest p95 | 0.2686 ms |
| Ingest p99 | 0.3368 ms |
| Graph nodes / artifacts | 2 / 200 (artifact cap reached as designed) |

Host: Windows 11 build 26200, Python 3.12.10. Raw output is retained in
`docs/provenance-benchmark-local.json`.

## Interpretation

This measures only synchronous local `EdrEngine.ingest_telemetry()` cost after
process nodes exist. It does not measure DNS socket handling, TLS inspection,
process polling delay, OS scheduling, browser behavior, response enforcement,
false-positive rate, or security detection efficacy. It is therefore not a
claim of end-to-end real-time performance.

## Adversarial mechanism results

`tests/test_provenance_adversarial.py` passed against privacy-before-egress
reordering, PID reuse, absent parent provenance, duplicate event ids, and a
500-event burst. These are local structural tests; live workload and Atomic
validation remain blocked.
