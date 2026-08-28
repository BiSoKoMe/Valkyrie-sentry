# Provenance Experiments

| Experiment | Status | Evidence |
|---|---|---|
| Process lineage and PID-reuse safety | IMPLEMENTED / structurally tested | `tests/test_causality.py` |
| Nyx metadata → normalized telemetry → graph | IMPLEMENTED / integration tested | `tests/test_nyx.py`, `tests/test_privacy_consequence.py` |
| Privacy/security consequence rule | EXPERIMENTAL | `tests/test_privacy_consequence.py` |
| Policy + authority-gated future DNS response | EXPERIMENTAL / dry-run | `tests/test_privacy_consequence.py`, `tests/test_playbooks.py` (persisted-record gate included) |
| Event-ordering, duplicate, missing-attribution challenges | MEASURED (structural) | `tests/test_provenance_adversarial.py` |
| Throughput and latency characterization | MEASURED (synthetic ingest) | `tools/provenance_benchmark.py`, `docs/PROVENANCE_EXPERIMENT_REPORT.md` |
| Atomic Red Team / Tier-B validation | LIVE VALIDATION BLOCKED | requires isolated disposable Windows VM snapshot, Sysmon, and Invoke-AtomicRedTeam |

Synthetic and integration tests establish mechanism, not detection efficacy.
