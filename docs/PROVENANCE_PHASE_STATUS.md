# Provenance Architecture Phase Status

| Phase | Objective | Status | Evidence / boundary |
|---|---|---|---|
| 0 | Architecture audit | IMPLEMENTED | `PROVENANCE_ARCHITECTURE_ASSESSMENT.md` |
| 1 | Minimal process/artifact provenance | IMPLEMENTED / structurally tested | `causality.py`, `tests/test_causality.py` |
| 2 | Cross-layer correlation | IMPLEMENTED / experimental | normalized Nyx + DNS/process artifacts; browser semantics are metadata-only and not PID-attributed |
| 3 | Consequence reasoning | EXPERIMENTAL | `consequence.py`; mature baseline and provenance-completeness guards |
| 4 | Real enforcement | IMPLEMENTED for DNS; EXPERIMENTAL for the unified rule | inline DNS exists; unified future-DNS playbook is dry-run and gated |
| 5 | Nyx/security unification | IMPLEMENTED / integration tested | metadata-only Nyx telemetry, privacy retention tests, policy/authority gates |
| 6 | Adversarial validation | PARTIAL / LIVE VALIDATION BLOCKED | local adversarial tests and synthetic benchmark pass; no disposable VM for Atomic/Tier-B |
| 7 | Browser semantic context | EXPERIMENTAL / integration tested | Manifest V3 extension → native host → loopback bridge; privacy/API boundary tested, no live browser or VM evidence |

## What “all phases” can mean honestly

All repository-local implementation, structural integration, adversarial
mechanism, documentation, and synthetic-performance work is complete for the
current narrow experiment. Phases 6 and 7 cannot be promoted to live-validated,
and the unified rule cannot be armed for enforcement, until a disposable
isolated Windows VM supplies the required evidence.

## Required VM evidence before phase promotion

1. Snapshot-capable isolated Windows VM with a documented restore point.
2. Sysmon coverage for required event IDs and a healthy Valkyrie agent.
3. Atomic Red Team installed; record technique, execution outcome, telemetry,
   provenance, decision, response, latency, and false-positive impact.
4. A benign installer/updater workload control run.
5. Repeat the run after restoring the snapshot; do not promote from one pass.

### Current gate evidence (2026-08-28)

The available machine identifies as physical ASUS TUF Gaming A15 hardware,
not a VM. Sysmon64 is stopped and Invoke-AtomicRedTeam is absent. These facts
are read-only checks and explain the live-validation block; they are not a
substitute for the required VM experiment.
