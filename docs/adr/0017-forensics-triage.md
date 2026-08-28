# ADR 0017 - Digital forensics triage collection

Date: 2026-07-19 . Status: accepted

## Context

When an incident matters, volatile host state (process tree, connections,
persistence surface) decays in minutes. Every enterprise EDR ships
one-click triage collection; Valkyrie had the incident record but no
evidence preservation. Ranked next after SIEM export (ADR 0016): high
analyst value, fully local, zero new architecture.

## Decision

`valkyrie/forensics.py` - `TriageCollector.collect(incident_id)` builds a
zip bundle in `DATA_DIR/forensics/`:

| artifact | source |
|---|---|
| `incident.json` | EdrEngine incident + detections + responses + timeline |
| `events.json` | store events ±30 min around incident creation |
| `processes.json` | live process tree with ancestry/cmdlines (psutil) |
| `connections.json` | live inet connections |
| `persistence.json` | ASEP snapshot via the existing PersistenceCollector |
| `host.json` | hostname/OS/boot/users context |
| `MANIFEST.json` | SHA256 + size per artifact, tool version, timestamps, per-artifact collection errors |

`verify_bundle(path)` re-hashes artifacts against the manifest anywhere,
stdlib-only - the integrity half of chain of custody. Tamper on any
artifact is detected (tested).

API: `POST /api/edr/incidents/{id}/triage` (control-token-gated off
loopback, like all state-revealing routes).

## Key properties

- **Partial beats none:** each artifact is collected best-effort; failures
  are recorded in `collection_errors` instead of failing the bundle.
- **Local only / privacy:** bundles never leave the machine by themselves;
  they contain host state and are stored under the operator's data dir.
- **Performance:** full live bundle ≈ 200 ms measured.

## Rollback

Delete `forensics.py` + the route; nothing else references them. Bundles
are plain zips - readable without Valkyrie.

## Honest boundary

This is triage (state now + recent events), not full disk/memory forensic
imaging; no RAM capture, no MFT/registry hive export, no upload pipeline.
Each is a clean extension of the artifact-collector pattern when needed.
