# Provenance Model

## Status: IMPLEMENTED (metadata provenance); OS-LIMITED (complete provenance)

`TelemetryEvent` is the ingestion contract. `EdrEngine._record_causality()`
creates process nodes keyed by `(pid, create_time)` and attaches artifacts to
the responsible process. `CausalityGraph.subgraph()` returns CGO, lineage,
descendants, artifacts, and explicit integrity flags (`inferred_nodes`,
`truncated`, `evicted`).

Privacy telemetry has the same path. It may retain only data-flow category,
destination, first-party origin, attribution confidence, and event id. The
graph rejects neither a missing process start nor a PID reuse risk silently:
missing lineage is flagged inferred and consequence scoring suppresses it.

It is not a complete Windows provenance recorder. Polling and user-mode port
attribution can miss, delay, or ambiguously associate activity; pre-operation
file and registry provenance needs a signed kernel component.
