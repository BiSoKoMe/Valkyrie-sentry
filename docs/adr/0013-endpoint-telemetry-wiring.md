# ADR 0013 — Wire process telemetry into the EDR pipeline

- **Status:** Accepted
- **Phase:** 3 (real endpoint telemetry)
- **Date:** 2026-07-12

## Context

ADR-0011 added the normalized event schema and ADR-0012 the process collector,
but nothing consumed them yet. This increment connects the collector to the live
detection pipeline so process activity becomes triageable incidents — the point
at which "Valkyrie sees only DNS" stops being true.

## Decision

- **`EdrEngine.ingest_telemetry(event)`** — accepts a `TelemetryEvent` (object or
  dict) from any non-DNS collector. Flagged / medium-and-above observations are
  converted to a `Detection` (with a rough MITRE technique derived from the
  process labels) and pushed through the **same correlation → incident pipeline**
  as DNS detections. Low/info observations are visibility only and are not
  escalated, so a normal process start does not become an incident.
- **`--endpoint` flag** (opt-in) — when set and the EDR layer is enabled,
  `__main__` starts a `ProcessCollector` whose `emit` calls
  `edr_engine.ingest_telemetry`. It degrades gracefully if psutil is missing.
- **AppContext** gains a `process_collector` field so the running collector is
  part of the injected service inventory (`components()`).

Opt-in (not default-on) is deliberate: the heuristics are young and process
polling adds some overhead and false positives, so we don't change default
behavior. It can graduate to default-on (with `--no-endpoint`) once matured.

## Change report

- **What changed:** `edr/engine.py` (`ingest_telemetry` + technique map);
  `__main__.py` (`--endpoint` flag + collector wiring); `context.py`
  (`process_collector` service); README flag doc.
- **Why:** deliver actual endpoint detection value — process-execution incidents
  correlated alongside DNS — closing the audit's biggest gap in a first,
  portable form.
- **Security impact:** positive. Valkyrie now surfaces LOLBin usage,
  Office-spawns-shell, and temp-dir execution as correlated incidents with MITRE
  tags. Observation only — it does not autonomously kill processes (the existing
  dry-run-first response actions remain the way to act).
- **Performance impact:** none unless `--endpoint` is passed. When on, a ~2s
  process-table poll, off the DNS hot path; detections reuse the existing
  correlation engine.
- **Compatibility impact:** none by default (opt-in flag). No existing behavior
  changes; DNS detection/correlation is untouched. `ingest_telemetry` is additive.
- **Risks:** heuristic false positives (admins legitimately using PowerShell) —
  contained because these are severity-tagged incidents for triage, not blocks,
  and the flag is opt-in. Poll-based collection can miss ultra-short-lived
  processes (documented; kernel sensor is the roadmap).
- **Tests added:** `tests/test_endpoint_integration.py` — flagged process exec →
  exactly one incident with the right process/severity; dict ingestion path;
  benign observation creates no incident. Existing EDR tests unaffected. Full
  suite: 30 passed, 0 failed, 2 skipped. `--endpoint` verified in `--help`.
- **Rollback plan:** revert the three edits (flag, wiring, `ingest_telemetry`);
  the collector module remains but is simply unused. Clean `git revert`.

## Consequences

Valkyrie now correlates a second, non-DNS signal source into incidents. The seam
is exactly what a future ETW (Windows) / eBPF (Linux) kernel sensor plugs into:
emit `TelemetryEvent`s, call `ingest_telemetry`, and the entire correlation, UI,
and response stack already handles them.
