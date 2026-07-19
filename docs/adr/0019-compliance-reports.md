# ADR 0019 — Compliance evidence reports

Date: 2026-07-19 · Status: accepted

## Context

Enterprise adoption requires evidence of operating controls (SOC 2 CC7.x,
ISO 27001 A.5.7/A.5.25-28/A.8.16): monitoring was running, incidents were
detected and resolved, response is audited, intel is current. Valkyrie
records all of that but had no way to hand it to an auditor.

## Decision

`valkyrie/compliance.py` — `ComplianceReporter(ctx).generate(hours)`
computes, at request time, from live services (no cached/hardcoded
values): monitoring coverage (wired components + heartbeat), incident
counts by severity/status, open high/critical, MTTR mean/median from
resolved incidents, threat-intel freshness incl. stale feeds, and the
response audit trail split human vs. playbook, plus SIEM export counters.
`render_markdown` produces the human-readable version.

API: `GET /api/compliance/report?hours=720&format=json|md` (token-gated
off loopback by the global guard).

## Honesty design (the module most tempted to lie)

- Every report opens with a disclaimer: **evidence toward controls, not a
  certification**. Framework refs label sections; no "compliant: true"
  field exists anywhere.
- Absent subsystems are reported `available: false` — never invented.
- Reports are generated and stay local.

## Rollback

Remove the module + route; read-only over existing data, nothing else
references it.

## Honest boundary

No scheduled report runs, no PDF, no control-by-control questionnaire
mapping, no multi-endpoint aggregation (the fleet server is that seam).
