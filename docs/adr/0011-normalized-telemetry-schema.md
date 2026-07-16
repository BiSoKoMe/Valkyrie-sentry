# ADR 0011 — Normalized telemetry event schema

- **Status:** Accepted
- **Phase:** 3 (real endpoint telemetry) — foundation
- **Date:** 2026-07-12

## Context

The architecture audit's headline finding was that Valkyrie **only sees DNS**.
Phase 3 adds more signal sources — process starts, network connections, and later
kernel (ETW/eBPF) telemetry. The detection/correlation layer today consumes a
DNS-specific dict shaped by the Store. If every new source invented its own dict
shape, the correlator, dashboard, storage, and export would each grow a tangle of
per-source special cases.

The redesign calls for one internal schema (OCSF-inspired) as the lingua franca.
A full OCSF implementation is far more than this codebase needs; a small, explicit
normalized event is the right first step — and it must land *before* the
collectors so they have something to emit into.

## Decision

Add `valkyrie/telemetry.py` with `TelemetryEvent`: a source-agnostic envelope
with first-class common fields (category, activity, action, actor process,
target, severity, reason, source) and a `fields` dict for source-specific extras.
Controlled vocabularies (categories, actions, severities) are small constants;
`severity_rank` gives ordering. `to_dict`/`from_dict` round-trip for the bus,
WebSocket, and storage; `bus_message()` wraps it as `{"type":"telemetry", …}`.

An adapter `from_dns_event()` maps the existing Store DNS-decision stream into the
schema (decision → action, suspicion → severity), so the current signal source
speaks the same language as the new ones — with **no change to existing code**
(nothing consumes the schema yet; collectors and the correlator adopt it next).

## Change report

- **What changed:** new `valkyrie/telemetry.py` (+ tests). No existing module
  touched.
- **Why:** give every present and future signal source one normalized shape, so
  correlation/UI/storage/export are written once, not per source.
- **Security impact:** neutral now; enabling — uniform events are the
  prerequisite for cross-source correlation (e.g. tying a process exec to the DNS
  beacon it makes), which is where real detections come from.
- **Performance impact:** none (unused on the hot path until collectors emit).
- **Compatibility impact:** none — purely additive.
- **Risks:** minimal. The schema will evolve as collectors reveal needs; kept
  small and versionable (`fields` absorbs extras without breaking consumers).
- **Tests added:** `tests/test_telemetry_schema.py` — round-trip, bus wrapping,
  severity ordering, and DNS-adapter action/severity mapping incl. escalation and
  bus-message unwrapping. Full suite: 28 passed, 0 failed, 2 skipped.
- **Rollback plan:** delete `telemetry.py` and its test; nothing imports it yet.

## Consequences

There is now one normalized event type. The next increment — a cross-platform
process/network collector — emits `TelemetryEvent`s onto the shared `EventBus`
(ADR-0007), and the EDR correlator gains a second, non-DNS signal source for the
first time, directly narrowing the audit's biggest gap.
