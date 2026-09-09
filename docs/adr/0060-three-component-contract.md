# ADR 0060 - Valkyrie, NYX and Aegis component contract

Date: 2026-09-07 . Status: accepted . Follows: ADR 0059

## Context

The repository used the Aegis name for privacy exposure inference while the
intended product direction uses Aegis for Cortex XDR-style investigation and
correlation. Leaving both meanings active would make APIs, the console and
future policy authority ambiguous. It would also encourage three separate
engines to compete over the same host controls.

The first serious release serves one Windows PC with local management. That
scope needs one evidence plane and one response authority. It does not need
three agents with separate stores, policies or control channels.

## Decision

The product remains one local suite with three named responsibilities:

| Component | Owns | Does not own |
|---|---|---|
| Valkyrie | Endpoint and network observation, deterministic detection, policy authority and audited host response | Privacy inference presentation or case-only reasoning |
| NYX | Outbound privacy inspection, tracker correlation, exposure inference and explicitly enabled request rewrites | General host response or incident authority |
| Aegis | Durable cases, evidence correlation, investigation timeline and analyst workflow | Independent enforcement |

All three use the existing local evidence store and in-process event delivery.
All host-changing action continues through Valkyrie's response manager,
invariants and lease system. Aegis may request or present a response, but it
cannot bypass that boundary. NYX may rewrite a request only inside its explicit
privacy policy and acting mode.

The machine-readable contract lives in `valkyrie/capabilities.py` and is served
at `GET /api/v1/capabilities`. It describes ownership and product maturity. It
does not claim that a runtime sensor is healthy. Live health remains on each
component's status endpoint.

New Aegis investigation routes use `/api/v1/aegis/*`. Existing incidents are
the durable case backend, so a case keeps the same identifier, evidence and
timeline through the migration.

Privacy exposure inference moves to `/api/nyx/exposure/*`. The old
`/api/aegis/status` and `/api/aegis/ledger` routes remain compatibility aliases
with their original response shape. They may be removed only in a documented
major compatibility change.

## Consequences

The console can now present each component without lying about duplicated
capabilities. Aegis gains a useful foundation immediately because it opens real
cases and the existing evidence replay. NYX keeps its prior exposure reasoning
without a breaking route change.

The three components are product boundaries, not process-isolation boundaries.
Service separation can be added where privilege or failure containment demands
it, especially for the Windows response broker. Splitting the whole suite into
three services now would add failure modes without improving the single-PC
security model.

The contract deliberately excludes the unsigned driver, fleet management and
cross-endpoint correlation from release claims. Those require separate evidence
and qualification.
