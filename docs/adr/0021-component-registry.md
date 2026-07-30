# ADR 0021 — Component registry: the uniform plugin contract

Date: 2026-07-19 · Status: accepted

## Context

The platform vision (docs/ARCHITECTURE.md) calls for a plugin architecture:
every subsystem registers itself and exposes health, metrics, config, and
events, and restarts independently without crashing the engine. Valkyrie
already had the *pieces* — the EventBus, the SensorManager's watchdog, the
SelfHealing loop, `AppContext.components()` — but three separate lifecycle
mechanisms and a different ad-hoc `status()`/`stats()` shape per service.
There was no single contract to observe or manage a subsystem uniformly.

## Decision

`valkyrie/components.py` adds the contract by **adaptation, not rewrite**:

- **`Component`** wraps an existing service object and normalizes it. It
  introspects for the methods the service already has —
  `available()` → `disabled`, `is_healthy()` → `up`/`degraded`,
  `is_running()` → `up`/`down`, `status()`/`stats()` → metrics,
  `start()`+`stop()` → restartable. No service changed a line.
- **`ComponentRegistry`** is the plugin host: `register`/`snapshot`/
  `health`/`overall`/`restart`. Every probe is fault-isolated — a
  component whose `health()` or `metrics()` raises is reported as `error`
  (or `_error` metrics) and can never crash the registry or the engine,
  the same guarantee the EventBus gives subscribers.
- **Event-driven**: health-state *transitions* publish a `component` event
  onto an EventBus, so future correlation and the dashboard can react to a
  subsystem degrading in real time.
- Wired in the composition root (`__main__`): 15 subsystems register with a
  `kind` (network/detection/sensor/response/privacy/…); exposed via
  `GET /api/components` (health + metrics + config + `overall`) and
  `POST /api/components/{name}/restart` (token-gated).

## No duplication

The curated `SelfHealing` registrations (dns_interceptor, store_writer,
ransomware_shield, sensor_manager, …) remain the **authoritative recovery
path** — the registry does *not* re-register them, avoiding a second
watchdog. `bind_self_heal()` exists as an opt-in for components without a
curated check, but is deliberately not called in `__main__`. The registry
is the observability + manual-control surface; the healer is autonomous
recovery. One event bus, one store, one API — nothing duplicated.

## Testing

`tests/test_components.py` (20 checks): adapter introspection across all
signal shapes, fault isolation on raising probes, independent restart
(incl. failing-start reporting), aggregate `overall()`, event-driven
transitions, a real `Store` as a live component, and registry survival
when a component throws everywhere.

## Rollback

`registry` is an `Optional` AppContext field; remove the `__main__` block
and the two routes and every subsystem behaves exactly as before.

## Honest boundary

This is the *management/observability* plane of the plugin architecture —
uniform health/metrics/config/restart/events over in-process services. It
is not yet dynamic module loading, hot-swap of running code, or an
out-of-process plugin ABI (the Rust-owned engine seam the language strategy
describes). Those are future increments that plug into this same contract.

## Cross-process note (added 2026-07-30, architecture audit)

A restart that takes down the whole engine process — `POST
/api/system/restart` (not a per-component restart, which stays in-process)
— has a consequence outside this file's scope: `web/server.py` mints a
fresh `_CONTROL_TOKEN` on every process start (`secrets.token_urlsafe(24)`
at module load). The Electron shell (`electron/src/main/engine.js`) caches
that token for its own process lifetime, which used to mean every POST
control action silently 403'd after any full-engine restart until the
whole desktop app was relaunched — the restart control itself was the one
action that broke every other control afterward. Fixed in `engine.js`'s
`apiPost` (retry-once-on-401/403 with a freshly fetched token, regression
test in `engine.test.js`), not in this file, since the registry's own
per-component `restart()` never touches the process-wide token at all.
Noted here anyway because the failure mode only makes sense read against
both halves at once.
