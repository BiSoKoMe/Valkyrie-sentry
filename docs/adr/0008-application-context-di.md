# ADR 0008 - Application context + dependency injection

- **Status:** Accepted
- **Phase:** 1 (core architecture)
- **Date:** 2026-07-12

## Context

Startup wiring lived in a ~1,100-line `__main__.py` plus a process-global,
mutable singleton inside `web/server.py`:

```python
class _AppState:
    store = None; firewall = None; ...
state = _AppState()
```

`__main__` reached into that global (`web_state.store = store; ...`) and the FastAPI
routes read it back. This is the classic global-singleton coupling: services are
wired by side effect on a shared bag, the dependency graph is implicit, and a
test can only exercise the server by mutating the same process global. It is also
the thing standing between Valkyrie and clean module boundaries.

A full DI *framework* (autowiring container) would be more machinery than this
codebase warrants - and the redesign brief explicitly says to avoid unnecessary
complexity. The Pythonic middle ground is an explicit **application context**
passed by parameter.

## Decision

Add `valkyrie/context.py` with `AppContext`: a typed dataclass holding the shared
services (`store`, `firewall`, `blocklist`, `intelligence`, `edr`,
`mac_randomizer`, `zero_log`, `self_heal`) plus timing/ports, and a
`components()` health/inventory view. Service fields are typed `Optional[object]`
to keep this root module free of import cycles; comments name the concrete types.

- **`web/server.py`** drops the anonymous `_AppState` bag; its module global is
  now `state = AppContext()` (kept so the server stays importable/testable
  standalone).
- **Injection:** `create_app(ctx=None)` and `run_server(..., ctx=None)` accept a
  context. When provided it is adopted as the global the routes read; when
  omitted (tests, the `__main__` docstring example) the existing global is used.
- **`__main__` becomes the composition root:** it constructs the `AppContext`,
  wires the services in at build time, and injects it into `run_server(ctx=...)`
  instead of mutating a global by side effect.

## Change report

- **What changed:** new `valkyrie/context.py`; `web/server.py` (`_AppState` ->
  injected `AppContext`, `create_app`/`run_server` take `ctx`); `__main__.py`
  builds and injects the context.
- **Why:** replace global-singleton coupling with an explicit, typed, testable
  service container - the seam for clean module boundaries and future services
  (endpoint sensor, NDR) that Phases 2-3 add.
- **Security impact:** neutral. Indirect positive: explicit wiring makes it
  auditable exactly which services a given deployment has running
  (`components()`), useful for the fleet health surface later.
- **Performance impact:** none. Same objects, constructed once at startup.
- **Compatibility impact:** none observable. Field names and route behavior are
  unchanged; `create_app()` with no argument behaves exactly as before, so the
  existing web tests are untouched. Verified the injected context reaches the
  routes end-to-end (a store-less context yields `/api/events 503`; a wired one
  yields `200`).
- **Risks:** low. `create_app(ctx)` reassigns the module global `state` - a
  deliberate, documented choice so routes need no edits; concurrent creation of
  two apps in one process would share the last-injected global, which never
  happens in production (one server per process) and is covered/ordered in tests.
- **Tests added:** `tests/test_context.py` - defaults, `components()`
  introspection, `repr`, and end-to-end DI (injected context with/without a store
  drives the route's 200/503). Also validated `__main__`'s exact kwargs and a
  clean `__main__` import. Full suite: 25 passed, 0 failed, 2 skipped.
- **Rollback plan:** revert the three edits and delete `context.py`; the web
  layer returns to its `_AppState` global. Clean `git revert`.

## Consequences

Valkyrie now has an explicit composition root and a typed service container.
Follow-on work builds on it directly: threading the same `AppContext` (and the
shared `EventBus` from ADR-0007) into the DNS/EDR/self-heal subsystems so they no
longer import each other's globals, and later registering new services (endpoint
sensor, NDR, SIEM exporter) in one obvious place.
