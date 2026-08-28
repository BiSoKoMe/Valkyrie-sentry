# ADR 0006 - Layered, validated configuration system

- **Status:** Accepted
- **Phase:** 1 (core architecture - foundational)
- **Date:** 2026-07-12

## Context

`config.py` is a flat module of ~80 constants. To change any of them - a DNS
port for a system-wide resolver, the web bind address, a detection threshold - an
operator had to edit source. There was:

- **no environment/file override** (bad for containers, fleet deployment, and
  air-gapped installs where editing code is undesirable);
- **no validation** (a typo'd port or an out-of-range threshold would either
  crash deep in the datapath or, worse, run silently wrong);
- **no single, introspectable list** of what is tunable.

This is the first Phase-1 step because a real configuration seam is the
foundation the later architecture (event bus, module boundaries, DI, fleet
policy) reads from. It was chosen deliberately as the *lowest-risk* first move:
purely additive, with a hard backward-compatibility guarantee.

## Decision

Add `valkyrie/settings.py`, a layered overlay resolved with precedence:

    code defaults (config.py)  <  config file  <  environment variables

- **Defaults are not duplicated.** The overlay takes `config.py`'s existing
  constants as its base; `settings.SPECS` adds only the env-var name, type,
  range/choices, and help text per overridable key. One source of truth for
  defaults.
- **Integration point is the *bottom* of `config.py`.** Python finishes executing
  the module (including the re-binding) before any `from .config import X`
  elsewhere resolves, so all 25 consumer modules transparently see the resolved
  value with zero changes on their side.
- **File discovery:** `$VALKYRIE_CONFIG` (must exist if set) -> `<data>/valkyrie.yaml`
  -> `.yml`. YAML (already a dependency), JSON fallback.
- **Environment:** `VALKYRIE_<CONSTANT_NAME>` (e.g. `VALKYRIE_DNS_LISTEN_PORT=53`).
- **Fail loud on bad *explicit* values** (`ConfigError` -> `SystemExit` with a
  clear message). A missing file / unset var is never an error - defaults stand.
- **Provenance:** `config.CONFIG_OVERRIDES` lists what changed and from where;
  `__main__` prints it at startup (nothing on a stock deployment).
- **Introspection:** `settings.describe()` enumerates every tunable.

Curated initial surface (19 settings): DNS host/port/upstream/timeout/local-only,
web host/port, fleet port/intervals, behavioral thresholds, blocklist/firewall
refresh ages, and store queue/flush tuning. More can be added by appending a
`Spec` - no consumer changes.

## Change report

- **What changed:** new `valkyrie/settings.py`; `config.py` gains a 20-line
  overlay block at the end; `__main__.py` prints active overrides; new
  `docs/valkyrie.example.yaml`.
- **Why:** make Valkyrie configurable for containers/fleet/air-gap without code
  edits, and catch misconfiguration at startup instead of at runtime.
- **Security impact:** positive. Misconfigurations (bad port, out-of-range
  threshold) now fail closed at startup with a clear message rather than running
  a security tool in an undefined state. Enables per-deployment hardening (e.g.
  `VALKYRIE_DNS_LOCAL_ONLY=true`) without patching.
- **Performance impact:** negligible - resolution runs once at import; the
  datapath reads the same module constants as before.
- **Compatibility impact:** **none by construction.** With no file and no
  `VALKYRIE_*` env vars, every constant keeps its exact default (pinned by test).
  All existing `from .config import X` sites are untouched.
- **Risks:** (1) an operator-set bad value now stops startup - intended, and
  clearly messaged. (2) Import-time `SystemExit` on bad env affects any process
  importing `config`; acceptable because it only triggers on an explicit bad
  override, which should stop the process. No default path can trigger it.
- **Tests added:** `tests/test_settings.py` - no-op default, env/file overrides,
  env-beats-file precedence, four invalid-value cases, unknown-key tolerance,
  missing explicit file, `describe()`, and the `config.CONFIG_OVERRIDES`
  integration. Full suite: 23 passed, 0 failed, 2 skipped.
- **Rollback plan:** delete `valkyrie/settings.py`, remove the overlay block from
  `config.py` and the override print from `__main__.py`. Constants revert to
  plain literals. Clean `git revert`.

## Consequences

Valkyrie now has a real configuration boundary with validation and provenance -
the seam that Phase-1's event bus and module wiring, and Phase-4's fleet policy
push, will build on. The `Spec` schema is also the natural place to later emit a
`--print-config` command and to drive fleet-pushed configuration.
