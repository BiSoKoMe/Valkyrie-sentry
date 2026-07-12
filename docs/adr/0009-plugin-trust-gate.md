# ADR 0009 — Plugin trust gate (SHA-256 allowlist)

- **Status:** Accepted
- **Phase:** 1 (core architecture — plugin system hardening)
- **Date:** 2026-07-12

## Context

The EDR plugin loader (`PluginRegistry.discover`) executes every `*.py` in a
directory: it imports the module and calls its `register(registry)`. Discovery is
opt-in (only via `--edr-plugin-dir`), and the code was honest that plugins "run
with the same privileges as Valkyrie." But there was **no verification** — any
file that landed in the directory (a supply-chain slip, a tampered update, a
malicious "detection pack") would execute silently with full privileges. The
architecture audit flagged this arbitrary-code-execution path, and the README now
promises hardening.

Full sandboxing (WASM with a capability manifest) is the right long-term answer
but is a Phase-2+ effort. The Phase-1-appropriate, low-risk step is a **trust
gate**: verify what is allowed to run, and make any unverified execution explicit.

## Decision

Gate `discover()` on a SHA-256 allowlist:

- **Explicit `allowlist=` argument**, or an **`allowed.sha256` manifest** in the
  plugin directory (one hex digest per line, `#` comments allowed) used when no
  argument is given.
- **When an allowlist is in force:** only modules whose file SHA-256 matches are
  loaded; every other `*.py` is skipped and the reason recorded. An **empty**
  allowlist loads nothing (fail closed).
- **When no allowlist is configured:** modules still load — preserving existing
  behavior so nobody's working setup breaks — but each is flagged
  `verified=False` and a single warning is recorded. Unverified code execution is
  now *explicit and auditable*, never silent.
- **Provenance:** every loaded module's name, path, SHA-256, and verification
  state is recorded (`PluginRegistry.loaded_plugins`) and surfaced through
  `EdrEngine.plugins()` for the console/audit trail.

## Change report

- **What changed:** `edr/plugins.py` — `sha256_file`, allowlist parsing, a
  rewritten `discover()` with the trust gate, and `loaded_plugins()` provenance;
  `edr/engine.py` surfaces `loaded` in `plugins()`; README documents the manifest.
- **Why:** stop silent arbitrary-code execution from the plugin directory; give
  operators a fail-closed lockdown mechanism and an auditable record of exactly
  what third-party code ran and its hash.
- **Security impact:** significant positive. Converts "any file here runs with
  our privileges, silently" into "only hash-approved files run, and any
  unverified load is flagged and logged." Enables a verified supply chain for the
  detection-content marketplace envisioned in the redesign.
- **Performance impact:** negligible — one SHA-256 over each candidate file at
  startup discovery time only; nothing on the event hot path.
- **Compatibility impact:** none for existing users. With no manifest and no
  `allowlist=` argument, the same plugins load as before (now flagged unverified).
  `discover()`'s signature only *adds* an optional parameter.
- **Risks:** low. The main behavioral change is fail-closed enforcement *once an
  allowlist exists* — intended. A user who edits an approved plugin must update
  its digest, which is the point.
- **Tests added:** `tests/test_plugin_trust.py` — no-allowlist unverified load +
  warning + provenance; allowlist match (verified) and mismatch (skipped); empty
  allowlist loads nothing; in-dir manifest honored; wrong manifest skips. Existing
  `test_edr` still passes. Full suite: 26 passed, 0 failed, 2 skipped.
- **Rollback plan:** revert the `plugins.py`/`engine.py`/README edits and delete
  the test. `discover()` returns to unconditional loading. Clean `git revert`.

## Consequences

The plugin system now has a verifiable trust boundary and provenance — the
foundation for signed detection content and, later, the WASM capability sandbox
(Phase 2+). Combined with the code-signing and transparency-log work planned for
the platform, plugins move from "trusted by location" to "trusted by hash".
