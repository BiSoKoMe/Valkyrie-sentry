# ADR 0010 — First native accelerator: Rust `IpSet` (PyO3) with Python fallback

- **Status:** Accepted
- **Phase:** 2 (selective Rust) — first increment
- **Date:** 2026-07-12

## Context

Phase 2 of the redesign calls for moving the hottest paths to a memory-safe
native language while keeping Python for orchestration/analytics/UI. Doing that
safely means proving a repeatable pattern on the smallest, most verifiable
component before touching the DNS datapath — and never making Rust a hard
dependency, so the "runs on a Pi with just Python" property survives.

The chosen first target is the CIDR membership set (`firewall._IPSet`): it is
small, pure (no I/O), on a real hot path (screened on every allowed DNS answer),
and already covered by a randomized differential test (ADR-0004). Integration
strategy — confirmed with the maintainer — is a **PyO3 extension imported
in-process, with a pure-Python fallback**.

## Decision

- New Rust crate `rust/valkyrie_accel` (PyO3, `cdylib`, `opt-level=3 + LTO`)
  exporting `IpSet` with the exact `load`/`contains`/`count` API and semantics of
  the Python class (prefix-length bucketing; `count()` = hosts + per-string
  network count; malformed/IPv6 input → `False`, never raises).
- `firewall.py` renames the pure-Python class to `_PyIPSet` and selects the
  backend at import: `from valkyrie_accel import IpSet as _IPSet` when available,
  else `_IPSet = _PyIPSet`. `FirewallManager`, all callers, and the tests use
  `_IPSet` unchanged and transparently get whichever backend is present.
  `_IPSET_BACKEND` records the choice and is surfaced at startup.
- **Fallback is the contract:** the import is wrapped in `try/except`, so any
  failure (no toolchain, no wheel, wrong platform) silently uses Python.
- CI gains an `accel` job that builds the extension and runs the **whole suite**
  with the Rust backend active; the existing `unit` job runs the same suite on
  the pure-Python fallback — so both paths are gated on every push.

## Change report

- **What changed:** new `rust/valkyrie_accel/` crate (+ its README, tracked
  `Cargo.lock`); `firewall.py` backend selection; `.gitignore` for build
  artifacts; CI `accel` job; new `tests/test_rust_accel.py`.
- **Why:** establish the Phase-2 Rust+PyO3 pattern (build, CI, fallback,
  differential-equivalence discipline) on a small, safe, verifiable component.
- **Security impact:** positive/neutral. Memory-safe Rust, no `unsafe`, no new
  I/O or network. Removes interpreter overhead from a path a query flood
  exercises, further shrinking the DoS-amplification surface the linear scan once
  created.
- **Performance impact:** **~0.10 µs/lookup vs 2.15 µs** pure-Python (measured,
  12k ranges) — ~20× on top of the bucketing win, i.e. ~16,000× faster than the
  original linear scan. Lookup remains O(≤32) and independent of list size.
- **Compatibility impact:** none. With no extension built, behavior is byte-for-
  byte the previous pure-Python path (verified: uninstalling the wheel flips the
  backend to `python` and the full suite still passes, 27/0/2). With it,
  behavior is proven identical by differential test.
- **Risks:** low. (1) A build-environment dependency for the *accelerated* path —
  mitigated by the mandatory fallback and a CI job that actually builds it.
  (2) The frozen `.exe` (PyInstaller) does not yet bundle the extension, so it
  uses the Python fallback until the packaging step is updated — acceptable and
  noted for a later packaging ADR. (3) Behavior drift between the two
  implementations — prevented by the differential test running both in CI.
- **Tests added:** `tests/test_rust_accel.py` — Rust↔Python differential (20k
  probes, 0 mismatches), boundary/malformed parity, backend-wiring assertion, and
  an informational benchmark; skips cleanly when the extension is absent. Existing
  `test_ipset_lookup`/`test_firewall`/`test_ip_leak` now also validate the Rust
  backend when built. Suite: 27 passed, 0 failed, 2 skipped (both backends).
- **Rollback plan:** delete the `valkyrie_accel` import block in `firewall.py`
  (leaving `_IPSet = _PyIPSet`) and/or remove the crate; nothing else depends on
  it. Uninstalling the wheel is an instant runtime rollback.

## Consequences

Valkyrie now has a proven Rust+PyO3 accelerator pattern with a hard fallback
guarantee and dual-path CI. The same skeleton (crate, differential test, backend
selection, CI job) is what the next Phase-2 targets — the DNS parse/decide loop
and, later, packet processing — will reuse, one verifiable component at a time.
