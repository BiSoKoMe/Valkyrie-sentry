# ADR 0037 — A real test pipeline: categorized runner + CI gate

- **Status:** Accepted
- **Phase:** 0 (foundation)
- **Date:** 2026-07-12

## Context

Valkyrie ships 21 test files under `tests/`, but they were never run by CI. The
only workflow (`build-windows-exe.yml`) *packages* the app; it does not execute a
single test. A regression could therefore ship "green". Worse, the tests are
standalone scripts (each a `main()` that `sys.exit`s 0/1), not a `pytest` suite,
so there was no single command to run them and no separation between:

- **unit tests** — offline, no privileges, safe for CI; and
- **integration tests** — `test_dns` (needs a running interceptor + a positional
  `domain` arg) and `test_resolver` (needs a live Unbound on port 5301).

Running everything naively turns CI red for environmental reasons that are not
code defects.

## Decision

1. Add `tests/run_tests.py`: discovers `test_*.py`, classifies integration tests
   via an explicit allow-list, runs the unit set as subprocesses, and returns a
   non-zero exit code if any fail. `--all` includes integration; `--list` and
   `-k SUBSTR` aid local use.
2. Add `.github/workflows/tests.yml`: on every push/PR touching `valkyrie/` or
   `tests/`, install runtime deps **plus the optional extras the suite needs**
   (`cryptography` for fleet signing/policy/updater; `httpx` for the fleet
   `TestClient`), run a `compileall` syntax gate, then `python tests/run_tests.py`
   across Python 3.10/3.11/3.12. A separate advisory `ruff` job flags syntax-level
   defects without gating merges (yet).

## Change report

- **What changed:** new `tests/run_tests.py`; new `tests/tests.yml` CI workflow.
  No product code touched.
- **Why:** make the existing tests an enforceable gate; make the unit/integration
  split explicit so CI is deterministic and offline-safe.
- **Security impact:** positive — regressions in security-relevant modules
  (firewall, fleet auth, zero-log) are now caught pre-merge.
- **Performance impact:** none on the product. CI runtime ≈ 1–2 min.
- **Compatibility impact:** none. Tests can still be run individually exactly as
  before; the runner is additive.
- **Risks:** the optional-dep install (`cryptography`) is the one fragile step; if
  a runner ships a broken wheel the crypto-dependent tests fail. Mitigation: pin
  a known-good version if this ever flakes (it built cleanly on ubuntu-latest).
- **Tests added:** the runner itself; baseline verified at **19 passed, 0 failed,
  2 skipped (integration)**.
- **Rollback plan:** delete `tests/run_tests.py` and `.github/workflows/tests.yml`.
  Nothing else depends on them.

## Consequences

Every subsequent Phase-0+ change is now guarded by a runnable, deterministic
suite. This ADR is deliberately first: it is the safety net the rest of the
redesign leans on.
