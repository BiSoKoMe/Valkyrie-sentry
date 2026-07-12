#!/usr/bin/env python3
"""Valkyrie test runner.

The individual ``tests/test_*.py`` files are standalone scripts that exit 0 on
success and non-zero on failure.  This runner discovers them, separates the
CI-safe *unit* tests from the *integration* tests that require live external
state (a running Valkyrie instance, an Unbound resolver, a positional CLI
argument), runs the requested set as subprocesses, and reports a single
aggregate pass/fail with a non-zero exit code if anything failed.

It replaces the ad-hoc "run each file by hand" workflow and is what CI invokes.

Usage:
    python tests/run_tests.py            # run the unit suite (CI default)
    python tests/run_tests.py --all      # also run integration tests
    python tests/run_tests.py --list     # list tests and their category
    python tests/run_tests.py -k fleet   # run only tests whose name matches

Integration tests are skipped by default (not failed): a missing resolver is an
environment condition, not a code defect, and must never turn CI red.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

_TESTS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _TESTS_DIR.parent

# Tests that require live external state and therefore cannot run in a clean,
# offline CI environment. They are skipped by default and only run with --all.
#   test_dns      — needs a running DNS interceptor + a positional `domain` arg
#   test_resolver — needs a live Unbound resolver listening on port 5301
_INTEGRATION = {
    "test_dns.py",
    "test_resolver.py",
}

# Some unit tests accept a --quick flag to skip optional network downloads.
# Passing it is harmless to tests that don't define it? No — argparse rejects
# unknown args, so only pass it to tests known to accept it.
_ACCEPTS_QUICK = {
    "test_firewall.py",
}


def _discover() -> list[Path]:
    return sorted(p for p in _TESTS_DIR.glob("test_*.py"))


def _category(path: Path) -> str:
    return "integration" if path.name in _INTEGRATION else "unit"


def _run_one(path: Path, timeout: int) -> tuple[bool, float, str]:
    """Run one test file as a subprocess. Returns (passed, seconds, tail)."""
    cmd = [sys.executable, str(path)]
    if path.name in _ACCEPTS_QUICK:
        cmd.append("--quick")
    start = time.monotonic()
    try:
        proc = subprocess.run(
            cmd, cwd=str(_REPO_ROOT), capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return (False, time.monotonic() - start, f"TIMEOUT after {timeout}s")
    elapsed = time.monotonic() - start
    if proc.returncode == 0:
        return (True, elapsed, "")
    tail = "\n".join((proc.stdout + proc.stderr).strip().splitlines()[-8:])
    return (False, elapsed, tail)


def main() -> int:
    ap = argparse.ArgumentParser(description="Run the Valkyrie test suite.")
    ap.add_argument("--all", action="store_true",
                    help="also run integration tests (need live resolver/server)")
    ap.add_argument("--list", action="store_true",
                    help="list discovered tests and their category, then exit")
    ap.add_argument("-k", metavar="SUBSTR", default="",
                    help="only run tests whose filename contains SUBSTR")
    ap.add_argument("--timeout", type=int, default=120,
                    help="per-test timeout in seconds (default 120)")
    args = ap.parse_args()

    tests = _discover()
    if args.k:
        tests = [t for t in tests if args.k in t.name]

    if args.list:
        for t in tests:
            print(f"  {_category(t):12s}  {t.name}")
        return 0

    if not tests:
        print("No tests discovered.")
        return 1

    passed: list[str] = []
    failed: list[tuple[str, str]] = []
    skipped: list[str] = []

    print(f"Valkyrie test runner — {len(tests)} discovered "
          f"({'incl. integration' if args.all else 'unit only'})\n")

    for t in tests:
        if _category(t) == "integration" and not args.all:
            print(f"  SKIP  {t.name}  (integration — use --all)")
            skipped.append(t.name)
            continue
        ok, secs, tail = _run_one(t, args.timeout)
        if ok:
            print(f"  PASS  {t.name}  ({secs:.1f}s)")
            passed.append(t.name)
        else:
            print(f"  FAIL  {t.name}  ({secs:.1f}s)")
            if tail:
                for line in tail.splitlines():
                    print(f"        │ {line}")
            failed.append((t.name, tail))

    print("\n" + "=" * 56)
    print(f"  {len(passed)} passed · {len(failed)} failed · {len(skipped)} skipped")
    print("=" * 56)
    if failed:
        print("\nFailed tests:")
        for name, _ in failed:
            print(f"  - {name}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
