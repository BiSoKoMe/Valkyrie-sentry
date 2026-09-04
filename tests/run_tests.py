#!/usr/bin/env python3
"""Valkyrie test runner.

Most ``tests/test_*.py`` files are standalone scripts that exit 0 on success and
non-zero on failure; a minority are pytest-style (module-level ``def test_*``,
no ``__main__`` guard) and are handed to pytest instead - see ``_is_pytest_style``.
This runner discovers them, separates the CI-safe *unit* tests from the
*integration* tests that require live external state (a running Valkyrie
instance, an Unbound resolver, a positional CLI argument), runs the requested
set as subprocesses, and reports a single aggregate pass/fail with a non-zero
exit code if anything failed.

It replaces the ad-hoc "run each file by hand" workflow and is what CI invokes.

Usage:
    python tests/run_tests.py            # run the unit suite (CI default)
    python tests/run_tests.py --all      # also run integration tests
    python tests/run_tests.py --list     # list tests and their category
    python tests/run_tests.py -k fleet   # run only tests whose name matches

Integration tests are skipped by default (not failed): a missing resolver is an
environment condition, not a code defect, and must never turn CI red.

**Outcomes are four, not two.** This runner previously judged solely on exit
code, which made a test that asserted *nothing* indistinguishable from one that
passed - three files were silently doing that, covering the telemetry killer,
the TLS path, and the Rust accelerator with zero assertions apiece. Now:

    PASS     asserted something, and it held
    FAIL     asserted something, and it did not hold
    SKIP     declined to run here (exit 77) - reported as absent coverage,
             never folded into "passed"
    VOID     exited 0 without asserting anything - treated as a FAILURE,
             because absent coverage wearing a green badge is worse than red

Files built on ``tests/harness.py`` report their counts directly; legacy files
are judged by whether their output shows any evidence a check ran.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from harness import EXIT_SKIP, parse_result_line   # noqa: E402

_TESTS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _TESTS_DIR.parent

# Tests that require live external state and therefore cannot run in a clean,
# offline CI environment. They are skipped by default and only run with --all.
#   test_dns      - needs a running DNS interceptor + a positional `domain` arg
#   test_resolver - needs a live Unbound resolver listening on port 5301
_INTEGRATION = {
    "test_dns.py",
    "test_resolver.py",
}

# Some unit tests accept a --quick flag to skip optional network downloads.
# Passing it is harmless to tests that don't define it? No - argparse rejects
# unknown args, so only pass it to tests known to accept it.
_ACCEPTS_QUICK = {
    "test_firewall.py",
}


# Most test files here are standalone scripts (a main() plus a __main__ guard).
# A minority - the whole Aegis reasoning layer and the Platform Alpha baseline -
# are pytest-style instead: module-level `def test_*` functions with bare
# asserts and no __main__ guard. Executing one of those as a script imports the
# module, defines the functions, calls none of them, and exits 0 in silence.
# The VOID guard below correctly refused to call that a pass, but the effect was
# that 10 files' worth of real, passing assertions never ran in CI at all - Aegis
# was wired into the live engine with its unit tests reporting VOID the whole
# time. Detect the style and hand those files to pytest, which is what they were
# always written for.
_PYTEST_STYLE = re.compile(r"^def test_", re.M)


def _is_pytest_style(path: Path) -> bool:
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return _PYTEST_STYLE.search(src) is not None and "__main__" not in src


def _discover() -> list[Path]:
    return sorted(p for p in _TESTS_DIR.glob("test_*.py"))


def _category(path: Path) -> str:
    return "integration" if path.name in _INTEGRATION else "unit"


# A test that exits 0 having asserted nothing is the failure mode this runner
# used to be blind to. Files using tests/harness.py say so explicitly via the
# VALKYRIE-RESULT line; for legacy files we look for any sign that a check
# actually executed. If a file exits 0 and shows none of these, it ran nothing.
_PRODUCTIVE = re.compile(r"\[\+\]|PASS|\bpassed\b|^\s*ok\s", re.M)

OUTCOME_PASS    = "pass"
OUTCOME_FAIL    = "fail"
OUTCOME_SKIP    = "skip"
OUTCOME_VACUOUS = "vacuous"


# pytest's own summary line, e.g. "37 passed in 1.30s" / "2 failed, 35 passed".
_PYTEST_PASSED = re.compile(r"(\d+) passed")

# pytest exit code 5 = "no tests were collected". For a file we routed to pytest
# *because* it looked like it had tests, that means the tests vanished or stopped
# being collectable - absent coverage, so VOID, not a pass and not a hard error.
_PYTEST_EXIT_NO_TESTS = 5


def _classify_pytest(returncode: int, out: str) -> tuple[str, str]:
    """Map a pytest-run file to (outcome, note)."""
    if returncode == _PYTEST_EXIT_NO_TESTS:
        return (OUTCOME_VACUOUS, "pytest collected no tests from this file")
    if "No module named pytest" in out:
        # Loud and specific: this is an environment gap, not a code defect, but
        # it still means these assertions did not run, so it stays a failure.
        return (OUTCOME_FAIL, "pytest is not installed - `pip install pytest`")
    if returncode != 0:
        return (OUTCOME_FAIL, "")
    m = _PYTEST_PASSED.search(out)
    if not m or m.group(1) == "0":
        return (OUTCOME_VACUOUS, "pytest exited 0 but reported no passing tests")
    return (OUTCOME_PASS, f"{m.group(1)} pytest tests")


def _classify(returncode: int, out: str) -> tuple[str, str]:
    """Map a finished test to (outcome, note).

    Exit code alone is not enough - that is precisely the bug this replaces.
    """
    if returncode == EXIT_SKIP:
        res = parse_result_line(out)
        n = res.get("skipped", 0) if res else 0
        return (OUTCOME_SKIP, f"skipped{f' ({n} check(s))' if n else ''} — not a pass")
    if returncode != 0:
        return (OUTCOME_FAIL, "")

    # Exited 0. Did it actually assert anything?
    res = parse_result_line(out)
    if res is not None:                      # harness-based: authoritative
        if res.get("checks", 0) == 0:
            return (OUTCOME_VACUOUS, "harness reported zero checks")
        return (OUTCOME_PASS, f"{res.get('checks', 0)} checks")
    if not _PRODUCTIVE.search(out):           # legacy: heuristic
        return (OUTCOME_VACUOUS,
                "exited 0 but printed no evidence any check ran")
    return (OUTCOME_PASS, "")


def _run_one(path: Path, timeout: int) -> tuple[str, float, str, str]:
    """Run one test file as a subprocess. Returns (outcome, seconds, note, output)."""
    pytest_style = _is_pytest_style(path)
    if pytest_style:
        cmd = [sys.executable, "-m", "pytest", str(path), "-q"]
    else:
        cmd = [sys.executable, str(path)]
        if path.name in _ACCEPTS_QUICK:
            cmd.append("--quick")
    # Force UTF-8 in the child. Windows consoles default to cp1252, and these
    # tests print arrows and box-drawing characters - without this, 7 suites die
    # with UnicodeEncodeError partway through and report a failure that has
    # nothing to do with the code under test. That was being worked around by
    # hand (`PYTHONUTF8=1 python tests/...`), which meant the documented
    # invocation `python tests/run_tests.py` did not actually work.
    env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    start = time.monotonic()
    try:
        proc = subprocess.run(
            cmd, cwd=str(_REPO_ROOT), capture_output=True, text=True,
            timeout=timeout, env=env, encoding="utf-8", errors="replace"
        )
    except subprocess.TimeoutExpired:
        return (OUTCOME_FAIL, time.monotonic() - start,
                f"TIMEOUT after {timeout}s", "")
    elapsed = time.monotonic() - start
    combined = proc.stdout + proc.stderr
    outcome, note = (_classify_pytest(proc.returncode, combined) if pytest_style
                     else _classify(proc.returncode, combined))
    if outcome in (OUTCOME_PASS, OUTCOME_SKIP):
        return (outcome, elapsed, note, "")
    # Full output, not just a tail: these files print one line per check, so
    # an 8-line tail routinely cut off the actual failing check whenever a
    # test earlier in the file printed enough PASS lines to push it out -
    # which is exactly what happened with test_endpoint_telemetry.py and
    # test_playbooks.py in CI: "10/11 passed" with no way to tell which
    # check, or why, because the one line that said so was already gone.
    return (outcome, elapsed, note, combined.strip())


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
    vacuous: list[tuple[str, str]] = []

    print(f"Valkyrie test runner — {len(tests)} discovered "
          f"({'incl. integration' if args.all else 'unit only'})\n")

    for t in tests:
        if _category(t) == "integration" and not args.all:
            print(f"  SKIP  {t.name}  (integration — use --all)")
            skipped.append(t.name)
            continue
        outcome, secs, note, out = _run_one(t, args.timeout)
        suffix = f"  [{note}]" if note else ""
        if outcome == OUTCOME_PASS:
            print(f"  PASS  {t.name}  ({secs:.1f}s){suffix}")
            passed.append(t.name)
        elif outcome == OUTCOME_SKIP:
            print(f"  SKIP  {t.name}  ({secs:.1f}s){suffix}")
            skipped.append(t.name)
        elif outcome == OUTCOME_VACUOUS:
            # Counted as a failure on purpose: a file that asserts nothing is
            # absent coverage wearing a green badge.
            print(f"  VOID  {t.name}  ({secs:.1f}s)  — {note}")
            vacuous.append((t.name, note))
        else:
            print(f"  FAIL  {t.name}  ({secs:.1f}s)")
            if out:
                for line in out.splitlines():
                    print(f"        │ {line}")
            failed.append((t.name, out))

    print("\n" + "=" * 56)
    print(f"  {len(passed)} passed · {len(failed)} failed · "
          f"{len(skipped)} skipped · {len(vacuous)} vacuous")
    print("=" * 56)
    if skipped:
        print("\nSkipped (NOT passes — these subsystems went untested here):")
        for name in skipped:
            print(f"  - {name}")
    if vacuous:
        print("\nVacuous (exited 0 without asserting anything):")
        for name, why in vacuous:
            print(f"  - {name}: {why}")
    if failed:
        print("\nFailed tests:")
        for name, _ in failed:
            print(f"  - {name}")
    return 1 if (failed or vacuous) else 0


if __name__ == "__main__":
    raise SystemExit(main())
