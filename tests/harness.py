"""Shared test harness - makes a test's result mean something.

The failure this exists to prevent: a standalone test file that records no
failures prints "ALL PASSED" and exits 0 **even when it executed zero
assertions**. The runner judged on exit code alone, so a test whose every check
was skipped - no admin, no optional dependency, wrong OS - was counted as a
passing test. Three files in this suite did exactly that, silently covering the
telemetry-killer pillar, the TLS path, and the Rust accelerator with nothing.

A test that tests nothing must never be indistinguishable from a test that
passes. This harness enforces that:

  * every check is **counted**, not just failures;
  * a file that runs zero checks **fails** rather than passing quietly;
  * a file that declares ``expect_min`` fails if fewer checks actually ran, so a
    check that silently disappears is a failure and not a quieter pass;
  * a deliberate skip is a **distinct outcome** (exit 77), never a pass.

It also prints one machine-readable summary line that ``run_tests.py`` parses,
so the aggregate report can show passed / failed / skipped / vacuous as separate
columns instead of collapsing them all into "passed".

Adoption is incremental: new tests should use this; legacy files still work,
and the runner applies a fallback heuristic to catch vacuous runs in those too.
"""

from __future__ import annotations

import sys

# Exit codes. 77 is the long-standing autotools convention for "skipped".
EXIT_OK   = 0
EXIT_FAIL = 1
EXIT_SKIP = 77

# The machine-readable line run_tests.py looks for. Authoritative when present.
RESULT_PREFIX = "VALKYRIE-RESULT"


class Checks:
    """Counts checks so an empty run is distinguishable from a passing one.

    Usage::

        c = Checks("dns decision matrix", expect_min=12)
        c.check("blocklist beats known-good", decide(...) == "blocked")
        c.skip("live resolver case", "no resolver on this host")
        raise SystemExit(c.finish())
    """

    def __init__(self, name: str, *, expect_min: int = 1) -> None:
        self.name = name
        self.expect_min = int(expect_min)
        self.passed: list[str] = []
        self.failed: list[str] = []
        self.skipped: list[tuple[str, str]] = []

    # -- recording ----------------------------------------------------------

    def check(self, label: str, ok: bool) -> bool:
        """Record one assertion. Returns ``ok`` so it can be chained."""
        if ok:
            self.passed.append(label)
            print(f"  [+] {label}: PASS")
        else:
            self.failed.append(label)
            print(f"  [!] {label}: FAIL")
        return bool(ok)

    def fail(self, label: str, why: str = "") -> None:
        """Record an outright failure (an exception path, say)."""
        self.failed.append(label)
        print(f"  [!] {label}: FAIL{f' — {why}' if why else ''}")

    def skip(self, label: str, why: str) -> None:
        """Record a check that could not run here. Never counts as a pass."""
        self.skipped.append((label, why))
        print(f"  [~] {label}: SKIP — {why}")

    # -- reporting ----------------------------------------------------------

    @property
    def ran(self) -> int:
        return len(self.passed) + len(self.failed)

    def finish(self) -> int:
        """Print the summary and return the process exit code."""
        n_pass, n_fail, n_skip = len(self.passed), len(self.failed), len(self.skipped)
        print(f"\n{RESULT_PREFIX} name={self.name!r} checks={self.ran} "
              f"passed={n_pass} failed={n_fail} skipped={n_skip} "
              f"expect_min={self.expect_min}")

        if n_fail:
            print(f"FAILED: {n_fail} check(s)")
            for f in self.failed:
                print(f"  - {f}")
            return EXIT_FAIL

        # Nothing ran. Either an honest skip, or a test that quietly did nothing.
        if self.ran == 0:
            if n_skip:
                print(f"SKIPPED: every check skipped ({n_skip}) — this is NOT a pass")
                return EXIT_SKIP
            print("VACUOUS: the file ran zero checks — failing, because a test "
                  "that tests nothing must not report success")
            return EXIT_FAIL

        # Ran, but fewer than declared: a check disappeared somewhere.
        if self.ran < self.expect_min:
            print(f"FAILED: only {self.ran} check(s) ran, expected at least "
                  f"{self.expect_min} — a check silently disappeared")
            return EXIT_FAIL

        suffix = f" ({n_skip} skipped)" if n_skip else ""
        print(f"All {n_pass} checks PASSED{suffix}.")
        return EXIT_OK


def skip_file(name: str, why: str) -> int:
    """Whole-file skip: prints the summary line and returns EXIT_SKIP.

    Use when a precondition makes the entire file inapplicable (not
    Administrator, optional dependency absent, wrong OS). The point is that the
    runner records it as *skipped* - visibly absent coverage - rather than
    letting an exit code of 0 pass it off as a tested subsystem.
    """
    print(f"  [~] {name}: SKIP — {why}")
    print(f"\n{RESULT_PREFIX} name={name!r} checks=0 passed=0 failed=0 "
          f"skipped=1 expect_min=0")
    print(f"SKIPPED: {why} — this is NOT a pass; the subsystem is untested here")
    return EXIT_SKIP


def parse_result_line(text: str) -> dict | None:
    """Extract the structured summary from a test's stdout, if it emitted one."""
    for line in reversed(text.splitlines()):
        if line.startswith(RESULT_PREFIX):
            out: dict = {}
            for tok in line[len(RESULT_PREFIX):].strip().split():
                if "=" in tok:
                    k, _, v = tok.partition("=")
                    out[k] = int(v) if v.isdigit() else v.strip("'\"")
            return out
    return None


if __name__ == "__main__":       # self-check: the harness must police itself
    c = Checks("harness self-test", expect_min=3)
    c.check("a passing check is counted", True)
    c.check("ran counts passes and failures", c.ran == 1)
    c.skip("a skipped check", "demonstration")
    c.check("skips are not counted as checks", c.ran == 2 and len(c.skipped) == 1)
    empty = Checks("empty", expect_min=1)
    c.check("a zero-check file fails, not passes", empty.finish() == EXIT_FAIL)
    only_skips = Checks("skips only", expect_min=1)
    only_skips.skip("x", "y")
    c.check("an all-skipped file exits SKIP, not OK", only_skips.finish() == EXIT_SKIP)
    short = Checks("short", expect_min=5)
    short.check("one", True)
    c.check("a file under its declared minimum fails", short.finish() == EXIT_FAIL)
    sys.exit(c.finish())
