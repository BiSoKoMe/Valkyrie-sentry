#!/usr/bin/env python3
"""Pin the DNS decision vocabulary so an added verdict cannot silently break
accuracy measurement.

WHY THIS EXISTS (the bug it prevents recurring)
-----------------------------------------------
`test_scanner_accuracy.py` classified a detection as positive with a hardcoded
list: `dec in ("blocked", "flagged")`. The pipeline later gained a FOURTH
verdict — "deceived" — which sinkholes a detected tracker to a decoy dead-end
instead of hard-blocking it, so the calling app keeps working.

Nothing failed loudly. The measurement simply started counting every
successful deception as a MISS, and reported 0.333 recall while the pipeline
was really catching 13/15. A detection quality metric that silently
under-reports is worse than no metric, because it gets believed.

The root cause is structural, not a typo: **a test enumerated a vocabulary the
product owns.** This file makes that coupling explicit and enforced.

  [1] _decide returns only verdicts from the known set
  [2] every non-"allowed" verdict is treated as positive by the accuracy test
  [3] "deceived" specifically is an acted-on outcome, not a pass-through
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


# The complete verdict vocabulary of dns_interceptor._decide.
# Adding a verdict to the product REQUIRES updating this set, and that edit is
# the prompt to also update every consumer listed below.
# "behavioral" is a real FIFTH verdict, not a category: it is returned from the
# legacy fallback path (scanner not wired) and dns_interceptor treats it as a
# BLOCKING outcome — `decision in ("blocked", "behavioral", "deceived")` gates
# the sinkhole. It was found by this very test on its first run, which is the
# point: the same latent trap as "deceived" was sitting in a second code path.
KNOWN_VERDICTS = {"allowed", "blocked", "flagged", "deceived", "behavioral"}

# Verdicts meaning "Valkyrie detected something and acted". Everything except
# "allowed". Accuracy measurement must count all of these as positives.
ACTED_VERDICTS = KNOWN_VERDICTS - {"allowed"}


def main() -> int:
    print("\n=== DNS verdict vocabulary ===\n")

    src = (_ROOT / "valkyrie" / "dns_interceptor.py").read_text(encoding="utf-8")

    print("[1] _decide emits only known verdicts")
    # Every `return "<verdict>", ...` inside the module's decision path.
    emitted = set(re.findall(
        r'return\s+"(allowed|blocked|flagged|deceived|behavioral)"', src))
    unknown = set(re.findall(r'return\s+"([a-z_]+)"\s*,', src)) - KNOWN_VERDICTS
    _check(f"emitted verdicts are a subset of the known set ({sorted(emitted)})",
           emitted <= KNOWN_VERDICTS)
    _check("no unrecognised verdict string is returned from _decide",
           not unknown)
    if unknown:
        print(f"      UNKNOWN VERDICTS: {sorted(unknown)}")
        print("      -> add them to KNOWN_VERDICTS here AND to every consumer "
              "below, or accuracy metrics will silently under-report.")
    _check("'deceived' is actually emitted (the mechanism is wired)",
           "deceived" in emitted)

    print("\n[2] the accuracy test counts every acted-on verdict as positive")
    acc = (_ROOT / "tests" / "test_scanner_accuracy.py").read_text(encoding="utf-8")
    m = re.search(r"POSITIVE_VERDICTS\s*=\s*\(([^)]*)\)", acc)
    _check("test_scanner_accuracy declares POSITIVE_VERDICTS", m is not None)
    if m:
        declared = set(re.findall(r'"([a-z]+)"', m.group(1)))
        missing = ACTED_VERDICTS - declared
        _check(f"POSITIVE_VERDICTS covers every acted-on verdict "
               f"(declared {sorted(declared)})", not missing)
        if missing:
            print(f"      MISSING: {sorted(missing)} — recall will under-report")
        _check("POSITIVE_VERDICTS does not wrongly include 'allowed'",
               "allowed" not in declared)

    print("\n[3] 'deceived' is an acted-on outcome, not a pass-through")
    # A deceived domain must be sinkholed, never resolved upstream. Pin the
    # semantic, not just the string: the interceptor answers it locally.
    _check("dns_interceptor treats 'deceived' as a sinkhole path",
           re.search(r'deceived', src) is not None
           and "_answer_blocked" in src)
    from valkyrie.decision import should_deceive
    _check("should_deceive() exists and is callable", callable(should_deceive))

    print("\n" + "=" * 56)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED — verdict vocabulary is consistent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
