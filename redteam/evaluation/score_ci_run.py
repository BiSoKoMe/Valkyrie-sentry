#!/usr/bin/env python3
r"""Score a Tier B CI run's DETECT/MISS counts CORRECTLY from its log.

Why this exists: `gh run view --log` returns the harness's Tee'd output, so
every verdict line appears more than once. A plain `grep -c "\[DETECT\]"`
therefore over-counts - on 2026-09-04 that turned three runs' real scores of
39 / 23 / 14 into a reported 63 / 32 / 14, which is wrong and flattering. The
inflation is not a constant factor, so it cannot be divided out.

The fix is to score by TECHNIQUE, not by line: pair each `[eval] -- <id>`
with the verdict line that follows it, keep one verdict per technique id, and
report a conflict if the same technique ever reports two different verdicts.

Usage:
    python redteam/evaluation/score_ci_run.py <run-id> [<run-id> ...]

Reads through `gh`, so it needs the GitHub CLI authenticated for this repo.
This scores the LOG. It is a convenience for reading CI, NOT a replacement for
score.py / union_coverage.py / the evidence librarian, which score the run's
own JSON artifact and are what any published number must come from.
"""
from __future__ import annotations

import re
import subprocess
import sys

_EVAL = re.compile(r"\[eval\] -- ([a-z0-9-]+)\s")
_VERDICT = re.compile(r"\[(DETECT|MISS)\]")
_TS = re.compile(r"^.*?\d\dZ ")


def score(run_id: str) -> dict:
    raw = subprocess.run(["gh", "run", "view", run_id, "--log"],
                         capture_output=True, text=True, errors="replace").stdout
    verdicts: dict[str, str] = {}
    conflicts: list[str] = []
    current: str | None = None
    for line in raw.splitlines():
        line = _TS.sub("", line.rstrip("\r"))
        m = _EVAL.match(line)
        if m:
            current = m.group(1)
            continue
        v = _VERDICT.search(line)
        if v and current:
            prior = verdicts.get(current)
            if prior is not None and prior != v.group(1):
                conflicts.append(f"{current}: {prior} vs {v.group(1)}")
            verdicts[current] = v.group(1)
            current = None
    detected = sorted(k for k, x in verdicts.items() if x == "DETECT")
    return {"run": run_id, "total": len(verdicts), "detected": detected,
            "conflicts": conflicts}


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    for run_id in argv:
        r = score(run_id)
        if not r["total"]:
            print(f"{run_id}: no verdict lines found (run still in progress, "
                  "or the log has expired)")
            continue
        n, t = len(r["detected"]), r["total"]
        print(f"{run_id}: DETECT {n}/{t}  ({n / t * 100:.1f}%)")
        for c in r["conflicts"]:
            print(f"  CONFLICT (same technique, two verdicts): {c}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
