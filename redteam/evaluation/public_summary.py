#!/usr/bin/env python3
"""Print a Tier B run's per-technique verdicts as GitHub Actions annotations.

A Tier B run's logs and artifacts are readable only by a repository admin
(`GET .../actions/jobs/{id}/logs` answers 403 "Must have admin rights" to
everyone else), so a session without the owner's GitHub login could launch a
run but never see what it proved. Check-run ANNOTATIONS are public on a public
repository (`GET .../check-runs/{id}/annotations`, no auth). This emits a
handful of `::notice` lines - a headline and the id lists per outcome - so
the result is readable by anyone, from the API, with nothing but the run id.

It reports; it never scores. The numbers are exactly the harness's own
`outcome` field, counted - the same records score.py / evidence.py read.

Usage:  python redteam/evaluation/public_summary.py <tierB.json|.partial.jsonl> ...
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

# GitHub caps notices per step; keep each line comfortably under the message
# size limit by splitting long id lists across several annotations.
_CHUNK = 1800


def load_records(paths) -> list[dict]:
    """Records from aggregate JSONs and crash-proof partial streams, deduped by
    catalog id (last one wins - a partial line and the final aggregate carry the
    same record)."""
    by_id: dict[str, dict] = {}
    for p in paths:
        path = Path(p)
        try:
            text = path.read_text(encoding="utf-8-sig")
        except OSError:
            continue
        if path.suffix == ".jsonl":
            rows = []
            for line in text.splitlines():
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
        else:
            try:
                rows = json.loads(text).get("records") or []
            except (ValueError, AttributeError):
                rows = []
        for r in rows:
            if isinstance(r, dict) and r.get("id"):
                by_id[r["id"]] = r
    return list(by_id.values())


def summary_lines(records: list[dict]) -> list[str]:
    groups: dict[str, list[str]] = defaultdict(list)
    for r in records:
        groups[str(r.get("outcome") or "unknown")].append(
            f"{r['id']}[{r.get('technique_id', '')}]")
    executed = [r for r in records if r.get("attack_executed")]
    detected = [r for r in records if r.get("outcome") == "detected"]
    fps = sum(int(r.get("false_positives_generated") or 0) for r in records)
    head = (f"TIERB-SUMMARY records={len(records)} executed={len(executed)} "
            f"detected_of_executed={len(detected)}/{len(executed) or 0} "
            f"fp_incidents={fps} "
            + " ".join(f"{k}={len(v)}" for k, v in sorted(groups.items())))
    lines = [head]
    for outcome, ids in sorted(groups.items()):
        chunk, part = [], 1
        for i in sorted(ids):
            if sum(len(x) + 1 for x in chunk) + len(i) > _CHUNK:
                lines.append(f"TIERB-{outcome.upper()} part{part}: " + " ".join(chunk))
                chunk, part = [], part + 1
            chunk.append(i)
        if chunk:
            lines.append(f"TIERB-{outcome.upper()} part{part}: " + " ".join(chunk))
    return lines


def main(argv) -> int:
    records = load_records(argv[1:])
    if not records:
        print("::notice title=Tier B summary::TIERB-SUMMARY records=0 (no result files)")
        return 0
    for line in summary_lines(records):
        print(f"::notice title=Tier B summary::{line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
