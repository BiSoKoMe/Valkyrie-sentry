#!/usr/bin/env python3
"""Offline attribution (redteam/evaluation/attribute.py).

This is the logic that used to live inside `run_live_evaluation.ps1`'s
per-technique polling loop, where it could never be tested. The properties
that matter:

  * technique ID is the primary key, the execution window only filters
    staleness and breaks ties - so a LATE artifact-at-rest detection is still
    attributed correctly instead of being lost to a closed poll window;
  * a detection folded into a PRE-EXISTING incident still counts;
  * user-defined rules are recorded and NOT counted as product detections;
  * a new incident matching nothing is a false positive, attributed to the
    technique that was executing when it landed;
  * latency comes from the detection's own timestamp, not from poll cadence.
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent.parent))
sys.path.insert(0, str(_HERE.parent.parent / "tests"))

from harness import Checks  # noqa: E402
import attribute as A       # noqa: E402


def _fired(tid, ident, start, end):
    return A.Fired(id=ident, technique_id=tid,
                   exec_start_utc=start, exec_end_utc=end)


def _inc(inc_id, dets, *, category="process", reason="", technique=""):
    return {"id": inc_id, "category": category, "reason": reason,
            "technique": technique, "detections": dets}


def _det(ts, technique="", *, source="behavioral", severity="high",
         title="rule hit", all_techniques=None, labels=None):
    return {"timestamp": ts, "technique": technique, "source": source,
            "severity": severity, "title": title,
            "details": {"all_techniques": all_techniques or [],
                        "labels": labels or []}}


def main() -> int:
    c = Checks("offline live-run attribution", expect_min=22)

    # Two techniques, disjoint execution windows.
    fired = [
        _fired("T1003.001", "lsass", "2026-08-23T10:00:00Z", "2026-08-23T10:00:10Z"),
        _fired("T1547.001", "runkey", "2026-08-23T10:00:20Z", "2026-08-23T10:00:30Z"),
    ]

    # ------------------------------------------------------------------ [1]
    print("\n[1] a detection is attributed by TECHNIQUE ID, not by clock luck")
    incs = [_inc("i1", [_det("2026-08-23T10:00:05Z", "T1003.001")])]
    r = {a.id: a for a in A.attribute(fired, incs)}
    c.check("the matching technique is detected", r["lsass"].detected)
    c.check("the other technique is not", not r["runkey"].detected)
    c.check("the incident is cited", r["lsass"].incident_id == "i1")
    c.check("latency measured from the detection's own timestamp",
            r["lsass"].latency_seconds == 5.0)

    # ------------------------------------------------------------------ [2]
    print("\n[2] a LATE artifact-at-rest detection still counts - this is the "
          "case a fixed poll window silently lost")
    late = [_inc("i2", [_det("2026-08-23T10:02:30Z", "T1547.001")])]
    r = {a.id: a for a in A.attribute(fired, late)}
    c.check("a detection long after the window still attributes",
            r["runkey"].detected)
    c.check("its latency reflects the real delay",
            r["runkey"].latency_seconds == 130.0)

    # ------------------------------------------------------------------ [3]
    print("\n[3] a detection that predates its technique is STALE, never a hit")
    stale = [_inc("i3", [_det("2026-08-23T09:59:00Z", "T1003.001")])]
    r = {a.id: a for a in A.attribute(fired, stale)}
    c.check("a pre-execution detection does not count",
            not r["lsass"].detected)

    # ------------------------------------------------------------------ [4]
    print("\n[4] a detection folded into a PRE-EXISTING incident still counts")
    folded = [_inc("old-1", [_det("2026-08-23T10:00:03Z", "T1003.001")])]
    r = {a.id: a for a in A.attribute(fired, folded,
                                      before_incident_ids=["old-1"])}
    c.check("folding into an older incident does not hide the hit",
            r["lsass"].detected)
    c.check("and that older incident is not counted as a false positive",
            all(not a.false_positive_ids for a in r.values()))

    # ------------------------------------------------------------------ [5]
    print("\n[5] correlated techniques on one detection are all reachable")
    corr = [_inc("i4", [_det("2026-08-23T10:00:25Z", "T9999",
                             all_techniques=["T1547.001", "T9999"])])]
    r = {a.id: a for a in A.attribute(fired, corr)}
    c.check("a technique named only in all_techniques still attributes",
            r["runkey"].detected)

    # ------------------------------------------------------------------ [6]
    print("\n[6] USER-DEFINED rules are recorded and NOT counted")
    for label, inc in (
        ("by category", _inc("i5", [_det("2026-08-23T10:00:05Z", "T1003.001")],
                             category="user_rule")),
        ("by marker", _inc("i6", [_det("2026-08-23T10:00:05Z", "T1003.001",
                                       title="user:always_block hit")])),
    ):
        r = {a.id: a for a in A.attribute(fired, [inc])}
        c.check(f"a user-rule hit does not score as detection ({label})",
                not r["lsass"].detected)
        c.check(f"but it is recorded rather than dropped ({label})",
                r["lsass"].user_rule_only)

    # A real detection alongside a user-rule one must still win.
    both = [_inc("i7", [_det("2026-08-23T10:00:04Z", "T1003.001",
                             title="user:always_block hit"),
                        _det("2026-08-23T10:00:06Z", "T1003.001",
                             title="real rule")])]
    r = {a.id: a for a in A.attribute(fired, both)}
    c.check("a real detection alongside a user-rule hit still counts",
            r["lsass"].detected and not r["lsass"].user_rule_only)

    # ------------------------------------------------------------------ [7]
    print("\n[7] false positives: NEW incidents that matched nothing")
    fps = [
        _inc("i8", [_det("2026-08-23T10:00:05Z", "T4444")]),   # during lsass
        _inc("i9", [_det("2026-08-23T10:00:25Z", "T5555")]),   # during runkey
        _inc("old-2", [_det("2026-08-23T10:00:05Z", "T6666")]),  # pre-existing
    ]
    r = {a.id: a for a in A.attribute(fired, fps,
                                      before_incident_ids=["old-2"])}
    c.check("an unmatched new incident is an FP for the running technique",
            r["lsass"].false_positive_ids == ("i8",))
    c.check("FPs attribute to the correct disjoint window",
            r["runkey"].false_positive_ids == ("i9",))
    c.check("a PRE-EXISTING incident is never an FP",
            "old-2" not in r["lsass"].false_positive_ids +
                           r["runkey"].false_positive_ids)
    c.check("neither technique was scored as detected by an FP",
            not r["lsass"].detected and not r["runkey"].detected)

    # ------------------------------------------------------------------ [8]
    print("\n[8] robustness: bad timestamps degrade one comparison, not the run")
    junk = [_inc("i10", [_det("not-a-date", "T1003.001")]),
            _inc("i11", [_det("2026-08-23T10:00:07Z", "T1003.001")])]
    try:
        r = {a.id: a for a in A.attribute(fired, junk)}
        c.check("an unparseable timestamp does not raise", True)
        c.check("a good detection alongside it still attributes",
                r["lsass"].detected)
    except Exception as exc:                       # noqa: BLE001
        c.fail("an unparseable timestamp does not raise", repr(exc))
        c.fail("a good detection alongside it still attributes", "aborted")

    c.check("parse_utc returns None rather than raising",
            A.parse_utc("nonsense") is None and A.parse_utc("") is None)
    c.check("parse_utc handles Z and +00:00 identically",
            A.parse_utc("2026-08-23T10:00:00Z") ==
            A.parse_utc("2026-08-23T10:00:00+00:00"))

    # ------------------------------------------------------------------ [9]
    print("\n[9] merge_into_records folds results in without touching schema")
    recs = [{"id": "lsass", "technique_id": "T1003.001", "tier": "B_live"},
            {"id": "runkey", "technique_id": "T1547.001", "tier": "B_live"}]
    atts = A.attribute(fired, [_inc("i12", [_det("2026-08-23T10:00:05Z",
                                                 "T1003.001")])])
    merged = A.merge_into_records(recs, atts)
    c.check("record count is unchanged", len(merged) == 2)
    c.check("existing fields survive", merged[0]["tier"] == "B_live")
    c.check("detection result is folded in", merged[0]["detected"] is True)
    c.check("the un-detected technique is explicitly False",
            merged[1]["detected"] is False)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
