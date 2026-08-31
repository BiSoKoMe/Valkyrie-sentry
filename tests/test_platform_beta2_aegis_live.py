#!/usr/bin/env python3
"""Platform Beta 2 (Aegis) live-fire harness (redteam/evaluation/platform_beta2_aegis_live.py).

Same convention as tests/test_beta05_reliability.py and
tests/test_nyx_reliability.py: never spins up a real browser/proxy - tests
score() offline against synthetic `run()`-shaped result dicts. The real
browser+collectors+proxy run only happens in CI.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def _good_result() -> dict:
    return {
        "ok": True,
        "subject_pid": 4242,
        "subject_event_count": 3,
        "subject_events_by_category": {"process": 1, "network": 1, "privacy": 1},
        "canonical_event_types": ["PROCESS", "NETWORK", "PRIVACY"],
        "exposure_observation_categories": ["DESTINATION", "DESTINATION"],
        "unavailable_categories_never_appeared": True,
        "unavailable_categories_declared": ["VOLUME", "DIRECTION", "IDENTITY", "SESSION"],
        "non_network_events_produced_zero_observations": True,
        "provenance_all_trace_to_real_event_ids": True,
        "real_event_ids": ["evt-1", "evt-2", "evt-3"],
        "fused_decision_hypothesis": {"name": "possible_data_theft", "confidence": 0.9},
        "aegis_inference_hypotheses": {"DESTINATION_DISCLOSURE": {}},
    }


def main() -> int:
    import redteam.evaluation.platform_beta2_aegis_live as m

    print("\n=== Platform Beta 2 (Aegis) live-fire harness (offline) ===\n")

    print("[1] score() - a clean, real chain passes every check")
    good = m.score(_good_result())
    _check("overall PASS", good["overall"] == "PASS")
    for name, c in good["checks"].items():
        _check(f"  {name} passes on a clean result", c["pass"])

    print("\n[2] score() - no chromium-like process ever captured fails cleanly")
    no_subject = m.score({"ok": False, "reason": "no chromium-like process event captured"})
    _check("overall FAILs when no subject was found", no_subject["overall"] == "FAIL")
    _check("real_chain_captured is the failing check",
           no_subject["checks"]["real_chain_captured"]["pass"] is False)

    print("\n[3] score() - a chain missing network/privacy events fails "
          "chain_spans_process_and_network_or_privacy")
    process_only = _good_result()
    process_only["subject_events_by_category"] = {"process": 1}
    scored = m.score(process_only)
    _check("fails when the chain never left the process category",
           scored["checks"]["chain_spans_process_and_network_or_privacy"]["pass"] is False)

    print("\n[4] score() - DESTINATION never derived fails destination_observation_derived")
    no_dest = _good_result()
    no_dest["exposure_observation_categories"] = []
    scored2 = m.score(no_dest)
    _check("fails when no DESTINATION observation was derived",
           scored2["checks"]["destination_observation_derived"]["pass"] is False)

    print("\n[5] score() - a fabricated unavailable category fails the honesty check")
    fabricated = _good_result()
    fabricated["unavailable_categories_never_appeared"] = False
    scored3 = m.score(fabricated)
    _check("fails when VOLUME/DIRECTION/IDENTITY/SESSION was fabricated",
           scored3["checks"]["unavailable_categories_never_fabricated"]["pass"] is False)

    print("\n[6] score() - a non-network event producing an observation fails "
          "the non_network_events_produce_zero_observations check")
    leaky = _good_result()
    leaky["non_network_events_produced_zero_observations"] = False
    scored4 = m.score(leaky)
    _check("fails when a process/persistence/registry-only event produced "
           "an Aegis observation", scored4["checks"]["non_network_events_produce_zero_observations"]["pass"] is False)

    print("\n[7] score() - missing provenance fails provenance_survives")
    no_prov = _good_result()
    no_prov["provenance_all_trace_to_real_event_ids"] = False
    scored5 = m.score(no_prov)
    _check("fails when provenance doesn't trace to a real event id",
           scored5["checks"]["provenance_survives"]["pass"] is False)

    print("\n[8] score() - an observe() error fails no_observe_errors but "
          "nothing else (crash-proof, partial results still scored)")
    with_errors = _good_result()
    with_errors["observe_errors"] = ["RuntimeError('boom')"]
    scored6 = m.score(with_errors)
    _check("no_observe_errors fails", scored6["checks"]["no_observe_errors"]["pass"] is False)
    _check("other checks still evaluated (not short-circuited)",
           scored6["checks"]["destination_observation_derived"]["pass"] is True)

    print("\n[9] _find_subject_pid() - prefers the real Nyx privacy "
          "observation's pid (ADR 0057's real attribution) over guessing "
          "from a process name - a real Chromium launch is multi-process, "
          "so the first chrome-shaped process event is often the WRONG "
          "child (not the one that actually owned the connection)")
    class _Ev:
        def __init__(self, category, actor_name, actor_pid):
            self.category = category
            self.actor_name = actor_name
            self.actor_pid = actor_pid

    events = [
        _Ev("process", "chrome", 100),           # main browser process
        _Ev("process", "chrome", 4242),          # the network-service child
        _Ev("network", "chrome", 4242),
        _Ev("privacy", "chrome", 4242),          # the real attributed pid
    ]
    pid = m._find_subject_pid(events)
    _check("prefers the privacy event's pid over the first process-name match",
           pid == 4242)

    print("  [9b] falls back to the network event's pid when no privacy "
          "event was captured (NetworkCollector, unlike a userland poller "
          "watching a snapshot, still resolved a real pid)")
    events_no_privacy = [
        _Ev("process", "chrome", 100),
        _Ev("network", "chrome", 4242),
    ]
    _check("falls back to the network event's pid",
           m._find_subject_pid(events_no_privacy) == 4242)

    print("  [9c] falls back to a name match only when neither privacy nor "
          "network events exist at all")
    events_process_only = [
        _Ev("process", "explorer.exe", 100),
        _Ev("process", "headless_shell", 4242),
    ]
    _check("falls back to a chrome/chromium/headless_shell name match",
           m._find_subject_pid(events_process_only) == 4242)
    _check("returns None when nothing browser-shaped was captured at all",
           m._find_subject_pid([_Ev("process", "svchost.exe", 1)]) is None)

    print("\n" + "=" * 52)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
