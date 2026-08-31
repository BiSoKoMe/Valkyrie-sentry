#!/usr/bin/env python3
"""Platform Beta 1 - Nyx reliability harness (redteam/evaluation/nyx_reliability.py).

Same convention as tests/test_beta05_reliability.py: never spins up a real
browser/proxy - tests score() and its helpers offline against synthetic
visit/sample/self_test data, the same way that file tests score() against
synthetic timelines. A live browser+proxy run only happens in CI (see
.github/workflows/nyx-reliability.yml); this file guards the SCORING logic
itself, which is exactly what silently deciding PASS/FAIL wrong would hide.
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


class _FakePersona:
    def __init__(self, advertising_id: str) -> None:
        self.advertising_id = advertising_id


def main() -> int:
    import redteam.evaluation.nyx_reliability as m

    print("\n=== Nyx reliability harness (offline) ===\n")

    persona = _FakePersona("11111111-2222-4333-8444-555555555555")
    real_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

    print("[1] _visit_url() - the 4 visit kinds")
    u1 = m._visit_url("unauthorized-tracker-1", "firstparty.test")
    u2 = m._visit_url("unauthorized-tracker-2", "firstparty.test")
    ua = m._visit_url("authorized-first-party", "firstparty.test")
    ub = m._visit_url("benign-no-personal-data", "firstparty.test")
    _check("tracker-1 points at tracker.test", "tracker=http://tracker.test:" in u1)
    _check("tracker-2 points at a DIFFERENT tracker domain",
           "tracker=http://tracker2.test:" in u2 and "tracker2" not in u1)
    _check("authorized-first-party posts back to its OWN origin",
           "tracker=http://firstparty.test:" in ua)
    _check("benign-no-personal-data carries the nopersonal=1 flag",
           ub.endswith("&nopersonal=1") and "tracker.test" in ub)
    _check("an unknown kind raises rather than silently misrouting",
           _raises(lambda: m._visit_url("bogus-kind", "firstparty.test")))

    print("\n[2] _score_visit() - unauthorized visit, correctly deceived")
    outcome = {
        "kind": "unauthorized-tracker-1",
        "beacon_id": real_id,
        "beacon_body": f"adid={real_id}&screen=1x1",
        "received": [{"body": f"adid={persona.advertising_id}&screen=1x1", "host": "tracker.test", "path": "/api/ingest", "t": 0.0}],
        "error": None,
    }
    s = m._score_visit(outcome, persona)
    _check("reached_endpoint is True", s["reached_endpoint"] is True)
    _check("real value did NOT leak", s["real_leaked"] is False)
    _check("fake persona value WAS served", s["fake_served"] is True)

    print("\n[3] _score_visit() - unauthorized visit, deception FAILED (real id leaked)")
    outcome2 = dict(outcome, received=[{"body": f"adid={real_id}&screen=1x1", "host": "tracker.test", "path": "/api/ingest", "t": 0.0}])
    s2 = m._score_visit(outcome2, persona)
    _check("real_leaked is True when the real id reaches the endpoint", s2["real_leaked"] is True)
    _check("fake_served is False (the real value, not the persona's, was sent)", s2["fake_served"] is False)

    print("\n[4] _score_visit() - authorized/benign visit, left untouched")
    outcome3 = {
        "kind": "authorized-first-party",
        "beacon_id": real_id,
        "beacon_body": f"adid={real_id}&screen=1x1",
        "received": [{"body": f"adid={real_id}&screen=1x1", "host": "firstparty.test", "path": "/api/ingest", "t": 0.0}],
        "error": None,
    }
    s3 = m._score_visit(outcome3, persona)
    _check("unaltered is True when the received body matches byte-for-byte", s3["unaltered"] is True)

    print("\n[5] _score_visit() - a browser/navigation error still scores cleanly")
    outcome4 = {"kind": "unauthorized-tracker-1", "beacon_id": None, "beacon_body": None,
                "received": [], "error": "TimeoutError: page.goto"}
    s4 = m._score_visit(outcome4, persona)
    _check("reached_endpoint is False on a failed visit", s4["reached_endpoint"] is False)
    _check("error is carried through, not swallowed", s4["error"] is not None)

    def _visits(n_unauth_ok=2, n_unauth_leak=0, n_auth_ok=2, n_auth_altered=0):
        out = []
        for _ in range(n_unauth_ok):
            out.append({"kind": "unauthorized-tracker-1", "reached_endpoint": True,
                       "real_leaked": False, "fake_served": True, "unaltered": False, "error": None})
        for _ in range(n_unauth_leak):
            out.append({"kind": "unauthorized-tracker-2", "reached_endpoint": True,
                       "real_leaked": True, "fake_served": False, "unaltered": False, "error": None})
        for _ in range(n_auth_ok):
            out.append({"kind": "authorized-first-party", "reached_endpoint": True,
                       "real_leaked": False, "fake_served": False, "unaltered": True, "error": None})
        for _ in range(n_auth_altered):
            out.append({"kind": "benign-no-personal-data", "reached_endpoint": True,
                       "real_leaked": False, "fake_served": False, "unaltered": False, "error": None})
        return out

    def _samples(n=5, proxy_down_at=None, rss_growth=False, depth=0, dropped=0):
        out = []
        for i in range(n):
            proc = {"cpu_percent": 1.0, "rss": 100 + (i if rss_growth else 0), "vms": 200,
                   "threads": 5, "handles": 50}
            out.append({
                "t": float(i),
                "proxy_running": (i != proxy_down_at),
                "process": proc,
                "queue": {"depth": depth, "maxsize": 10000, "dropped": dropped},
            })
        return out

    print("\n[6] score() - a clean run passes every check")
    good = m.score(_visits(), _samples(), [{"caught": 5, "faked": 4, "total": 5}] * 3)
    _check("overall PASS", good["overall"] == "PASS")
    for name, c in good["checks"].items():
        _check(f"  {name} passes on a clean run", c["pass"])

    print("\n[7] score() - a real-value leak fails the run, and ONLY the relevant check")
    leaky = m.score(_visits(n_unauth_leak=1), _samples(), [{"caught": 5, "faked": 4, "total": 5}])
    _check("overall FAIL when a real value leaked", leaky["overall"] == "FAIL")
    _check("zero_real_value_leaks is the failing check",
           leaky["checks"]["zero_real_value_leaks"]["pass"] is False)
    _check("authorized_benign_flows_unaltered is UNAFFECTED (independent criteria)",
           leaky["checks"]["authorized_benign_flows_unaltered"]["pass"] is True)

    print("\n[8] score() - proxy going down at any sample fails proxy_alive_throughout")
    down = m.score(_visits(), _samples(proxy_down_at=2), [{"caught": 5, "faked": 4, "total": 5}])
    _check("proxy_alive_throughout fails if even one sample saw it down",
           down["checks"]["proxy_alive_throughout"]["pass"] is False)

    print("\n[9] score() - an authorized/benign flow getting altered is caught")
    altered = m.score(_visits(n_auth_altered=1), _samples(), [{"caught": 5, "faked": 4, "total": 5}])
    _check("authorized_benign_flows_unaltered fails when one was altered",
           altered["checks"]["authorized_benign_flows_unaltered"]["pass"] is False)

    print("\n[10] score() - self_test() drifting mid-run fails nyx_self_test_stable")
    drifted = m.score(_visits(), _samples(),
                      [{"caught": 5, "faked": 4, "total": 5}, {"caught": 4, "faked": 3, "total": 5}])
    _check("nyx_self_test_stable fails on a drifted self_test() result",
           drifted["checks"]["nyx_self_test_stable"]["pass"] is False)

    print("\n[11] score() - a run_error fails no_process_crash but nothing else, "
          "so partial results are still scored (crash-proof, same as Beta 0.5)")
    crashed = m.score(_visits(), _samples(), [{"caught": 5, "faked": 4, "total": 5}],
                      run_error="RuntimeError('boom')")
    _check("no_process_crash fails", crashed["checks"]["no_process_crash"]["pass"] is False)
    _check("other checks still evaluated (not short-circuited)",
           crashed["checks"]["proxy_alive_throughout"]["pass"] is True)

    print("\n[12] score() - empty inputs must FAIL, not vacuously PASS "
          "(an empty visit_log/samples/self_tests must never read as success)")
    empty = m.score([], [], [])
    _check("overall FAILs on a totally empty run", empty["overall"] == "FAIL")
    _check("proxy_alive_throughout fails with zero samples",
           empty["checks"]["proxy_alive_throughout"]["pass"] is False)
    _check("zero_real_value_leaks fails with zero unauthorized visits (nothing to prove)",
           empty["checks"]["zero_real_value_leaks"]["pass"] is False)
    _check("nyx_self_test_stable fails when self_test() was never sampled",
           empty["checks"]["nyx_self_test_stable"]["pass"] is False)

    print("\n[13] _resource_trend() / _store_queue_trend() - exploratory, non-gating")
    rt = m._resource_trend(_samples(n=5, rss_growth=True))
    _check("resource_trend reports first/last/max RSS", rt is not None and rt["max_rss"] >= rt["first_rss"])
    qt = m._store_queue_trend(_samples(n=3, depth=7, dropped=2))
    _check("store_queue_trend reports depth/dropped", qt is not None and qt["last_dropped"] == 2)
    _check("both return None on empty samples (not a crash)",
           m._resource_trend([]) is None and m._store_queue_trend([]) is None)

    print("\n[14] Sampler._sample_once() - shape, without a real proxy/store")
    class _FakeInsp:
        def is_running(self):
            return True

    class _FakeStore:
        def queue_stats(self):
            return {"depth": 0, "maxsize": 10000, "dropped": 0}

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        out_path = Path(td) / "sample.jsonl"
        sampler = m.Sampler(_FakeInsp(), _FakeStore(), out_path)
        rec = sampler._sample_once()
        _check("proxy_running reflects is_running()", rec["proxy_running"] is True)
        _check("queue carries the store's queue_stats()", rec["queue"]["depth"] == 0)
        _check("process key is present (None only if psutil is missing)", "process" in rec)

    print("\n[15] Sampler._sample_once() - a raising insp/store never crashes the sampler")
    class _BoomInsp:
        def is_running(self):
            raise RuntimeError("proxy handle gone")

    class _BoomStore:
        def queue_stats(self):
            raise RuntimeError("store gone")

    with tempfile.TemporaryDirectory() as td:
        out_path = Path(td) / "sample2.jsonl"
        sampler2 = m.Sampler(_BoomInsp(), _BoomStore(), out_path)
        rec2 = sampler2._sample_once()
        _check("a raising is_running() is caught, not propagated", rec2["proxy_running"] is False)
        _check("a raising queue_stats() is caught, not propagated", "error" in rec2["queue"])

    print("\n" + "=" * 52)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


def _raises(fn) -> bool:
    try:
        fn()
        return False
    except Exception:
        return True


if __name__ == "__main__":
    raise SystemExit(main())
