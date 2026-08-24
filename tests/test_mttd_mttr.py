#!/usr/bin/env python3
"""MTTD / MTTR product metrics (valkyrie/edr/metrics.py, Clinton ch.10 +
IIBA §9.1.2).

Two layers:
  [1-4] Pure metric-math unit tests against constructed incident dicts —
        no engine, no store, no timing sensitivity.
  [5]   The real fix that makes MTTD non-trivial: ingest_telemetry() used to
        discard the collector's own event.ts and always stamp Detection.
        timestamp as "now". Pins that a TelemetryEvent with ts in the past
        now produces a Detection carrying THAT time, not "now".
  [6]   End-to-end through a real EdrEngine + Store: a telemetry event with
        a known-past ts produces a measurable, correct MTTD; a completed
        (non-dry-run) response produces a measurable, correct MTTR.
  [7]   GET /api/edr/metrics/mttd-mttr.
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from harness import Checks   # noqa: E402

from valkyrie.edr import metrics                              # noqa: E402
from valkyrie.edr.schema import iso_from_epoch, parse_iso      # noqa: E402

c = Checks("MTTD/MTTR product metrics", expect_min=20)


# ---------------------------------------------------------------------------
# [1] parse_iso / iso_from_epoch round-trip
# ---------------------------------------------------------------------------

def test_timestamp_helpers() -> None:
    print("\n[1] iso_from_epoch / parse_iso round-trip")
    now = time.time()
    iso = iso_from_epoch(now)
    back = parse_iso(iso)
    c.check("round-trips within 1ms", back is not None and abs(back - now) < 0.001)
    c.check("parse_iso('') -> None", parse_iso("") is None)
    c.check("parse_iso(garbage) -> None", parse_iso("not-a-timestamp") is None)
    c.check("parse_iso(None) -> None", parse_iso(None) is None)


# ---------------------------------------------------------------------------
# [2] mttd_seconds
# ---------------------------------------------------------------------------

def test_mttd_seconds() -> None:
    print("\n[2] mttd_seconds()")
    t0 = time.time()
    inc = {
        "created_at": iso_from_epoch(t0 + 3.0),
        "detections": [
            {"timestamp": iso_from_epoch(t0 + 1.0)},
            {"timestamp": iso_from_epoch(t0 + 3.0)},   # the one that created it
        ],
    }
    d = metrics.mttd_seconds(inc)
    c.check("uses the EARLIEST detection, not the incident-creating one",
            d is not None and abs(d - 2.0) < 0.01)

    c.check("no detections -> None (not a fabricated 0)",
            metrics.mttd_seconds({"created_at": iso_from_epoch(t0), "detections": []}) is None)
    c.check("missing created_at -> None",
            metrics.mttd_seconds({"detections": [{"timestamp": iso_from_epoch(t0)}]}) is None)
    c.check("never negative even if clocks are weird (floored at 0)",
            metrics.mttd_seconds({
                "created_at": iso_from_epoch(t0),
                "detections": [{"timestamp": iso_from_epoch(t0 + 5.0)}],
            }) == 0.0)


# ---------------------------------------------------------------------------
# [3] mttr_seconds
# ---------------------------------------------------------------------------

def test_mttr_seconds() -> None:
    print("\n[3] mttr_seconds()")
    t0 = time.time()
    inc = {
        "created_at": iso_from_epoch(t0),
        "responses": [
            {"dry_run": True, "status": "succeeded",
             "timestamp": iso_from_epoch(t0 + 0.5)},          # excluded: dry_run
            {"dry_run": False, "status": "pending",
             "timestamp": iso_from_epoch(t0 + 0.8)},          # excluded: not terminal
            {"dry_run": False, "status": "succeeded",
             "timestamp": iso_from_epoch(t0 + 2.0)},          # <- the one that counts
            {"dry_run": False, "status": "failed",
             "timestamp": iso_from_epoch(t0 + 5.0)},          # later; ignored (first wins)
        ],
    }
    r = metrics.mttr_seconds(inc)
    c.check("dry_run responses are excluded", r is not None)
    c.check("non-terminal (pending) responses are excluded", r is not None)
    c.check("uses the FIRST real terminal response (2.0s), not the last (5.0s)",
            r is not None and abs(r - 2.0) < 0.01)

    c.check("only dry_run/pending responses present -> None",
            metrics.mttr_seconds({
                "created_at": iso_from_epoch(t0),
                "responses": [{"dry_run": True, "status": "succeeded",
                              "timestamp": iso_from_epoch(t0 + 1)}],
            }) is None)
    c.check("no responses at all -> None (open incident, not a 0s response)",
            metrics.mttr_seconds({"created_at": iso_from_epoch(t0), "responses": []}) is None)


# ---------------------------------------------------------------------------
# [4] summarize / compute
# ---------------------------------------------------------------------------

def test_summarize_and_compute() -> None:
    print("\n[4] summarize() median/p95 + compute() over a batch")
    stats = metrics.summarize([1.0, 2.0, 3.0, 4.0, None, None])
    c.check("n counts only measurable values", stats.n == 4)
    c.check("total defaults to len(values) including Nones", stats.total == 6)
    c.check("median is correct", stats.median_seconds == 2.5)
    c.check("p95 is the near-max of a small sample",
            stats.p95_seconds is not None and stats.p95_seconds >= 3.0)

    empty = metrics.summarize([])
    c.check("empty input -> n=0, median/p95 None, not a crash",
            empty.n == 0 and empty.median_seconds is None and empty.p95_seconds is None)

    t0 = time.time()
    incidents = [
        {"created_at": iso_from_epoch(t0 + 1), "detections": [{"timestamp": iso_from_epoch(t0)}],
         "responses": [{"dry_run": False, "status": "succeeded",
                       "timestamp": iso_from_epoch(t0 + 2)}]},
        {"created_at": iso_from_epoch(t0 + 5), "detections": [{"timestamp": iso_from_epoch(t0 + 3)}],
         "responses": []},
    ]
    result = metrics.compute(incidents)
    c.check("compute() returns both mttd and mttr", set(result.keys()) == {"mttd", "mttr"})
    c.check("mttd total reflects both incidents", result["mttd"].total == 2)
    c.check("mttd n reflects both had measurable detections", result["mttd"].n == 2)
    c.check("mttr n reflects only ONE incident had a completed response",
            result["mttr"].n == 1)


# ---------------------------------------------------------------------------
# [5] ingest_telemetry preserves the collector's own event.ts
# ---------------------------------------------------------------------------

def test_ingest_telemetry_preserves_event_timestamp() -> None:
    print("\n[5] ingest_telemetry() carries event.ts into Detection.timestamp "
          "(previously always defaulted to 'now', discarding it)")
    from valkyrie.edr.engine import EdrEngine
    from valkyrie.store import Store

    tmp = Path(tempfile.mkdtemp(prefix="valkyrie_mttd_"))
    store = Store(db_path=tmp / "t.db")
    store.start()
    engine = EdrEngine(store)
    engine.start()

    past_ts = time.time() - 4.0   # simulate: collector observed this 4s "ago"
    ev = {
        "category": "process", "activity": "exec", "action": "flagged",
        "ts": past_ts, "severity": "high", "actor_name": "evil.exe",
        "actor_pid": 4242, "actor_path": "C:/temp/evil.exe",
        "source": "process_collector", "labels": ["suspicious_path"],
        "target": {}, "fields": {}, "reason": "test fixture",
    }
    inc_id = engine.ingest_telemetry(ev)
    c.check("a high-severity telemetry event raises an incident", bool(inc_id))

    detail = engine.get_incident(inc_id) if inc_id else None
    c.check("incident detail is retrievable", detail is not None)
    if detail:
        dets = detail.get("detections") or []
        c.check("incident carries exactly one detection", len(dets) == 1)
        if dets:
            det_ts = parse_iso(dets[0].get("timestamp"))
            c.check("Detection.timestamp matches the ORIGINAL event.ts, not "
                    "'now' at processing time",
                    det_ts is not None and abs(det_ts - past_ts) < 0.5)

    engine.stop()
    store.stop()


# ---------------------------------------------------------------------------
# [6] End-to-end MTTD + MTTR through a real EdrEngine
# ---------------------------------------------------------------------------

def test_end_to_end_mttd_mttr() -> None:
    print("\n[6] end-to-end: EdrEngine.mttd_mttr() over real incidents")
    from valkyrie.edr.engine import EdrEngine
    from valkyrie.store import Store

    tmp = Path(tempfile.mkdtemp(prefix="valkyrie_mttdmttr_"))
    store = Store(db_path=tmp / "t.db")
    store.start()

    class _Intel:
        def __init__(self):
            self.blocked = set()
        def remember_block(self, d, r=""):
            self.blocked.add(d)
        def remember_good(self, d, r=""):
            pass

    engine = EdrEngine(store, intelligence=_Intel())
    engine.start()

    past_ts = time.time() - 2.5
    ev = {
        "category": "process", "activity": "exec", "action": "flagged",
        "ts": past_ts, "severity": "high", "actor_name": "mal.exe",
        "actor_pid": 9999, "actor_path": "C:/temp/mal.exe",
        "source": "process_collector", "labels": ["suspicious_path"],
        "target": {}, "fields": {}, "reason": "test fixture 2",
    }
    inc_id = engine.ingest_telemetry(ev)
    c.check("second fixture incident created", bool(inc_id))

    # A real (non-dry-run), reversible response — safe to actually run in a
    # test: block_domain only writes to the in-memory _Intel stub above, it
    # never touches this host's real DNS/firewall/registry.
    if inc_id:
        engine.respond("block_domain", "evil-c2.example", dry_run=False,
                       incident_id=inc_id)

    result = engine.mttd_mttr(limit=50)
    c.check("mttd_mttr() returns the expected top-level shape",
            {"mttd", "mttr"} <= set(result.keys()))
    c.check("mttd has at least one measurable incident",
            result["mttd"]["n"] >= 1)
    c.check("mttd median reflects the ~2.5s injected latency (not near-zero)",
            result["mttd"]["median_seconds"] is not None
            and result["mttd"]["median_seconds"] > 1.0)
    c.check("mttr has at least one measurable (real, completed) response",
            result["mttr"]["n"] >= 1)
    c.check("mttr median is a small, real number (near-instant in-process "
            "responder, not None and not absurd)",
            result["mttr"]["median_seconds"] is not None
            and 0.0 <= result["mttr"]["median_seconds"] < 10.0)

    engine.stop()
    store.stop()


# ---------------------------------------------------------------------------
# [7] GET /api/edr/metrics/mttd-mttr
# ---------------------------------------------------------------------------

def test_api_endpoint() -> None:
    print("\n[7] GET /api/edr/metrics/mttd-mttr")
    try:
        from starlette.testclient import TestClient   # noqa: F401
    except Exception as exc:                          # noqa: BLE001
        c.skip("API endpoint checks", f"test client unavailable: {exc}")
        return
    try:
        from valkyrie.web.server import create_app, state
    except ImportError as exc:
        c.skip("API endpoint checks", f"fastapi/web stack unavailable: {exc}")
        return

    from testclient_compat import make_client   # noqa: E402

    prior_edr = state.edr
    try:
        state.edr = None
        app = create_app()
        client = make_client(app, "127.0.0.1")
        resp = client.get("/api/edr/metrics/mttd-mttr")
        c.check("EDR disabled -> 503, not a crash", resp.status_code == 503)

        from valkyrie.edr.engine import EdrEngine
        from valkyrie.store import Store
        tmp = Path(tempfile.mkdtemp(prefix="valkyrie_mttdapi_"))
        store = Store(db_path=tmp / "t.db")
        store.start()
        engine = EdrEngine(store)
        engine.start()
        state.edr = engine
        app2 = create_app()
        client2 = make_client(app2, "127.0.0.1")
        resp2 = client2.get("/api/edr/metrics/mttd-mttr")
        c.check("EDR enabled -> 200", resp2.status_code == 200)
        body = resp2.json()
        c.check("response has mttd + mttr, each with n/total/median/p95",
                {"mttd", "mttr"} <= set(body.keys())
                and {"n", "total", "median_seconds", "p95_seconds"} <= set(body["mttd"].keys()))
        c.check("no incidents yet -> n=0, not an error",
                body["mttd"]["n"] == 0 and body["mttr"]["n"] == 0)
        c.check("no POST route exists (read-only monitoring surface)",
                client2.post("/api/edr/metrics/mttd-mttr").status_code == 405)
        engine.stop()
        store.stop()
    finally:
        state.edr = prior_edr


def main() -> int:
    print("=" * 60)
    print("MTTD / MTTR product metrics (Clinton ch.10 + IIBA §9.1.2)")
    print("=" * 60)
    test_timestamp_helpers()
    test_mttd_seconds()
    test_mttr_seconds()
    test_summarize_and_compute()
    test_ingest_telemetry_preserves_event_timestamp()
    test_end_to_end_mttd_mttr()
    test_api_endpoint()
    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
