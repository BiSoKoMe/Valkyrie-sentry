#!/usr/bin/env python3
"""DoH-bypass surfacing: store counters + the /api/doh/status endpoint.

DoH-bypass attempts (a process resolving DNS-over-HTTPS straight to a public
resolver's IP, routing around Valkyrie's interception entirely) have always
landed in the event store (raw_category="doh_bypass") and the live
DoHDetector has always tracked its own health via .status() — but neither
ever reached an API endpoint, so the packaged app had zero visibility into
this despite the detector actively running. This pins:

  1. Store.doh_bypass_stats() — reads doh_detector.py's own raw_category
     label (never redefines it, so it cannot drift from what the detector
     actually found) into counts + a "most recent attempt" a UI can render.
  2. GET /api/doh/status — combines the LIVE detector's own health (is
     psutil available, is the scan loop actually running) with those store
     counts, so "detector can't run here" and "detector fine, nothing
     found" render as the two distinct states they are.

Requires fastapi + httpx (the test client). Skips cleanly if either is
absent — same convention as tests/test_web_auth.py.
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks                                       # noqa: E402
from valkyrie.store import DnsEvent, Store                        # noqa: E402


def _bypass(ip: str, proc: str) -> DnsEvent:
    return DnsEvent.now(domain=ip, decision="flagged", process_name=proc,
                        process_pid=1234, process_path="", suspicion=0.9,
                        reason=f"DoH bypass attempt -> {ip}:443",
                        raw_category="doh_bypass")


def _normal(domain: str) -> DnsEvent:
    return DnsEvent.now(domain=domain, decision="allowed", process_name="p.exe",
                        process_pid=1, process_path="", reason="",
                        suspicion=0.0, raw_category="dns")


def main() -> int:
    c = Checks("DoH bypass status (store + API)")

    tmp = Path(tempfile.mkdtemp(prefix="valkyrie_dohstatus_"))
    store = Store(db_path=tmp / "t.db")
    store.start()

    # ------------------------------------------------------------------
    # 1. Store-level counters
    # ------------------------------------------------------------------
    baseline = store.doh_bypass_stats()
    c.check("a fresh store has zero bypass counters and no 'most recent'",
            baseline == {"bypass_attempts_24h": 0, "bypass_processes_24h": 0,
                        "bypass_attempts_total": 0, "most_recent": None})

    store.log(_bypass("1.1.1.1", "chrome.exe"))
    store.log(_bypass("8.8.8.8", "chrome.exe"))       # same process again
    store.log(_bypass("9.9.9.9", "firefox.exe"))
    store.log(_normal("allowed.example"))              # must not be counted
    time.sleep(0.5)   # writer thread is async

    stats = store.doh_bypass_stats()
    c.check(f"3 bypass attempts counted, not the normal DNS event "
            f"({stats['bypass_attempts_24h']} counted)",
            stats["bypass_attempts_24h"] == 3)
    c.check(f"2 DISTINCT processes attempting bypass, not 3 events "
            f"({stats['bypass_processes_24h']} distinct)",
            stats["bypass_processes_24h"] == 2)
    c.check("lifetime total matches the 24h window (all events are recent)",
            stats["bypass_attempts_total"] == 3)
    c.check("most_recent names the LAST attempt's process and resolver",
            stats["most_recent"] is not None
            and stats["most_recent"]["process_name"] == "firefox.exe"
            and stats["most_recent"]["resolver_ip"] == "9.9.9.9")

    # ------------------------------------------------------------------
    # 2. The API endpoint the renderer actually polls
    # ------------------------------------------------------------------
    try:
        from starlette.testclient import TestClient   # noqa: F401
    except Exception as exc:      # noqa: BLE001
        c.skip("API endpoint checks", f"test client unavailable: {exc}")
        return c.finish()

    try:
        from valkyrie.web.server import create_app, state
    except ImportError as exc:
        c.skip("API endpoint checks", f"fastapi/web stack unavailable: {exc}")
        return c.finish()

    from testclient_compat import make_client                     # noqa: E402

    # 2a. No live detector wired (state.doh is None) — must degrade honestly,
    # never 500, and never claim the detector is running when it is not.
    state.store = store
    state.doh = None
    app = create_app()
    client = make_client(app, "127.0.0.1")

    resp = client.get("/api/doh/status")
    c.check("GET /api/doh/status -> 200 even with no live detector wired",
            resp.status_code == 200)
    body = resp.json()
    c.check("no detector wired -> running/available both False, not a crash",
            body.get("running") is False and body.get("available") is False)
    c.check("store counters still reach the API without a live detector",
            body.get("bypass_attempts_24h") == 3
            and body.get("bypass_processes_24h") == 2)

    # 2b. A live detector IS wired — its own health reaches the same payload.
    from valkyrie.doh_detector import DoHDetector
    live = DoHDetector(store=store)
    state.doh = live
    app2 = create_app()
    client2 = make_client(app2, "127.0.0.1")
    body2 = client2.get("/api/doh/status").json()
    c.check("live detector's own status() fields reach the endpoint "
            "('available' reflects psutil, not hardcoded)",
            body2.get("available") == live.status()["available"])
    c.check("counters are unaffected by which detector instance is wired "
            "(same store, same counts)",
            body2.get("bypass_attempts_24h") == 3)

    # A monitoring-only endpoint must never let a caller change anything.
    c.check("no POST route exists for /api/doh/* (read-only surface)",
            client2.post("/api/doh/status").status_code == 405)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
