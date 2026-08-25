#!/usr/bin/env python3
"""Deception status: store counters + the /api/deception/status endpoint.

Two days of deception-engine work (persona.py, deception.py) had no product
surface at all - no counter of how many beacons were answered, no way to see
the current persona short of reading a JSON seed file on disk by hand. This
pins the two pieces that make it visible:

  1. Store.deception_stats() - reads dns_interceptor's own "deceived" decision
     label (never redefines it, so it cannot drift from what happened on the
     wire) and turns it into counts a UI can render.
  2. GET /api/deception/status - the endpoint the Electron renderer polls,
     wrapping those counts with the live persona (persona.py's single source
     of truth, read-only: this endpoint cannot rotate or influence it).

Requires fastapi + httpx (the test client). Skips cleanly if either is absent
- same convention as tests/test_web_auth.py.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks                                       # noqa: E402
from valkyrie.store import DnsEvent, Store                        # noqa: E402


def _event(domain: str, decision: str) -> DnsEvent:
    return DnsEvent.now(domain=domain, decision=decision, process_name="p.exe",
                        process_pid=1, process_path="", reason="",
                        suspicion=0.0, raw_category="dns")


def main() -> int:
    c = Checks("deception status (store + API)")

    tmp = Path(tempfile.mkdtemp(prefix="valkyrie_decstatus_"))
    store = Store(db_path=tmp / "t.db")
    store.start()

    # ------------------------------------------------------------------
    # 1. Store-level counters
    # ------------------------------------------------------------------
    baseline = store.deception_stats()
    c.check("a fresh store has zero deception counters",
            baseline == {"beacons_deceived_24h": 0, "trackers_deceived_24h": 0,
                        "trackers_deceived_total": 0, "beacons_deceived_total": 0})

    store.log(_event("tracker-a.example", "deceived"))
    store.log(_event("tracker-a.example", "deceived"))   # same tracker again
    store.log(_event("tracker-b.example", "deceived"))
    store.log(_event("allowed.example", "allowed"))       # must not be counted
    store.log(_event("blocked.example", "blocked"))       # must not be counted
    import time
    time.sleep(0.5)   # writer thread is async

    stats = store.deception_stats()
    c.check(f"3 deceived beacons counted, not the allowed/blocked ones "
            f"({stats['beacons_deceived_24h']} counted)",
            stats["beacons_deceived_24h"] == 3)
    c.check(f"2 DISTINCT trackers deceived, not 3 events "
            f"({stats['trackers_deceived_24h']} distinct)",
            stats["trackers_deceived_24h"] == 2)
    c.check("lifetime totals match the 24h window (all events are recent)",
            stats["trackers_deceived_total"] == 2
            and stats["beacons_deceived_total"] == 3)

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
    from valkyrie.persona import current_persona                  # noqa: E402

    state.store = store
    app = create_app()
    client = make_client(app, "127.0.0.1")

    resp = client.get("/api/deception/status")
    c.check("GET /api/deception/status -> 200", resp.status_code == 200)
    body = resp.json()

    c.check("endpoint's counters match the store's own counters",
            body.get("beacons_deceived_24h") == 3
            and body.get("trackers_deceived_24h") == 2)

    p = current_persona()
    persona_block = body.get("persona") or {}
    c.check("endpoint reports the SAME persona as the deception engine uses "
            "(no second, divergent source)",
            persona_block.get("locale") == p.locale
            and persona_block.get("timezone") == p.timezone
            and persona_block.get("city") == p.city
            and persona_block.get("os") == p.os_name)
    c.check("browser hint is a real 'Name Version' string",
            isinstance(persona_block.get("browser"), str)
            and " " in persona_block["browser"])

    # A monitoring-only endpoint must never let a caller change the identity
    # it reports - there is deliberately no POST here to pin that.
    c.check("no POST route exists for /api/deception/* (read-only surface)",
            client.post("/api/deception/status").status_code == 405)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
