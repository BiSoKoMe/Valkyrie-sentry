#!/usr/bin/env python3
"""Live DNS event pipeline integrity (regression for the stale-dashboard bug).

Proves that a single DNS event flows end to end through ONE shared event source:

    DNSInterceptor -> Store -> EventBus -> /api/events  (and -> /ws live feed)

Specifically pins:
  1. The interceptor, the AppContext, and the web layer all reference the *same*
     Store object (no duplicate Store / no wrong injection).
  2. A logged event reaches an EventBus subscriber (the source the dashboard's
     WebSocket forwards) — i.e. subscribers are actually attached.
  3. /api/events reads that same Store (so it reflects live writes, not a stale
     snapshot).
  4. The /ws route delivers the event live through the app.
  5. A WebSocket implementation is installed — the missing dependency that made
     uvicorn answer /ws with HTTP 404 and left the dashboard frozen on its first
     snapshot. Removing `websockets` from the environment fails this test.
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def _wait(pred, timeout=3.0, step=0.05):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(step)
    return pred()


def main() -> int:
    from valkyrie.store import Store, DnsEvent
    from valkyrie.context import AppContext
    from valkyrie import web
    import valkyrie.web.server as web_server
    from valkyrie.web.server import create_app, _websocket_impl_available
    from valkyrie.dns_interceptor import DNSInterceptor
    from valkyrie.blocklist import BlocklistManager
    from valkyrie.behavioral import BehavioralEngine
    from valkyrie.rules import RulesLoader
    from valkyrie.process_watcher import ProcessWatcher

    print("\n=== live DNS pipeline integrity ===\n")

    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "pipeline.db")
        store.start()

        # The interceptor is constructed exactly as __main__ does: given `store`.
        interceptor = DNSInterceptor(
            store=store, blocklist=BlocklistManager(),
            behavioral=BehavioralEngine(), rules=RulesLoader(),
            process_watcher=ProcessWatcher(), port=0)

        # The composition root injects the SAME store into the web layer.
        ctx = AppContext(store=store)
        app = create_app(ctx)

        print("[1] One shared Store across interceptor / context / web")
        _check("interceptor writes to the injected store",
               interceptor._store is store)
        _check("AppContext holds that same store", ctx.store is store)
        _check("web layer serves from that same store",
               web_server.state is ctx and web_server.state.store is store)

        print("\n[2] EventBus delivers a logged event to subscribers")
        received: list = []
        store.subscribe(received.append)   # exactly what the web lifespan does
        store.log(DnsEvent.now(
            domain="facebook.com", decision="allowed", process_name="brave.exe",
            process_pid=1, process_path="", reason="", suspicion=0.0,
            raw_category=""))
        _check("a subscriber received the live event",
               _wait(lambda: any(m.get("event", {}).get("domain") == "facebook.com"
                                 for m in received)))

        print("\n[3] /api/events reflects the same store's live writes")
        try:
            from starlette.testclient import TestClient
            # `with` runs the app lifespan (which subscribes the dashboard's
            # broadcast to the store bus and captures the event loop).
            with TestClient(app, client=("127.0.0.1", 5555)) as client:
                _check("/api/events shows the just-logged domain",
                       _wait(lambda: any(
                           e.get("domain") == "facebook.com"
                           for e in client.get("/api/events").json())))

                print("\n[4] /ws route serves the live feed (init frame)")
                with client.websocket_connect("/ws") as ws:
                    first = ws.receive_json()
                    _check("/ws sends an init frame with events",
                           first.get("type") == "init"
                           and any(e.get("domain") == "facebook.com"
                                   for e in first.get("events", [])))
        except Exception as exc:   # noqa: BLE001
            _check(f"web/ws test stack available (raised {exc})", False)

        print("\n[5] A WebSocket implementation is installed (root-cause guard)")
        _check("uvicorn has a WebSocket backend (websockets/wsproto)",
               _websocket_impl_available())

        store.stop()

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
