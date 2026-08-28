"""Nyx LIVE test - the reliable one.

Not offline synthetic strings. This stands up Valkyrie's REAL mitmproxy + Nyx,
drives a REAL headless Chromium through it, loads a page that a REAL browser
fingerprints and beacons from (device id via crypto.randomUUID), and MEASURES
what actually happened at the tracker's own endpoint:

  * did Nyx CATCH the real browser's beacon?  (observe proof)
  * in ACT mode, did the tracker endpoint receive a FAKE id instead of the
    browser's real one?  (the killer end-to-end deception proof)
  * did farble give a DIFFERENT canvas fingerprint per origin?  (un-linkable)

This is the Nyx equivalent of the EDR's live Tier B: real execution, real
payloads, improve from the real misses. Runs on Linux CI (Nyx/farble/proxy are
cross-platform; no Sysmon needed).

Usage: python redteam/nyx_live/nyx_live_test.py   (needs mitmproxy + playwright
+ chromium installed, and hosts entries firstparty.test/other.test/tracker.test
-> 127.0.0.1). Exit 0 only if the core claims hold.
"""
from __future__ import annotations

import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import valkyrie.config as cfg
cfg.NYX_ACT = True                       # test the full deception, end to end

from valkyrie.store import Store          # noqa: E402
from valkyrie.tls_inspector import TLSInspector   # noqa: E402
from valkyrie.persona import current_persona      # noqa: E402

PORT = 8899
PROXY_PORT = 8443
PAGE = (Path(__file__).resolve().parent / "page.html").read_bytes()
RECEIVED: list[dict] = []                 # bodies the tracker endpoint received


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):            # keep the run log clean
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(PAGE)))
        self.end_headers()
        self.wfile.write(PAGE)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(n) if n else b""
        RECEIVED.append({"path": self.path,
                         "host": self.headers.get("Host", ""),
                         "body": body.decode("utf-8", "replace")})
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")


def main() -> int:
    store = Store(ram_uri="file:nyxlive?mode=memory&cache=shared")
    store.start()

    insp = TLSInspector(store, port=PROXY_PORT)
    try:
        insp.setup_ca()
    except Exception as e:
        print("NYX-LIVE: setup_ca warning:", e)
    if not insp.start():
        print("NYX-LIVE: FAIL — proxy did not start (is mitmproxy installed?)")
        return 2

    srv = ThreadingHTTPServer(("127.0.0.1", PORT), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(1.0)

    persona = current_persona()
    real_ids: list[str] = []
    canvas: dict[str, int] = {}

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("NYX-LIVE: FAIL — playwright not installed")
        return 2

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox"])
            for origin in ("firstparty.test", "other.test"):
                ctx = browser.new_context(
                    proxy={"server": f"http://127.0.0.1:{PROXY_PORT}"},
                    ignore_https_errors=True)
                page = ctx.new_page()
                url = (f"http://{origin}:{PORT}/page.html"
                       f"?tracker=http://tracker.test:{PORT}")
                page.goto(url, wait_until="load", timeout=30000)
                page.wait_for_function(
                    "document.getElementById('beacon-status') && "
                    "/sent|err|no-tracker/.test("
                    "document.getElementById('beacon-status').textContent)",
                    timeout=15000)
                canvas[origin] = page.evaluate("window.__canvasHash")
                bid = page.evaluate("window.__beaconId")
                if bid:
                    real_ids.append(str(bid))
                ctx.close()
            browser.close()
    except Exception as e:
        print("NYX-LIVE: browser drive error:", e)

    time.sleep(2.0)                        # let the store's async writer drain
    try:
        insp.stop()
    except Exception:
        pass
    srv.shutdown()

    events = store.recent_events(limit=1000)
    nyx_ev = [e for e in events
              if (e.get("raw_category") or "") in ("nyx_leak", "nyx_fake")
              and "tracker.test" in (e.get("domain") or "")]
    faked_ev = [e for e in nyx_ev if (e.get("raw_category") == "nyx_fake")]
    tracker_bodies = [r["body"] for r in RECEIVED]     # every POST the endpoint got

    from collections import Counter
    print("received request paths:", [r["path"] for r in RECEIVED])
    print("nyx event categories seen:",
          dict(Counter((e.get("raw_category") or "") for e in events
                       if (e.get("raw_category") or "").startswith("nyx"))))
    print("all event categories seen:",
          dict(Counter((e.get("raw_category") or "?") for e in events)))

    caught = len(nyx_ev) > 0
    real_leaked = any(any(rid in b for rid in real_ids) for b in tracker_bodies)
    fake_served = any(persona.advertising_id in b for b in tracker_bodies)
    cross_origin_differs = len(set(canvas.values())) > 1 if canvas else False

    print("=" * 64)
    print("NYX LIVE — real Chromium through the real Valkyrie proxy")
    print("=" * 64)
    print("beacons received at the tracker endpoint:", len(tracker_bodies))
    for b in tracker_bodies[:3]:
        print("   received:", b[:120])
    print("real browser beacon ids:", [r[:12] + '…' for r in real_ids])
    print("NYX caught the real beacon:", caught, f"({len(nyx_ev)} nyx events)")
    print("NYX faked it (nyx_fake events):", len(faked_ev))
    print("real browser id LEAKED to tracker:", real_leaked, "(want False)")
    print("FAKE persona id served to tracker:", fake_served, "(want True)")
    print("farble canvas differs per origin:", cross_origin_differs, canvas)
    ok = caught and (not real_leaked) and fake_served
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
