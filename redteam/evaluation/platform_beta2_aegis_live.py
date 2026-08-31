r"""Platform Beta 2 (Aegis): the live-fire proof over REAL events.

docs/AEGIS_PLATFORM_BRIDGE.md ("Platform Alpha") proved the translation
boundary (`valkyrie.aegis_bridge`) correctly turns a `CanonicalEvent`
stream into `ExposureObservation`s and back into Aegis's own reasoning,
over ONE hand-built, fabricated-but-structurally-real event chain
(`platform_alpha_evidence_story.py`). Its own closing line named the next
question directly: "It does not prove... live-host reliability - those
remain the next environmental wall, named rather than simulated."

This is that proof. Same shape (one causal chain: a process, a network
connection, an unauthorized NYX privacy observation, all one subject) -
but every event here comes from REAL collectors observing REAL activity:
a real Playwright Chromium process, launched and polled by the real
`ProcessCollector`/`NetworkCollector` (same classes Beta 0.5 qualified),
driven through the real `TLSInspector`/Nyx addon (same ones Beta 1
qualified) to a real unauthorized-tracker page. Nothing here is a new
reasoning layer - it is the same `DetectionArchitectureV2` -> `aegis_bridge`
-> `aegis_exposure` pipeline already proven over fabricated events, now
fed real ones.

Runs entirely in-process (no separate engine subprocess, matching
nyx_reliability.py's own shape - `DetectionArchitectureV2` is constructed
directly here, the same way platform_alpha_evidence_story.py already does,
rather than requiring a live engine process to expose new introspection).

Usage:
    python redteam/evaluation/platform_beta2_aegis_live.py
"""

from __future__ import annotations

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))

RESULTS_DIR = Path(__file__).resolve().parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)

PAGE_PATH = _ROOT / "nyx_live" / "page.html"
HTTP_PORT = 8898
PROXY_PORT = 8444
FIRST_PARTY_HOST = "firstparty.test"
TRACKER_HOST = "tracker.test"

# How chromium's own process names itself - matched against ProcessCollector's
# real, live-captured events to find the one subject this whole chain is
# about, since Playwright's sync API does not hand back the browser's OS pid
# directly. A CI runner launches nothing else chromium-shaped in this window.
_BROWSER_NAME_HINTS = ("chrome", "chromium", "headless_shell")

_PAGE_BYTES = PAGE_PATH.read_bytes() if PAGE_PATH.exists() else b""
RECEIVED: list[dict] = []


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(_PAGE_BYTES)))
        self.end_headers()
        self.wfile.write(_PAGE_BYTES)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(n) if n else b""
        RECEIVED.append({"path": self.path, "body": body.decode("utf-8", "replace")})
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")


class _EdrCapture:
    """Stands in for the live engine's `Engine.ingest_telemetry` - just
    enough surface (this one method) for TLSInspector's addon to resolve a
    real causality pid via the real `pid_for_local_port()` lookup (ADR
    0057) and hand back a real TelemetryEvent, without needing a full
    separate engine process running to capture it."""

    def __init__(self, sink: list) -> None:
        self._sink = sink

    def ingest_telemetry(self, event) -> None:
        self._sink.append(event)


def _find_subject_pid(events: list) -> int | None:
    """The real Nyx privacy observation's pid is ground truth for "which
    process this chain is about" - it was resolved by the real ADR-0057
    `pid_for_local_port()` attribution against the real OS connection
    table at the moment of the real beacon, not guessed. A name-match over
    "process" events is a poor substitute: a real Chromium launch is
    MULTI-PROCESS (a main browser process plus separate renderer/GPU/
    network-service child processes on Linux), and the child that actually
    owns the outbound socket Nyx observed is often not the first
    chrome-shaped process event to appear."""
    for e in events:
        if e.category == "privacy" and e.actor_pid:
            return e.actor_pid
    # Fallback (no privacy event captured at all) - the network event's own
    # pid is the next-best ground truth for "who owned the connection."
    for e in events:
        if e.category == "network" and e.actor_pid:
            return e.actor_pid
    for e in events:
        if e.category == "process" and any(
                h in (e.actor_name or "").lower() for h in _BROWSER_NAME_HINTS):
            return e.actor_pid
    return None


def run() -> dict:
    import valkyrie.config as cfg
    cfg.NYX_ACT = True

    from valkyrie.store import Store
    from valkyrie.tls_inspector import TLSInspector
    from valkyrie.process_telemetry import ProcessCollector
    from valkyrie.network_telemetry import NetworkCollector
    from valkyrie.aegis_bridge import translate_session, UNAVAILABLE_CATEGORIES
    from valkyrie.aegis_exposure import evaluate_pair
    from valkyrie.edr.detection_v2 import DetectionArchitectureV2, ArchitectureResult

    captured: list = []
    cap_lock = threading.Lock()

    def _capture(event) -> None:
        with cap_lock:
            captured.append(event)

    RECEIVED.clear()
    store = Store(ram_uri="file:beta2aegis?mode=memory&cache=shared")
    store.start()

    proc_collector = ProcessCollector(emit=_capture, interval=1.0)
    net_collector = NetworkCollector(emit=_capture, interval=1.0)
    proc_collector.start()
    net_collector.start()
    time.sleep(1.5)   # let both establish their baselines before anything new appears

    insp = TLSInspector(store, edr=_EdrCapture(captured), port=PROXY_PORT)
    try:
        insp.setup_ca()
    except Exception as exc:                                  # noqa: BLE001
        print("BETA2-AEGIS: setup_ca warning:", exc)
    if not insp.start():
        print("BETA2-AEGIS: FAIL - proxy did not start (is mitmproxy installed?)")
        return {"ok": False, "reason": "proxy_start_failed"}

    srv = ThreadingHTTPServer(("127.0.0.1", HTTP_PORT), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(1.0)

    browser_error = None
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("BETA2-AEGIS: FAIL - playwright not installed")
        proc_collector.stop(); net_collector.stop(); insp.stop(); srv.shutdown()
        return {"ok": False, "reason": "playwright_missing"}

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox"])
            ctx = browser.new_context(
                proxy={"server": f"http://127.0.0.1:{PROXY_PORT}"},
                ignore_https_errors=True)
            page = ctx.new_page()
            url = (f"http://{FIRST_PARTY_HOST}:{HTTP_PORT}/page.html"
                   f"?tracker=http://{TRACKER_HOST}:{HTTP_PORT}")
            page.goto(url, wait_until="load", timeout=15000)
            page.wait_for_function(
                "document.getElementById('beacon-status') && "
                "/sent|err|no-tracker/.test("
                "document.getElementById('beacon-status').textContent)",
                timeout=10000)
            # Give the still-open browser process a few more real poll
            # cycles to be SEEN as "new" by ProcessCollector, and its
            # connection to be SEEN by NetworkCollector - closing it
            # immediately would let it exit before either collector's next
            # poll runs, and there would be nothing left to observe.
            time.sleep(3.5)
            ctx.close()
            browser.close()
    except Exception as exc:                                  # noqa: BLE001
        browser_error = repr(exc)

    time.sleep(1.0)
    proc_collector.stop()
    net_collector.stop()
    try:
        insp.stop()
    except Exception:
        pass
    srv.shutdown()

    with cap_lock:
        all_events = list(captured)

    subject_pid = _find_subject_pid(all_events)
    result: dict = {
        "ok": False,
        "browser_error": browser_error,
        "total_events_captured": len(all_events),
        "all_events_debug": [
            {"category": e.category, "actor_pid": e.actor_pid, "actor_name": e.actor_name}
            for e in all_events
        ],
        "events_by_category": {},
    }
    for e in all_events:
        result["events_by_category"][e.category] = result["events_by_category"].get(e.category, 0) + 1

    if subject_pid is None:
        result["reason"] = "no chromium-like process event captured - nothing to build a chain from"
        return result

    subject_events = [e for e in all_events if e.actor_pid == subject_pid]
    subject_events.sort(key=lambda e: e.ts)
    result["subject_pid"] = subject_pid
    result["subject_event_count"] = len(subject_events)
    result["subject_events_by_category"] = {}
    for e in subject_events:
        result["subject_events_by_category"][e.category] = (
            result["subject_events_by_category"].get(e.category, 0) + 1)

    # The real pipeline, over the real chain - identical shape to
    # platform_alpha_evidence_story.run(), just fed real events instead of
    # the 3 hand-built ones.
    arch = DetectionArchitectureV2()
    arch_results: list[ArchitectureResult] = []
    for e in subject_events:
        try:
            arch_results.append(arch.observe(e))
        except Exception as exc:                              # noqa: BLE001
            result.setdefault("observe_errors", []).append(repr(exc))

    canonical_events = [r.event for r in arch_results]
    exposure_observations = translate_session(canonical_events)
    aegis = evaluate_pair(exposure_observations, canonical_events[0].subject.instance_id) \
        if canonical_events and exposure_observations else None

    non_network_types = {"PROCESS", "PERSISTENCE", "REGISTRY"}
    non_network_events = [e for e in canonical_events if e.event_type in non_network_types]
    non_network_observation_count = sum(
        1 for e in non_network_events for _ in translate_session([e]))

    result.update({
        "ok": True,
        "canonical_event_types": [e.event_type for e in canonical_events],
        "exposure_observation_categories": [o.category for o in exposure_observations],
        "unavailable_categories_never_appeared": all(
            cat not in UNAVAILABLE_CATEGORIES for o in exposure_observations
            for cat in (o.category,)) if exposure_observations else True,
        "unavailable_categories_declared": list(UNAVAILABLE_CATEGORIES),
        "non_network_events_produced_zero_observations": non_network_observation_count == 0,
        "fused_decision_hypothesis": (arch_results[-1].hypothesis.to_dict()
                                      if arch_results else None),
        "aegis_inference_hypotheses": (
            {hyp: dec.to_dict() for hyp, dec in aegis["decisions"].items()} if aegis else {}),
        "provenance_all_trace_to_real_event_ids": all(
            bool(o.provenance) for o in exposure_observations) if exposure_observations else True,
        "real_event_ids": [e.event_id for e in canonical_events],
    })
    return result


def _write_summary(result: dict) -> Path:
    ts = time.strftime("%Y%m%d_%H%M%S")
    path = RESULTS_DIR / f"beta2_aegis_live_{ts}.json"
    path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    print(f"\n[SUMMARY] written to {path}")
    return path


def score(result: dict) -> dict:
    """Predeclared checks - mirrors Beta 0.5/Beta 1's score() shape: a
    checks dict of {"pass": bool, "detail": str}, overall = all(...)."""
    checks: dict[str, dict] = {}
    checks["real_chain_captured"] = {
        "pass": result.get("ok", False) and result.get("subject_event_count", 0) >= 2,
        "detail": f"subject_event_count={result.get('subject_event_count')}, reason={result.get('reason')}",
    }
    by_cat = result.get("subject_events_by_category", {})
    checks["chain_spans_process_and_network_or_privacy"] = {
        "pass": "process" in by_cat and ("network" in by_cat or "privacy" in by_cat),
        "detail": f"subject_events_by_category={by_cat}",
    }
    checks["destination_observation_derived"] = {
        "pass": "DESTINATION" in result.get("exposure_observation_categories", []),
        "detail": f"exposure_observation_categories={result.get('exposure_observation_categories')}",
    }
    checks["unavailable_categories_never_fabricated"] = {
        "pass": result.get("unavailable_categories_never_appeared", False),
        "detail": f"declared unavailable: {result.get('unavailable_categories_declared')}",
    }
    checks["non_network_events_produce_zero_observations"] = {
        "pass": result.get("non_network_events_produced_zero_observations", False),
        "detail": "process/persistence/registry-only events must never become Aegis evidence",
    }
    checks["provenance_survives"] = {
        "pass": result.get("provenance_all_trace_to_real_event_ids", False),
        "detail": f"real_event_ids={result.get('real_event_ids')}",
    }
    checks["no_observe_errors"] = {
        "pass": not result.get("observe_errors"),
        "detail": str(result.get("observe_errors") or "none"),
    }
    overall = all(c["pass"] for c in checks.values())
    return {"overall": "PASS" if overall else "FAIL", "checks": checks, "raw": result}


def main() -> int:
    print("=" * 70)
    print("PLATFORM BETA 2 (AEGIS) - live-fire proof over REAL events")
    print("=" * 70)
    result = run()
    scored = score(result)
    _write_summary(scored)
    print("\n" + "=" * 70)
    print(f"PLATFORM BETA 2 (AEGIS) -- RESULT: {scored['overall']}")
    print("=" * 70)
    for name, c in scored["checks"].items():
        mark = "+" if c["pass"] else "!"
        print(f"  [{mark}] {name}: {c['detail']}")
    return 0 if scored["overall"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
