r"""Platform Beta 3: the fused reasoning pipeline under sustained real load.

Beta 2 (docs/PLATFORM_BETA2_AEGIS_LIVE.md) proved the CanonicalEvent ->
ExposureObservation bridge over ONE real causal chain. That leaves the
property a single-subject run cannot exercise at all: does ONE long-lived
`DetectionArchitectureV2` instance - the same lifetime shape the real
engine actually uses, one instance for the whole process, not one per
request - correctly keep MANY real subjects' evidence isolated from each
other over time? A single chain has nothing else to leak into; a
sustained, multi-visit, multi-subject run does.

Same real components as Beta 2 (real Playwright Chromium, real
TLSInspector/Nyx addon, real ProcessCollector/NetworkCollector, real
DetectionArchitectureV2/aegis_bridge/aegis_exposure), run continuously
across MANY real browser visits instead of one, all sharing ONE engine
instance the way a real deployment would.

Modes:
    dry-run   ~2 minutes  - validates the harness end to end
    soak      configurable (default 10 min) - the real qualification run

Usage:
    python redteam/evaluation/platform_beta3_fused_reliability.py --mode dry-run
    python redteam/evaluation/platform_beta3_fused_reliability.py --mode soak --minutes 10
"""

from __future__ import annotations

import argparse
import json
import os
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
HTTP_PORT = 8897
PROXY_PORT = 8445
FIRST_PARTY_HOST = "firstparty.test"
TRACKER_HOST = "tracker.test"
VISIT_PACING_S = 2.0

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
    """See platform_beta2_aegis_live.py's identical class - stands in for
    the live engine's `Engine.ingest_telemetry` so TLSInspector's addon can
    resolve a real causality pid via the real ADR-0057
    `pid_for_local_port()` lookup without a separate engine process."""

    def __init__(self, sink: list, lock: threading.Lock) -> None:
        self._sink = sink
        self._lock = lock

    def ingest_telemetry(self, event) -> None:
        with self._lock:
            self._sink.append(event)


def _find_subject_pid(events: list) -> int | None:
    for e in events:
        if e.category == "privacy" and e.actor_pid:
            return e.actor_pid
    for e in events:
        if e.category == "network" and e.actor_pid:
            return e.actor_pid
    for e in events:
        if e.category == "process" and any(
                h in (e.actor_name or "").lower() for h in _BROWSER_NAME_HINTS):
            return e.actor_pid
    return None


_PROC_HANDLE = None


def _process_stats() -> dict | None:
    global _PROC_HANDLE
    try:
        import psutil
    except ImportError:
        return None
    try:
        if _PROC_HANDLE is None:
            _PROC_HANDLE = psutil.Process(os.getpid())
            _PROC_HANDLE.cpu_percent(interval=None)
        with _PROC_HANDLE.oneshot():
            return {"rss": _PROC_HANDLE.memory_info().rss,
                   "threads": _PROC_HANDLE.num_threads()}
    except Exception as exc:                                  # noqa: BLE001
        return {"error": repr(exc)}


def _do_one_visit(ctx, before_n: int, all_events: list, events_lock: threading.Lock) -> dict:
    """Drive one real page visit and return its own isolated chain outcome.
    `before_n` is the captured-events list length at the moment this visit
    started - everything from there on that belongs to THIS visit's own
    subject pid is this visit's chain; anything for a DIFFERENT pid in that
    same window belongs to some other, concurrently-finishing visit and
    must not be pulled in."""
    page = ctx.new_page()
    error = None
    try:
        url = (f"http://{FIRST_PARTY_HOST}:{HTTP_PORT}/page.html"
               f"?tracker=http://{TRACKER_HOST}:{HTTP_PORT}")
        page.goto(url, wait_until="load", timeout=15000)
        page.wait_for_function(
            "document.getElementById('beacon-status') && "
            "/sent|err|no-tracker/.test("
            "document.getElementById('beacon-status').textContent)",
            timeout=10000)
    except Exception as exc:                                  # noqa: BLE001
        error = repr(exc)
    finally:
        try:
            page.close()
        except Exception:
            pass

    with events_lock:
        window = list(all_events[before_n:])
    subject_pid = _find_subject_pid(window)
    subject_events = ([e for e in window if e.actor_pid == subject_pid]
                      if subject_pid is not None else [])
    return {"error": error, "subject_pid": subject_pid,
           "subject_events": subject_events}


def _run(minutes: float, label: str, evidence: bool) -> int:
    print("=" * 70)
    print(f"MODE: {label}" + ("" if evidence else "  -- NOT QUALIFICATION EVIDENCE"))
    print("=" * 70)

    import valkyrie.config as cfg
    cfg.NYX_ACT = True

    from valkyrie.store import Store
    from valkyrie.tls_inspector import TLSInspector
    from valkyrie.process_telemetry import ProcessCollector
    from valkyrie.network_telemetry import NetworkCollector
    from valkyrie.aegis_bridge import translate_session, UNAVAILABLE_CATEGORIES
    from valkyrie.aegis_exposure import evaluate_pair
    from valkyrie.edr.detection_v2 import DetectionArchitectureV2

    all_events: list = []
    events_lock = threading.Lock()

    def _capture(event) -> None:
        with events_lock:
            all_events.append(event)

    RECEIVED.clear()
    store = Store(ram_uri=f"file:beta3fused_{label}?mode=memory&cache=shared")
    store.start()

    proc_collector = ProcessCollector(emit=_capture, interval=1.0)
    net_collector = NetworkCollector(emit=_capture, interval=1.0)
    proc_collector.start()
    net_collector.start()
    time.sleep(1.5)

    insp = TLSInspector(store, edr=_EdrCapture(all_events, events_lock), port=PROXY_PORT)
    try:
        insp.setup_ca()
    except Exception as exc:                                  # noqa: BLE001
        print("BETA3-FUSED: setup_ca warning:", exc)
    if not insp.start():
        print("BETA3-FUSED: FAIL - proxy did not start (is mitmproxy installed?)")
        return 2

    srv = ThreadingHTTPServer(("127.0.0.1", HTTP_PORT), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(1.0)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("BETA3-FUSED: FAIL - playwright not installed")
        proc_collector.stop(); net_collector.stop(); insp.stop(); srv.shutdown()
        return 2

    # ONE shared engine instance for the whole run - the real lifetime
    # shape (the live engine builds exactly one, for its whole process),
    # not one per visit. Whether it keeps many real subjects' evidence
    # isolated over time is the entire point of this stage.
    arch = DetectionArchitectureV2()
    visit_reports: list[dict] = []
    run_error: str | None = None
    resource_samples: list[dict] = []

    end_at = time.monotonic() + minutes * 60.0
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox"])
            ctx = browser.new_context(
                proxy={"server": f"http://127.0.0.1:{PROXY_PORT}"},
                ignore_https_errors=True)
            try:
                while time.monotonic() < end_at:
                    with events_lock:
                        before_n = len(all_events)
                    outcome = _do_one_visit(ctx, before_n, all_events, events_lock)
                    resource_samples.append({"t": time.time(), "process": _process_stats()})

                    report: dict = {
                        "error": outcome["error"],
                        "subject_pid": outcome["subject_pid"],
                        "subject_event_count": len(outcome["subject_events"]),
                    }
                    subject_events = sorted(outcome["subject_events"], key=lambda e: e.ts)
                    canonical_events = []
                    for e in subject_events:
                        try:
                            canonical_events.append(arch.observe(e).event)
                        except Exception as exc:                  # noqa: BLE001
                            report.setdefault("observe_errors", []).append(repr(exc))
                    exposure_observations = translate_session(canonical_events)
                    report["exposure_observation_categories"] = [
                        o.category for o in exposure_observations]
                    report["unavailable_categories_never_appeared"] = all(
                        cat not in UNAVAILABLE_CATEGORIES for o in exposure_observations
                        for cat in (o.category,)) if exposure_observations else True
                    # Cross-contamination check: every provenance-linked event
                    # id this visit's observations point to must belong to
                    # THIS visit's own canonical events, never another
                    # visit's - the property a single-subject Beta 2 run has
                    # no way to exercise at all.
                    this_visit_ids = {e.event_id for e in canonical_events}
                    report["provenance_never_crosses_into_another_visit"] = all(
                        pid in this_visit_ids for o in exposure_observations
                        for pid in o.provenance if pid.startswith("evt:") or pid.startswith("nyx_")
                    ) if exposure_observations else True
                    visit_reports.append(report)
                    time.sleep(VISIT_PACING_S)
            finally:
                ctx.close()
                browser.close()
    except Exception as exc:                                  # noqa: BLE001
        run_error = repr(exc)

    time.sleep(1.0)
    proc_collector.stop()
    net_collector.stop()
    try:
        insp.stop()
    except Exception:
        pass
    srv.shutdown()

    result = score(visit_reports, resource_samples, run_error)
    result["evidence"] = evidence
    result["minutes_requested"] = minutes
    _write_summary(label, result)

    print("\n" + "=" * 70)
    print(f"PLATFORM BETA 3 (FUSED) [{label}] -- RESULT: {result['overall']}")
    print("=" * 70)
    for name, c in result["checks"].items():
        mark = "+" if c["pass"] else "!"
        print(f"  [{mark}] {name}: {c['detail']}")
    print(f"visits_total={result['visits_total']}")

    return 0 if result["overall"] == "PASS" else 1


def score(visit_reports: list[dict], resource_samples: list[dict],
          run_error: str | None) -> dict:
    checks: dict[str, dict] = {}

    resolved = [v for v in visit_reports if v["subject_pid"] is not None]
    checks["most_visits_resolved_a_real_subject"] = {
        "pass": bool(visit_reports) and len(resolved) >= max(1, int(0.8 * len(visit_reports))),
        "detail": f"{len(resolved)} of {len(visit_reports)} visits resolved a real subject pid",
    }

    with_chain = [v for v in resolved if v["subject_event_count"] >= 1]
    checks["resolved_visits_produced_a_chain"] = {
        "pass": bool(resolved) and len(with_chain) == len(resolved),
        "detail": f"{len(with_chain)} of {len(resolved)} resolved visits produced >=1 subject event",
    }

    with_dest = sum(1 for v in visit_reports if "DESTINATION" in v.get("exposure_observation_categories", []))
    checks["destination_derived_across_most_visits"] = {
        "pass": bool(visit_reports) and with_dest >= max(1, int(0.5 * len(visit_reports))),
        "detail": f"{with_dest} of {len(visit_reports)} visits derived a DESTINATION observation",
    }

    unavailable_ok = sum(1 for v in visit_reports if v.get("unavailable_categories_never_appeared", False))
    checks["unavailable_categories_never_fabricated_any_visit"] = {
        "pass": bool(visit_reports) and unavailable_ok == len(visit_reports),
        "detail": f"{unavailable_ok} of {len(visit_reports)} visits never fabricated VOLUME/DIRECTION/IDENTITY/SESSION",
    }

    no_cross = sum(1 for v in visit_reports if v.get("provenance_never_crosses_into_another_visit", False))
    checks["no_cross_visit_contamination"] = {
        "pass": bool(visit_reports) and no_cross == len(visit_reports),
        "detail": f"{no_cross} of {len(visit_reports)} visits' observations trace ONLY to that visit's own events",
    }

    obs_errors = sum(len(v.get("observe_errors") or []) for v in visit_reports)
    checks["no_observe_errors_any_visit"] = {
        "pass": obs_errors == 0,
        "detail": f"{obs_errors} observe() error(s) across the whole run",
    }

    checks["no_process_crash"] = {
        "pass": run_error is None,
        "detail": run_error or "no unhandled exception escaped the run",
    }

    overall = all(c["pass"] for c in checks.values())
    procs = [s["process"] for s in resource_samples if s.get("process") and "error" not in s["process"]]
    return {
        "overall": "PASS" if overall else "FAIL",
        "checks": checks,
        "visits_total": len(visit_reports),
        "unique_subjects": len({v["subject_pid"] for v in resolved}),
        "resource_trend": ({"first_rss": procs[0]["rss"], "last_rss": procs[-1]["rss"],
                           "max_rss": max(p["rss"] for p in procs)} if procs else None),
    }


def _write_summary(label: str, result: dict) -> Path:
    ts = time.strftime("%Y%m%d_%H%M%S")
    path = RESULTS_DIR / f"beta3_fused_{label}_{ts}.json"
    path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    print(f"\n[SUMMARY] written to {path}")
    return path


def run_dry_run() -> int:
    return _run(minutes=2.0, label="dry-run", evidence=False)


def run_soak(minutes: float) -> int:
    return _run(minutes=minutes, label="soak", evidence=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=["dry-run", "soak"], default="dry-run")
    ap.add_argument("--minutes", type=float, default=10.0)
    args = ap.parse_args()
    if args.mode == "dry-run":
        return run_dry_run()
    return run_soak(args.minutes)


if __name__ == "__main__":
    raise SystemExit(main())
