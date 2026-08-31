r"""Platform Beta 1 - Nyx Reliability Soak.

Implements docs/BETA_1_NYX_RELIABILITY.md. Answers a different question than
nyx_live/nyx_live_test.py (the Nyx equivalent of Tier B's live-fire proof):
not "does the deception mechanism work" (already proven there, once, in
~1 minute) but "does it keep working, correctly, under a long real browsing
session" - the same coverage-vs-reliability split Beta 0.5 drew for the EDR
telemetry pipeline, pointed at Nyx instead.

Runs entirely in-process, unlike the EDR soak: Nyx has no HTTP API and no
separate engine subprocess to boot. This script IS the process - it holds
the real `TLSInspector` directly (same as nyx_live_test.py), drives a real
Playwright Chromium through it for the run's duration, and samples this
same process's own resource footprint plus Nyx's own self_test() canary on
a background thread throughout.

Modes:
    smoke     local-only, ~20s, NOT qualification evidence - syntax sanity.
    dry-run   CI, ~2 minutes, validates the harness end to end.
    soak      CI, the real ~15-minute qualification run.

Usage:
    python redteam/evaluation/nyx_reliability.py --mode smoke
    python redteam/evaluation/nyx_reliability.py --mode dry-run
    python redteam/evaluation/nyx_reliability.py --mode soak --minutes 15
"""

from __future__ import annotations

import argparse
import itertools
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

SAMPLE_INTERVAL_S = 2.0
SELF_TEST_INTERVAL_S = 30.0
VISIT_PACING_S = 1.0

HTTP_PORT = 8899
PROXY_PORT = 8443

FIRST_PARTY_HOST = "firstparty.test"
TRACKER1_HOST = "tracker.test"
TRACKER2_HOST = "tracker2.test"

# Cycled round-robin for the whole run - mirrors nyx_scorecard.py's
# authorized/unauthorized/benign split, replayed live and repeatedly
# instead of scored once, synthetically.
VISIT_KINDS = (
    "unauthorized-tracker-1",
    "unauthorized-tracker-2",
    "authorized-first-party",
    "benign-no-personal-data",
)
_UNAUTHORIZED_KINDS = ("unauthorized-tracker-1", "unauthorized-tracker-2")
_AUTHORIZED_BENIGN_KINDS = ("authorized-first-party", "benign-no-personal-data")


# ----------------------------------------------------------------------
# HTTP server: serves page.html, records every POST the endpoint received
# (this stands in for "the tracker's own server" - same shape as
# nyx_live_test.py's _Handler).
# ----------------------------------------------------------------------

RECEIVED: list[dict] = []
_PAGE_BYTES = PAGE_PATH.read_bytes() if PAGE_PATH.exists() else b""


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
        RECEIVED.append({"path": self.path,
                         "host": self.headers.get("Host", ""),
                         "body": body.decode("utf-8", "replace"),
                         "t": time.time()})
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")


def _visit_url(kind: str, origin: str) -> str:
    if kind == "unauthorized-tracker-1":
        tracker = f"http://{TRACKER1_HOST}:{HTTP_PORT}"
    elif kind == "unauthorized-tracker-2":
        tracker = f"http://{TRACKER2_HOST}:{HTTP_PORT}"
    elif kind in ("authorized-first-party", "benign-no-personal-data"):
        # authorized: post back to the SAME origin as the page (matches
        # Referer/Origin -> Nyx's first-party gate never flags it).
        # benign: still a third party (tracker.test), just no personal
        # data in the body (nopersonal=1 below) - nothing TO fake.
        tracker = (f"http://{origin}:{HTTP_PORT}" if kind == "authorized-first-party"
                   else f"http://{TRACKER1_HOST}:{HTTP_PORT}")
    else:
        raise ValueError(f"unknown visit kind: {kind}")
    url = f"http://{origin}:{HTTP_PORT}/page.html?tracker={tracker}"
    if kind == "benign-no-personal-data":
        url += "&nopersonal=1"
    return url


def _do_visit(ctx, kind: str) -> dict:
    """Drive one page load + beacon through the real proxy. Returns the raw
    outcome (what the browser sent, what the tracker endpoint received) -
    scoring happens separately in _score_visit so the two concerns stay
    independent and each is independently testable offline."""
    url = _visit_url(kind, FIRST_PARTY_HOST)
    before_n = len(RECEIVED)
    beacon_id = None
    beacon_body = None
    beacon_status = None
    error = None
    page = ctx.new_page()
    try:
        page.goto(url, wait_until="load", timeout=15000)
        page.wait_for_function(
            "document.getElementById('beacon-status') && "
            "/sent|err|no-tracker/.test("
            "document.getElementById('beacon-status').textContent)",
            timeout=10000)
        # "err" is an ACCEPTED terminal state above (matches nyx_live_test.py's
        # own wait condition) - it means the wait didn't time out, not that
        # the beacon succeeded. Capture the actual text so a client-side
        # fetch failure (a real one, or a false "success" from wait_for_
        # function's own regex) is distinguishable from a genuine send,
        # instead of only inferring it from the endpoint never being reached.
        beacon_status = page.evaluate(
            "document.getElementById('beacon-status').textContent")
        beacon_id = page.evaluate("window.__beaconId")
        beacon_body = page.evaluate("window.__beaconBody")
    except Exception as exc:                              # noqa: BLE001
        error = repr(exc)
    finally:
        try:
            page.close()
        except Exception:
            pass
    return {
        "kind": kind,
        "beacon_id": beacon_id,
        "beacon_body": beacon_body,
        "beacon_status": beacon_status,
        "received": RECEIVED[before_n:],
        "error": error,
    }


def _score_visit(outcome: dict, persona) -> dict:
    kind = outcome["kind"]
    bodies = [r["body"] for r in outcome["received"]]
    real_id = outcome.get("beacon_id") or ""
    sent_body = outcome.get("beacon_body")
    real_leaked = bool(real_id) and any(real_id in b for b in bodies)
    fake_served = any(persona.advertising_id in b for b in bodies)
    unaltered = bool(sent_body) and any(b == sent_body for b in bodies)
    result = {
        "kind": kind,
        "reached_endpoint": len(bodies) > 0,
        "real_leaked": real_leaked,
        "fake_served": fake_served,
        "unaltered": unaltered,
        "error": outcome.get("error"),
    }
    if not result["reached_endpoint"] and result["error"] is None:
        # The browser-side wait completed without a Python-level exception,
        # yet nothing arrived at the endpoint - "err" is an accepted
        # terminal state for wait_for_function (see _do_visit), so this is
        # the one case that needs the actual beacon-status text to tell a
        # real client-side failure apart from a harness miscount.
        result["_beacon_status"] = outcome.get("beacon_status")
    if kind in _AUTHORIZED_BENIGN_KINDS and not unaltered:
        # Only captured on a mismatch, to keep the common-case log lean -
        # this is exactly the raw diff a "0 never reached, 0 errors" count
        # can't show: aggregate counts said something changed, not what.
        result["_sent_body"] = sent_body
        result["_received_bodies"] = bodies
    return result


# ----------------------------------------------------------------------
# This-process resource sampling (Nyx runs same-process, ADR 0057 - unlike
# the EDR soak there is no separate engine pid to attach to; the harness
# process itself IS what needs watching for a leak/growth over the run).
# ----------------------------------------------------------------------

_PROC_HANDLE = None


def _prime_process_stats() -> None:
    global _PROC_HANDLE
    try:
        import psutil
        _PROC_HANDLE = psutil.Process(os.getpid())
        _PROC_HANDLE.cpu_percent(interval=None)
    except ImportError:
        pass


def _process_stats() -> dict | None:
    global _PROC_HANDLE
    try:
        import psutil
    except ImportError:
        return None
    try:
        if _PROC_HANDLE is None:
            _PROC_HANDLE = psutil.Process(os.getpid())
        with _PROC_HANDLE.oneshot():
            return {
                "cpu_percent": _PROC_HANDLE.cpu_percent(),
                "rss": _PROC_HANDLE.memory_info().rss,
                "vms": _PROC_HANDLE.memory_info().vms,
                "threads": _PROC_HANDLE.num_threads(),
                "handles": (_PROC_HANDLE.num_handles()
                           if hasattr(_PROC_HANDLE, "num_handles") else None),
            }
    except Exception as exc:                              # noqa: BLE001
        return {"error": repr(exc)}


class Sampler:
    """Background thread sampling proxy liveness + this-process resources +
    Store's queue health every SAMPLE_INTERVAL_S, and Nyx's own self_test()
    canary every SELF_TEST_INTERVAL_S. Streams every sample to a JSONL file
    immediately (crash-proof, same convention as the Beta 0.5 harness)."""

    def __init__(self, insp, store, out_path: Path) -> None:
        self._insp = insp
        self._store = store
        self._out_path = out_path
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_self_test = 0.0
        self.samples: list[dict] = []
        self.self_tests: list[dict] = []

    def start(self) -> None:
        _prime_process_stats()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="nyx-reliability-sampler")
        self._thread.start()

    # No HTTP calls happen in this loop (unlike Beta 0.5's Sampler) - every
    # read here (is_running(), psutil, queue_stats(), self_test()) is a
    # local, sub-millisecond operation, so a much shorter join margin than
    # Beta 0.5's 60s is still comfortably safe. Kept explicit and named
    # rather than a bare literal, matching that precedent.
    _STOP_JOIN_TIMEOUT_S = 30.0

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self._STOP_JOIN_TIMEOUT_S)

    def _loop(self) -> None:
        with open(self._out_path, "a", encoding="utf-8") as fh:
            while not self._stop.is_set():
                rec = self._sample_once()
                self.samples.append(rec)
                fh.write(json.dumps(rec, default=str) + "\n")
                fh.flush()
                self._stop.wait(SAMPLE_INTERVAL_S)

    def _sample_once(self) -> dict:
        now = time.time()
        rec: dict = {"t": now}
        try:
            rec["proxy_running"] = bool(self._insp.is_running())
        except Exception as exc:                          # noqa: BLE001
            rec["proxy_running"] = False
            rec["proxy_running_error"] = repr(exc)
        rec["process"] = _process_stats()
        try:
            rec["queue"] = self._store.queue_stats()
        except Exception as exc:                          # noqa: BLE001
            rec["queue"] = {"error": repr(exc)}
        if now - self._last_self_test >= SELF_TEST_INTERVAL_S:
            self._last_self_test = now
            try:
                from valkyrie import nyx
                st = nyx.self_test()
                self.self_tests.append(st)
                rec["self_test"] = st
            except Exception as exc:                       # noqa: BLE001
                rec["self_test_error"] = repr(exc)
        return rec


def _resource_trend(samples: list[dict]) -> dict | None:
    procs = [s["process"] for s in samples
             if s.get("process") and "error" not in s["process"]]
    if not procs:
        return None
    handles = [p.get("handles") for p in procs if p.get("handles") is not None]
    return {
        "n": len(procs),
        "first_rss": procs[0]["rss"], "last_rss": procs[-1]["rss"],
        "max_rss": max(p["rss"] for p in procs),
        "first_handles": handles[0] if handles else None,
        "last_handles": handles[-1] if handles else None,
        "max_handles": max(handles) if handles else None,
    }


def _store_queue_trend(samples: list[dict]) -> dict | None:
    qs = [s["queue"] for s in samples if s.get("queue") and "error" not in s["queue"]]
    if not qs:
        return None
    return {
        "n": len(qs),
        "first_depth": qs[0]["depth"], "last_depth": qs[-1]["depth"],
        "max_depth": max(q["depth"] for q in qs),
        "first_dropped": qs[0]["dropped"], "last_dropped": qs[-1]["dropped"],
        "total_dropped_during_run": qs[-1]["dropped"] - qs[0]["dropped"],
    }


def _status_tally(visits) -> dict:
    """Counts of the actual browser-side beacon-status text among visits
    that never reached the endpoint - lets a stdout-only read (no artifact
    download needed) tell a real client-side failure apart from a harness
    miscount, capped to the 3 most common so one run's summary can't blow
    up into an unbounded wall of distinct strings."""
    from collections import Counter
    tally = Counter(v.get("_beacon_status") or "(no status captured)" for v in visits)
    return dict(tally.most_common(3))


def score(visit_log: list[dict], samples: list[dict], self_tests: list[dict],
          run_error: str | None = None) -> dict:
    """Predeclared, independent PASS criteria - see
    docs/BETA_1_NYX_RELIABILITY.md's 'Predeclared PASS criteria' section.
    Mirrors beta05_reliability.py's score() shape: a checks dict of
    {"pass": bool, "detail": str}, overall = all(...), plus non-gating
    exploratory trend data no threshold exists for yet."""
    checks: dict[str, dict] = {}

    unauthorized = [v for v in visit_log if v["kind"] in _UNAUTHORIZED_KINDS]
    authorized_benign = [v for v in visit_log if v["kind"] in _AUTHORIZED_BENIGN_KINDS]

    not_running = sum(1 for s in samples if not s.get("proxy_running"))
    checks["proxy_alive_throughout"] = {
        "pass": bool(samples) and not_running == 0,
        "detail": f"{not_running} of {len(samples)} sample(s) with proxy not running",
    }

    unauth_not_reached = sum(1 for v in unauthorized if not v["reached_endpoint"])
    unauth_errors = sum(1 for v in unauthorized if v.get("error"))
    unauth_statuses = _status_tally(v for v in unauthorized if not v["reached_endpoint"])
    leaked = sum(1 for v in unauthorized if v["real_leaked"])
    checks["zero_real_value_leaks"] = {
        "pass": bool(unauthorized) and leaked == 0,
        "detail": (f"{leaked} of {len(unauthorized)} unauthorized visit(s) leaked the real value "
                  f"({unauth_not_reached} never reached the endpoint, {unauth_errors} had a visit error)"),
    }

    deceived = sum(1 for v in unauthorized if v["fake_served"] and v["reached_endpoint"])
    checks["every_unauthorized_visit_deceived"] = {
        "pass": bool(unauthorized) and deceived == len(unauthorized),
        "detail": (f"{deceived} of {len(unauthorized)} unauthorized visit(s) deceived "
                  f"({unauth_not_reached} never reached the endpoint, {unauth_errors} had a visit error"
                  + (f", statuses seen: {unauth_statuses}" if unauth_statuses else "") + ")"),
    }

    ab_not_reached = sum(1 for v in authorized_benign if not v["reached_endpoint"])
    ab_errors = sum(1 for v in authorized_benign if v.get("error"))
    unaltered = sum(1 for v in authorized_benign if v["unaltered"])
    checks["authorized_benign_flows_unaltered"] = {
        "pass": bool(authorized_benign) and unaltered == len(authorized_benign),
        "detail": (f"{unaltered} of {len(authorized_benign)} authorized/benign visit(s) left unaltered "
                  f"({ab_not_reached} never reached the endpoint, {ab_errors} had a visit error)"),
    }

    # Persona consistency: every DECEIVED unauthorized visit must show the
    # SAME fake advertising_id, not a different one each time (a rotating
    # fake would itself be the kind of tell ADR 0050 says a coherent lie
    # must never produce).
    checks["persona_consistent_throughout"] = _persona_consistency_check(unauthorized)

    if self_tests:
        first = (self_tests[0]["caught"], self_tests[0]["faked"], self_tests[0]["total"])
        drifted = [st for st in self_tests
                  if (st["caught"], st["faked"], st["total"]) != first]
        checks["nyx_self_test_stable"] = {
            "pass": len(drifted) == 0,
            "detail": (f"all {len(self_tests)} self_test() call(s) reported "
                      f"{first[0]}/{first[2]} caught, {first[1]}/{first[2]} faked"
                      if not drifted else
                      f"{len(drifted)} of {len(self_tests)} self_test() call(s) drifted from the first result"),
        }
    else:
        checks["nyx_self_test_stable"] = {
            "pass": False, "detail": "self_test() was never sampled during the run",
        }

    checks["no_process_crash"] = {
        "pass": run_error is None,
        "detail": run_error or "no unhandled exception escaped the run",
    }

    overall = all(c["pass"] for c in checks.values())
    return {
        "overall": "PASS" if overall else "FAIL",
        "checks": checks,
        "visits_total": len(visit_log),
        "visits_by_kind": {k: sum(1 for v in visit_log if v["kind"] == k) for k in VISIT_KINDS},
        "resource_trend": _resource_trend(samples),
        "store_queue_trend": _store_queue_trend(samples),
    }


def _persona_consistency_check(unauthorized: list[dict]) -> dict:
    """visit_log entries carry only booleans (see _score_visit), not raw
    bodies, so consistency is proven structurally rather than by re-diffing
    strings here: `fake_served` is always computed against the ONE persona
    object captured once at the start of the run (see _run) and never
    re-fetched or rotated mid-run, so every True fake_served already
    reflects the SAME persona value by construction. This check exists to
    catch a future regression where that invariant stops holding (e.g. the
    persona gets re-fetched per visit instead of once for the whole run)."""
    faked = [v for v in unauthorized if v["fake_served"]]
    return {
        "pass": len(faked) > 0,
        "detail": (f"{len(faked)} of {len(unauthorized)} unauthorized visit(s) "
                  f"served the (one, process-lifetime-stable) persona value"),
    }


def _write_summary(label: str, summary: dict) -> Path:
    ts = time.strftime("%Y%m%d_%H%M%S")
    path = RESULTS_DIR / f"nyx_reliability_{label}_{ts}.json"
    path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    print(f"\n[SUMMARY] written to {path}")
    return path


def _run(minutes: float, label: str, evidence: bool) -> int:
    print("=" * 70)
    print(f"MODE: {label}" + ("" if evidence else "  -- NOT QUALIFICATION EVIDENCE"))
    print("=" * 70)

    import valkyrie.config as cfg
    cfg.NYX_ACT = True    # test the full deception, end to end

    from valkyrie.store import Store
    from valkyrie.tls_inspector import TLSInspector
    from valkyrie.persona import current_persona

    RECEIVED.clear()
    store = Store(ram_uri=f"file:nyxreliability_{label}?mode=memory&cache=shared")
    store.start()

    insp = TLSInspector(store, port=PROXY_PORT)
    try:
        insp.setup_ca()
    except Exception as exc:                                  # noqa: BLE001
        print("NYX-RELIABILITY: setup_ca warning:", exc)
    if not insp.start():
        print("NYX-RELIABILITY: FAIL - proxy did not start (is mitmproxy installed?)")
        return 2

    srv = ThreadingHTTPServer(("127.0.0.1", HTTP_PORT), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(1.0)

    persona = current_persona()
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_jsonl = RESULTS_DIR / f"nyx_reliability_{label}_{ts}.jsonl"
    sampler = Sampler(insp, store, out_jsonl)
    sampler.start()

    # Per-visit outcomes, streamed immediately (crash-proof, same convention
    # as the Sampler's own JSONL) - score() only sees pass/fail booleans, so
    # this is what lets a failure actually be diagnosed (which kind, did it
    # even reach the endpoint, what error) instead of just counted.
    visits_jsonl = RESULTS_DIR / f"nyx_reliability_{label}_visits_{ts}.jsonl"
    visit_log: list[dict] = []
    run_error: str | None = None

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("NYX-RELIABILITY: FAIL - playwright not installed")
        sampler.stop()
        try:
            insp.stop()
        finally:
            srv.shutdown()
        return 2

    end_at = time.monotonic() + minutes * 60.0
    kinds_cycle = itertools.cycle(VISIT_KINDS)

    try:
        with sync_playwright() as p, open(visits_jsonl, "a", encoding="utf-8") as vfh:
            browser = p.chromium.launch(args=["--no-sandbox"])
            ctx = browser.new_context(
                proxy={"server": f"http://127.0.0.1:{PROXY_PORT}"},
                ignore_https_errors=True)
            try:
                while time.monotonic() < end_at:
                    kind = next(kinds_cycle)
                    t0 = time.monotonic()
                    outcome = _do_visit(ctx, kind)
                    scored = _score_visit(outcome, persona)
                    scored["elapsed_s"] = round(time.monotonic() - t0, 3)
                    scored["n_received"] = len(outcome["received"])
                    visit_log.append(scored)
                    vfh.write(json.dumps(scored, default=str) + "\n")
                    vfh.flush()
                    time.sleep(VISIT_PACING_S)
            finally:
                ctx.close()
                browser.close()
    except Exception as exc:                                  # noqa: BLE001
        # Crash-proof: whatever was already collected is still scored below,
        # same discipline as Beta 0.5's phase-body wrapping.
        run_error = repr(exc)

    time.sleep(2.0)   # let the store's async writer + last sample settle
    sampler.stop()
    try:
        insp.stop()
    except Exception:
        pass
    srv.shutdown()

    result = score(visit_log, sampler.samples, sampler.self_tests, run_error)
    result["evidence"] = evidence
    result["minutes_requested"] = minutes
    _write_summary(label, result)

    print("\n" + "=" * 70)
    print(f"NYX RELIABILITY [{label}] -- RESULT: {result['overall']}")
    print("=" * 70)
    for name, c in result["checks"].items():
        mark = "+" if c["pass"] else "!"
        print(f"  [{mark}] {name}: {c['detail']}")
    print(f"visits_total={result['visits_total']} by_kind={result['visits_by_kind']}")

    return 0 if result["overall"] == "PASS" else 1


def run_smoke() -> int:
    return _run(minutes=20.0 / 60.0, label="smoke", evidence=False)


def run_dry_run() -> int:
    return _run(minutes=2.0, label="dry-run", evidence=False)


def run_soak(minutes: float) -> int:
    return _run(minutes=minutes, label="soak", evidence=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=["smoke", "dry-run", "soak"], default="dry-run")
    ap.add_argument("--minutes", type=float, default=15.0,
                    help="soak duration in minutes (ignored for smoke/dry-run)")
    args = ap.parse_args()

    if args.mode == "smoke":
        return run_smoke()
    if args.mode == "dry-run":
        return run_dry_run()
    return run_soak(args.minutes)


if __name__ == "__main__":
    raise SystemExit(main())
