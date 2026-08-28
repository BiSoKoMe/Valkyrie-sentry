"""FastAPI web dashboard backend for Valkyrie.

Endpoints:
  GET  /           -> serve dashboard.html
  GET  /api/stats  -> aggregate stats (24h) + top blocked domains
  GET  /api/events -> last 200 events
  WS   /ws         -> real-time event stream (Store subscribe)

Usage (from __main__.py):
    from .web.server import state as web_state, run_server
    web_state.store      = store
    web_state.firewall   = firewall
    web_state.blocklist  = blocklist
    web_state.start_time = time.time()
    run_server(host="0.0.0.0", port=8080)   # blocks - run in daemon thread
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import subprocess
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from ..config import DATA_DIR, WEB_HOST, WEB_PORT
from ..context import AppContext
from .cache import (CACHE, COLD_TIMEOUT_S, TTL_COMPONENTS, TTL_COVERAGE,
                    TTL_EVENTS, TTL_MAC, TTL_STATS)

_WEB_DIR = Path(__file__).parent
_PROJECT_ROOT = _WEB_DIR.parent.parent   # .../valkyrie/web -> .../valkyrie -> repo root

# Module-level FastAPI imports so annotations resolve correctly.
# (from __future__ import annotations makes ws: WebSocket a lazy string;
#  FastAPI resolves it against module globals - a local import won't be found.)
try:
    from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
    from fastapi.responses import FileResponse, JSONResponse
    from starlette.concurrency import run_in_threadpool
    _FASTAPI_OK = True
except ImportError:
    _FASTAPI_OK = False


# ---------------------------------------------------------------------------
# App state (populated by __main__.py before starting the server)
# ---------------------------------------------------------------------------

# The dashboard reads its services from an AppContext. `__main__` (the
# composition root) builds one, wires the services in, and injects it via
# create_app(ctx=...)/run_server(ctx=...). This module-level default keeps the
# server importable and testable on its own (tests set fields on it directly).
state = AppContext()

# asyncio event loop captured inside lifespan - used to bridge sync -> async
_loop: Optional[asyncio.AbstractEventLoop] = None


# ---------------------------------------------------------------------------
# WebSocket connection manager
# ---------------------------------------------------------------------------

def _try_put(q: asyncio.Queue, item: str) -> None:
    try:
        q.put_nowait(item)
    except asyncio.QueueFull:
        pass


class _ConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[int, asyncio.Queue] = {}
        self._lock = threading.Lock()

    def add(self, ws, q: asyncio.Queue) -> None:
        with self._lock:
            self._connections[id(ws)] = q

    def remove(self, ws) -> None:
        with self._lock:
            self._connections.pop(id(ws), None)

    def broadcast_sync(self, data: dict) -> None:
        """Called from sync Store-writer thread - schedules puts on async queues."""
        if _loop is None or not _loop.is_running():
            return
        msg = json.dumps(data, default=str)
        with self._lock:
            queues = list(self._connections.values())
        for q in queues:
            _loop.call_soon_threadsafe(_try_put, q, msg)


manager = _ConnectionManager()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _safe_json(request) -> dict:
    """Parse a JSON request body into a dict, tolerating empty/bad bodies."""
    try:
        data = await request.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _utc_iso(ts: str) -> str:
    """Return an ISO-8601 timestamp explicitly marked as UTC.

    Stored event timestamps are naive UTC (``datetime.utcnow().isoformat()``)
    with no zone suffix. The browser parses a suffix-less ISO date-time as
    *local* time, which is exactly what produced the "times are N hours off"
    bug. Appending ``Z`` marks the value as UTC so the dashboard can render it
    in the viewer's own timezone. Values that already carry a zone/offset are
    returned unchanged.
    """
    if not ts:
        return ts
    if ts.endswith("Z") or "+" in ts[10:]:
        return ts
    return ts + "Z"


def _fmt_events(raw: list) -> list:
    out = []
    for r in raw:
        out.append({
            "timestamp":    _utc_iso(r.get("timestamp", "")),
            "domain":       r.get("domain", ""),
            "decision":     r.get("decision", ""),
            "process_name": r.get("process_name", ""),
            "reason":       r.get("reason", ""),
            "suspicion":    r.get("suspicion", 0.0),
            "category":     r.get("raw_category", ""),
            "url":          r.get("url", ""),
        })
    return out


async def _cached(key: str, producer, ttl_s: float):
    """Serve ``producer()`` through the response cache, off the event loop.

    On failure with no previously good value this returns a 503 carrying the
    real reason - never a zero-filled payload. The renderer already treats a
    failed poll as "no data" and renders the - sentinel (30827db, 86cc36a);
    handing it fabricated zeros instead would put the "numbers turn to 0" bug
    back, this time with the server as the source.
    """
    try:
        return await CACHE.get(key, producer, ttl_s=ttl_s,
                               timeout_s=COLD_TIMEOUT_S)
    except (asyncio.TimeoutError, TimeoutError):
        return JSONResponse(
            {"error": f"{key} timed out after {COLD_TIMEOUT_S}s"},
            status_code=503)
    except Exception as exc:                                  # noqa: BLE001
        log.warning("%s unavailable: %s: %s", key, type(exc).__name__, exc)
        return JSONResponse(
            {"error": f"{key} unavailable: {type(exc).__name__}: {exc}"},
            status_code=503)


def _build_coverage() -> dict:
    """Producer for /api/controls/coverage. ~3.3s of real host probing.

    NEVER call this from a request handler directly - it is handed to the
    response cache, which runs it in a worker thread and serves the result for
    TTL_COVERAGE seconds. Called inline it blocks the whole event loop, which
    is what made this endpoint take 22.4s and drag every other route with it.
    """
    from ..coverage import CoverageContext, check_all, summarize
    ctx = CoverageContext(
        firewall=state.firewall,
        sensor_tamper=state.sensor_tamper,
        playbook_engine=state.playbooks,
        sensor_manager=state.sensor_manager,
        # The component and responder registries are live health surfaces the
        # engine already maintains. Without them 50 of 57 controls report
        # "no independent liveness probe is wired" -- which measures coverage.py,
        # not the host.
        component_registry=state.registry,
        # EdrEngine.available_actions() is the dispatchable-action surface;
        # _check_responder only needs that one method.
        responder_registry=state.edr,
    )
    summary = summarize(check_all(ctx))
    return {
        "fraction_effective": round(summary.fraction_effective, 4),
        "counts": summary.counts,
        "total": summary.total,
        "gaps": [{"name": r.name, "category": r.category,
                 "state": r.state, "detail": r.detail}
                for r in summary.gaps],
    }


def _subsystem_unavailable(name: str) -> JSONResponse:
    """503 for a subsystem that is absent - saying WHICH KIND of absent.

    "not yet" and "never" are different answers. The web server binds in about a
    second and subsystems attach behind it, so `state.edr is None` is true both
    while the engine is three seconds from existing AND when the user ran with
    --no-edr. Twelve endpoints returned the identical payload for both, so a
    caller - including this project's own desktop app - could not tell a warming
    agent from a disabled feature, and the capability-delivery test read a
    startup race as a hard failure.

    Status stays 503 either way; the BODY now carries `starting`, so a client can
    retry a warming subsystem and give up on a disabled one.
    """
    starting = not getattr(state, "ready", False)
    return JSONResponse(
        {"error": f"{name} still starting" if starting else f"{name} not enabled",
         "starting": starting},
        status_code=503)


def _build_components() -> dict:
    if state.registry is None:
        return {"enabled": False, "components": []}
    reg = state.registry
    return {"enabled": True, "overall": reg.overall(),
            "components": reg.snapshot()}


# Request verdicts that count as "a tracker was stopped" for Nyx's defended
# tally - the acted-on outcomes already produced by the addon/DNS pipeline.
_NYX_BLOCK_CATS = {
    "blocked", "tracker_pixel", "tracker_js", "fingerprint",
    "threat_intel_url", "behavioral", "rule_block", "exfil",
}


def _build_nyx() -> dict:
    """Roll up Nyx's report from the event store: the personal-data leaks it
    SAW crossing to third parties (observe-only), plus the defenses that
    already ACTED (pages cleaned, trackers blocked, beacons fed fake data)."""
    store  = state.store
    events = store.recent_events(limit=1000)

    leaks: list[dict] = []
    faked: list[dict] = []
    defended = {"pages_cleaned": 0, "trackers_blocked": 0, "fake_data_served": 0}
    for e in events:
        rc  = e.get("raw_category", "") or ""
        dec = e.get("decision", "") or ""
        if rc == "nyx_leak":
            leaks.append({
                "when":     e.get("timestamp", ""),
                "host":     e.get("domain", ""),
                "sentence": e.get("reason", ""),
            })
        elif rc == "nyx_fake":          # Nyx ACTED - fed the tracker fake data
            faked.append({
                "when":     e.get("timestamp", ""),
                "host":     e.get("domain", ""),
                "sentence": e.get("reason", ""),
            })
            defended["fake_data_served"] += 1
        elif rc == "page_clean":
            defended["pages_cleaned"] += 1
        elif dec == "deceived":
            defended["fake_data_served"] += 1
        elif dec in ("blocked", "behavioral") or rc in _NYX_BLOCK_CATS:
            defended["trackers_blocked"] += 1

    try:
        from ..config import NYX_ACT
        acting = bool(NYX_ACT)
    except ImportError:
        acting = False

    # Correlation brain: connect a tracker's sightings across sites, channels and
    # hostnames so the report can show WHO is following you and how far they reach.
    try:
        from ..nyx_graph import build_from_events
        graph = build_from_events(events)
        trackers = graph.top_trackers(8)
        tracker_summary = graph.summary()
    except Exception:
        trackers, tracker_summary = [], {}

    s = store.stats()
    return {
        "watched_24h":     s.get("total_24h", 0),
        "mode":            "acting" if acting else "watching",
        "leak_count":      len(leaks),
        "leaks":           leaks[:50],   # most recent first (recent_events is DESC)
        "fake_count":      len(faked),
        "faked":           faked[:50],   # leaks Nyx actively fed fake data to
        "defended":        defended,
        "trackers":        trackers,        # top trackers by cross-site reach
        "tracker_summary": tracker_summary,
    }


def _build_mac_status() -> dict:
    """Producer for /api/mac/status. Enumerates network adapters, which is the
    slow part (see TTL_MAC in cache.py for the measurements)."""
    return {"enabled": True, "interfaces": _get_mac_randomizer().status()}


def _dns_active() -> bool:
    """True only if the DNS interceptor is registered AND reporting healthy.

    Conservative by design: any missing registry, missing component, or probe
    error yields False. For a security product, "I cannot confirm protection"
    must never render as "protected".
    """
    try:
        reg = state.registry
        if reg is None:
            return False
        comp = reg.get("dns_interceptor")
        if comp is None:
            return False
        return comp.snapshot()["health"]["state"] == "up"
    except Exception:
        return False


def _build_stats() -> dict:
    from ..service_manager import is_running_as_service

    s        = state.store.stats()
    top      = state.store.top_blocked_domains(limit=5)
    fw_count = state.firewall.count() if state.firewall else 0

    zero_active = state.zero_log is not None and state.zero_log.is_active()

    healthy = True
    if state.heartbeat is not None:
        try:
            healthy = state.heartbeat.is_healthy()
        except Exception:
            healthy = True

    from ..meeting_mode import MeetingMode
    try:
        meeting = MeetingMode().status()
    except Exception:
        meeting = {"active": False, "duration_minutes": 0}

    return {
        "total_24h":          s["total_24h"],
        "dns_blocked":        s["blocked_24h"],
        "fw_blocked":         fw_count,
        "flagged":            s["flagged_24h"],
        "allowed":            s["allowed_24h"],
        "top_domain":         s["top_domain"],
        "top_process":        s["top_process"],
        "top_blocked":        top,
        "uptime_seconds":     int(time.time() - state.start_time),
        "dns_port":           state.dns_port,
        # Ground truth for "is DNS interception actually running right now".
        # The desktop shell previously inferred protection SOLELY from the
        # presence of valkyrie_dns_adapter.txt, a marker that survives a crash,
        # a reboot or a stopped service - so a two-week-old file made the app
        # report "Protected / All clear" while nothing was intercepting. The
        # registry knows whether the interceptor is wired AND healthy, so the
        # engine states it plainly rather than letting the UI guess.
        "dns_active":         _dns_active(),
        "web_port":           state.web_port,
        "protection_healthy": healthy,
        "meeting_active":     meeting.get("active", False),
        "meeting_minutes":    meeting.get("duration_minutes", 0),
        "running_as_service": is_running_as_service(),
        "scanner_decisions":  state.store.scanner_decision_count(),
        # `elements_cleaned` counts page_clean rows, which ONLY the TLS
        # inspection addon ever writes. TLS inspection is off by default, so
        # this reported a hard 0 forever on a default install while the UI
        # rendered it as a live counter - a number that cannot move reads as
        # "nothing is happening", not as "this layer isn't running". Report
        # None when the producing layer is absent so the UI can say so
        # honestly; the count itself is unchanged when it IS running.
        "elements_cleaned":   (state.store.cleaned_count()
                               if state.tls_inspector is not None else None),
        "tls_inspection_active": state.tls_inspector is not None,
        # Background page-content analysis (content_watch.py).
        "content_analysis":   (state.content_watch.stats()
                               if state.content_watch is not None else None),
        "zero_log_active":    zero_active,
    }


# ---------------------------------------------------------------------------
# System control (localhost + token gated)
#
# The launcher / dashboard "Restart" and "Stop" buttons spawn PowerShell, so
# these endpoints are locked down against the two realistic attack vectors:
#   1. Other devices on the LAN - the server binds 0.0.0.0, so we require the
#      peer IP to be loopback.
#   2. Cross-site request forgery - a malicious page you visit runs in *your*
#      browser and can POST to 127.0.0.1, so a loopback check alone is not
#      enough. We additionally require a per-process secret token that only a
#      same-origin (or explicitly launcher-injected) caller can obtain, plus a
#      same-origin Origin check as defence in depth.
# ---------------------------------------------------------------------------

log = logging.getLogger("valkyrie.web")

_CONTROL_TOKEN = secrets.token_urlsafe(24)
_CONTROL_TOKEN_FILE = DATA_DIR / "control_token.txt"
try:
    _CONTROL_TOKEN_FILE.write_text(_CONTROL_TOKEN, encoding="utf-8")
    # This file IS the credential for every state-changing route - isolate the
    # host, kill a process, disable telemetry protection, shut the engine down.
    # Written under DATA_DIR, which on Windows inherits a BUILTIN\Users:read ACE
    # from %ProgramData%, so without this any local account could read the token
    # and drive those routes. The routes' auth was correct; the key to it was
    # lying in the open, which makes the whole gate decorative.
    from ..secure_file import harden as _harden_secret
    _ok, _detail = _harden_secret(_CONTROL_TOKEN_FILE)
    if not _ok:
        log.error("control token file could not be protected (%s) — any local "
                  "account may be able to read it and drive control routes",
                  _detail)
except OSError:
    pass


def _peer_is_local(request) -> bool:
    host = request.client.host if request.client else ""
    return host in ("127.0.0.1", "::1", "::ffff:127.0.0.1")


def _origin_is_local(request) -> bool:
    """True when the Origin header is absent/null (non-browser or file://
    callers) or resolves to a loopback host. Blocks state-changing POSTs whose
    Origin is a real remote website."""
    origin = request.headers.get("origin")
    if not origin or origin == "null":
        return True   # curl / launcher.html (file://) - the token is the gate
    try:
        host = urlparse(origin).hostname
    except ValueError:
        return False
    return host in ("127.0.0.1", "localhost", "::1")


def _token_ok(request) -> bool:
    token = request.headers.get("x-valkyrie-token") or request.query_params.get("token", "")
    return bool(token) and secrets.compare_digest(token, _CONTROL_TOKEN)


def _control_guard(request):
    """Return a JSONResponse to short-circuit with, or None if the caller is
    authorised to run a system-control action."""
    if os.name != "nt":
        return JSONResponse({"error": "system control is only available on Windows"}, status_code=501)
    if not _peer_is_local(request):
        return JSONResponse({"error": "forbidden: control endpoints are loopback-only"}, status_code=403)
    if not _origin_is_local(request):
        return JSONResponse({"error": "forbidden: cross-origin control blocked"}, status_code=403)
    if not _token_ok(request):
        return JSONResponse({"error": "forbidden: missing or invalid control token"}, status_code=403)
    return None


def _edr_guard(request):
    """Gate a state-changing EDR endpoint (respond / status / investigate).

    Same defence-in-depth as the system-control guard - loopback peer, local
    Origin, and the per-process control token - but cross-platform, since EDR
    actions (isolate host, kill process, block domain) are not Windows-only.
    """
    if not _peer_is_local(request):
        return JSONResponse({"error": "forbidden: EDR actions are loopback-only"}, status_code=403)
    if not _origin_is_local(request):
        return JSONResponse({"error": "forbidden: cross-origin EDR action blocked"}, status_code=403)
    if not _token_ok(request):
        return JSONResponse({"error": "forbidden: missing or invalid control token"}, status_code=403)
    return None


def _run_detached_ps(ps_command: str) -> None:
    """Launch a detached PowerShell command that outlives this process.

    The restart path runs stop_all.ps1 (which kills THIS very process) and then
    start_all.ps1, so the runner must survive its parent dying - hence
    DETACHED_PROCESS + a new process group and no inherited handles.
    """
    creationflags = 0
    if os.name == "nt":
        creationflags = 0x00000008 | 0x00000200   # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    subprocess.Popen(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_command],
        creationflags=creationflags,
        close_fds=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _get_mac_randomizer():
    """Return the shared MacRandomizer, creating one on first use.

    --mac-rand at startup only controls the auto-randomize-on-reconnect
    monitor thread; the dashboard's manual Randomise/Restore buttons must
    work regardless of whether that flag was passed.
    """
    if state.mac_randomizer is None:
        from ..mac_randomizer import MacRandomizer
        state.mac_randomizer = MacRandomizer(store=state.store)
    return state.mac_randomizer


# ---------------------------------------------------------------------------
# FastAPI app factory
# ---------------------------------------------------------------------------

def create_app(ctx: Optional[AppContext] = None):
    if not _FASTAPI_OK:
        raise ImportError("fastapi is required for --web.  Run: pip install fastapi uvicorn")

    # Dependency injection: when the composition root passes a context, adopt it
    # as the module-global the routes read. Called with no ctx (e.g. in tests),
    # the existing module-global `state` is used unchanged.
    if ctx is not None:
        global state
        state = ctx

    async def _loop_stall_monitor():
        """Diagnostic: measure the event loop's OWN responsiveness from inside
        it. This coroutine expects to wake every 1s; if it wakes much later, the
        loop was BLOCKED for the difference - i.e. a CPU-heavy thread saturated
        the GIL or an async handler ran blocking work, and during that window
        the loop could not accept connections and /api/health went deaf.

        Added 2026-08-24 to pinpoint the Tier B 'engine went deaf after 2 OK'
        failure (see valkyrie_startup_deafness). Writes to stderr with a
        wall-clock stamp so it lands in the CI transcript next to whatever
        subsystem log fired at the same moment, naming the GIL hog instead of
        guessing. Cheap (one 1s sleep); safe to leave on."""
        import sys as _sys
        interval = 1.0
        while True:
            t0 = time.monotonic()
            try:
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                return
            drift = time.monotonic() - t0 - interval
            if drift > 1.5:
                print(f"[loop-stall] {time.strftime('%H:%M:%S')} event loop was "
                      f"BLOCKED for {drift:.1f}s (health would have been deaf this "
                      f"whole time)", file=_sys.stderr, flush=True)

    @asynccontextmanager
    async def _lifespan(app: FastAPI):
        # Startup: capture loop, register live-event subscriber
        global _loop
        _loop = asyncio.get_running_loop()
        _stall_task = asyncio.create_task(_loop_stall_monitor())
        if state.store is not None:
            state.store.subscribe(manager.broadcast_sync)
        # Stream EDR incidents to dashboards over the same WebSocket.
        if state.edr is not None:
            state.edr.subscribe(manager.broadcast_sync)
        yield
        # Shutdown: unregister subscriber
        _stall_task.cancel()
        if state.store is not None:
            state.store.unsubscribe(manager.broadcast_sync)
        if state.edr is not None:
            state.edr.unsubscribe(manager.broadcast_sync)

    app = FastAPI(title="Valkyrie Dashboard", lifespan=_lifespan,
                  docs_url=None, redoc_url=None)
    # No CORSMiddleware - Starlette's CORS middleware blocks WebSocket upgrades
    # on some versions. The dashboard is served from the same origin, so CORS
    # is unnecessary and the middleware would break the /ws endpoint.

    @app.middleware("http")
    async def _offloopback_api_guard(request, call_next):
        # The dashboard's data endpoints expose live DNS/browsing history and
        # system status. When the server is bound off-loopback (the explicit
        # --web-host 0.0.0.0 opt-in for router/LAN viewing), every /api/* call
        # from a non-loopback peer must present the control token. Loopback
        # callers - the local dashboard on the same machine - are unaffected, so
        # the default single-user experience is unchanged. State-changing
        # control/EDR POSTs keep their own stricter loopback+origin+token guards
        # layered on top of this.
        path = request.url.path
        if (path.startswith("/api/")
                and not _peer_is_local(request)
                and not _token_ok(request)):
            return JSONResponse(
                {"error": "forbidden: off-loopback API access requires the control token"},
                status_code=403,
            )
        return await call_next(request)

    # --- Routes ---
    #
    # THE ASYNC RULE FOR EVERY ROUTE BELOW - read before adding one.
    #
    # uvicorn serves this whole app from ONE asyncio event loop, and that loop
    # is also what accepts new TCP connections. A route declared `async def`
    # runs its body *directly on that loop*, so any blocking call inside it -
    # a SQLite query, a registry read, subprocess/netsh/PowerShell, a socket -
    # freezes the entire API for its duration. A call that blocks forever
    # freezes it forever.
    #
    # That is not theoretical: it is the "Engine unreachable" bug. Every route
    # here was `async def` while doing plain synchronous work, so one slow
    # handler stalled the loop, the accept queue filled with connections the
    # server never read (observed live: 1 LISTEN + 202 CLOSE_WAIT sockets),
    # and once the backlog saturated the kernel refused new connects outright.
    # The desktop app's 1s /api/health poll then failed forever and reported
    # the engine as unreachable - while the engine was running perfectly and
    # still writing to its database. Note that /api/health itself is trivially
    # cheap; it went down purely as collateral, which is the whole point: on a
    # single loop, one blocking handler takes the liveness probe with it.
    #
    # So:
    #   * a handler that does blocking work is a plain `def` - Starlette then
    #     runs it in its threadpool and it CANNOT stall the loop;
    #   * a handler is `async def` ONLY if it genuinely awaits something, and
    #     any blocking work inside it goes through `run_in_threadpool` (or
    #     `_cached`, which already offloads its producer).
    #
    # Rule of thumb: if the body contains no `await`, it must not be `async`.

    @app.get("/", include_in_schema=False)
    def serve_dashboard():
        return FileResponse(_WEB_DIR / "dashboard.html", media_type="text/html")

    @app.get("/api/stats")
    async def get_stats():
        if state.store is None:
            return JSONResponse({"error": "store not ready"}, status_code=503)
        return await _cached("stats", _build_stats, TTL_STATS)

    @app.get("/api/events")
    async def get_events():
        if state.store is None:
            return JSONResponse({"error": "store not ready"}, status_code=503)
        return await _cached(
            "events", lambda: _fmt_events(state.store.recent_events(limit=200)),
            TTL_EVENTS)

    @app.get("/api/nyx")
    async def get_nyx():
        """Nyx's plain-language report: what personal data it saw leaving to
        third parties (observe-only), plus the defenses that already fired."""
        if state.store is None:
            return JSONResponse({"error": "store not ready"}, status_code=503)
        return await _cached("nyx", _build_nyx, TTL_EVENTS)

    @app.get("/api/nyx/self-test")
    def nyx_self_test():
        """Run Nyx's data guard against synthetic leaks and return what it caught
        and faked - the live 'watch it happen' demo, no real tracker needed."""
        from ..nyx import self_test
        return self_test()

    @app.get("/api/browser/context/status")
    def browser_context_status():
        """Local health and sanitized recent browser-context observations."""
        if state.browser_context is None:
            return JSONResponse({"enabled": False, "status": "starting" if not state.ready else "disabled"},
                                status_code=503 if not state.ready else 200)
        return state.browser_context.status()

    @app.post("/api/browser/events")
    async def browser_context_event(request: Request):
        """Receive a native-host forwarded browser event.

        This endpoint is intentionally distinct from system-control routes:
        browser context cannot execute an action.  It is still loopback and
        secret gated so a website cannot inject a forged local interaction.
        """
        if not _peer_is_local(request):
            return JSONResponse({"error": "browser context is loopback-only"}, status_code=403)
        collector = state.browser_context
        if collector is None:
            return JSONResponse({"error": "browser context bridge not ready"}, status_code=503)
        if not collector.token_ok(request.headers.get("x-valkyrie-browser-token", "")):
            return JSONResponse({"error": "invalid browser context token"}, status_code=403)
        payload = await _safe_json(request)
        result = await run_in_threadpool(collector.ingest, payload)
        return JSONResponse(result, status_code=202 if result.get("accepted") else 422)

    @app.get("/api/telemetry/status")
    def telemetry_status():
        from ..telemetry_killer import TelemetryKiller
        findings = TelemetryKiller().scan()
        if not findings:
            return {"status": "UNKNOWN", "settings": [], "error": "admin rights required"}
        active = [n for n, f in findings.items() if f["active"]]
        if not active:
            status = "KILLED"
        elif len(active) == len(findings):
            status = "ACTIVE"
        else:
            status = "PARTIAL"
        return {
            "status": status,
            "settings": [
                {"name": n, "active": f["active"], "current": f["current"]}
                for n, f in findings.items()
            ],
        }

    @app.post("/api/telemetry/kill")
    def telemetry_kill():
        from ..telemetry_killer import TelemetryKiller
        results = TelemetryKiller().kill()
        if not results:
            return JSONResponse({"error": "admin rights required"}, status_code=403)
        return {"results": results}

    @app.post("/api/telemetry/restore")
    def telemetry_restore():
        from ..telemetry_killer import TelemetryKiller
        results = TelemetryKiller().restore()
        if not results:
            return JSONResponse({"error": "admin rights required or no backup found"}, status_code=403)
        return {"results": results}

    @app.get("/api/intelligence")
    def intelligence_status():
        if state.intelligence is None:
            return {"enabled": False}
        info = state.intelligence.status()
        info["enabled"] = True
        info["blocklist_domains"] = state.blocklist.count() if state.blocklist else 0
        try:
            from ..seed_blocklist import SEED_DOMAINS
            info["seed_domains"] = len(SEED_DOMAINS)
        except ImportError:
            info["seed_domains"] = 0
        from ..config import USE_EXTERNAL_LISTS
        info["external_lists"] = USE_EXTERNAL_LISTS
        if state.self_heal is not None:
            info["self_heal"] = state.self_heal.status()
        return info

    # /api/compliance/report removed - compliance reporting moved to
    # experimental/ (generating audit evidence for a product with no customers
    # and no certification is theatre). See experimental/README.md.

    @app.get("/api/edr/playbooks/status")
    def playbooks_status():
        if state.playbooks is None:
            return {"enabled": False}
        info = state.playbooks.status()
        info["enabled"] = True
        return info

    @app.get("/api/components")
    async def components_list():
        # Uniform plugin surface: every subsystem's health + metrics + config.
        if state.registry is None:
            return {"enabled": False, "components": []}
        return await _cached("components", _build_components, TTL_COMPONENTS)

    @app.post("/api/components/{name}/restart")
    def component_restart(name: str, request: Request):
        # Restarting a subsystem is state-changing - token-gated off loopback.
        guard = _control_guard(request)
        if guard is not None:
            return guard
        if state.registry is None:
            return JSONResponse({"error": "registry not active"}, status_code=503)
        result = state.registry.restart(name)
        if not result.get("ok") and "no such component" in result.get("error", ""):
            return JSONResponse(result, status_code=404)
        return result

    @app.get("/api/siem/status")
    def siem_status():
        if state.siem is None:
            return {"enabled": False}
        info = state.siem.status()
        info["enabled"] = True
        return info

    @app.get("/api/intel/status")
    def threat_intel_status():
        if state.threat_intel is None:
            return {"enabled": False}
        info = state.threat_intel.status()
        info["enabled"] = True
        return info

    @app.get("/api/ping")
    async def ping():                                      # noqa: RUF029
        """Pure liveness: can the ASGI app accept and answer a request.

        THE ONE DELIBERATE EXCEPTION to the "no `async def` without an `await`"
        rule documented at the top of the routes. Every other handler is a sync
        `def` so it runs in the threadpool and cannot stall the loop; this one
        is the reverse case, and for the same underlying reason.

        A sync handler is dispatched through Starlette's threadpool, which has
        a finite worker count (anyio's default limiter is 40). Saturate those
        workers with slow requests and a sync /api/ping QUEUES behind them -
        measured at 1094ms with 40 slow reads in flight, versus ~3ms idle. The
        liveness probe would then report the server as slow-to-dead exactly
        when it is busy, which is the same "measures LOAD, reports load as
        death" mistake described below, just relocated from the endpoint's cost
        to the dispatch queue.

        Running on the event loop instead makes it unqueueable: the body does
        no I/O, takes no lock and touches no state, so it cannot block the loop
        it runs on, and it answers in microseconds no matter how many blocking
        handlers are in flight. Keep it that way - if this handler ever needs
        to read anything, it is no longer a liveness probe.

        Deliberately touches NO state - no store, no heartbeat, no registry.
        The self-healing watchdog used to probe /api/stats, which is a
        five-query 24h aggregate; with a 3s timeout against a measured 2.5s
        (6.3s under concurrency) response, the watchdog was timing out on a
        perfectly healthy server and logging "web_dashboard unhealthy" every
        30s forever.

        A liveness probe must measure liveness. Probing an expensive endpoint
        measures LOAD, and then reports load as death - which is how a busy
        server gets declared dead and "recovered" while it is working fine.
        /api/health is a different question (is PROTECTION healthy) and is not
        a substitute for this one.
        """
        return {"ok": True}

    @app.get("/api/cache/stats")
    def cache_stats():
        """Per-key age, refresh errors and hit counters for the response cache.

        Exposed because a cache that has silently stopped refreshing looks
        from the outside exactly like a system where nothing is happening -
        and those two must never be indistinguishable in a security product.
        """
        return CACHE.snapshot()

    @app.get("/api/stats/cleaned")
    def get_cleaned_stats():
        if state.store is None:
            return JSONResponse({"error": "store not ready"}, status_code=503)
        return {"elements_cleaned": state.store.cleaned_count()}

    @app.get("/api/mac/status")
    async def mac_status():
        # Cached, unlike its neighbours: mac.status() enumerates adapters and
        # measured 356-1164 ms steady state (3,465 ms cold) on the rebuilt
        # engine, against ~12 ms for the other status endpoints. The privacy
        # view fires it every 3 s alongside six others, so it was the most
        # expensive thing the dashboard did on repeat. Both mutating routes
        # below invalidate the key, so a randomise still shows up instantly.
        return await _cached("mac", _build_mac_status, TTL_MAC)

    @app.post("/api/mac/randomize")
    def mac_randomize():
        mac = _get_mac_randomizer()
        new_mac = mac.randomize()
        if not new_mac:
            return JSONResponse(
                {"error": mac.last_error or "MAC randomisation failed"},
                status_code=500,
            )
        # The address just changed; a stale cached status would make the UI
        # report the OLD MAC right after the user pressed the button, which
        # reads as "the action did nothing".
        CACHE.invalidate("mac")
        return {"new_mac": new_mac, "status": "randomised"}

    @app.post("/api/mac/restore")
    def mac_restore():
        mac = _get_mac_randomizer()
        restored = mac.restore()
        if not restored:
            return JSONResponse(
                {"error": "No backup found to restore (has a MAC ever been randomised?)"},
                status_code=404,
            )
        CACHE.invalidate("mac")
        return {"restored_mac": restored, "status": "restored"}

    @app.get("/api/fingerprint/status")
    def fingerprint_status():
        """TCP/IP fingerprint spoof state (TTL / TCP-timestamps normalisation)."""
        try:
            from ..fingerprint import NetworkFingerprint
            return NetworkFingerprint().status()
        except Exception as exc:      # noqa: BLE001 - status must never 500
            return {"supported": False, "normalized": False, "error": str(exc)}

    @app.get("/api/profile")
    def profile_get():
        """Risk profiles + which is active (drives block-vs-deceive)."""
        from ..profiles import list_profiles, get_profile
        return {"current": get_profile().value, "profiles": list_profiles()}

    @app.post("/api/profile/set")
    async def profile_set(request: Request):
        from ..profiles import set_profile, get_profile
        try:
            body = await request.json()
        except Exception:
            body = {}
        set_profile(str((body or {}).get("profile", "")))
        return {"current": get_profile().value}

    @app.get("/api/deception/status")
    def deception_status():
        """How the deception engine is doing: how many tracker/telemetry
        beacons were answered with a fabricated persona instead of hard-
        failed (dns_interceptor's own 'deceived' decision - read here, not
        redefined, so this can never disagree with what actually happened on
        the wire), and what that persona currently looks like.

        Read-only. There is no endpoint that lets a caller pick, rotate, or
        otherwise influence the persona - the whole point of persona.py is
        that it does NOT change on request.
        """
        if state.store is None:
            stats = {"beacons_deceived_24h": 0, "trackers_deceived_24h": 0,
                     "trackers_deceived_total": 0, "beacons_deceived_total": 0}
        else:
            stats = state.store.deception_stats()
        from ..persona import current_persona
        p = current_persona()
        return {
            **stats,
            "persona": {
                "locale":  p.locale,
                "country": p.country,
                "timezone": p.timezone,
                "city":    p.city,
                "region":  p.region,
                "os":      p.os_name,
                "browser": f"{p.browser} {p.browser_version}",
                "screen":  f"{p.screen_width}x{p.screen_height}",
                "cores":   p.hardware_concurrency,
                "memory_gb": p.device_memory,
            },
        }

    @app.get("/api/doh/status")
    def doh_status():
        """DNS-over-HTTPS bypass detection: a process that resolves straight
        to a public DoH resolver's IP is routing DNS around Valkyrie's
        interception entirely - the same "escape the blocker" story as an
        undeceived tracker, one layer down the stack (see deception_status
        above). Combines the LIVE detector's own health (doh_detector.py's
        `status()` - is psutil available, is the scan loop actually running)
        with the store's counts of what it has caught, so "detector running
        but psutil missing" and "detector fine, nothing to report" read as
        the two distinct states they are, not the same silent zero.
        """
        if state.doh is not None:
            live = state.doh.status()
        else:
            live = {"running": False, "available": False, "alerts_seen": 0,
                    "scan_errors": 0, "last_error": ""}
        if state.store is None:
            stats = {"bypass_attempts_24h": 0, "bypass_processes_24h": 0,
                     "bypass_attempts_total": 0, "most_recent": None}
        else:
            stats = state.store.doh_bypass_stats()
        return {**live, **stats}

    @app.get("/api/sysmon/status")
    def sysmon_status():
        """Sysmon presence/health, and whether detection is running degraded
        without it (ADR 0048). Reads the sensor-tamper monitor's cached last
        poll rather than probing live - probe_sysmon() shells out to
        PowerShell several times, which is too slow for a status endpoint a
        dashboard may poll on every refresh."""
        if state.sensor_tamper is None:
            return {"monitored": False,
                    "note": "sensor tamper detection is not active "
                            "(EDR disabled, or --no-edr)"}
        status = state.sensor_tamper.current_status()
        sysmon_healthy = status.get("sysmon")
        # Real prose from the last probe (present? running? which EIDs are
        # missing?) when one has completed - see sensor_tamper.py's
        # _sysmon_health(). Falls back to a generic line only before the
        # first poll has had a chance to run.
        live_detail = state.sensor_tamper.current_detail().get("sysmon")
        return {"monitored": True,
                "sysmon_healthy": sysmon_healthy,
                "degraded": sysmon_healthy is False,
                "detail": live_detail if live_detail else (
                          "unknown — no poll has completed yet"
                          if sysmon_healthy is None else
                          ("Sysmon is providing the event types Valkyrie needs"
                           if sysmon_healthy else
                           "Sysmon is degraded or absent — command-line, "
                           "process-injection and credential-dump detection "
                           "may be running in degraded mode"))}

    @app.get("/api/controls/taxonomy")
    def controls_taxonomy():
        """Every Valkyrie control classified preventive/detective/corrective/
        deterrent/compensating/directive/recovery (IIBA §4.2.3), plus any
        category with no primary control - an empty category is a finding,
        not a bug in this endpoint. Static classification merged with the
        LIVE compensating-control activation state (sensor_tamper.py) where
        available, so 'compensating' reflects whether it is actually
        running right now, not just whether the code exists."""
        from ..control_taxonomy import CATEGORIES, by_category, gaps
        grouped = by_category()
        live_compensation = (state.sensor_tamper.current_compensation()
                             if state.sensor_tamper is not None else {})
        return {
            "categories": {
                cat: [
                    {"name": ctl.name, "module": ctl.module,
                     "secondary": ctl.category != cat, "note": ctl.note}
                    for ctl in grouped[cat]
                ]
                for cat in CATEGORIES
            },
            "gaps": gaps(),
            "live_compensation_active": live_compensation,
        }

    @app.get("/api/controls/coverage")
    async def controls_coverage():
        """What fraction of Valkyrie's intended defenses are actually live,
        right now, on THIS host - not a static claim. Three states per
        control (effective/degraded/absent), not a binary installed/not -
        see valkyrie/coverage.py. Wires in every live singleton this
        process actually has, so e.g. Sysmon installed-but-stopped reports
        'absent', not 'effective'.

        Served from the response cache: the probe costs ~3.3s of real host
        interrogation, which is why this endpoint measured 22.4s and starved
        every other route. See valkyrie/web/cache.py."""
        return await _cached("coverage", _build_coverage, TTL_COVERAGE)

    @app.get("/api/decoys/status")
    def decoys_status():
        """How many decoy honeytokens are live (0 = not deployed)."""
        from .. import decoys as _dm
        mgr = getattr(_dm, "_ACTIVE", None)
        return {"active": mgr is not None,
                "count": len(mgr.tokens()) if mgr else 0,
                "paths": mgr.paths()[:20] if mgr else []}

    # /api/vpn/status removed - multi-hop VPN moved to experimental/.
    # Valkyrie is an endpoint security + privacy agent, not a VPN product.

    @app.get("/api/zero-log/status")
    def zero_log_status():
        if state.zero_log is None:
            return {"active": False, "mode": "disk",
                    "session_events": 0, "disk_writes": "enabled",
                    "integrity": "verified", "tampered_files": []}
        return state.zero_log.status()

    # --- Ransomware Shield ---
    @app.get("/api/ransomware/status")
    def ransomware_status():
        rs = getattr(state, "ransomware_shield", None)
        if rs is None:
            return {"enabled": False}
        return rs.status()

    @app.post("/api/ransomware/self-test")
    def ransomware_self_test(request: Request):
        # State-changing only in a throwaway temp dir; still token-gated so a
        # remote page can't trigger it. Proves the tripwire + entropy logic live.
        guard = _control_guard(request)
        if guard is not None:
            return guard
        rs = getattr(state, "ransomware_shield", None)
        if rs is None:
            return JSONResponse({"error": "ransomware shield not active"}, status_code=503)
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            return rs.simulate(Path(td))

    # --- AMSI content scanning ---
    @app.get("/api/amsi/status")
    def amsi_status():
        sc = getattr(state, "amsi", None)
        if sc is None:
            return {"enabled": False}
        return sc.status()

    @app.post("/api/amsi/self-test")
    def amsi_self_test(request: Request):
        # Token-gated: a working provider records a detection in its own
        # history when it convicts the marker, so this must not be triggerable
        # by a remote page. Returns a tri-state conclusion - a non-conviction
        # is reported as inconclusive, never as a pass or a failure.
        guard = _control_guard(request)
        if guard is not None:
            return guard
        sc = getattr(state, "amsi", None)
        if sc is None:
            return JSONResponse({"error": "AMSI scanning not active"}, status_code=503)
        return sc.self_test()

    @app.post("/api/edr/incidents/{incident_id}/triage")
    def collect_triage(incident_id: str, request: Request):
        # Collects live host state into a local evidence bundle - state-
        # revealing, so token-gated like every response-capable route.
        guard = _control_guard(request)
        if guard is not None:
            return guard
        if state.edr is None or state.store is None:
            return JSONResponse({"error": "EDR not active"}, status_code=503)
        from ..forensics import TriageCollector
        try:
            manifest = TriageCollector(state.edr, state.store).collect(incident_id)
        except KeyError:
            return JSONResponse({"error": "incident not found"}, status_code=404)
        return manifest

    # --- Endpoint telemetry visibility ---
    @app.get("/api/telemetry/endpoint")
    def endpoint_telemetry_status():
        pc = getattr(state, "persistence_collector", None)
        return {
            "process_collector":    getattr(state, "process_collector", None) is not None,
            "network_collector":    getattr(state, "network_collector", None) is not None,
            "persistence_collector": pc is not None,
            "persistence_running":  bool(pc and pc.is_running()),
        }

    @app.get("/api/asset-inventory")
    def asset_inventory_status():
        """CIS Controls #1/#2: the most recent snapshot of what's
        installed, listening, and loaded, plus counts. Reads the
        collector's CACHE (``last_snapshot()``), never a fresh probe --
        confirmed via a real boot that a fresh snapshot takes 30+ SECONDS
        on a real host (474 kernel-driver registry keys alone), which would
        block this whole async server for that long on every request. Same
        cache-not-probe contract as ``/api/sysmon/status``. See
        ``AssetSnapshot.taken_at`` in the response for exactly how stale the
        data is (poll interval defaults to 1h). 503 (not a crash) when the
        collector isn't available, or hasn't completed its first poll yet."""
        ai = getattr(state, "asset_inventory", None)
        if ai is None:
            return JSONResponse({"error": "asset inventory not available"},
                                status_code=503)
        snap = ai.last_snapshot()
        if snap is None:
            return JSONResponse(
                {"error": "asset inventory has not completed its first poll yet"},
                status_code=503)
        return {
            "counts": snap.counts(),
            "software": snap.software,
            "listening_ports": snap.listening_ports,
            "kernel_drivers": snap.kernel_drivers,
            "taken_at": snap.taken_at,
            "collector_running": ai.is_running(),
            # The delta is the product; the snapshot above is bookkeeping.
            # Most recent first, capped at 50 (AssetInventoryCollector's own
            # bound) -- empty until a second poll has run (default 1h after
            # start, since nothing "changed" relative to nothing on the
            # first poll).
            "recent_changes": ai.recent_changes(),
        }

    # --- System control (launcher / dashboard buttons) ---
    @app.get("/api/system/token")
    def system_token(request: Request):
        # Same-origin loopback only. Lets the dashboard fetch the control
        # token it needs for restart/stop. A cross-origin page cannot read
        # this response (no CORS headers) and fails the origin check anyway.
        if not _peer_is_local(request) or not _origin_is_local(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        return {"token": _CONTROL_TOKEN, "web_port": int(state.web_port or 0)}

    @app.post("/api/system/restart")
    def system_restart(request: Request):
        guard = _control_guard(request)
        if guard is not None:
            return guard
        stop  = _PROJECT_ROOT / "stop_all.ps1"
        start = _PROJECT_ROOT / "start_all.ps1"
        _run_detached_ps(f"& '{stop}'; Start-Sleep -Seconds 3; & '{start}'")
        return {"status": "restarting"}

    @app.post("/api/system/shutdown")
    def system_shutdown(request: Request):
        guard = _control_guard(request)
        if guard is not None:
            return guard
        stop = _PROJECT_ROOT / "stop_all.ps1"
        _run_detached_ps(f"& '{stop}'")
        return {"status": "stopping"}

    # --- Protection heartbeat (read-only) ---
    @app.get("/api/health")
    def get_health():
        if state.heartbeat is None:
            return {"healthy": True, "monitored": False}
        try:
            st = state.heartbeat.status()
            st["monitored"] = True
            return st
        except Exception:
            return {"healthy": True, "monitored": False}

    # --- Meeting Mode (kill switch) ---
    @app.get("/api/meeting/status")
    def meeting_status():
        from ..meeting_mode import MeetingMode
        return MeetingMode().status()

    @app.post("/api/meeting/start")
    def meeting_start(request: Request):
        guard = _control_guard(request)
        if guard is not None:
            return guard
        from ..meeting_mode import MeetingMode
        return MeetingMode().activate()

    @app.post("/api/meeting/stop")
    def meeting_stop(request: Request):
        guard = _control_guard(request)
        if guard is not None:
            return guard
        from ..meeting_mode import MeetingMode
        return MeetingMode().deactivate()

    # --- EDR / SOC layer ---
    @app.get("/edr", include_in_schema=False)
    def serve_edr_console():
        return FileResponse(_WEB_DIR / "edr.html", media_type="text/html")

    @app.get("/api/edr/stats")
    def edr_stats():
        if state.edr is None:
            return {"enabled": False}
        s = state.edr.stats(); s["enabled"] = True
        return s

    @app.get("/api/edr/incidents")
    async def edr_incidents(status: Optional[str] = None,
                            severity: Optional[str] = None,
                            brief: bool = False):
        if state.edr is None:
            return _subsystem_unavailable("EDR")
        # Off the event loop: list_incidents is a synchronous SQLite read (opens a
        # connection, ORDER BY ... LIMIT 200). Run on the loop it blocks every
        # other request - including the self-heal /api/ping - for its whole
        # duration, which under eval/dashboard polling load is exactly how the
        # server declared ITSELF "web_dashboard unhealthy" in a tight loop.
        return await run_in_threadpool(
            state.edr.list_incidents, status=status, severity=severity,
            limit=200, brief=brief)

    @app.get("/api/edr/metrics/mttd-mttr")
    async def edr_mttd_mttr():
        """Median + p95 MTTD (first observable event -> incident raised) and
        MTTR (incident raised -> first real responder action completed) over
        the most recent real incidents -- Clinton ch.10 / IIBA §9.1.2's
        headline security metrics, for actual production incidents, not just
        the eval harness (see valkyrie/edr/metrics.py for the exact
        definitions and their honest limits)."""
        if state.edr is None:
            return _subsystem_unavailable("EDR")
        # Off the event loop: mttd_mttr fans out to get_incident for up to 200
        # incidents (~3 queries + impact assessment each) - by far the heaviest
        # read in the API. On the loop it stalls everything for seconds.
        return await run_in_threadpool(state.edr.mttd_mttr)

    @app.get("/api/sensors/status")
    def sensors_status():
        """Real-time sensor host health + metrics (observability for the
        SensorManager: per-sensor state, dedup/backpressure drops, restarts)."""
        sm = getattr(state, "sensor_manager", None)
        if sm is None:
            return {"enabled": False}
        s = sm.stats(); s["enabled"] = True
        # POLL-BASED collectors report separately, because "running" is not the
        # same as "able to detect". The persistence collector works by DIFFING
        # snapshots, so before its first baseline exists it can detect nothing -
        # and silence from a sensor that has not started looking must not read
        # as an all-clear. A harness (or an operator) can wait on
        # baseline_ready instead of racing it.
        pc = getattr(state, "persistence_collector", None)
        if pc is not None and hasattr(pc, "status"):
            try:
                s["persistence_collector"] = pc.status()
            except Exception as exc:   # noqa: BLE001
                s["persistence_collector"] = {"error": exc.__class__.__name__}
        return s

    @app.get("/api/edr/incidents/{incident_id}")
    async def edr_incident(incident_id: str):
        if state.edr is None:
            return _subsystem_unavailable("EDR")
        # Off the event loop: get_incident runs ~3 synchronous SQLite queries
        # (incident + detections + responses) plus an impact assessment.
        inc = await run_in_threadpool(state.edr.get_incident, incident_id)
        if inc is None:
            return JSONResponse({"error": "unknown incident"}, status_code=404)
        return inc

    @app.get("/api/edr/incidents/{incident_id}/decision")
    def edr_incident_decision(incident_id: str):
        """The recommended graded action (allow/alert/deceive/block/contain) for
        an incident, under the current risk profile, with a plain-language reason
        and user message. Deterministic - the explainable 'why' behind response."""
        if state.edr is None:
            return _subsystem_unavailable("EDR")
        inc = state.edr.get_incident(incident_id)
        if inc is None:
            return JSONResponse({"error": "unknown incident"}, status_code=404)
        from ..decision import decide, signal_from_incident
        from ..profiles import get_profile
        dets = inc.get("detections") or [inc]
        sig = signal_from_incident(dets[0])
        return decide(sig, get_profile()).to_dict()

    @app.get("/api/edr/incidents/{incident_id}/causality")
    async def edr_incident_causality(incident_id: str):
        """The causality subgraph behind an incident: the Causality Group Owner
        (what started this), the process chain down to the alerting process, the
        rest of that owner's process tree, and every artifact attributed to it.

        The honesty flags on the payload are load-bearing and must be rendered,
        not dropped: ``inferred_nodes`` counts ancestry the graph guessed at
        rather than observed, ``truncated`` means the tree walk hit its bound,
        and ``evicted`` means nodes had already been dropped for memory before
        this query ran. A short chain for any of those reasons is not the same
        claim as a genuinely short chain.

        404 (not an empty graph) when the incident has no attributable pid, so a
        caller can tell "nothing to show" from "no process to show it for".
        """
        if state.edr is None:
            return _subsystem_unavailable("EDR")
        inc = await run_in_threadpool(state.edr.get_incident, incident_id)
        if inc is None:
            return JSONResponse({"error": "unknown incident"}, status_code=404)
        pid = int(inc.get("process_pid") or 0)
        if pid <= 0:
            # process_pid is live-only (not persisted - see edr/store.py), so
            # fall back to the pid carried on the incident's own detections
            # before giving up on it.
            for det in (inc.get("detections") or []):
                pid = int(det.get("process_pid") or 0)
                if pid > 0:
                    break
        if pid <= 0:
            return JSONResponse(
                {"error": "incident has no attributed process"}, status_code=404)
        graph = state.edr.causality_subgraph(pid)
        graph["incident_id"] = incident_id
        return graph

    @app.get("/api/edr/causality/stats")
    def edr_causality_stats():
        """Process-ancestry graph size and health (nodes, inferred, evicted)."""
        if state.edr is None:
            return _subsystem_unavailable("EDR")
        return state.edr.causality_stats()

    @app.post("/api/edr/incidents/{incident_id}/status")
    async def edr_incident_status(incident_id: str, request: Request):
        if state.edr is None:
            return _subsystem_unavailable("EDR")
        guard = _edr_guard(request)
        if guard is not None:
            return guard
        body = await _safe_json(request)
        inc = state.edr.update_incident(
            incident_id, status=body.get("status"), notes=body.get("notes"),
            assignee=body.get("assignee"), operator="dashboard")
        if inc is None:
            return JSONResponse({"error": "unknown incident"}, status_code=404)
        return inc

    @app.post("/api/edr/incidents/{incident_id}/investigate")
    async def edr_investigate(incident_id: str, request: Request):
        if state.edr is None:
            return _subsystem_unavailable("EDR")
        guard = _edr_guard(request)
        if guard is not None:
            return guard
        body = await _safe_json(request)
        report = state.edr.investigate(
            incident_id, use_ai=bool(body.get("use_ai")), operator="dashboard")
        if report is None:
            return JSONResponse({"error": "unknown incident"}, status_code=404)
        return report

    @app.post("/api/edr/respond")
    async def edr_respond(request: Request):
        if state.edr is None:
            return _subsystem_unavailable("EDR")
        guard = _edr_guard(request)
        if guard is not None:
            return guard
        body = await _safe_json(request)
        action = str(body.get("action", ""))
        if not action:
            return JSONResponse({"error": "action is required"}, status_code=400)
        # dry_run defaults to True - a real action must be explicitly requested.
        dry_run = bool(body.get("dry_run", True))
        return state.edr.respond(
            action, str(body.get("target", "")), dry_run=dry_run,
            operator="dashboard", incident_id=str(body.get("incident_id", "")))

    @app.get("/api/edr/hunt/saved")
    def edr_saved_hunts():
        if state.edr is None:
            return _subsystem_unavailable("EDR")
        return {"hunts": state.edr.saved_hunts(),
                "facets": state.edr.hunt_facets(24)}

    @app.post("/api/edr/hunt")
    async def edr_hunt(request: Request):
        if state.edr is None:
            return _subsystem_unavailable("EDR")
        body = await _safe_json(request)
        limit = int(body.get("limit", 200) or 200)
        if body.get("saved"):
            return state.edr.run_saved_hunt(str(body["saved"]), limit)
        return state.edr.hunt(body.get("filters") or {}, limit)

    @app.get("/api/edr/plugins")
    def edr_plugins():
        if state.edr is None:
            return _subsystem_unavailable("EDR")
        return state.edr.plugins()

    @app.websocket("/ws")
    async def websocket_endpoint(ws: WebSocket):
        # The live event stream is the single most sensitive surface - real-time
        # browsing history. The HTTP middleware does not cover WebSocket scope,
        # so apply the same off-loopback rule here: a non-loopback subscriber
        # must supply ?token=<control token>. Loopback (the local dashboard) is
        # trusted and connects with no token, exactly as before.
        if not _peer_is_local(ws) and not _token_ok(ws):
            await ws.close(code=1008)   # 1008 = policy violation
            return
        await ws.accept()
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        manager.add(ws, q)

        try:
            # --- Initial payload (isolated try - failure must NOT close the WS) ---
            if state.store is not None:
                try:
                    # Built in the threadpool, never inline: _build_stats() is a
                    # multi-query 24h SQLite aggregate (that is why the HTTP route
                    # serves it through _cached) and recent_events() hits the same
                    # DB. Awaiting them here on the event loop would stall EVERY
                    # other connection - including /api/health and the accept loop
                    # itself - for the whole duration, which is exactly the wedge
                    # this endpoint's own docstring warns about elsewhere.
                    def _init_payload() -> str:
                        return json.dumps({
                            "type":   "init",
                            "stats":  _build_stats(),
                            "events": _fmt_events(state.store.recent_events(limit=50)),
                        })
                    init = await run_in_threadpool(_init_payload)
                    await ws.send_text(init)
                except Exception:
                    pass   # init failed but keep the connection alive

            # --- Relay loop ---
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=25.0)
                except (asyncio.TimeoutError, TimeoutError):
                    # Keep-alive ping every 25 s
                    try:
                        await ws.send_text('{"type":"ping"}')
                    except Exception:
                        break
                    continue

                try:
                    await ws.send_text(msg)
                except Exception:
                    break   # client disconnected

        except asyncio.CancelledError:
            raise   # let uvicorn handle shutdown cancellation
        except Exception:
            pass
        finally:
            manager.remove(ws)

    return app


# ---------------------------------------------------------------------------
# Runner (called from __main__.py in a daemon thread)
# ---------------------------------------------------------------------------

def run_server(host: str = WEB_HOST, port: int = WEB_PORT,
               ctx: Optional[AppContext] = None) -> None:
    """Block the calling thread running the uvicorn server.

    The host default is LOOPBACK, not 0.0.0.0. Every real caller passes an
    explicit host (``__main__`` uses ``--web-host``, defaulting to WEB_HOST and
    warning loudly when it is off-loopback), so the old ``0.0.0.0`` default was
    never actually reached - but it was a live footgun: this app exposes the
    control routes (isolate host, kill process, disable telemetry), and any
    future caller that omitted ``host`` would have published them to every
    interface. A dangerous default that happens to be unused is still a
    dangerous default; secure-by-default costs nothing here.

    ``ctx`` is the injected AppContext; when omitted the module-global ``state``
    is used (preserving the standalone/test entry point).
    """
    try:
        import uvicorn
    except ImportError:
        raise ImportError("uvicorn is required for --web.  Run: pip install fastapi uvicorn")

    # uvicorn needs a WebSocket implementation (websockets or wsproto) to serve
    # the dashboard's live /ws feed. Plain `pip install uvicorn` does NOT include
    # one, and uvicorn then answers the /ws upgrade with HTTP 404 - the dashboard
    # loads its initial snapshot and never updates. Detect that and say so loudly
    # rather than failing silently; uvicorn auto-selects websockets when present.
    if not _websocket_impl_available():
        print("[valkyrie] WARNING: no WebSocket library installed "
              "(websockets/wsproto). The dashboard's live feed (/ws) will return "
              "HTTP 404 and the page will NOT update in real time. "
              "Fix: pip install websockets")

    app = create_app(ctx)
    uvicorn.run(app, host=host, port=port, log_level="warning", access_log=False)


def _websocket_impl_available() -> bool:
    """True if uvicorn has a WebSocket backend it can use for /ws."""
    for mod in ("websockets", "wsproto"):
        try:
            __import__(mod)
            return True
        except ImportError:
            continue
    return False
