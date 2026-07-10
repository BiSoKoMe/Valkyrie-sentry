"""FastAPI web dashboard backend for Valkyrie.

Endpoints:
  GET  /           → serve dashboard.html
  GET  /api/stats  → aggregate stats (24h) + top blocked domains
  GET  /api/events → last 200 events
  WS   /ws         → real-time event stream (Store subscribe)

Usage (from __main__.py):
    from .web.server import state as web_state, run_server
    web_state.store      = store
    web_state.firewall   = firewall
    web_state.blocklist  = blocklist
    web_state.start_time = time.time()
    run_server(host="0.0.0.0", port=8080)   # blocks — run in daemon thread
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import subprocess
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from ..config import DATA_DIR

_WEB_DIR = Path(__file__).parent
_PROJECT_ROOT = _WEB_DIR.parent.parent   # .../valkyrie/web -> .../valkyrie -> repo root

# Module-level FastAPI imports so annotations resolve correctly.
# (from __future__ import annotations makes ws: WebSocket a lazy string;
#  FastAPI resolves it against module globals — a local import won't be found.)
try:
    from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
    from fastapi.responses import FileResponse, JSONResponse
    _FASTAPI_OK = True
except ImportError:
    _FASTAPI_OK = False


# ---------------------------------------------------------------------------
# App state (populated by __main__.py before starting the server)
# ---------------------------------------------------------------------------

class _AppState:
    store          = None      # valkyrie.store.Store
    firewall       = None      # valkyrie.firewall.FirewallManager
    blocklist      = None      # valkyrie.blocklist.BlocklistManager
    mac_randomizer = None      # valkyrie.mac_randomizer.MacRandomizer (optional)
    zero_log       = None      # valkyrie.zero_log.ZeroLogMode (optional)
    intelligence   = None      # valkyrie.intelligence.Intelligence (optional)
    self_heal      = None      # valkyrie.intelligence.SelfHealing (optional)
    edr            = None      # valkyrie.edr.EdrEngine (optional)
    start_time: float = 0.0
    dns_port: int  = 0         # actual DNS listen port (for dashboard display)
    web_port: int  = 0         # actual web dashboard port


state = _AppState()

# asyncio event loop captured inside lifespan — used to bridge sync → async
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
        """Called from sync Store-writer thread — schedules puts on async queues."""
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


def _fmt_events(raw: list) -> list:
    out = []
    for r in raw:
        ts = r.get("timestamp", "")
        if "T" in ts:
            ts = ts[11:19]
        out.append({
            "timestamp":    ts,
            "domain":       r.get("domain", ""),
            "decision":     r.get("decision", ""),
            "process_name": r.get("process_name", ""),
            "reason":       r.get("reason", ""),
            "suspicion":    r.get("suspicion", 0.0),
            "category":     r.get("raw_category", ""),
            "url":          r.get("url", ""),
        })
    return out


def _build_stats() -> dict:
    from ..service_manager import is_running_as_service

    s        = state.store.stats()
    top      = state.store.top_blocked_domains(limit=5)
    fw_count = state.firewall.count() if state.firewall else 0

    from ..multihop import MultiHopVPN
    mh_status = MultiHopVPN().status()

    zero_active = state.zero_log is not None and state.zero_log.is_active()

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
        "web_port":           state.web_port,
        "running_as_service": is_running_as_service(),
        "scanner_decisions":  state.store.scanner_decision_count(),
        "elements_cleaned":   state.store.cleaned_count(),
        "zero_log_active":    zero_active,
        "multihop_hop1_ready": mh_status["hop1_conf_exists"],
        "multihop_hop2_ready": mh_status["hop2_conf_exists"],
    }


# ---------------------------------------------------------------------------
# System control (localhost + token gated)
#
# The launcher / dashboard "Restart" and "Stop" buttons spawn PowerShell, so
# these endpoints are locked down against the two realistic attack vectors:
#   1. Other devices on the LAN — the server binds 0.0.0.0, so we require the
#      peer IP to be loopback.
#   2. Cross-site request forgery — a malicious page you visit runs in *your*
#      browser and can POST to 127.0.0.1, so a loopback check alone is not
#      enough. We additionally require a per-process secret token that only a
#      same-origin (or explicitly launcher-injected) caller can obtain, plus a
#      same-origin Origin check as defence in depth.
# ---------------------------------------------------------------------------

_CONTROL_TOKEN = secrets.token_urlsafe(24)
_CONTROL_TOKEN_FILE = DATA_DIR / "control_token.txt"
try:
    _CONTROL_TOKEN_FILE.write_text(_CONTROL_TOKEN, encoding="utf-8")
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
        return True   # curl / launcher.html (file://) — the token is the gate
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

    Same defence-in-depth as the system-control guard — loopback peer, local
    Origin, and the per-process control token — but cross-platform, since EDR
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
    start_all.ps1, so the runner must survive its parent dying — hence
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

def create_app():
    if not _FASTAPI_OK:
        raise ImportError("fastapi is required for --web.  Run: pip install fastapi uvicorn")

    @asynccontextmanager
    async def _lifespan(app: FastAPI):
        # Startup: capture loop, register live-event subscriber
        global _loop
        _loop = asyncio.get_running_loop()
        if state.store is not None:
            state.store.subscribe(manager.broadcast_sync)
        # Stream EDR incidents to dashboards over the same WebSocket.
        if state.edr is not None:
            state.edr.subscribe(manager.broadcast_sync)
        yield
        # Shutdown: unregister subscriber
        if state.store is not None:
            state.store.unsubscribe(manager.broadcast_sync)
        if state.edr is not None:
            state.edr.unsubscribe(manager.broadcast_sync)

    app = FastAPI(title="Valkyrie Dashboard", lifespan=_lifespan,
                  docs_url=None, redoc_url=None)
    # No CORSMiddleware — Starlette's CORS middleware blocks WebSocket upgrades
    # on some versions. The dashboard is served from the same origin, so CORS
    # is unnecessary and the middleware would break the /ws endpoint.

    # ── Routes ──────────────────────────────────────────────────────────

    @app.get("/", include_in_schema=False)
    async def serve_dashboard():
        return FileResponse(_WEB_DIR / "dashboard.html", media_type="text/html")

    @app.get("/api/stats")
    async def get_stats():
        if state.store is None:
            return JSONResponse({"error": "store not ready"}, status_code=503)
        return _build_stats()

    @app.get("/api/events")
    async def get_events():
        if state.store is None:
            return JSONResponse({"error": "store not ready"}, status_code=503)
        return _fmt_events(state.store.recent_events(limit=200))

    @app.get("/api/telemetry/status")
    async def telemetry_status():
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
    async def telemetry_kill():
        from ..telemetry_killer import TelemetryKiller
        results = TelemetryKiller().kill()
        if not results:
            return JSONResponse({"error": "admin rights required"}, status_code=403)
        return {"results": results}

    @app.post("/api/telemetry/restore")
    async def telemetry_restore():
        from ..telemetry_killer import TelemetryKiller
        results = TelemetryKiller().restore()
        if not results:
            return JSONResponse({"error": "admin rights required or no backup found"}, status_code=403)
        return {"results": results}

    @app.get("/api/intelligence")
    async def intelligence_status():
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

    @app.get("/api/stats/cleaned")
    async def get_cleaned_stats():
        if state.store is None:
            return JSONResponse({"error": "store not ready"}, status_code=503)
        return {"elements_cleaned": state.store.cleaned_count()}

    @app.get("/api/mac/status")
    async def mac_status():
        mac = _get_mac_randomizer()
        return {"enabled": True, "interfaces": mac.status()}

    @app.post("/api/mac/randomize")
    async def mac_randomize():
        mac = _get_mac_randomizer()
        new_mac = mac.randomize()
        if not new_mac:
            return JSONResponse(
                {"error": mac.last_error or "MAC randomisation failed"},
                status_code=500,
            )
        return {"new_mac": new_mac, "status": "randomised"}

    @app.post("/api/mac/restore")
    async def mac_restore():
        mac = _get_mac_randomizer()
        restored = mac.restore()
        if not restored:
            return JSONResponse(
                {"error": "No backup found to restore (has a MAC ever been randomised?)"},
                status_code=404,
            )
        return {"restored_mac": restored, "status": "restored"}

    @app.get("/api/vpn/status")
    async def vpn_status():
        from ..multihop import MultiHopVPN
        return MultiHopVPN().status()

    @app.get("/api/zero-log/status")
    async def zero_log_status():
        if state.zero_log is None:
            return {"active": False, "mode": "disk",
                    "session_events": 0, "disk_writes": "enabled",
                    "integrity": "verified", "tampered_files": []}
        return state.zero_log.status()

    # ── System control (launcher / dashboard buttons) ───────────────────
    @app.get("/api/system/token")
    async def system_token(request: Request):
        # Same-origin loopback only. Lets the dashboard fetch the control
        # token it needs for restart/stop. A cross-origin page cannot read
        # this response (no CORS headers) and fails the origin check anyway.
        if not _peer_is_local(request) or not _origin_is_local(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        return {"token": _CONTROL_TOKEN, "web_port": int(state.web_port or 0)}

    @app.post("/api/system/restart")
    async def system_restart(request: Request):
        guard = _control_guard(request)
        if guard is not None:
            return guard
        stop  = _PROJECT_ROOT / "stop_all.ps1"
        start = _PROJECT_ROOT / "start_all.ps1"
        _run_detached_ps(f"& '{stop}'; Start-Sleep -Seconds 3; & '{start}'")
        return {"status": "restarting"}

    @app.post("/api/system/shutdown")
    async def system_shutdown(request: Request):
        guard = _control_guard(request)
        if guard is not None:
            return guard
        stop = _PROJECT_ROOT / "stop_all.ps1"
        _run_detached_ps(f"& '{stop}'")
        return {"status": "stopping"}

    # ── EDR / SOC layer ─────────────────────────────────────────────────
    @app.get("/edr", include_in_schema=False)
    async def serve_edr_console():
        return FileResponse(_WEB_DIR / "edr.html", media_type="text/html")

    @app.get("/api/edr/stats")
    async def edr_stats():
        if state.edr is None:
            return {"enabled": False}
        s = state.edr.stats(); s["enabled"] = True
        return s

    @app.get("/api/edr/incidents")
    async def edr_incidents(status: Optional[str] = None,
                            severity: Optional[str] = None):
        if state.edr is None:
            return JSONResponse({"error": "EDR not enabled"}, status_code=503)
        return state.edr.list_incidents(status=status, severity=severity, limit=200)

    @app.get("/api/edr/incidents/{incident_id}")
    async def edr_incident(incident_id: str):
        if state.edr is None:
            return JSONResponse({"error": "EDR not enabled"}, status_code=503)
        inc = state.edr.get_incident(incident_id)
        if inc is None:
            return JSONResponse({"error": "unknown incident"}, status_code=404)
        return inc

    @app.post("/api/edr/incidents/{incident_id}/status")
    async def edr_incident_status(incident_id: str, request: Request):
        if state.edr is None:
            return JSONResponse({"error": "EDR not enabled"}, status_code=503)
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
            return JSONResponse({"error": "EDR not enabled"}, status_code=503)
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
            return JSONResponse({"error": "EDR not enabled"}, status_code=503)
        guard = _edr_guard(request)
        if guard is not None:
            return guard
        body = await _safe_json(request)
        action = str(body.get("action", ""))
        if not action:
            return JSONResponse({"error": "action is required"}, status_code=400)
        # dry_run defaults to True — a real action must be explicitly requested.
        dry_run = bool(body.get("dry_run", True))
        return state.edr.respond(
            action, str(body.get("target", "")), dry_run=dry_run,
            operator="dashboard", incident_id=str(body.get("incident_id", "")))

    @app.get("/api/edr/hunt/saved")
    async def edr_saved_hunts():
        if state.edr is None:
            return JSONResponse({"error": "EDR not enabled"}, status_code=503)
        return {"hunts": state.edr.saved_hunts(),
                "facets": state.edr.hunt_facets(24)}

    @app.post("/api/edr/hunt")
    async def edr_hunt(request: Request):
        if state.edr is None:
            return JSONResponse({"error": "EDR not enabled"}, status_code=503)
        body = await _safe_json(request)
        limit = int(body.get("limit", 200) or 200)
        if body.get("saved"):
            return state.edr.run_saved_hunt(str(body["saved"]), limit)
        return state.edr.hunt(body.get("filters") or {}, limit)

    @app.get("/api/edr/plugins")
    async def edr_plugins():
        if state.edr is None:
            return JSONResponse({"error": "EDR not enabled"}, status_code=503)
        return state.edr.plugins()

    @app.websocket("/ws")
    async def websocket_endpoint(ws: WebSocket):
        await ws.accept()
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        manager.add(ws, q)

        try:
            # ── Initial payload (isolated try — failure must NOT close the WS) ──
            if state.store is not None:
                try:
                    init = json.dumps({
                        "type":   "init",
                        "stats":  _build_stats(),
                        "events": _fmt_events(state.store.recent_events(limit=50)),
                    })
                    await ws.send_text(init)
                except Exception:
                    pass   # init failed but keep the connection alive

            # ── Relay loop ───────────────────────────────────────────────────
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

def run_server(host: str = "0.0.0.0", port: int = 8080) -> None:
    """Block the calling thread running the uvicorn server."""
    try:
        import uvicorn
    except ImportError:
        raise ImportError("uvicorn is required for --web.  Run: pip install fastapi uvicorn")

    app = create_app()
    uvicorn.run(app, host=host, port=port, log_level="warning", access_log=False)
