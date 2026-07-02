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
        yield
        # Shutdown: unregister subscriber
        if state.store is not None:
            state.store.unsubscribe(manager.broadcast_sync)

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

    @app.get("/api/stats/cleaned")
    async def get_cleaned_stats():
        if state.store is None:
            return JSONResponse({"error": "store not ready"}, status_code=503)
        return {"elements_cleaned": state.store.cleaned_count()}

    @app.get("/api/mac/status")
    async def mac_status():
        if state.mac_randomizer is None:
            return {"enabled": False, "interfaces": {}}
        return {"enabled": True, "interfaces": state.mac_randomizer.status()}

    @app.post("/api/mac/randomize")
    async def mac_randomize():
        if state.mac_randomizer is None:
            return JSONResponse({"error": "MAC randomizer not running (start with --mac-rand)"}, status_code=503)
        new_mac = state.mac_randomizer.randomize()
        return {"new_mac": new_mac, "status": "randomised"}

    @app.post("/api/mac/restore")
    async def mac_restore():
        if state.mac_randomizer is None:
            return JSONResponse({"error": "MAC randomizer not running"}, status_code=503)
        restored = state.mac_randomizer.restore()
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
