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

# The dashboard reads its services from an AppContext. `__main__` (the
# composition root) builds one, wires the services in, and injects it via
# create_app(ctx=...)/run_server(ctx=...). This module-level default keeps the
# server importable and testable on its own (tests set fields on it directly).
state = AppContext()

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


def _build_stats() -> dict:
    from ..service_manager import is_running_as_service

    s        = state.store.stats()
    top      = state.store.top_blocked_domains(limit=5)
    fw_count = state.firewall.count() if state.firewall else 0

    from ..multihop import MultiHopVPN
    mh_status = MultiHopVPN().status()

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
        "web_port":           state.web_port,
        "protection_healthy": healthy,
        "meeting_active":     meeting.get("active", False),
        "meeting_minutes":    meeting.get("duration_minutes", 0),
        "running_as_service": is_running_as_service(),
        "scanner_decisions":  state.store.scanner_decision_count(),
        # `elements_cleaned` counts page_clean rows, which ONLY the TLS
        # inspection addon ever writes. TLS inspection is off by default, so
        # this reported a hard 0 forever on a default install while the UI
        # rendered it as a live counter — a number that cannot move reads as
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

log = logging.getLogger("valkyrie.web")

_CONTROL_TOKEN = secrets.token_urlsafe(24)
_CONTROL_TOKEN_FILE = DATA_DIR / "control_token.txt"
try:
    _CONTROL_TOKEN_FILE.write_text(_CONTROL_TOKEN, encoding="utf-8")
    # This file IS the credential for every state-changing route — isolate the
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

def create_app(ctx: Optional[AppContext] = None):
    if not _FASTAPI_OK:
        raise ImportError("fastapi is required for --web.  Run: pip install fastapi uvicorn")

    # Dependency injection: when the composition root passes a context, adopt it
    # as the module-global the routes read. Called with no ctx (e.g. in tests),
    # the existing module-global `state` is used unchanged.
    if ctx is not None:
        global state
        state = ctx

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

    @app.middleware("http")
    async def _offloopback_api_guard(request, call_next):
        # The dashboard's data endpoints expose live DNS/browsing history and
        # system status. When the server is bound off-loopback (the explicit
        # --web-host 0.0.0.0 opt-in for router/LAN viewing), every /api/* call
        # from a non-loopback peer must present the control token. Loopback
        # callers — the local dashboard on the same machine — are unaffected, so
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

    @app.get("/api/compliance/report")
    async def compliance_report(request: Request, hours: int = 720,
                                format: str = "json"):
        # Aggregates operational posture — token-gated off loopback like all
        # data-revealing endpoints (enforced by the global guard middleware).
        from ..compliance import ComplianceReporter, render_markdown
        report = ComplianceReporter(state).generate(period_hours=max(1, hours))
        if format == "md":
            from fastapi.responses import PlainTextResponse
            return PlainTextResponse(render_markdown(report),
                                     media_type="text/markdown")
        return report

    @app.get("/api/edr/playbooks/status")
    async def playbooks_status():
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
        reg = state.registry
        return {"enabled": True, "overall": reg.overall(),
                "components": reg.snapshot()}

    @app.post("/api/components/{name}/restart")
    async def component_restart(name: str, request: Request):
        # Restarting a subsystem is state-changing — token-gated off loopback.
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
    async def siem_status():
        if state.siem is None:
            return {"enabled": False}
        info = state.siem.status()
        info["enabled"] = True
        return info

    @app.get("/api/intel/status")
    async def threat_intel_status():
        if state.threat_intel is None:
            return {"enabled": False}
        info = state.threat_intel.status()
        info["enabled"] = True
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

    @app.get("/api/fingerprint/status")
    async def fingerprint_status():
        """TCP/IP fingerprint spoof state (TTL / TCP-timestamps normalisation)."""
        try:
            from ..fingerprint import NetworkFingerprint
            return NetworkFingerprint().status()
        except Exception as exc:      # noqa: BLE001 — status must never 500
            return {"supported": False, "normalized": False, "error": str(exc)}

    @app.get("/api/profile")
    async def profile_get():
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

    @app.get("/api/decoys/status")
    async def decoys_status():
        """How many decoy honeytokens are live (0 = not deployed)."""
        from .. import decoys as _dm
        mgr = getattr(_dm, "_ACTIVE", None)
        return {"active": mgr is not None,
                "count": len(mgr.tokens()) if mgr else 0,
                "paths": mgr.paths()[:20] if mgr else []}

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

    # ── Ransomware Shield ────────────────────────────────────────────────
    @app.get("/api/ransomware/status")
    async def ransomware_status():
        rs = getattr(state, "ransomware_shield", None)
        if rs is None:
            return {"enabled": False}
        return rs.status()

    @app.post("/api/ransomware/self-test")
    async def ransomware_self_test(request: Request):
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

    # ── AMSI content scanning ────────────────────────────────────────────
    @app.get("/api/amsi/status")
    async def amsi_status():
        sc = getattr(state, "amsi", None)
        if sc is None:
            return {"enabled": False}
        return sc.status()

    @app.post("/api/amsi/self-test")
    async def amsi_self_test(request: Request):
        # Token-gated: a working provider records a detection in its own
        # history when it convicts the marker, so this must not be triggerable
        # by a remote page. Returns a tri-state conclusion — a non-conviction
        # is reported as inconclusive, never as a pass or a failure.
        guard = _control_guard(request)
        if guard is not None:
            return guard
        sc = getattr(state, "amsi", None)
        if sc is None:
            return JSONResponse({"error": "AMSI scanning not active"}, status_code=503)
        return sc.self_test()

    @app.post("/api/edr/incidents/{incident_id}/triage")
    async def collect_triage(incident_id: str, request: Request):
        # Collects live host state into a local evidence bundle — state-
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

    # ── Endpoint telemetry visibility ────────────────────────────────────
    @app.get("/api/telemetry/endpoint")
    async def endpoint_telemetry_status():
        pc = getattr(state, "persistence_collector", None)
        return {
            "process_collector":    getattr(state, "process_collector", None) is not None,
            "network_collector":    getattr(state, "network_collector", None) is not None,
            "persistence_collector": pc is not None,
            "persistence_running":  bool(pc and pc.is_running()),
        }

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

    # ── Protection heartbeat (read-only) ────────────────────────────────
    @app.get("/api/health")
    async def get_health():
        if state.heartbeat is None:
            return {"healthy": True, "monitored": False}
        try:
            st = state.heartbeat.status()
            st["monitored"] = True
            return st
        except Exception:
            return {"healthy": True, "monitored": False}

    # ── Meeting Mode (kill switch) ──────────────────────────────────────
    @app.get("/api/meeting/status")
    async def meeting_status():
        from ..meeting_mode import MeetingMode
        return MeetingMode().status()

    @app.post("/api/meeting/start")
    async def meeting_start(request: Request):
        guard = _control_guard(request)
        if guard is not None:
            return guard
        from ..meeting_mode import MeetingMode
        return MeetingMode().activate()

    @app.post("/api/meeting/stop")
    async def meeting_stop(request: Request):
        guard = _control_guard(request)
        if guard is not None:
            return guard
        from ..meeting_mode import MeetingMode
        return MeetingMode().deactivate()

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

    @app.get("/api/sensors/status")
    async def sensors_status():
        """Real-time sensor host health + metrics (observability for the
        SensorManager: per-sensor state, dedup/backpressure drops, restarts)."""
        sm = getattr(state, "sensor_manager", None)
        if sm is None:
            return {"enabled": False}
        s = sm.stats(); s["enabled"] = True
        return s

    @app.get("/api/edr/incidents/{incident_id}")
    async def edr_incident(incident_id: str):
        if state.edr is None:
            return JSONResponse({"error": "EDR not enabled"}, status_code=503)
        inc = state.edr.get_incident(incident_id)
        if inc is None:
            return JSONResponse({"error": "unknown incident"}, status_code=404)
        return inc

    @app.get("/api/edr/incidents/{incident_id}/decision")
    async def edr_incident_decision(incident_id: str):
        """The recommended graded action (allow/alert/deceive/block/contain) for
        an incident, under the current risk profile, with a plain-language reason
        and user message. Deterministic — the explainable 'why' behind response."""
        if state.edr is None:
            return JSONResponse({"error": "EDR not enabled"}, status_code=503)
        inc = state.edr.get_incident(incident_id)
        if inc is None:
            return JSONResponse({"error": "unknown incident"}, status_code=404)
        from ..decision import decide, signal_from_incident
        from ..profiles import get_profile
        dets = inc.get("detections") or [inc]
        sig = signal_from_incident(dets[0])
        return decide(sig, get_profile()).to_dict()

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
        # The live event stream is the single most sensitive surface — real-time
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

def run_server(host: str = WEB_HOST, port: int = WEB_PORT,
               ctx: Optional[AppContext] = None) -> None:
    """Block the calling thread running the uvicorn server.

    The host default is LOOPBACK, not 0.0.0.0. Every real caller passes an
    explicit host (``__main__`` uses ``--web-host``, defaulting to WEB_HOST and
    warning loudly when it is off-loopback), so the old ``0.0.0.0`` default was
    never actually reached — but it was a live footgun: this app exposes the
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
    # one, and uvicorn then answers the /ws upgrade with HTTP 404 — the dashboard
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
