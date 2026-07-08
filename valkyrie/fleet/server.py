"""Fleet control-plane HTTP server (FastAPI).

Thin shell over FleetController. Agent-facing endpoints handle enroll/heartbeat;
operator-facing endpoints serve the fleet console and its JSON.

Endpoints:
  POST /api/agent/enroll      {enroll_token,label,platform,agent_version}
  POST /api/agent/heartbeat   {device_id,device_token,heartbeat}
  GET  /api/fleet             fleet summary + device list
  GET  /api/fleet/{id}        one device's detail
  GET  /                      fleet console (dashboard.html)

Run:
  from valkyrie.fleet.server import run_fleet_server
  run_fleet_server(host="0.0.0.0", port=8091, enroll_token="...")
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from ..config import (
    FLEET_DB_PATH,
    FLEET_ENROLL_TOKEN_ENV,
    FLEET_OFFLINE_AFTER,
    FLEET_SERVER_PORT,
)
from .controller import AuthError, FleetController
from .protocol import EnrollmentRequest, Heartbeat
from .store import FleetStore

_FLEET_DIR = Path(__file__).parent

try:
    from fastapi import FastAPI, Request
    from fastapi.responses import FileResponse, JSONResponse
    _FASTAPI_OK = True
except ImportError:
    _FASTAPI_OK = False


def create_fleet_app(controller: FleetController):
    """Build the FastAPI app around an existing controller (used by tests too)."""
    if not _FASTAPI_OK:
        raise ImportError("fastapi is required for the fleet server. "
                          "Run: pip install fastapi uvicorn")

    app = FastAPI(title="Valkyrie Fleet Control Plane")

    @app.post("/api/agent/enroll")
    async def enroll(request: Request):
        body = await _json(request)
        try:
            result = controller.enroll(EnrollmentRequest.from_dict(body))
        except AuthError as exc:
            return JSONResponse({"error": str(exc)}, status_code=403)
        return result.to_dict()

    @app.post("/api/agent/heartbeat")
    async def heartbeat(request: Request):
        body = await _json(request)
        device_id    = str(body.get("device_id", ""))
        device_token = str(body.get("device_token", ""))
        hb = Heartbeat.from_dict(body.get("heartbeat") or {})
        try:
            return controller.heartbeat(device_id, device_token, hb)
        except AuthError as exc:
            return JSONResponse({"error": str(exc)}, status_code=401)

    @app.get("/api/fleet")
    async def fleet():
        return {
            "summary": controller.fleet_summary(),
            "devices": controller.list_devices(),
        }

    @app.get("/api/fleet/{device_id}")
    async def fleet_device(device_id: str):
        d = controller.get_device(device_id)
        if d is None:
            return JSONResponse({"error": "unknown device"}, status_code=404)
        return d

    @app.get("/")
    async def index():
        html = _FLEET_DIR / "dashboard.html"
        if html.exists():
            return FileResponse(str(html))
        return JSONResponse({"error": "fleet dashboard not found"}, status_code=404)

    return app


async def _json(request) -> dict:
    try:
        data = await request.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def run_fleet_server(host: str = "0.0.0.0",
                     port: int = FLEET_SERVER_PORT,
                     enroll_token: Optional[str] = None,
                     db_path: Path = FLEET_DB_PATH) -> None:
    """Blocking entrypoint. enroll_token falls back to the env var; if neither
    is set the server refuses to start rather than silently accept anyone."""
    try:
        import uvicorn
    except ImportError:
        raise ImportError("uvicorn is required for the fleet server. "
                          "Run: pip install fastapi uvicorn")

    token = enroll_token or os.environ.get(FLEET_ENROLL_TOKEN_ENV, "")
    if not token:
        raise SystemExit(
            f"Refusing to start: no enrollment token. Set ${FLEET_ENROLL_TOKEN_ENV} "
            f"or pass --fleet-enroll-token so only authorised devices can join."
        )

    store = FleetStore(db_path)
    controller = FleetController(store, enroll_token=token,
                                 offline_after=FLEET_OFFLINE_AFTER)
    app = create_fleet_app(controller)
    uvicorn.run(app, host=host, port=port, log_level="warning", access_log=False)
