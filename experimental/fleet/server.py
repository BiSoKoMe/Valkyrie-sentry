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
  run_fleet_server(port=8091, enroll_token="...")            # loopback only

A fleet server genuinely does need to be reachable by the endpoints it manages,
so binding off-loopback is a legitimate deployment choice — but it must be an
explicit one. The default is 127.0.0.1 so that publishing the enrolment and
policy API to every interface is something an operator opts into deliberately,
rather than the thing that happens when the host argument is forgotten.
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
from ..updater import UpdateError
from .controller import AuthError, FleetController
from .protocol import EnrollmentRequest, Heartbeat, tokens_equal
from .store import FleetStore

_FLEET_DIR = Path(__file__).parent

try:
    from fastapi import FastAPI, Request
    from fastapi.responses import FileResponse, JSONResponse
    _FASTAPI_OK = True
except ImportError:
    _FASTAPI_OK = False


def create_fleet_app(controller: FleetController, admin_token: str = ""):
    """Build the FastAPI app around an existing controller (used by tests too).

    admin_token gates the operator-only policy-set endpoint. If empty, that
    endpoint is disabled (fail closed) — you cannot push policy without one.
    """
    if not _FASTAPI_OK:
        raise ImportError("fastapi is required for the fleet server. "
                          "Run: pip install fastapi uvicorn")

    app = FastAPI(title="Valkyrie Fleet Control Plane")

    def _bearer(request) -> str:
        h = request.headers.get("authorization", "")
        return h[7:].strip() if h.lower().startswith("bearer ") else ""

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

    @app.post("/api/agent/policy")
    async def agent_policy(request: Request):
        body = await _json(request)
        device_id    = str(body.get("device_id", ""))
        device_token = str(body.get("device_token", ""))
        try:
            bundle = controller.get_policy_for_device(device_id, device_token)
        except AuthError as exc:
            return JSONResponse({"error": str(exc)}, status_code=401)
        if bundle is None:
            return JSONResponse({"error": "no policy set for this device's org"},
                                status_code=404)
        return bundle

    @app.post("/api/policy")
    async def set_policy(request: Request):
        # Operator-only. Requires a configured admin token (fail closed) AND a
        # policy bundle whose signature verifies against the pinned policy key.
        if not admin_token or not tokens_equal(_bearer(request), admin_token):
            return JSONResponse({"error": "admin token required"}, status_code=403)
        body = await _json(request)
        org = str(body.get("org", ""))
        try:
            result = controller.set_policy(org, body.get("bundle") or {})
        except UpdateError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        return result

    @app.post("/api/agent/commands")
    async def agent_commands(request: Request):
        body = await _json(request)
        device_id    = str(body.get("device_id", ""))
        device_token = str(body.get("device_token", ""))
        try:
            cmds = controller.get_commands_for_device(device_id, device_token)
        except AuthError as exc:
            return JSONResponse({"error": str(exc)}, status_code=401)
        return {"commands": cmds}

    @app.post("/api/agent/commands/ack")
    async def agent_command_ack(request: Request):
        body = await _json(request)
        device_id    = str(body.get("device_id", ""))
        device_token = str(body.get("device_token", ""))
        try:
            return controller.ack_command(
                device_id, device_token, str(body.get("command_id", "")),
                str(body.get("status", "")), str(body.get("result", "")))
        except AuthError as exc:
            return JSONResponse({"error": str(exc)}, status_code=401)

    @app.post("/api/command")
    async def set_command(request: Request):
        # Operator-only. Same admin-token gate as policy, plus signature check.
        if not admin_token or not tokens_equal(_bearer(request), admin_token):
            return JSONResponse({"error": "admin token required"}, status_code=403)
        body = await _json(request)
        org = str(body.get("org", ""))
        try:
            result = controller.queue_command(org, body.get("bundle") or {})
        except UpdateError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        return result

    @app.get("/api/command/{command_id}")
    async def command_status(command_id: str, request: Request):
        if not admin_token or not tokens_equal(_bearer(request), admin_token):
            return JSONResponse({"error": "admin token required"}, status_code=403)
        return {"command_id": command_id, "acks": controller.command_status(command_id)}

    @app.get("/api/fleet")
    async def fleet(org: Optional[str] = None):
        return {
            "summary": controller.fleet_summary(org=org),
            "devices": controller.list_devices(org=org),
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


def _is_loopback(host: str) -> bool:
    return host in ("127.0.0.1", "::1", "localhost")


def run_fleet_server(host: str = "127.0.0.1",
                     port: int = FLEET_SERVER_PORT,
                     enroll_token: Optional[str] = None,
                     db_path: Path = FLEET_DB_PATH,
                     policy_public_key_hex: str = "",
                     admin_token: str = "",
                     allow_insecure_http: bool = False) -> None:
    """Blocking entrypoint. enroll_token falls back to the env var; if neither
    is set the server refuses to start rather than silently accept anyone.

    Enrollment/device tokens are bearer credentials, so binding a non-loopback
    host over plain HTTP would put them on the wire in cleartext. That is
    refused unless allow_insecure_http=True (which asserts TLS is terminated by
    a reverse proxy in front of this process)."""
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

    if not _is_loopback(host) and not allow_insecure_http:
        raise SystemExit(
            f"Refusing to bind {host} over plain HTTP: enrollment and device "
            f"tokens would cross the network in cleartext. Put a TLS-terminating "
            f"reverse proxy (Caddy/nginx) in front and either bind 127.0.0.1 "
            f"(proxy forwards to it) or pass --fleet-insecure-http to assert TLS "
            f"is handled upstream."
        )

    store = FleetStore(db_path)
    controller = FleetController(store, enroll_token=token,
                                 offline_after=FLEET_OFFLINE_AFTER,
                                 policy_public_key_hex=policy_public_key_hex)
    app = create_fleet_app(controller, admin_token=admin_token)
    uvicorn.run(app, host=host, port=port, log_level="warning", access_log=False)
