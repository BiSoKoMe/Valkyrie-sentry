"""FleetController — the enroll/heartbeat/list logic with no HTTP dependency.

All authentication and state transitions live here so they can be unit-tested
directly (see tests/test_fleet.py). server.py is a thin FastAPI shell that
calls these methods and maps the AuthError/result into HTTP responses.
"""

from __future__ import annotations

import time
import uuid
from typing import Optional

from .protocol import (
    AGENT_PROTOCOL_VERSION,
    EnrollmentRequest,
    EnrollmentResult,
    Heartbeat,
    hash_token,
    new_device_token,
    tokens_equal,
)
from .store import FleetStore


class AuthError(Exception):
    """Raised on any authentication/authorisation failure (maps to HTTP 401/403)."""


class FleetController:
    def __init__(self, store: FleetStore, enroll_token: str,
                 offline_after: float = 90.0) -> None:
        # enroll_token is the pre-shared secret an agent must present to join.
        # An empty enroll_token disables enrollment entirely (fail closed) —
        # the server must be configured with a real secret to accept devices.
        self._store         = store
        self._enroll_token  = enroll_token or ""
        self._offline_after = offline_after

    # ------------------------------------------------------------------
    # Enrollment
    # ------------------------------------------------------------------

    def enroll(self, req: EnrollmentRequest) -> EnrollmentResult:
        if not self._enroll_token:
            raise AuthError("enrollment disabled: server has no enroll token configured")
        if not tokens_equal(req.enroll_token, self._enroll_token):
            raise AuthError("invalid enrollment token")

        device_id = uuid.uuid4().hex
        token     = new_device_token()
        self._store.add_device(
            device_id     = device_id,
            token_hash    = hash_token(token),
            label         = req.label,
            platform      = req.platform,
            agent_version = req.agent_version,
        )
        return EnrollmentResult(device_id=device_id, device_token=token)

    # ------------------------------------------------------------------
    # Heartbeat
    # ------------------------------------------------------------------

    def heartbeat(self, device_id: str, device_token: str, hb: Heartbeat) -> dict:
        stored_hash = self._store.token_hash_for(device_id)
        if stored_hash is None:
            raise AuthError("unknown device")
        # Constant-time compare of the presented token's hash against the
        # stored hash — never compares raw tokens, never leaks timing.
        if not tokens_equal(hash_token(device_token or ""), stored_hash):
            raise AuthError("invalid device token")

        status = {
            "counts":     hb.counts,
            "categories": hb.categories,
            "components": hb.components,
        }
        self._store.record_status(device_id, status, hb.agent_version)
        # Reply carries the server's expectations so the agent can self-correct.
        return {
            "ok": True,
            "server_protocol_version": AGENT_PROTOCOL_VERSION,
            "agent_up_to_date": hb.protocol_version == AGENT_PROTOCOL_VERSION,
        }

    # ------------------------------------------------------------------
    # Read views (for the dashboard / API)
    # ------------------------------------------------------------------

    def list_devices(self) -> list[dict]:
        now = time.time()
        out = []
        for d in self._store.list_devices():
            d["online"] = (d["last_seen"] > 0
                           and (now - d["last_seen"]) <= self._offline_after)
            out.append(d)
        return out

    def get_device(self, device_id: str) -> Optional[dict]:
        d = self._store.get_device(device_id)
        if d is None:
            return None
        now = time.time()
        d["online"] = (d["last_seen"] > 0
                       and (now - d["last_seen"]) <= self._offline_after)
        return d

    def fleet_summary(self) -> dict:
        """Aggregate rollup across all devices — the top-line the console shows."""
        devices = self.list_devices()
        online = sum(1 for d in devices if d["online"])
        blocked = allowed = flagged = 0
        for d in devices:
            counts = (d.get("status") or {}).get("counts") or {}
            blocked += int(counts.get("blocked", 0))
            allowed += int(counts.get("allowed", 0))
            flagged += int(counts.get("flagged", 0))
        return {
            "devices_total":  len(devices),
            "devices_online": online,
            "blocked_24h":    blocked,
            "allowed_24h":    allowed,
            "flagged_24h":    flagged,
        }
