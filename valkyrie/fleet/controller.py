"""FleetController — the enroll/heartbeat/list logic with no HTTP dependency.

All authentication and state transitions live here so they can be unit-tested
directly (see tests/test_fleet.py). server.py is a thin FastAPI shell that
calls these methods and maps the AuthError/result into HTTP responses.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Optional, Union

from ..updater import UpdateError
from .policy import SignedPolicy, verify_signed_policy
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
    def __init__(self, store: FleetStore,
                 enroll_token: Union[str, dict, None] = None,
                 offline_after: float = 90.0,
                 policy_public_key_hex: str = "") -> None:
        """enroll_token accepts either:
          - a single string (single-tenant; all devices land in org "")
          - a dict {token: org} for multi-tenant use, where the org a device
            belongs to is decided SERVER-SIDE by which token it presented —
            a device can never self-select its org.
        An empty/None enroll_token disables enrollment (fail closed).

        policy_public_key_hex pins the Ed25519 key that signed policies must
        verify against before the server will accept set_policy() input.
        """
        self._store         = store
        self._offline_after = offline_after
        self._policy_pubkey = policy_public_key_hex or ""
        if isinstance(enroll_token, dict):
            self._enroll_tokens = {str(k): str(v) for k, v in enroll_token.items() if k}
        elif enroll_token:
            self._enroll_tokens = {str(enroll_token): ""}
        else:
            self._enroll_tokens = {}

    # ------------------------------------------------------------------
    # Enrollment
    # ------------------------------------------------------------------

    def _org_for_enroll_token(self, presented: str) -> Optional[str]:
        """Return the org for a presented enroll token via constant-time
        comparison against every configured token, or None if no match.
        Compares against all tokens (no early return) so response time does
        not reveal which token, if any, matched."""
        matched_org: Optional[str] = None
        for token, org in self._enroll_tokens.items():
            if tokens_equal(presented, token):
                matched_org = org
        return matched_org

    def enroll(self, req: EnrollmentRequest) -> EnrollmentResult:
        if not self._enroll_tokens:
            raise AuthError("enrollment disabled: server has no enroll token configured")
        org = self._org_for_enroll_token(req.enroll_token)
        if org is None:
            raise AuthError("invalid enrollment token")

        device_id = uuid.uuid4().hex
        token     = new_device_token()
        self._store.add_device(
            device_id     = device_id,
            token_hash    = hash_token(token),
            label         = req.label,
            platform      = req.platform,
            agent_version = req.agent_version,
            org           = org,
        )
        return EnrollmentResult(device_id=device_id, device_token=token)

    # ------------------------------------------------------------------
    # Heartbeat
    # ------------------------------------------------------------------

    def _authenticate(self, device_id: str, device_token: str) -> None:
        """Raise AuthError unless the device token matches. Central so every
        device-authenticated endpoint uses identical constant-time logic."""
        stored_hash = self._store.token_hash_for(device_id)
        if stored_hash is None:
            raise AuthError("unknown device")
        # Constant-time compare of the presented token's hash against the
        # stored hash — never compares raw tokens, never leaks timing.
        if not tokens_equal(hash_token(device_token or ""), stored_hash):
            raise AuthError("invalid device token")

    def heartbeat(self, device_id: str, device_token: str, hb: Heartbeat) -> dict:
        self._authenticate(device_id, device_token)

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

    def list_devices(self, org: Optional[str] = None) -> list[dict]:
        """List devices. org=None -> all tenants (operator/global view);
        org="acme" -> only that tenant's devices (scoped console)."""
        now = time.time()
        out = []
        for d in self._store.list_devices(org=org):
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

    def fleet_summary(self, org: Optional[str] = None) -> dict:
        """Aggregate rollup — the top-line the console shows. Scoped by org
        when given."""
        devices = self.list_devices(org=org)
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

    # ------------------------------------------------------------------
    # Policy distribution
    # ------------------------------------------------------------------

    def set_policy(self, org: str, bundle: dict) -> dict:
        """Operator-side: store a signed policy bundle for an org. The bundle's
        signature is verified against the pinned policy key BEFORE it is stored,
        so the server never persists (and therefore never serves) an unsigned
        or tampered policy. Raises UpdateError on any verification failure."""
        if not self._policy_pubkey:
            raise UpdateError("server has no policy public key configured — "
                              "refusing to accept any policy")
        sp = SignedPolicy.from_dict(bundle)
        verify_signed_policy(sp, self._policy_pubkey)   # raises if bad
        self._store.set_policy(org or "", json.dumps(sp.to_dict()))
        return {"ok": True, "org": org or "", "version": sp.policy.version}

    def get_policy_for_device(self, device_id: str, device_token: str) -> Optional[dict]:
        """Agent-side: authenticate the device, then return the signed policy
        bundle for that device's org (or None if none set). The agent verifies
        the signature again locally before applying — defence in depth."""
        self._authenticate(device_id, device_token)
        org = self._store.org_for(device_id) or ""
        raw = self._store.get_policy(org)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            return None
