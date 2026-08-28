"""Fleet wire protocol - the exact shapes that cross the network, plus the
auth-token primitives.

WHAT CROSSES THE WIRE (and what deliberately does NOT):

  Enrollment  (agent -> server, once):
    enroll_token   pre-shared secret proving the agent is authorised to join
    label          human label for the device (operator-chosen, e.g. hostname)
    platform       OS string (e.g. "Windows-11")
    agent_version  Valkyrie version running on the device

  Heartbeat   (agent -> server, every FLEET_HEARTBEAT_INTERVAL):
    counts         integer tallies only: blocked/allowed/flagged in last 24h
    categories     tally by CATEGORY (e.g. {"tracker": 40, "malware": 3}) -
                   never the domains themselves
    components     health booleans (dns, firewall, resolver, ...)
    agent_version  running version (so the server can flag out-of-date agents)

  EXPLICITLY NEVER SENT: resolved domains, query names, process paths, URLs,
  IP addresses of visited hosts, or any per-request record. If a future
  "detailed telemetry" feature is added it MUST be opt-in per device and is
  out of scope for this protocol version.

Auth model:
  - Enrollment requires a pre-shared enroll_token (constant-time compared).
  - On success the server issues a random per-device token (returned once).
  - The server stores only sha256(token) - a DB leak never reveals a usable
    device token. Heartbeats present the raw token; the server hashes and
    constant-time compares.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from typing import Optional

# Bumped when the payload shape changes in a backwards-incompatible way so a
# server can reject or special-case mismatched agents.
AGENT_PROTOCOL_VERSION = 1


# ---------------------------------------------------------------------------
# Token primitives
# ---------------------------------------------------------------------------

def new_device_token() -> str:
    """Return a fresh, URL-safe per-device auth token (256 bits of entropy)."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Return sha256 hex of a token. Only the hash is ever persisted."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tokens_equal(a: str, b: str) -> bool:
    """Constant-time string comparison (avoids timing side-channels on auth)."""
    return hmac.compare_digest(a or "", b or "")


# ---------------------------------------------------------------------------
# Wire shapes
# ---------------------------------------------------------------------------

@dataclass
class EnrollmentRequest:
    enroll_token: str
    label: str
    platform: str = ""
    agent_version: str = ""
    protocol_version: int = AGENT_PROTOCOL_VERSION

    def to_dict(self) -> dict:
        return {
            "enroll_token":     self.enroll_token,
            "label":            self.label,
            "platform":         self.platform,
            "agent_version":    self.agent_version,
            "protocol_version": self.protocol_version,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "EnrollmentRequest":
        return cls(
            enroll_token     = str(d.get("enroll_token", "")),
            label            = str(d.get("label", "")).strip() or "unnamed-device",
            platform         = str(d.get("platform", "")),
            agent_version    = str(d.get("agent_version", "")),
            protocol_version = int(d.get("protocol_version", AGENT_PROTOCOL_VERSION)),
        )


@dataclass
class EnrollmentResult:
    device_id: str
    device_token: str          # returned exactly once; never stored raw server-side

    def to_dict(self) -> dict:
        return {"device_id": self.device_id, "device_token": self.device_token}


@dataclass
class Heartbeat:
    counts: dict = field(default_factory=dict)        # {"blocked":N,"allowed":N,"flagged":N}
    categories: dict = field(default_factory=dict)    # {"tracker":N, "malware":N, ...}
    components: dict = field(default_factory=dict)     # {"dns":True,"firewall":True,...}
    agent_version: str = ""
    protocol_version: int = AGENT_PROTOCOL_VERSION

    def to_dict(self) -> dict:
        return {
            "counts":           self.counts,
            "categories":       self.categories,
            "components":       self.components,
            "agent_version":    self.agent_version,
            "protocol_version": self.protocol_version,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Heartbeat":
        # Coerce to safe primitive shapes - a hostile/broken agent must not be
        # able to smuggle nested objects or non-int counts into the registry.
        def _int_map(x) -> dict:
            out = {}
            if isinstance(x, dict):
                for k, v in x.items():
                    try:
                        out[str(k)[:64]] = int(v)
                    except (TypeError, ValueError):
                        continue
            return out

        def _bool_map(x) -> dict:
            out = {}
            if isinstance(x, dict):
                for k, v in x.items():
                    out[str(k)[:64]] = bool(v)
            return out

        return cls(
            counts           = _int_map(d.get("counts")),
            categories       = _int_map(d.get("categories")),
            components       = _bool_map(d.get("components")),
            agent_version    = str(d.get("agent_version", ""))[:32],
            protocol_version = int(d.get("protocol_version", AGENT_PROTOCOL_VERSION)),
        )
