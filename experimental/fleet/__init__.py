"""Valkyrie fleet control plane - multi-device management.

Turns Valkyrie from a single-machine tool into a device *agent* that reports
to a central *control plane* server, so one operator can protect and monitor
many machines from one place.

Design principle - privacy-preserving by construction:
  The agent reports STATUS METADATA (component health, block/allow counts,
  category tallies, agent version) and NEVER raw domains or traffic. The
  server therefore never accumulates a browsing-history honeypot. This is the
  one property that keeps Valkyrie's local-first privacy story intact even
  once devices report to a shared server. See protocol.py for the exact
  payload shape and what is explicitly excluded.

Modules:
  protocol   - wire shapes (enrollment, heartbeat) + auth token helpers
  store      - server-side SQLite device registry (stores token HASHES only)
  controller - pure enroll/heartbeat/list logic (no HTTP; fully unit-testable)
  server     - FastAPI app wrapping the controller + fleet dashboard
  agent      - device-side enroll + heartbeat loop
"""

from .protocol import (
    AGENT_PROTOCOL_VERSION,
    EnrollmentRequest,
    EnrollmentResult,
    Heartbeat,
    hash_token,
    new_device_token,
    tokens_equal,
)

__all__ = [
    "AGENT_PROTOCOL_VERSION",
    "EnrollmentRequest",
    "EnrollmentResult",
    "Heartbeat",
    "hash_token",
    "new_device_token",
    "tokens_equal",
]
