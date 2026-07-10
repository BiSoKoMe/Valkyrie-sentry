"""Signed remote-response commands — the operator→device control channel.

This is the "R" in EDR extended across the fleet. An operator issues a response
action (block a domain, kill a process, network-isolate an endpoint) and signs
it with the fleet's Ed25519 key. Agents pull pending commands, verify the
signature against the pinned public key, run the action through the LOCAL
:class:`valkyrie.edr.ResponseManager`, and acknowledge the result.

Security properties (identical in spirit to the signed-policy channel):
  - Authenticity: a command runs only if Ed25519-verified against the pinned
    key. An unsigned or wrong-key command is refused (fail-closed).
  - Anti-replay: every command carries a unique id (nonce); the server tracks
    which device has acked which command, so a command runs at most once per
    device and a captured command can't be replayed.
  - Bounded blast radius: only a fixed allow-list of actions can be encoded,
    and a command may target one device (`device_id`) or a whole org.

Privacy note: this is *control* flowing server→device, not telemetry flowing
device→server. The ack reports action status/result for a target the operator
*already chose and sent* — it never carries the device's browsing history, so
the fleet privacy invariant is preserved.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field

from ..updater import UpdateError, verify_ed25519

# The only actions a remote command may request. Kept in lock-step with the
# built-in responders so a command can never smuggle an arbitrary action.
ALLOWED_ACTIONS = frozenset({
    "block_domain", "unblock_domain",
    "kill_process", "isolate_host", "release_isolation",
})


def new_command_id() -> str:
    """Fresh unique command nonce (anti-replay)."""
    return "cmd_" + secrets.token_urlsafe(18)


@dataclass
class ResponseCommand:
    action:    str
    target:    str = ""
    device_id: str = ""                         # "" = every device in the org
    id:        str = field(default_factory=new_command_id)
    issued_at: float = field(default_factory=lambda: time.time())

    def canonical_bytes(self) -> bytes:
        """Deterministic bytes the signature covers (sorted keys, no spaces)."""
        return json.dumps({
            "id":        self.id,
            "action":    self.action,
            "target":    self.target,
            "device_id": self.device_id,
            "issued_at": round(float(self.issued_at), 3),
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_dict(self) -> dict:
        return {
            "id":        self.id,
            "action":    self.action,
            "target":    self.target,
            "device_id": self.device_id,
            "issued_at": round(float(self.issued_at), 3),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ResponseCommand":
        if not isinstance(d, dict):
            raise UpdateError("command is not an object")
        action = str(d.get("action", ""))
        if action not in ALLOWED_ACTIONS:
            raise UpdateError(f"command action not allowed: {action!r}")
        target = str(d.get("target", ""))
        # Bare hostname / pid / empty only — no shell/URL/whitespace payloads.
        if target and not all(c.isalnum() or c in ".-_*:" for c in target):
            raise UpdateError("command target has illegal characters")
        return cls(
            action    = action,
            target    = target,
            device_id = str(d.get("device_id", "")),
            id        = str(d.get("id") or new_command_id()),
            issued_at = float(d.get("issued_at", time.time())),
        )


@dataclass
class SignedCommand:
    command:       ResponseCommand
    signature_hex: str

    def to_dict(self) -> dict:
        return {"command": self.command.to_dict(), "signature": self.signature_hex}

    @classmethod
    def from_dict(cls, d: dict) -> "SignedCommand":
        if not isinstance(d, dict) or "command" not in d:
            raise UpdateError("malformed signed-command bundle")
        return cls(
            command       = ResponseCommand.from_dict(d.get("command") or {}),
            signature_hex = str(d.get("signature", "")),
        )


def sign_command(command: ResponseCommand, private_key) -> SignedCommand:
    """Sign a command with an Ed25519 private key (operator side / tests)."""
    sig = private_key.sign(command.canonical_bytes())
    return SignedCommand(command=command, signature_hex=sig.hex())


def verify_signed_command(bundle: SignedCommand, public_key_hex: str) -> ResponseCommand:
    """Return the verified command or raise UpdateError. Fail-closed."""
    try:
        sig = bytes.fromhex(bundle.signature_hex)
    except ValueError as exc:
        raise UpdateError(f"command signature is not valid hex: {exc}")
    verify_ed25519(bundle.command.canonical_bytes(), sig, public_key_hex)
    return bundle.command
