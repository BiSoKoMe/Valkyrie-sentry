"""Central protection policy - signed, versioned, pushed to the fleet.

This is the "protect clients" half of the control plane: an operator defines a
policy (extra domains to block, domains to always allow, a monotonic version)
and signs it with the fleet's Ed25519 policy key. Agents pull the signed bundle,
verify it against a pinned public key, and apply it ONLY if it is both
authentic and newer than what they've already applied.

Security properties:
  - Authenticity: a policy is applied only if Ed25519-verified against the
    pinned public key (reuses valkyrie.updater.verify_ed25519). An unsigned or
    wrong-key policy is refused (fail-closed).
  - Anti-rollback: agents track the last applied version and never apply an
    equal or lower version, so a captured older (signed) bundle can't be
    replayed to downgrade protection.
  - No code execution: a policy is data (domain lists), never scripts. Applying
    it only changes block/allow sets - it cannot run commands on the device.

The private policy key never ships; only the public key is pinned on agents.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from ..updater import UpdateError, verify_ed25519


@dataclass
class Policy:
    version: int                                   # monotonic; higher = newer
    block_domains: list = field(default_factory=list)
    allow_domains: list = field(default_factory=list)
    notes: str = ""

    def canonical_bytes(self) -> bytes:
        """Deterministic bytes the signature is computed over (sorted domains,
        sorted keys, no whitespace) so signer and verifier agree exactly."""
        return json.dumps(
            {
                "version":       int(self.version),
                "block_domains": sorted(str(d).lower() for d in self.block_domains),
                "allow_domains": sorted(str(d).lower() for d in self.allow_domains),
                "notes":         self.notes,
            },
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")

    def to_dict(self) -> dict:
        return {
            "version":       int(self.version),
            "block_domains": [str(d).lower() for d in self.block_domains],
            "allow_domains": [str(d).lower() for d in self.allow_domains],
            "notes":         self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Policy":
        if not isinstance(d, dict):
            raise UpdateError("policy is not an object")
        try:
            version = int(d["version"])
        except (KeyError, TypeError, ValueError) as exc:
            raise UpdateError(f"policy missing/invalid version: {exc}")

        def _domlist(x) -> list:
            if not isinstance(x, list):
                return []
            out = []
            for item in x:
                s = str(item).strip().lower()
                # Reject anything that isn't a bare hostname - a policy must not
                # be able to carry shell/URL/whitespace payloads into local
                # block/allow sets.
                if s and all(c.isalnum() or c in ".-_" for c in s):
                    out.append(s)
            return out

        return cls(
            version       = version,
            block_domains = _domlist(d.get("block_domains")),
            allow_domains = _domlist(d.get("allow_domains")),
            notes         = str(d.get("notes", ""))[:500],
        )


@dataclass
class SignedPolicy:
    """A policy plus its detached Ed25519 signature (hex). This is what the
    server serves and the agent fetches."""
    policy: Policy
    signature_hex: str

    def to_dict(self) -> dict:
        return {"policy": self.policy.to_dict(), "signature": self.signature_hex}

    @classmethod
    def from_dict(cls, d: dict) -> "SignedPolicy":
        if not isinstance(d, dict) or "policy" not in d:
            raise UpdateError("malformed signed-policy bundle")
        return cls(
            policy        = Policy.from_dict(d.get("policy") or {}),
            signature_hex = str(d.get("signature", "")),
        )


def sign_policy(policy: Policy, private_key) -> SignedPolicy:
    """Sign a policy with an Ed25519 private key (offline/operator side; also
    used by tests). `private_key` is a cryptography Ed25519PrivateKey."""
    sig = private_key.sign(policy.canonical_bytes())
    return SignedPolicy(policy=policy, signature_hex=sig.hex())


def verify_signed_policy(bundle: SignedPolicy, public_key_hex: str) -> Policy:
    """Return the verified Policy or raise UpdateError. Fail-closed."""
    try:
        sig = bytes.fromhex(bundle.signature_hex)
    except ValueError as exc:
        raise UpdateError(f"policy signature is not valid hex: {exc}")
    verify_ed25519(bundle.policy.canonical_bytes(), sig, public_key_hex)
    return bundle.policy
