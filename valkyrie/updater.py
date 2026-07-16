"""Signed update verification — the security-critical half of auto-update.

An update channel is the single most dangerous feature you can add to security
software: if an attacker can push you an "update", they own every device that
trusts the channel. So this module does the ONE thing that has to be
bulletproof — cryptographically verify that an update manifest was signed by
the holder of the Valkyrie release private key — and deliberately does NOT
auto-execute anything. Applying an update (running an installer, swapping
files) stays a separate, explicitly-gated step; this module only ever answers
"is this update authentic and intact?".

Threat model this defends against:
  - A compromised/MITM'd update server serving a malicious manifest or binary.
  - A tampered download (wrong bytes) even from an authentic manifest.
  - A rollback/downgrade attempt (optional, via `allow_downgrade=False`).

What it intentionally does NOT do (must stay human/operator-gated):
  - Download-and-run. Verify first, then a human decides to apply.

Signing (offline, on a machine that has the private key — never shipped):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sig = priv.sign(canonical_manifest_bytes)   # detached signature over the JSON

The public key ships with the client (RELEASE_PUBLIC_KEY_HEX below / config);
the private key never leaves the release signer.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Optional


# Placeholder release public key (Ed25519, 32-byte hex). Replace at release
# time with the real public key whose private half is held offline by the
# signer. A blank/placeholder key makes verify_manifest() refuse everything
# (fail closed) rather than accept unsigned updates.
RELEASE_PUBLIC_KEY_HEX = ""


class UpdateError(Exception):
    """Any verification failure — signature, hash, or shape."""


@dataclass
class UpdateManifest:
    version: str
    url: str
    sha256: str            # expected hash of the downloaded artifact
    notes: str = ""

    def canonical_bytes(self) -> bytes:
        """Deterministic byte encoding that the signature is computed over.

        Sorted keys + no whitespace so the signer and verifier hash exactly the
        same bytes regardless of dict ordering or formatting on the wire.
        """
        return json.dumps(
            {"version": self.version, "url": self.url,
             "sha256": self.sha256, "notes": self.notes},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def from_dict(cls, d: dict) -> "UpdateManifest":
        try:
            return cls(
                version = str(d["version"]),
                url     = str(d["url"]),
                sha256  = str(d["sha256"]).lower(),
                notes   = str(d.get("notes", "")),
            )
        except (KeyError, TypeError) as exc:
            raise UpdateError(f"malformed manifest: {exc}")


# ---------------------------------------------------------------------------
# Version comparison (simple dotted-int semver)
# ---------------------------------------------------------------------------

def _parse_version(v: str) -> tuple[int, ...]:
    parts = []
    for chunk in str(v).strip().split("."):
        num = ""
        for ch in chunk:
            if ch.isdigit():
                num += ch
            else:
                break
        parts.append(int(num) if num else 0)
    return tuple(parts) or (0,)


def is_newer(candidate: str, current: str) -> bool:
    """True if `candidate` is a strictly higher version than `current`."""
    a, b = _parse_version(candidate), _parse_version(current)
    n = max(len(a), len(b))
    a += (0,) * (n - len(a))
    b += (0,) * (n - len(b))
    return a > b


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_ed25519(data: bytes, signature: bytes, public_key_hex: str) -> None:
    """Raise UpdateError unless `signature` is a valid Ed25519 signature over
    `data` for `public_key_hex`. Shared by manifest and policy verification.

    Fail-closed: a blank public key or a missing `cryptography` package raises
    rather than silently accepting.
    """
    key_hex = (public_key_hex or "").strip()
    if not key_hex:
        raise UpdateError("no public key configured — refusing to trust the payload")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError as exc:
        raise UpdateError("cannot verify signature: 'cryptography' is not installed") from exc
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))
    except ValueError as exc:
        raise UpdateError(f"public key is not valid hex/length: {exc}")
    try:
        pub.verify(signature, data)
    except InvalidSignature:
        raise UpdateError("signature does not match payload (untrusted or tampered)")


def verify_manifest(manifest: UpdateManifest, signature: bytes,
                    public_key_hex: Optional[str] = None) -> None:
    """Raise UpdateError unless `signature` is a valid Ed25519 signature over
    the manifest's canonical bytes for the configured release public key.
    """
    key_hex = (public_key_hex if public_key_hex is not None
               else RELEASE_PUBLIC_KEY_HEX)
    if not (key_hex or "").strip():
        raise UpdateError(
            "no release public key configured — refusing to trust any update "
            "(set RELEASE_PUBLIC_KEY_HEX to the real signing key)")
    verify_ed25519(manifest.canonical_bytes(), signature, key_hex)


def verify_artifact(data: bytes, expected_sha256: str) -> None:
    """Raise UpdateError unless `data` hashes to `expected_sha256`."""
    got = hashlib.sha256(data).hexdigest()
    if not _consteq(got, str(expected_sha256).lower()):
        raise UpdateError(
            f"artifact hash mismatch: expected {expected_sha256}, got {got}")


def check_update(current_version: str, manifest: UpdateManifest, signature: bytes,
                 public_key_hex: Optional[str] = None,
                 allow_downgrade: bool = False) -> dict:
    """Full gate: verify signature, then decide whether it's an upgrade.

    Returns {"update_available": bool, "version": str, "verified": True}.
    Raises UpdateError if the signature is invalid (never reports an
    unverified manifest as available).
    """
    verify_manifest(manifest, signature, public_key_hex)  # raises if bad
    newer = is_newer(manifest.version, current_version)
    available = newer or (allow_downgrade and manifest.version != current_version)
    return {
        "update_available": available,
        "version": manifest.version,
        "current": current_version,
        "verified": True,
    }


def _consteq(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(a, b)
