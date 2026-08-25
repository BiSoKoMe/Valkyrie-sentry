"""Tests for valkyrie/updater.py - signed update verification.

Generates a throwaway Ed25519 keypair in-process, signs a manifest, and proves:
  - a valid signature verifies;
  - a tampered manifest is rejected;
  - a signature from the WRONG key is rejected;
  - a fail-closed refusal when no public key is configured;
  - artifact hash mismatch is caught;
  - version comparison (upgrade / same / downgrade) is correct;
  - check_update never reports an unverified manifest as available.

Usage: python tests/test_updater.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PASS = 0
FAIL = 0


def check(label: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  + [PASS]  {label}")
    else:
        FAIL += 1
        print(f"  X [FAIL]  {label}" + (f"  ({detail})" if detail else ""))


print("Valkyrie signed-update verification test")
print("=" * 50)

from valkyrie.updater import (
    UpdateManifest, UpdateError, verify_manifest, verify_artifact,
    check_update, is_newer,
)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    print("  [-] SKIP — cryptography not installed")
    sys.exit(0)

# Two independent signing keys - one legitimate, one attacker's.
priv = Ed25519PrivateKey.generate()
pub_hex = priv.public_key().public_bytes_raw().hex()
attacker = Ed25519PrivateKey.generate()

man = UpdateManifest(version="0.3.0", url="https://example/v0.3.0.msi",
                     sha256="a" * 64, notes="test release")
sig = priv.sign(man.canonical_bytes())

# --- Version comparison ---
print("\n-- Version comparison --------------------------------")
check("0.3.0 newer than 0.2.0", is_newer("0.3.0", "0.2.0"))
check("0.2.0 not newer than 0.2.0", not is_newer("0.2.0", "0.2.0"))
check("0.2.1 newer than 0.2.0", is_newer("0.2.1", "0.2.0"))
check("0.1.9 not newer than 0.2.0", not is_newer("0.1.9", "0.2.0"))
check("1.0 newer than 0.9.9", is_newer("1.0", "0.9.9"))

# --- Signature verification ---
print("\n-- Signature verification ----------------------------")
try:
    verify_manifest(man, sig, pub_hex)
    check("valid signature verifies", True)
except UpdateError as e:
    check("valid signature verifies", False, str(e))

# Tamper with the manifest after signing.
tampered = UpdateManifest(version="0.3.0",
                          url="https://evil/backdoor.msi",   # swapped URL
                          sha256="a" * 64, notes="test release")
try:
    verify_manifest(tampered, sig, pub_hex)
    check("tampered manifest rejected", False, "verify did not raise")
except UpdateError:
    check("tampered manifest rejected", True)

# Signature from the attacker's key must not verify against the real key.
evil_sig = attacker.sign(man.canonical_bytes())
try:
    verify_manifest(man, evil_sig, pub_hex)
    check("wrong-key signature rejected", False, "verify did not raise")
except UpdateError:
    check("wrong-key signature rejected", True)

# Fail closed when no public key is configured.
try:
    verify_manifest(man, sig, "")
    check("no public key -> fail closed", False, "verify did not raise")
except UpdateError:
    check("no public key -> fail closed", True)

# --- Artifact hash ---
print("\n-- Artifact hash -------------------------------------")
import hashlib
data = b"the real installer bytes"
good_hash = hashlib.sha256(data).hexdigest()
try:
    verify_artifact(data, good_hash)
    check("correct artifact hash accepted", True)
except UpdateError as e:
    check("correct artifact hash accepted", False, str(e))
try:
    verify_artifact(b"tampered installer", good_hash)
    check("wrong artifact hash rejected", False, "verify did not raise")
except UpdateError:
    check("wrong artifact hash rejected", True)

# --- check_update gate ---
print("\n-- check_update gate ---------------------------------")
res = check_update("0.2.0", man, sig, pub_hex)
check("verified upgrade reported available",
      res["update_available"] and res["verified"])
res_same = check_update("0.3.0", man, sig, pub_hex)
check("same version -> not available", not res_same["update_available"])
try:
    check_update("0.2.0", man, evil_sig, pub_hex)
    check("unverified manifest never reported available", False,
          "check_update did not raise")
except UpdateError:
    check("unverified manifest never reported available", True)

# --- Summary ---
print(f"\n{'=' * 50}")
print(f"  {PASS} passed  /  {FAIL} failed")
if FAIL:
    print("  RESULT: SOME TESTS FAILED")
    sys.exit(1)
else:
    print("  RESULT: ALL TESTS PASSED")
    sys.exit(0)
