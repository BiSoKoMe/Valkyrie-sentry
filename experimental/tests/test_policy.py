"""Tests for multi-tenant isolation + central signed policy push.

Covers:
  - enroll tokens map to orgs SERVER-SIDE; a device can't self-select its org;
  - fleet views are scoped per org (org A's device invisible to org B);
  - policy sign/verify (valid / tampered / wrong-key / no-key fail-closed);
  - controller.set_policy refuses an unsigned/tampered bundle;
  - get_policy_for_device returns the device's org policy, authenticated;
  - agent applies a verified policy and ENFORCES anti-rollback (never applies
    an equal/older version, even though it's validly signed).

Usage: python tests/test_policy.py
"""

import sys
import tempfile
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


print("Valkyrie multi-tenant + policy push test")
print("=" * 50)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    print("  [-] SKIP — cryptography not installed")
    sys.exit(0)

from valkyrie.fleet.store import FleetStore
from valkyrie.fleet.controller import FleetController
from valkyrie.fleet.protocol import EnrollmentRequest
from valkyrie.fleet.policy import Policy, SignedPolicy, sign_policy, verify_signed_policy
from valkyrie.fleet.agent import FleetAgent
from valkyrie.updater import UpdateError


def _raise_404():
    from valkyrie.fleet.agent import _HttpError
    raise _HttpError("404")


# Policy signing keys - real vs attacker.
priv = Ed25519PrivateKey.generate()
pub_hex = priv.public_key().public_bytes_raw().hex()
attacker = Ed25519PrivateKey.generate()

_stores = []
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
    store = FleetStore(Path(tmp) / "f.db")
    _stores.append(store)
    # Multi-tenant: two orgs, each with its own enroll token.
    ctl = FleetController(
        store,
        enroll_token={"tok-acme": "acme", "tok-globex": "globex"},
        policy_public_key_hex=pub_hex,
    )

    # --- Multi-tenant enrollment + isolation ---
    print("\n-- Multi-tenant isolation ----------------------------")
    a = ctl.enroll(EnrollmentRequest(enroll_token="tok-acme", label="acme-pc"))
    g = ctl.enroll(EnrollmentRequest(enroll_token="tok-globex", label="globex-pc"))
    check("device enrolled with acme token lands in org 'acme'",
          store.org_for(a.device_id) == "acme")
    check("device enrolled with globex token lands in org 'globex'",
          store.org_for(g.device_id) == "globex")

    acme_view = ctl.list_devices(org="acme")
    globex_view = ctl.list_devices(org="globex")
    check("acme view shows only acme's device",
          len(acme_view) == 1 and acme_view[0]["label"] == "acme-pc")
    check("globex view shows only globex's device",
          len(globex_view) == 1 and globex_view[0]["label"] == "globex-pc")
    check("global view (org=None) shows both", len(ctl.list_devices()) == 2)
    check("acme summary counts only acme devices",
          ctl.fleet_summary(org="acme")["devices_total"] == 1)

    # --- Policy signing / verification ---
    print("\n-- Policy signing / verification ---------------------")
    pol = Policy(version=2, block_domains=["ads.example", "track.example"],
                 allow_domains=["intranet.acme"], notes="acme baseline")
    signed = sign_policy(pol, priv)
    try:
        verify_signed_policy(signed, pub_hex)
        check("valid policy signature verifies", True)
    except UpdateError as e:
        check("valid policy signature verifies", False, str(e))

    tampered = SignedPolicy.from_dict({
        "policy": {**pol.to_dict(), "block_domains": ["evil.example"]},
        "signature": signed.signature_hex,
    })
    try:
        verify_signed_policy(tampered, pub_hex)
        check("tampered policy rejected", False, "verify did not raise")
    except UpdateError:
        check("tampered policy rejected", True)

    evil_signed = sign_policy(pol, attacker)
    try:
        verify_signed_policy(evil_signed, pub_hex)
        check("wrong-key policy rejected", False, "verify did not raise")
    except UpdateError:
        check("wrong-key policy rejected", True)

    # --- set_policy on the controller enforces verification ---
    print("\n-- Controller set_policy gate ------------------------")
    res = ctl.set_policy("acme", signed.to_dict())
    check("valid signed policy accepted + stored", res.get("version") == 2)
    try:
        ctl.set_policy("acme", evil_signed.to_dict())
        check("controller rejects wrong-key policy", False)
    except UpdateError:
        check("controller rejects wrong-key policy", True)

    ctl_nokey = FleetController(store, enroll_token="x", policy_public_key_hex="")
    try:
        ctl_nokey.set_policy("acme", signed.to_dict())
        check("no policy key -> set_policy fails closed", False)
    except UpdateError:
        check("no policy key -> set_policy fails closed", True)

    # --- get_policy_for_device is authenticated + org-scoped ---
    print("\n-- Policy delivery to device -------------------------")
    try:
        ctl.get_policy_for_device(a.device_id, "wrong-token")
        check("policy fetch requires valid device token", False)
    except Exception as e:
        check("policy fetch requires valid device token",
              e.__class__.__name__ == "AuthError")
    bundle = ctl.get_policy_for_device(a.device_id, a.device_token)
    check("acme device receives acme policy (v2)",
          bundle and bundle["policy"]["version"] == 2)
    check("globex device (no policy set) receives none",
          ctl.get_policy_for_device(g.device_id, g.device_token) is None)

    # --- Agent apply + anti-rollback (no HTTP; drive fetch_and_apply) ---
    print("\n-- Agent apply + anti-rollback -----------------------")
    applied = []
    agent = FleetAgent(
        "http://unused", status_provider=lambda: {},
        identity_path=Path(tmp) / "agent_id.json",
        policy_public_key_hex=pub_hex,
        policy_applier=lambda p: applied.append(p.version),
    )
    # Inject enrolled identity + stub the network fetch with controller output.
    agent._device_id = a.device_id
    agent._device_token = a.device_token
    agent._post = lambda path, body, auth=None: ctl.get_policy_for_device(
        body["device_id"], body["device_token"]) or _raise_404()

    check("agent applies verified v2 policy", agent.fetch_and_apply_policy() is True)
    check("applier received version 2", applied == [2])
    check("re-fetching same v2 is a no-op (not re-applied)",
          agent.fetch_and_apply_policy() is False and applied == [2])

    # Push an OLDER but validly-signed policy - must be refused (rollback).
    old = sign_policy(Policy(version=1, block_domains=["old.example"]), priv)
    ctl.set_policy("acme", old.to_dict())
    check("older signed policy is NOT applied (anti-rollback)",
          agent.fetch_and_apply_policy() is False and applied == [2])

    # Push a NEWER policy - applied.
    newer = sign_policy(Policy(version=3, block_domains=["new.example"]), priv)
    ctl.set_policy("acme", newer.to_dict())
    check("newer signed policy IS applied", agent.fetch_and_apply_policy() is True)
    check("applier received version 3", applied == [2, 3])

    # A tampered bundle from the server is refused by the agent even though the
    # server would never store it - defence in depth at the apply site.
    agent._post = lambda path, body, auth=None: {
        "policy": {**newer.policy.to_dict(), "version": 4,
                   "block_domains": ["evil.example"]},
        "signature": newer.signature_hex,
    }
    check("agent refuses a tampered v4 bundle",
          agent.fetch_and_apply_policy() is False and applied == [2, 3])

    for s in _stores:
        try:
            s.close()
        except Exception:
            pass


print(f"\n{'=' * 50}")
print(f"  {PASS} passed  /  {FAIL} failed")
if FAIL:
    print("  RESULT: SOME TESTS FAILED")
    sys.exit(1)
else:
    print("  RESULT: ALL TESTS PASSED")
    sys.exit(0)
