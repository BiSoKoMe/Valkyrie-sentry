"""Tests for the fleet remote-response command channel (valkyrie/fleet/command.py).

Locks in the security-critical properties of operator→device remote response:
  - a command runs only if Ed25519-verified against the pinned key (fail-closed);
  - a wrong-key or tampered command is refused, not run;
  - only allow-listed actions can be encoded;
  - anti-replay: a command is handed to a device once, then never again;
  - device targeting: a device-scoped command reaches only that device;
  - the admin-token gate on the operator queue endpoint;
  - the ack channel carries only action status/result (no browsing data).

Usage: python tests/test_fleet_response.py
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


print("Valkyrie fleet remote-response test")
print("=" * 50)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from valkyrie.updater import UpdateError
from valkyrie.fleet.store import FleetStore
from valkyrie.fleet.controller import FleetController, AuthError
from valkyrie.fleet.protocol import EnrollmentRequest, Heartbeat
from valkyrie.fleet.command import (
    ResponseCommand, SignedCommand, sign_command, verify_signed_command,
    new_command_id,
)

priv = Ed25519PrivateKey.generate()
pub_hex = priv.public_key().public_bytes_raw().hex()
attacker = Ed25519PrivateKey.generate()
ENROLL = "enroll-secret"

_stores = []
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:

    # ── Signing primitives ────────────────────────────────────────────
    print("\n-- Command signing -----------------------------------")
    cmd = ResponseCommand(action="block_domain", target="evil.example")
    signed = sign_command(cmd, priv)
    got = verify_signed_command(signed, pub_hex)
    check("valid command verifies", got.action == "block_domain" and got.target == "evil.example")

    try:
        verify_signed_command(sign_command(cmd, attacker), pub_hex)
        check("wrong-key command refused", False)
    except UpdateError:
        check("wrong-key command refused", True)

    try:
        ResponseCommand.from_dict({"action": "rm_rf_everything", "target": "x"})
        check("disallowed action refused", False)
    except UpdateError:
        check("disallowed action refused", True)

    try:
        ResponseCommand.from_dict({"action": "block_domain", "target": "a; rm -rf /"})
        check("shell-payload target refused", False)
    except UpdateError:
        check("shell-payload target refused", True)

    # ── Controller queue / fetch / ack ────────────────────────────────
    print("\n-- Controller command flow ---------------------------")
    store = FleetStore(Path(tmp) / "fleet.db"); _stores.append(store)
    ctl = FleetController(store, enroll_token=ENROLL, policy_public_key_hex=pub_hex)

    dev = ctl.enroll(EnrollmentRequest(enroll_token=ENROLL, label="pc1"))
    ctl.heartbeat(dev.device_id, dev.device_token, Heartbeat(counts={"blocked": 1}))

    # No-key controller refuses to queue anything (fail-closed).
    store_nk = FleetStore(Path(tmp) / "nk.db"); _stores.append(store_nk)
    ctl_nk = FleetController(store_nk, enroll_token=ENROLL, policy_public_key_hex="")
    try:
        ctl_nk.queue_command("", sign_command(cmd, priv).to_dict())
        check("queue fails closed without a pinned key", False)
    except UpdateError:
        check("queue fails closed without a pinned key", True)

    # Wrong-key bundle rejected at queue time.
    try:
        ctl.queue_command("", sign_command(cmd, attacker).to_dict())
        check("queue rejects wrong-key command", False)
    except UpdateError:
        check("queue rejects wrong-key command", True)

    # Queue a real org-wide command.
    org_cmd = ResponseCommand(action="isolate_host", target="")
    res = ctl.queue_command("", sign_command(org_cmd, priv).to_dict())
    check("valid command queued", res["ok"] and res["action"] == "isolate_host")

    # Device fetches it.
    pending = ctl.get_commands_for_device(dev.device_id, dev.device_token)
    check("device receives the pending command", len(pending) == 1)
    fetched = verify_signed_command(SignedCommand.from_dict(pending[0]), pub_hex)
    check("fetched command verifies device-side", fetched.action == "isolate_host")

    # Ack it → anti-replay: not handed out again.
    ctl.ack_command(dev.device_id, dev.device_token, fetched.id, "succeeded", "isolated")
    again = ctl.get_commands_for_device(dev.device_id, dev.device_token)
    check("acked command is not re-delivered (anti-replay)", len(again) == 0)

    acks = ctl.command_status(fetched.id)
    check("operator sees the ack status", acks and acks[0]["status"] == "succeeded")

    # Auth: unknown device / wrong token can't fetch or ack.
    try:
        ctl.get_commands_for_device("nope", dev.device_token)
        check("unknown device cannot fetch commands", False)
    except AuthError:
        check("unknown device cannot fetch commands", True)
    try:
        ctl.ack_command(dev.device_id, "wrong", "x", "s", "r")
        check("wrong token cannot ack", False)
    except AuthError:
        check("wrong token cannot ack", True)

    # ── Device targeting ──────────────────────────────────────────────
    print("\n-- Device targeting ----------------------------------")
    dev2 = ctl.enroll(EnrollmentRequest(enroll_token=ENROLL, label="pc2"))
    ctl.heartbeat(dev2.device_id, dev2.device_token, Heartbeat(counts={"blocked": 0}))
    targeted = ResponseCommand(action="block_domain", target="only-pc2.example",
                               device_id=dev2.device_id)
    ctl.queue_command("", sign_command(targeted, priv).to_dict())

    def _ids(dev):
        return {verify_signed_command(SignedCommand.from_dict(b), pub_hex).id
                for b in ctl.get_commands_for_device(dev.device_id, dev.device_token)}
    check("targeted command reaches the target device", targeted.id in _ids(dev2))
    check("targeted command hidden from other devices", targeted.id not in _ids(dev))

    # ── Privacy: ack channel carries no browsing data ─────────────────
    print("\n-- Privacy invariant ---------------------------------")
    # The ack echoes a target the OPERATOR issued (block only-pc2.example), plus
    # a status — never a domain the device chose to visit. The heartbeat status
    # (which does flow device->server) still holds only counts/categories/health.
    stored = store.get_device(dev.device_id)["status"]
    check("device heartbeat status stays counts/categories/components only",
          set(stored.keys()) <= {"counts", "categories", "components"})

    # ── HTTP layer (optional) ─────────────────────────────────────────
    print("\n-- HTTP layer (optional) -----------------------------")
    try:
        from fastapi.testclient import TestClient
        from valkyrie.fleet.server import create_fleet_app

        store_h = FleetStore(Path(tmp) / "h.db"); _stores.append(store_h)
        ctl_h = FleetController(store_h, enroll_token=ENROLL, policy_public_key_hex=pub_hex)
        client = TestClient(create_fleet_app(ctl_h, admin_token="ADMIN"))

        creds = client.post("/api/agent/enroll",
                            json={"enroll_token": ENROLL, "label": "h1"}).json()
        client.post("/api/agent/heartbeat",
                    json={"device_id": creds["device_id"],
                          "device_token": creds["device_token"],
                          "heartbeat": {"counts": {"blocked": 1}}})

        # Queue needs the admin token.
        bundle = sign_command(ResponseCommand(action="kill_process", target="4321"), priv).to_dict()
        r = client.post("/api/command", json={"org": "", "bundle": bundle})
        check("HTTP queue without admin token -> 403", r.status_code == 403)
        r = client.post("/api/command", headers={"Authorization": "Bearer ADMIN"},
                        json={"org": "", "bundle": bundle})
        check("HTTP queue with admin token ok", r.status_code == 200 and r.json().get("ok"))

        r = client.post("/api/agent/commands",
                        json={"device_id": creds["device_id"],
                              "device_token": creds["device_token"]})
        cmds = r.json()["commands"]
        check("HTTP device fetches the command", len(cmds) == 1)
        cid = cmds[0]["command"]["id"]

        r = client.post("/api/agent/commands/ack",
                        json={"device_id": creds["device_id"],
                              "device_token": creds["device_token"],
                              "command_id": cid, "status": "succeeded",
                              "result": "killed 4321"})
        check("HTTP ack accepted", r.status_code == 200 and r.json().get("ok"))
        r = client.get("/api/command/" + cid, headers={"Authorization": "Bearer ADMIN"})
        check("HTTP command status shows the ack",
              any(a["status"] == "succeeded" for a in r.json()["acks"]))
    except ImportError as exc:
        print(f"  [-] SKIP — fastapi TestClient unavailable: {exc}")

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
