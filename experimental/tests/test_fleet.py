"""Tests for the fleet control plane (valkyrie/fleet/).

Covers the security-critical logic directly on FleetController (no HTTP), then
- if fastapi's TestClient is importable - the same paths through the real app.

Locks in:
  - enrollment requires the pre-shared enroll token (fail closed);
  - the server stores only a token HASH, never a usable token;
  - heartbeats require the correct device token (constant-time compared);
  - an unknown device / wrong token is rejected;
  - the heartbeat payload carries counts/categories/health but the protocol
    drops any domain-shaped data (privacy invariant);
  - fleet summary/list reflect reported state and online/offline.

Usage: python tests/test_fleet.py
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


print("Valkyrie fleet control-plane test")
print("=" * 50)

from valkyrie.fleet.store import FleetStore
from valkyrie.fleet.controller import FleetController, AuthError
from valkyrie.fleet.protocol import (
    EnrollmentRequest, Heartbeat, hash_token, new_device_token, tokens_equal,
)

ENROLL = "super-secret-enroll-token"


def _fresh_controller(tmp):
    store = FleetStore(Path(tmp) / "fleet.db")
    return store, FleetController(store, enroll_token=ENROLL, offline_after=90.0)


# ignore_cleanup_errors: on Windows an open SQLite file can't be unlinked; we
# close every store explicitly below, this is just belt-and-suspenders.
_open_stores = []
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
    store, ctl = _fresh_controller(tmp)
    _open_stores.append(store)

    # --- Token primitives ---
    print("\n-- Token primitives ----------------------------------")
    t = new_device_token()
    check("token has real entropy (>=32 chars)", len(t) >= 32)
    check("hash is deterministic", hash_token(t) == hash_token(t))
    check("hash != raw token", hash_token(t) != t)
    check("tokens_equal true for match", tokens_equal("abc", "abc"))
    check("tokens_equal false for mismatch", not tokens_equal("abc", "abd"))

    # --- Enrollment auth ---
    print("\n-- Enrollment ----------------------------------------")
    try:
        ctl.enroll(EnrollmentRequest(enroll_token="wrong", label="pc1"))
        check("wrong enroll token rejected", False, "no AuthError raised")
    except AuthError:
        check("wrong enroll token rejected", True)

    res = ctl.enroll(EnrollmentRequest(enroll_token=ENROLL, label="pc1",
                                       platform="Windows-11", agent_version="0.2.0"))
    check("valid enroll returns a device_id", bool(res.device_id))
    check("valid enroll returns a device_token", bool(res.device_token))

    # Server must persist only the HASH, never the raw token.
    stored_hash = store.token_hash_for(res.device_id)
    check("server stores token HASH, not raw token",
          stored_hash == hash_token(res.device_token) and stored_hash != res.device_token)
    dev_public = store.get_device(res.device_id)
    check("device public view never exposes token_hash",
          "token_hash" not in dev_public and "device_token" not in dev_public)

    # --- Enrollment disabled when server has no token (fail closed) ---
    store2 = FleetStore(Path(tmp) / "fleet2.db")
    _open_stores.append(store2)
    ctl_notoken = FleetController(store2, enroll_token="")
    try:
        ctl_notoken.enroll(EnrollmentRequest(enroll_token="anything", label="x"))
        check("enrollment fails closed when server has no token", False)
    except AuthError:
        check("enrollment fails closed when server has no token", True)

    # --- Heartbeat auth ---
    print("\n-- Heartbeat auth ------------------------------------")
    hb = Heartbeat(counts={"blocked": 12, "allowed": 300, "flagged": 4},
                   categories={"tracker": 10, "malware": 2},
                   components={"dns": True, "firewall": True},
                   agent_version="0.2.0")
    try:
        ctl.heartbeat("no-such-device", res.device_token, hb)
        check("heartbeat from unknown device rejected", False)
    except AuthError:
        check("heartbeat from unknown device rejected", True)

    try:
        ctl.heartbeat(res.device_id, "wrong-token", hb)
        check("heartbeat with wrong token rejected", False)
    except AuthError:
        check("heartbeat with wrong token rejected", True)

    reply = ctl.heartbeat(res.device_id, res.device_token, hb)
    check("valid heartbeat accepted", reply.get("ok") is True)

    # --- Privacy invariant: domains never survive into stored status ---
    print("\n-- Privacy invariant ---------------------------------")
    leaky = Heartbeat.from_dict({
        "counts": {"blocked": 5},
        "categories": {"tracker": 5},
        "components": {"dns": True},
        # A hostile/buggy agent tries to smuggle domains via unknown keys:
        "domains": ["secret-bank.example", "medical-site.example"],
        "top_domains": {"secret-bank.example": 5},
    })
    ctl.heartbeat(res.device_id, res.device_token, leaky)
    stored = store.get_device(res.device_id)["status"]
    blob = repr(stored)
    check("no domain string survived into stored status",
          "secret-bank.example" not in blob and "medical-site.example" not in blob)
    check("stored status keeps only counts/categories/components",
          set(stored.keys()) <= {"counts", "categories", "components"})

    # --- Fleet views ---
    print("\n-- Fleet views ---------------------------------------")
    res2 = ctl.enroll(EnrollmentRequest(enroll_token=ENROLL, label="pc2"))
    devices = ctl.list_devices()
    check("list_devices returns both enrolled devices", len(devices) == 2)
    check("device that heartbeated is online",
          any(d["label"] == "pc1" and d["online"] for d in devices))
    check("device that never heartbeated is offline",
          any(d["label"] == "pc2" and not d["online"] for d in devices))
    summary = ctl.fleet_summary()
    check("summary counts both devices", summary["devices_total"] == 2)
    check("summary online count is 1", summary["devices_online"] == 1)
    check("summary aggregates blocked from last heartbeat", summary["blocked_24h"] == 5)

    # --- HTTP round-trip (optional - needs fastapi TestClient) ---
    print("\n-- HTTP layer (optional) -----------------------------")
    try:
        from fastapi.testclient import TestClient
        from valkyrie.fleet.server import create_fleet_app

        store3 = FleetStore(Path(tmp) / "fleet3.db")
        _open_stores.append(store3)
        ctl3 = FleetController(store3, enroll_token=ENROLL)
        client = TestClient(create_fleet_app(ctl3))

        r = client.post("/api/agent/enroll",
                        json={"enroll_token": "nope", "label": "h1"})
        check("HTTP enroll with bad token -> 403", r.status_code == 403)

        r = client.post("/api/agent/enroll",
                        json={"enroll_token": ENROLL, "label": "h1",
                              "platform": "Linux-6", "agent_version": "0.2.0"})
        check("HTTP enroll ok -> 200", r.status_code == 200)
        creds = r.json()

        r = client.post("/api/agent/heartbeat",
                        json={"device_id": creds["device_id"],
                              "device_token": "bad",
                              "heartbeat": {"counts": {"blocked": 1}}})
        check("HTTP heartbeat with bad token -> 401", r.status_code == 401)

        r = client.post("/api/agent/heartbeat",
                        json={"device_id": creds["device_id"],
                              "device_token": creds["device_token"],
                              "heartbeat": {"counts": {"blocked": 7},
                                            "components": {"dns": True}}})
        check("HTTP heartbeat ok", r.status_code == 200 and r.json().get("ok"))

        r = client.get("/api/fleet")
        body = r.json()
        check("HTTP /api/fleet lists the device",
              any(d["label"] == "h1" for d in body["devices"]))
        check("HTTP fleet never leaks token_hash",
              "token_hash" not in r.text)
    except ImportError as exc:
        print(f"  [-] SKIP — fastapi TestClient unavailable: {exc}")

    for _s in _open_stores:
        try:
            _s.close()
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

