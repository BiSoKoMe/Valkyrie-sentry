"""Tests for the system-control endpoint gating in valkyrie/web/server.py.

Verifies the defence-in-depth on /api/system/* and /api/meeting/*:
  - loopback-only peer check
  - same-origin (or null/absent) Origin check
  - per-process secret token check

These are the guards that stop a LAN device or a malicious website from
stopping your protection, so they get direct unit coverage.

Usage: python test_control_api.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import fastapi  # noqa: F401
except ImportError:
    print("  SKIP — fastapi not installed (pip install fastapi)")
    sys.exit(0)

from valkyrie.web import server as srv

PASS = 0
FAIL = 0

def check(label, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  + [PASS]  {label}")
    else:
        FAIL += 1; print(f"  X [FAIL]  {label}" + (f"  ({detail})" if detail else ""))


_MISSING = object()

class _Req:
    """Minimal stand-in for a Starlette Request."""
    def __init__(self, host="127.0.0.1", origin=_MISSING, token=None, qtoken=None):
        self.client = type("C", (), {"host": host})() if host is not None else None
        self.headers = {}
        if origin is not _MISSING and origin is not None:
            self.headers["origin"] = origin
        if token is not None:
            self.headers["x-valkyrie-token"] = token
        self.query_params = {"token": qtoken} if qtoken is not None else {}


print("Valkyrie control-API gating tests")
print("=" * 50)

TOKEN = srv._CONTROL_TOKEN

# ── peer check ───────────────────────────────────────────────────────────────
print("\n-- loopback peer -------------------------------------")
check("127.0.0.1 is local",         srv._peer_is_local(_Req(host="127.0.0.1")))
check("::1 is local",               srv._peer_is_local(_Req(host="::1")))
check("LAN IP is NOT local",    not srv._peer_is_local(_Req(host="192.168.1.50")))
check("public IP is NOT local", not srv._peer_is_local(_Req(host="8.8.8.8")))

# ── origin check ─────────────────────────────────────────────────────────────
print("\n-- origin --------------------------------------------")
check("absent Origin allowed (curl/launcher)", srv._origin_is_local(_Req()))
check("null Origin allowed (file://)",         srv._origin_is_local(_Req(origin="null")))
check("localhost Origin allowed",              srv._origin_is_local(_Req(origin="http://localhost:8090")))
check("127.0.0.1 Origin allowed",              srv._origin_is_local(_Req(origin="http://127.0.0.1:8090")))
check("remote Origin blocked",             not srv._origin_is_local(_Req(origin="https://evil.example.com")))

# ── token check ──────────────────────────────────────────────────────────────
print("\n-- token ---------------------------------------------")
check("correct token in header",     srv._token_ok(_Req(token=TOKEN)))
check("correct token in query",      srv._token_ok(_Req(qtoken=TOKEN)))
check("wrong token rejected",    not srv._token_ok(_Req(token="nope")))
check("missing token rejected",  not srv._token_ok(_Req()))

# ── full guard ───────────────────────────────────────────────────────────────
print("\n-- _control_guard ------------------------------------")
if os.name != "nt":
    g = srv._control_guard(_Req(host="127.0.0.1", origin="http://localhost:8090", token=TOKEN))
    check("non-Windows guard returns 501", g is not None and g.status_code == 501)
else:
    ok = srv._control_guard(_Req(host="127.0.0.1", origin="http://localhost:8090", token=TOKEN))
    check("valid local+token+origin is ALLOWED (guard None)", ok is None, str(ok))

    bad_token = srv._control_guard(_Req(host="127.0.0.1", origin="http://localhost:8090", token="wrong"))
    check("bad token -> 403", bad_token is not None and bad_token.status_code == 403)

    remote = srv._control_guard(_Req(host="192.168.1.50", origin="http://localhost:8090", token=TOKEN))
    check("remote peer -> 403", remote is not None and remote.status_code == 403)

    xorigin = srv._control_guard(_Req(host="127.0.0.1", origin="https://evil.example.com", token=TOKEN))
    check("cross-site origin -> 403", xorigin is not None and xorigin.status_code == 403)

    no_token = srv._control_guard(_Req(host="127.0.0.1", origin="http://localhost:8090"))
    check("missing token -> 403", no_token is not None and no_token.status_code == 403)

print(f"\n{'=' * 50}")
print(f"  {PASS} passed  /  {FAIL} failed")
sys.exit(1 if FAIL else 0)
