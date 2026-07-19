#!/usr/bin/env python3
"""Dashboard exposure guard: off-loopback callers must present the control token.

Pins the ADR-0003 security fix. The dashboard's data endpoints expose live
DNS/browsing history. With the server bound loopback-only by default this is
moot, but when an operator opts into LAN/router exposure (--web-host 0.0.0.0)
every /api/* call and the /ws live stream from a non-loopback peer must carry
the per-process control token. Loopback callers are unaffected.

Requires fastapi + httpx (the test client). Skips cleanly if either is absent.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def main() -> int:
    try:
        from starlette.testclient import TestClient
        from starlette.websockets import WebSocketDisconnect
    except Exception as exc:   # noqa: BLE001
        print(f"  [-] SKIP — test client unavailable: {exc}")
        return 0

    try:
        from valkyrie.web.server import create_app, state, _CONTROL_TOKEN
        from valkyrie.store import Store
    except ImportError as exc:
        print(f"  [-] SKIP — fastapi/web stack unavailable: {exc}")
        return 0

    print("\n=== dashboard off-loopback auth guard ===\n")

    td = tempfile.mkdtemp()
    store = Store(db_path=Path(td) / "web_auth_test.db")
    store.start()
    state.store = store
    app = create_app()

    from testclient_compat import make_client
    local  = make_client(app, "127.0.0.1")
    remote = make_client(app, "192.168.1.50")
    good = {"X-Valkyrie-Token": _CONTROL_TOKEN}

    print("[1] HTTP data endpoints")
    _check("loopback /api/events allowed (no token needed)",
           local.get("/api/events").status_code == 200)
    _check("loopback /api/stats allowed",
           local.get("/api/stats").status_code == 200)
    _check("remote /api/events without token -> 403",
           remote.get("/api/events").status_code == 403)
    _check("remote /api/events with valid token -> 200",
           remote.get("/api/events", headers=good).status_code == 200)
    _check("remote /api/events with WRONG token -> 403",
           remote.get("/api/events", headers={"X-Valkyrie-Token": "wrong"}).status_code == 403)
    _check("remote /api/stats without token -> 403",
           remote.get("/api/stats").status_code == 403)

    print("\n[2] HTML shell stays reachable (data behind it is gated)")
    _check("remote GET / (dashboard shell) -> 200",
           remote.get("/").status_code == 200)

    print("\n[3] WebSocket live stream")
    # Loopback subscriber connects and receives the initial payload.
    try:
        with local.websocket_connect("/ws") as ws:
            msg = ws.receive_json()
            _check("loopback /ws connects and streams", msg.get("type") == "init")
    except Exception as exc:   # noqa: BLE001
        _check(f"loopback /ws connects and streams (raised {exc})", False)

    # Remote subscriber without a token is rejected before accept.
    try:
        with remote.websocket_connect("/ws"):
            _check("remote /ws without token rejected", False)
    except WebSocketDisconnect:
        _check("remote /ws without token rejected", True)
    except Exception:
        # Any refusal to establish the stream is an acceptable rejection.
        _check("remote /ws without token rejected", True)

    # Remote subscriber WITH the token (query param) is allowed.
    try:
        with remote.websocket_connect(f"/ws?token={_CONTROL_TOKEN}") as ws:
            msg = ws.receive_json()
            _check("remote /ws with token connects", msg.get("type") == "init")
    except Exception as exc:   # noqa: BLE001
        _check(f"remote /ws with token connects (raised {exc})", False)

    store.stop()

    print("\n" + "=" * 44)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
