"""Version-independent TestClient with a controllable peer address.

Starlette only grew ``TestClient(client=...)`` in 0.41.x, and the pinned
FastAPI holds starlette below that. The auth tests must simulate loopback
vs. LAN peers, so instead of depending on the kwarg we rewrite
``scope["client"]`` in a thin ASGI wrapper - identical behaviour on every
starlette version, for HTTP and WebSocket scopes alike.
"""

from __future__ import annotations

from starlette.testclient import TestClient


def make_client(app, host: str, port: int = 5555) -> TestClient:
    """A TestClient whose requests appear to originate from (host, port)."""

    async def _with_peer(scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            scope = dict(scope)
            scope["client"] = (host, port)
        await app(scope, receive, send)

    return TestClient(_with_peer)
