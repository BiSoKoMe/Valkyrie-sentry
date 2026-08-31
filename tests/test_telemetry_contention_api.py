#!/usr/bin/env python3
"""GET /api/telemetry/contention - the engine's own resource self-stats.

Platform Beta 0.5's investigation built CPU/RSS/thread visibility for the
engine process into the external test harness (`_engine_process_stats()` in
redteam/evaluation/beta05_reliability.py) to diagnose an engine that had
become unreachable mid-run. That visibility only ever existed in the
harness - the product itself had no way to report its own resource
footprint through its own API. This pins the promoted, product-side
equivalent (`_self_process_stats()` in valkyrie/web/server.py), reachable
at the same async, contention-safe endpoint that already reports the event
loop, AnyIO worker pool, and collector health.

Requires fastapi + httpx (the test client) and psutil. Skips cleanly if
either is absent - same convention as tests/test_doh_status_api.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks   # noqa: E402


def main() -> int:
    c = Checks("Engine self-process stats (/api/telemetry/contention)")

    try:
        from starlette.testclient import TestClient   # noqa: F401
    except Exception as exc:      # noqa: BLE001
        c.skip("all checks", f"test client unavailable: {exc}")
        return c.finish()

    try:
        from valkyrie.web.server import create_app, state
    except ImportError as exc:
        c.skip("all checks", f"fastapi/web stack unavailable: {exc}")
        return c.finish()

    try:
        import psutil   # noqa: F401
        has_psutil = True
    except ImportError:
        has_psutil = False

    from testclient_compat import make_client   # noqa: E402

    app = create_app()
    client = make_client(app, "127.0.0.1")

    resp = client.get("/api/telemetry/contention")
    c.check("GET /api/telemetry/contention -> 200", resp.status_code == 200)
    body = resp.json()
    c.check("response carries an engine_process key",
            "engine_process" in body)

    ep = body.get("engine_process") or {}
    if not has_psutil:
        c.check("no psutil -> engine_process reports unavailable, not a crash",
                ep.get("available") is False)
        return c.finish()

    c.check("psutil installed -> engine_process reports available",
            ep.get("available") is True)
    c.check("carries a numeric cpu_percent", isinstance(ep.get("cpu_percent"), (int, float)))
    c.check("carries rss_bytes for THIS process (nonzero - a live server has memory)",
            isinstance(ep.get("rss_bytes"), int) and ep["rss_bytes"] > 0)
    c.check("carries num_threads (nonzero - the process is running)",
            isinstance(ep.get("num_threads"), int) and ep["num_threads"] > 0)

    # A second call must not error - proves the cached process handle
    # (module-scoped, reused across calls) survives repeat reads rather
    # than only working once.
    resp2 = client.get("/api/telemetry/contention")
    c.check("a second call also succeeds (cached handle reused, not re-opened)",
            resp2.status_code == 200
            and (resp2.json().get("engine_process") or {}).get("available") is True)

    # Monitoring-only surface: no way to mutate anything through this route.
    c.check("no POST route exists for /api/telemetry/contention (read-only)",
            client.post("/api/telemetry/contention").status_code == 405)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
