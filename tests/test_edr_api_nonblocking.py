#!/usr/bin/env python3
"""EDR read endpoints must not block the event loop (live-fire regression).

During the first Tier B live-fire run the server logged "web_dashboard
unhealthy (health check returned False)" in a tight loop, and the eval harness's
own reads timed out — even though detection was working and incidents existed.
Root cause: ``/api/edr/incidents`` and ``/api/edr/incidents/{id}`` were
``async def`` handlers that called SYNCHRONOUS SQLite reads directly on the
event loop. While one ran, every other request — including the self-heal
``/api/ping`` liveness probe — was stalled, so a busy server declared ITSELF
dead and the harness couldn't read the incidents it was scoring against.

The fix runs those blocking reads in a threadpool. This test pins it: a slow
``list_incidents`` must not delay ``/api/ping``. It fails if either handler goes
back to calling the store synchronously on the loop.
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks, skip_file  # noqa: E402

SLOW_DB_S = 0.80


class _SlowEdr:
    """Stand-in EDR facade whose reads block like a slow SQLite query."""

    def list_incidents(self, status=None, severity=None, limit=200):
        time.sleep(SLOW_DB_S)
        return [{"id": "inc_test", "technique": "T1218.010", "severity": "high",
                 "category": "process", "updated_at": "2026-08-11T07:00:00+00:00"}]

    def get_incident(self, inc_id):
        time.sleep(SLOW_DB_S)
        return {"id": inc_id, "technique": "T1218.010", "detections": []}

    def mttd_mttr(self):
        time.sleep(SLOW_DB_S)
        return {"mttd": {}, "mttr": {}}


def main() -> int:
    try:
        import httpx
        from valkyrie.web import server as S
    except ImportError as exc:
        return skip_file("edr api nonblocking", f"dependency missing: {exc}")

    c = Checks("EDR read endpoints must not starve the event loop", expect_min=4)

    S.state.edr = _SlowEdr()
    S.state.start_time = time.time()
    app = S.create_app()

    async def run() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport,
                                     base_url="http://test") as client:
            # sanity: the endpoint answers correctly (through the threadpool)
            r = await client.get("/api/edr/incidents")
            c.check("/api/edr/incidents is 200",
                    r.status_code == 200 and r.json()[0]["id"] == "inc_test")

            # THE BUG: a slow incidents read must not delay /api/ping.
            slow = asyncio.create_task(client.get("/api/edr/incidents"))
            await asyncio.sleep(0.05)          # let it get into its thread
            t0 = time.perf_counter()
            ping = await client.get("/api/ping")
            ping_ms = (time.perf_counter() - t0) * 1000
            slow_resp = await slow
            c.check("the slow incidents read still answered",
                    slow_resp.status_code == 200)
            c.check(f"/api/ping answered in {ping_ms:.0f}ms while a "
                    f"{int(SLOW_DB_S*1000)}ms incidents read was in flight "
                    f"(blocking-on-loop would make it >= {int(SLOW_DB_S*1000)}ms)",
                    ping_ms < SLOW_DB_S * 1000 * 0.5)

            # the detail endpoint is the other synchronous read the harness hits
            slow2 = asyncio.create_task(client.get("/api/edr/incidents/inc_test"))
            await asyncio.sleep(0.05)
            t0 = time.perf_counter()
            ping2 = await client.get("/api/ping")
            ping2_ms = (time.perf_counter() - t0) * 1000
            await slow2
            c.check(f"/api/ping stays fast ({ping2_ms:.0f}ms) during a slow "
                    f"incident-DETAIL read too",
                    ping2_ms < SLOW_DB_S * 1000 * 0.5)

    asyncio.run(run())
    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
