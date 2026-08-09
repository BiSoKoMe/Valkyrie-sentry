#!/usr/bin/env python3
"""End-to-end: a slow endpoint must not starve the rest of the API.

test_response_cache.py pins the cache in isolation. This drives the REAL ASGI
app through the real routing stack, because the bug was never in a helper --
it was in how FastAPI schedules ``async def`` handlers. A unit test of the
cache cannot prove the routes were actually wired to it.

Measured before this fix, against the live engine, five endpoints requested
concurrently:

    /api/stats               6,326 ms
    /api/events              7,262 ms
    /api/components          9,092 ms
    /api/controls/coverage  10,254 ms
    /api/health             11,175 ms   <-- the endpoint that does no work

``/api/health`` was the slowest because every handler shares one event-loop
thread, so its latency was other people's work. That is the property under
test here, with a deliberately slow coverage probe standing in for the real
3.3s one.

In-process ASGI only: no socket is bound, no service is contacted, and every
service on the AppContext is a fake. Nothing touches the host.
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

SLOW_PROBE_S = 0.80


class _FakeStore:
    def stats(self):
        return {"total_24h": 7, "blocked_24h": 3, "flagged_24h": 1,
                "allowed_24h": 3, "top_domain": "a.example",
                "top_process": "p.exe"}

    def top_blocked_domains(self, limit=5):
        return [{"domain": "a.example", "count": 3}]

    def recent_events(self, limit=200):
        return [{"timestamp": "2026-08-09T00:00:00", "domain": "a.example",
                 "decision": "blocked", "process_name": "p.exe",
                 "reason": "test", "suspicion": 0.9, "raw_category": "",
                 "url": ""}]

    def scanner_decision_count(self):
        return 11

    def cleaned_count(self):
        return 0


class _FakeRegistry:
    def overall(self):
        return "healthy"

    def snapshot(self):
        return [{"name": "fake", "health": "ok"}]


def main() -> int:
    try:
        import httpx
        from valkyrie.web import server as S
        from valkyrie.web import cache as CM
    except ImportError as exc:
        return skip_file("api concurrency", f"dependency missing: {exc}")

    c = Checks("API concurrency (a slow route must not starve the API)",
               expect_min=10)

    CM.CACHE.clear()
    S.state.store = _FakeStore()
    S.state.registry = _FakeRegistry()
    S.state.start_time = time.time()

    probe_calls = {"n": 0}

    def slow_coverage():
        """Stands in for the real ~3.3s coverage probe."""
        probe_calls["n"] += 1
        time.sleep(SLOW_PROBE_S)
        return {"fraction_effective": 0.193, "counts": {"effective": 11},
                "total": 57, "gaps": []}

    S._build_coverage = slow_coverage           # noqa: SLF001
    app = S.create_app()

    async def run() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport,
                                     base_url="http://test") as client:

            # ------------------------------------------------------------ [1]
            print("\n[1] the endpoints still answer correctly through the cache")
            r = await client.get("/api/stats")
            c.check("/api/stats is 200", r.status_code == 200)
            c.check("and carries real values, not a zero-filled placeholder",
                    r.json().get("total_24h") == 7)
            r = await client.get("/api/events")
            c.check("/api/events returns the formatted rows",
                    r.status_code == 200 and len(r.json()) == 1)
            r = await client.get("/api/components")
            c.check("/api/components returns the registry snapshot",
                    r.status_code == 200 and r.json().get("enabled") is True)

            # ------------------------------------------------------------ [2]
            print(f"\n[2] THE BUG: a {SLOW_PROBE_S}s coverage probe must not "
                  f"delay /api/stats")
            cov = asyncio.create_task(client.get("/api/controls/coverage"))
            await asyncio.sleep(0.05)          # let it get into its thread
            t0 = time.perf_counter()
            fast = await client.get("/api/stats")
            fast_ms = (time.perf_counter() - t0) * 1000
            cov_resp = await cov
            c.check("coverage still answered correctly",
                    cov_resp.status_code == 200
                    and cov_resp.json()["fraction_effective"] == 0.193)
            c.check(f"/api/stats answered in {fast_ms:.0f}ms while the slow "
                    f"probe was in flight — before this fix the trivial "
                    f"endpoint was the SLOWEST at 11.2s, purely from queueing",
                    fast_ms < SLOW_PROBE_S * 1000 * 0.5)

            # ------------------------------------------------------------ [3]
            print("\n[3] a cached coverage read is effectively free")
            t0 = time.perf_counter()
            r = await client.get("/api/controls/coverage")
            warm_ms = (time.perf_counter() - t0) * 1000
            c.check(f"the second coverage request took {warm_ms:.0f}ms "
                    f"(cold was ~{SLOW_PROBE_S * 1000:.0f}ms)",
                    warm_ms < 100 and r.status_code == 200)
            c.check("the expensive probe ran ONCE across both requests",
                    probe_calls["n"] == 1)

            # ------------------------------------------------------------ [4]
            print("\n[4] 20 concurrent pollers do not multiply the work")
            before = probe_calls["n"]
            CM.CACHE.invalidate("coverage")
            t0 = time.perf_counter()
            rs = await asyncio.gather(*[
                client.get("/api/controls/coverage") for _ in range(20)])
            wall_ms = (time.perf_counter() - t0) * 1000
            c.check("all 20 got 200", all(x.status_code == 200 for x in rs))
            c.check(f"the probe ran once more, not 20 more times "
                    f"({probe_calls['n'] - before} run(s))",
                    probe_calls["n"] - before == 1)
            c.check(f"20 concurrent requests finished in {wall_ms:.0f}ms — "
                    f"about one probe, not twenty serialised",
                    wall_ms < SLOW_PROBE_S * 1000 * 2)

            # ------------------------------------------------------------ [5]
            print("\n[5] a broken producer returns an honest 503, never zeros")
            def broken():
                raise RuntimeError("coverage probe exploded")

            S._build_coverage = broken           # noqa: SLF001
            CM.CACHE.invalidate("coverage")
            r = await client.get("/api/controls/coverage")
            c.check("a cold failure is a 503, not a 200 with fabricated data — "
                    "a made-up 0 is indistinguishable from a real 0",
                    r.status_code == 503)
            c.check("and the reason is reported rather than swallowed",
                    "exploded" in r.text)

            # ------------------------------------------------------------ [6]
            print("\n[6] the cache is observable from outside the process")
            r = await client.get("/api/cache/stats")
            body = r.json()
            c.check("/api/cache/stats exposes counters and per-key age",
                    r.status_code == 200 and "counters" in body
                    and "keys" in body)

    asyncio.run(run())
    CM.CACHE.clear()
    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
