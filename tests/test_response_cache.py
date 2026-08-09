#!/usr/bin/env python3
"""API response cache (valkyrie/web/cache.py).

The measured fault this fixes: with all 57 route handlers declared ``async
def``, FastAPI runs them ON the event loop, so one slow handler blocks every
other request. Against the live engine, ``/api/health`` -- which does almost no
work -- was the SLOWEST endpoint under concurrency at 11.2 s, purely from
queueing behind ``/api/controls/coverage`` (22.4 s). That is the accept-backlog
exhaustion that wedged the engine.

So the properties pinned here are about scheduling and honesty, not hit rates:

  * a slow producer must NOT delay a concurrent fast one (the actual bug);
  * N concurrent cold callers must run the producer ONCE, not N times --
    a TTL cache that stampedes on every miss barely helps a 1.5s poller;
  * a stale value is served immediately while a refresh runs, so a TTL expiry
    never charges the full cost to whichever request happens to arrive first;
  * a failed refresh keeps the last GOOD value rather than erroring;
  * but a COLD producer that fails RAISES -- it must never invent a value.
    A fabricated 0 is indistinguishable from a real 0, and "0 threats blocked"
    is the most dangerous number a security product can make up. This is the
    same class of bug the UI was fixed for in 30827db/86cc36a.

Pure asyncio against injected clocks and fake producers. Touches no host state,
no database, no network.
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402


class _Clock:
    """Injected time so tests never sleep to age a cache entry."""

    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


async def _settle(cache) -> None:
    """Wait for background refreshes to actually finish.

    This used to spin ``await asyncio.sleep(0)`` a fixed number of times.
    That yields to the event loop but does NOT wait for the worker-thread
    round trip a stale refresh performs, so it was a race: it passed on an
    idle machine and failed under load, which is exactly how a flaky test
    launders a real timing assumption into an apparent pass.
    """
    await cache.drain()


def main() -> int:
    c = Checks("API response cache (single-flight, SWR, no fabricated values)",
               expect_min=18)

    from valkyrie.web import cache as CM

    async def run() -> None:
        # -------------------------------------------------------------- [1]
        print("\n[1] a cold key computes once and is then served from cache")
        clock = _Clock()
        cache = CM.ResponseCache(clock=clock)
        calls = {"n": 0}

        def producer():
            calls["n"] += 1
            return {"value": calls["n"]}

        v1 = await cache.get("k", producer, ttl_s=10.0)
        v2 = await cache.get("k", producer, ttl_s=10.0)
        c.check("first call computes", v1 == {"value": 1})
        c.check("second call inside the TTL does NOT recompute",
                v2 == {"value": 1} and calls["n"] == 1)
        c.check("the hit is counted", cache.stats.hits == 1)

        # -------------------------------------------------------------- [2]
        print("\n[2] SINGLE-FLIGHT: N concurrent cold callers -> ONE producer run")
        clock = _Clock()
        cache = CM.ResponseCache(clock=clock)
        runs = {"n": 0}

        def slow_producer():
            runs["n"] += 1
            time.sleep(0.15)          # real blocking work, in a worker thread
            return "computed"

        results = await asyncio.gather(*[
            cache.get("cold", slow_producer, ttl_s=10.0) for _ in range(10)
        ])
        c.check("all 10 callers got the value", results == ["computed"] * 10)
        c.check("the producer ran EXACTLY once for 10 concurrent callers — a "
                "cache that stampedes on every miss does not help a 1.5s "
                "poller at all", runs["n"] == 1)
        c.check("the collapsed waiters are counted", cache.stats.collapsed == 9)

        # -------------------------------------------------------------- [3]
        print("\n[3] THE ACTUAL BUG: a slow producer must not delay a fast one")
        cache = CM.ResponseCache(clock=time.monotonic)

        def slow():                    # stands in for /api/controls/coverage
            time.sleep(0.60)
            return "coverage"

        def fast():                    # stands in for /api/health
            return "health"

        t0 = time.perf_counter()
        slow_task = asyncio.create_task(cache.get("slow", slow, ttl_s=10.0))
        await asyncio.sleep(0)         # let it reach the thread
        t_fast0 = time.perf_counter()
        got_fast = await cache.get("fast", fast, ttl_s=10.0)
        fast_ms = (time.perf_counter() - t_fast0) * 1000
        await slow_task
        total_ms = (time.perf_counter() - t0) * 1000
        c.check("the fast endpoint returned its own value", got_fast == "health")
        c.check(f"the fast request finished in {fast_ms:.0f}ms while a 600ms "
                f"producer was in flight — this is the head-of-line blocking "
                f"that made /api/health the SLOWEST endpoint at 11.2s",
                fast_ms < 250)
        c.check(f"the slow one still completed ({total_ms:.0f}ms) — it was "
                f"offloaded, not dropped", total_ms >= 550)

        # -------------------------------------------------------------- [4]
        print("\n[4] STALE-WHILE-REVALIDATE: an expired TTL never charges the "
              "full cost to the next caller")
        clock = _Clock()
        cache = CM.ResponseCache(clock=clock)
        gen = {"n": 0}

        def counted():
            gen["n"] += 1
            return gen["n"]

        first = await cache.get("swr", counted, ttl_s=5.0)
        clock.advance(99.0)            # now well past the TTL
        stale = await cache.get("swr", counted, ttl_s=5.0)
        c.check("the expired read returns the previous value IMMEDIATELY "
                "rather than blocking on a recompute",
                first == 1 and stale == 1)
        c.check("a stale serve is counted as such, not as a hit",
                cache.stats.stale_serves == 1)
        await _settle(cache)
        fresh = await cache.get("swr", counted, ttl_s=5.0)
        c.check("the background refresh did land, so the next read is new data",
                fresh == 2)
        c.check("and it refreshed exactly once, not once per stale read",
                gen["n"] == 2)

        # -------------------------------------------------------------- [5]
        print("\n[5] a FAILED refresh keeps the last good value")
        clock = _Clock()
        cache = CM.ResponseCache(clock=clock)
        mode = {"fail": False}

        def flaky():
            if mode["fail"]:
                raise RuntimeError("probe exploded")
            return "good"

        await cache.get("f", flaky, ttl_s=5.0)
        mode["fail"] = True
        clock.advance(99.0)
        held = await cache.get("f", flaky, ttl_s=5.0)
        await _settle(cache)
        held2 = await cache.get("f", flaky, ttl_s=5.0)
        c.check("the last good value survives a failing refresh", held == "good")
        c.check("and keeps being served rather than turning into an error",
                held2 == "good")
        c.check("the failure is COUNTED, not swallowed silently",
                cache.stats.refresh_failures >= 1)
        snap = cache.snapshot()
        c.check("the failure is visible from outside the process — a cache "
                "that quietly stopped refreshing looks exactly like a system "
                "where nothing is happening",
                snap["keys"]["f"]["last_error"] is not None
                and "probe exploded" in snap["keys"]["f"]["last_error"])

        # -------------------------------------------------------------- [6]
        print("\n[6] a COLD failure RAISES — it must never fabricate a value")
        cache = CM.ResponseCache(clock=_Clock())

        def always_fails():
            raise RuntimeError("no data available")

        raised = False
        try:
            await cache.get("never", always_fails, ttl_s=5.0)
        except RuntimeError:
            raised = True
        c.check("a cold producer failure propagates so the endpoint can return "
                "an honest error and the UI can render its no-data sentinel — "
                "serving 0 here would recreate the exact bug 30827db fixed",
                raised)
        c.check("nothing was cached from the failure",
                cache.age_s("never") is None)

        # -------------------------------------------------------------- [7]
        print("\n[7] keys do not bleed into each other")
        cache = CM.ResponseCache(clock=_Clock())
        a = await cache.get("a", lambda: "A", ttl_s=10.0)
        b = await cache.get("b", lambda: "B", ttl_s=10.0)
        c.check("distinct keys hold distinct values", a == "A" and b == "B")

        # -------------------------------------------------------------- [8]
        print("\n[8] a hung cold producer times out instead of hanging forever")
        cache = CM.ResponseCache(clock=time.monotonic)

        def hangs():
            time.sleep(30.0)
            return "never seen"

        timed_out = False
        try:
            await cache.get("hang", hangs, ttl_s=10.0, timeout_s=0.25)
        except (asyncio.TimeoutError, TimeoutError):
            timed_out = True
        c.check("the request gives up rather than wedging the endpoint — "
                "an unbounded wait is the failure this module exists to "
                "prevent", timed_out)

        # -------------------------------------------------------------- [9]
        print("\n[9] the configured TTLs match the measured producer costs")
        c.check("coverage (~3.3s of host probing) is cached far longer than "
                "the 1.5s poll interval", CM.TTL_COVERAGE >= 15.0)
        c.check("stats/events stay near-live — the win there is single-flight, "
                "not staleness",
                CM.TTL_STATS <= 2.0 and CM.TTL_EVENTS <= 2.0)

    asyncio.run(run())
    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
