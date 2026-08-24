"""Response cache for the API — the fix for a self-inflicted availability bug.

WHAT WAS ACTUALLY WRONG
-----------------------
Measured against the live engine (75 MB DB, 44,544 events), each endpoint
alone, sequentially:

    /api/controls/coverage   22,441 ms
    /api/stats                2,530 ms
    /api/health               1,758 ms
    /api/events                 981 ms
    /api/components             477 ms

Then the same five requested CONCURRENTLY, which is what the Electron app
actually does:

    /api/stats                6,326 ms
    /api/events               7,262 ms
    /api/components           9,092 ms
    /api/controls/coverage   10,254 ms
    /api/health              11,175 ms   <-- the trivial one is the SLOWEST

That last line is the whole diagnosis. ``/api/health`` does essentially no
work, so 11.2 seconds is not its cost — it is time spent waiting behind other
requests. Every one of server.py's 57 route handlers is declared ``async
def``, and FastAPI runs an ``async def`` handler ON the event loop rather than
in a threadpool. A handler that blocks therefore blocks *the entire server*,
including the accept loop. With a 1.5 s client poll and multi-second handlers,
the queue only grows: that is the accept-backlog exhaustion that wedged the
engine, and it is why the wedged socket stayed in LISTEN while connections
were reset.

Two separate faults, needing two separate fixes, both here:

1. **Blocking the loop.** Work is handed to ``asyncio.to_thread`` so a slow
   probe can never again starve every other endpoint. This alone decouples
   ``/api/health`` from ``/api/controls/coverage``.

2. **Recomputing per request.** Coverage genuinely costs ~3.3 s of host
   probing (``secure_file`` 1.74 s, ``dns_sinkhole`` 0.52 s,
   ``killchain_correlator`` 0.44 s, ``etw_sysmon`` 0.43 s). No amount of
   threading makes that cheap enough to run every 1.5 s. It has to be
   computed once and served many times — the precedent set by
   ``sensor_tamper.current_status()`` and by the asset-inventory fix in
   dfee807, which took that endpoint from 33.9 s to 0.1 s the same way.

WHAT THIS DELIBERATELY DOES NOT DO
----------------------------------
It never invents a value. A cold key whose producer fails raises, so the
endpoint returns an honest error and the UI renders its "no data" sentinel.
Serving a zero here would recreate exactly the bug the UI was just fixed for:
a fabricated 0 is indistinguishable from a real 0, and in a security product
"0 threats blocked" is the single most dangerous number to make up.

Stale data IS served, but only data that was genuinely observed at a known
time, and only while a refresh of it is already in flight.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class _Entry:
    """The last value a producer successfully returned, and when."""
    value: Any
    computed_at: float
    # Set when a REFRESH failed while a previous good value exists. The value
    # stays; this records that it is no longer being updated, so a caller (or
    # /api/cache/stats) can tell "quiet" from "broken".
    last_error: Optional[str] = None
    error_at: float = 0.0


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    stale_serves: int = 0
    collapsed: int = 0          # concurrent callers that joined an in-flight compute
    refresh_failures: int = 0

    def as_dict(self) -> dict:
        return {"hits": self.hits, "misses": self.misses,
                "stale_serves": self.stale_serves,
                "collapsed": self.collapsed,
                "refresh_failures": self.refresh_failures}


class ResponseCache:
    """TTL cache with single-flight and stale-while-revalidate.

    Three behaviours, each earning its place:

    ``fresh``
        Age below the TTL: return immediately, no work.

    ``stale-while-revalidate``
        Age above the TTL but a good value exists: return that value NOW and
        refresh in the background. This is what keeps a 3.3 s probe off the
        request path permanently rather than only between polls. Without it,
        every TTL expiry would hand one unlucky request the full cost.

    ``single-flight``
        N concurrent callers of a cold key run the producer ONCE and all await
        the same result. A plain TTL cache under a concurrent poller is barely
        better than no cache at all, because every miss stampedes.

    The clock is injectable so tests never sleep.
    """

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._entries: dict[str, _Entry] = {}
        self._inflight: dict[str, asyncio.Task] = {}
        self.stats = CacheStats()

    # ------------------------------------------------------------------ read
    async def get(self, key: str, producer: Callable[[], Any], *,
                  ttl_s: float, timeout_s: Optional[float] = None) -> Any:
        """Return ``producer()``'s value, computing it at most every ``ttl_s``.

        ``producer`` is a plain synchronous callable and is ALWAYS run in a
        worker thread — never inline on the event loop.

        Raises whatever ``producer`` raises, but only when there is no
        previously good value to fall back on. See the module docstring: an
        honest error beats a fabricated number.
        """
        now = self._clock()
        entry = self._entries.get(key)

        if entry is not None and (now - entry.computed_at) < ttl_s:
            self.stats.hits += 1
            return entry.value

        if entry is not None:
            # Stale but real. Serve it and refresh out of band, so the cost of
            # a TTL expiry is never charged to whichever request happens to
            # arrive first.
            self.stats.stale_serves += 1
            self._ensure_refresh(key, producer)
            return entry.value

        # Cold: nothing observed yet, so this caller genuinely has to wait.
        self.stats.misses += 1
        task = self._ensure_refresh(key, producer)
        if timeout_s is None:
            return await asyncio.shield(task)
        # shield: a timeout abandons THIS caller's wait, it does not cancel the
        # shared computation other callers are also waiting on.
        return await asyncio.wait_for(asyncio.shield(task), timeout_s)

    # --------------------------------------------------------------- refresh
    def _ensure_refresh(self, key: str, producer: Callable[[], Any]) -> asyncio.Task:
        task = self._inflight.get(key)
        if task is not None and not task.done():
            self.stats.collapsed += 1
            return task
        task = asyncio.get_running_loop().create_task(self._run(key, producer))
        self._inflight[key] = task
        # A background (stale-path) refresh has no awaiter. Without this,
        # a raising task would surface as "Task exception was never retrieved"
        # noise on the event loop instead of being handled here.
        task.add_done_callback(lambda t: t.cancelled() or t.exception())
        return task

    async def _run(self, key: str, producer: Callable[[], Any]) -> Any:
        try:
            value = await asyncio.to_thread(producer)
        except Exception as exc:                              # noqa: BLE001
            self.stats.refresh_failures += 1
            prev = self._entries.get(key)
            if prev is not None:
                # Keep the last good value and record why it stopped updating.
                prev.last_error = f"{type(exc).__name__}: {exc}"
                prev.error_at = self._clock()
                return prev.value
            raise
        finally:
            self._inflight.pop(key, None)
        self._entries[key] = _Entry(value, self._clock())
        return value

    # ----------------------------------------------------------------- debug
    def age_s(self, key: str) -> Optional[float]:
        entry = self._entries.get(key)
        return None if entry is None else self._clock() - entry.computed_at

    def snapshot(self) -> dict:
        """Per-key age and last refresh error — for /api/cache/stats.

        Exposed because a cache that silently stops refreshing looks exactly
        like a system where nothing is happening, and those must be
        distinguishable from outside the process.
        """
        return {
            "counters": self.stats.as_dict(),
            "keys": {
                k: {"age_s": round(self._clock() - e.computed_at, 3),
                    "last_error": e.last_error,
                    "stale_since_s": (round(self._clock() - e.error_at, 3)
                                      if e.error_at else None)}
                for k, e in self._entries.items()
            },
        }

    async def drain(self) -> None:
        """Await any background refreshes currently in flight.

        Stale-while-revalidate deliberately returns before its refresh
        finishes, so there is otherwise no way to observe "the refresh
        landed" — a caller that spins on ``asyncio.sleep(0)`` yields to the
        event loop but never waits for the worker-thread round trip, which
        makes it a race that passes under light load and fails under heavy
        load. Also useful on shutdown, to avoid abandoning a refresh midway.
        """
        while True:
            pending = [t for t in self._inflight.values() if not t.done()]
            if not pending:
                return
            await asyncio.gather(*pending, return_exceptions=True)

    def invalidate(self, key: str) -> None:
        self._entries.pop(key, None)

    def clear(self) -> None:
        self._entries.clear()


# Process-wide cache used by the API routes.
CACHE = ResponseCache()

# TTLs. Chosen against the measured cost of each producer and how fast the
# underlying truth can actually change -- not uniform, because the endpoints
# are not alike.
#
#   coverage   30s : ~3.3s of host probing (service state, registry, ACLs).
#                    None of that changes meaningfully between two 1.5s polls;
#                    a service stopping is still surfaced within 30s.
#   stats       1s : cheap (~103ms of SQL) but polled hardest. The TTL matters
#                    less than the single-flight -- the win is collapsing
#                    concurrent duplicate pollers, not skipping the query.
#   events      1s : same shape as stats; it is a LIMIT 200 read.
#   components  2s : registry snapshot of subsystem health.
TTL_COVERAGE = 30.0
TTL_STATS = 1.0
TTL_EVENTS = 1.0
TTL_COMPONENTS = 2.0

# A cold producer that hangs must not hang the request forever -- that is the
# failure this whole module exists to prevent. Generous enough that a genuinely
# slow first coverage pass still succeeds.
COLD_TIMEOUT_S = 25.0
