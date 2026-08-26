#!/usr/bin/env python3
"""No dashboard route may run blocking work on the event loop (regression).

``test_edr_api_nonblocking.py`` fixed this for the EDR reads. It was never
fixed for the REST of the API, and that is what produced the desktop app's
"Engine unreachable" screen on a freshly installed, perfectly healthy engine.

Observed live on the owner's machine: the ValkyrieShield service was Running,
uvicorn held ``127.0.0.1:8090`` in LISTEN, and the engine was still writing to
its 91 MB database -- while the app had been showing "Engine unreachable" for
hours. ``netstat`` explained it: 1 LISTEN socket and **202 CLOSE_WAIT** sockets
on port 8090, with 202 matching FIN_WAIT_2 on the app side. The kernel had
accepted 202 connections into the backlog; uvicorn had read none of them,
because its single event loop was blocked inside a synchronous handler. Once
the backlog saturated, new connects were refused outright -- a listening port
that answers no one.

The cause was structural, not one bad line: 45 of the 60 routes were declared
``async def`` while containing no ``await`` at all -- plain synchronous code
(SQLite aggregates, registry reads, ``netsh``/PowerShell spawns) executing
directly on the loop that also runs ``accept()``. Any one of them stalled
every other request, ``/api/health`` included. ``/api/health`` is trivially
cheap and went down purely as collateral, which is the point: on a single
loop, one blocking handler takes the liveness probe down with it.

Three checks, deliberately different in kind:

  1. STATIC -- no route function is ``async def`` without an ``await`` (bar the
     documented ``_LOOP_ONLY`` exception). This is the rule that is cheap to
     violate by accident when adding an endpoint, and it catches the whole
     class at once rather than one endpoint at a time.
  2. BEHAVIOURAL (stall) -- with a store whose queries are slow, ``/api/ping``
     still answers promptly while a slow read is in flight.
  3. BEHAVIOURAL (queue) -- ``/api/ping`` also stays fast when 60 blocking
     requests have saturated the threadpool the fix offloads them to. Moving
     blocking work off the loop trades a stalled loop for a bounded worker
     pool, so the probe gets a second way to go slow; this pins that shut.
"""

from __future__ import annotations

import ast
import asyncio
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks, skip_file  # noqa: E402

SERVER_PY = _ROOT / "valkyrie" / "web" / "server.py"
SLOW_DB_S = 0.80

_ROUTE_DECORATORS = ("app.get", "app.post", "app.put", "app.delete",
                     "app.patch", "app.websocket")

# Handlers that must stay ON the event loop, and so are allowed to be
# `async def` with no `await`. The bar is absolute: the body does no I/O, takes
# no lock and touches no state, so it cannot block the loop it runs on.
#
# Only /api/ping qualifies, and it has to: sync handlers are dispatched through
# a threadpool with a finite worker count (anyio's default is 40), so a sync
# ping QUEUES behind saturated workers -- measured at 1094ms with 40 slow reads
# in flight against ~3ms idle. A liveness probe that gets slower the busier the
# server is reports load as death, which is the failure it exists to rule out.
# Adding a name here is a claim that the handler does NO blocking work at all.
_LOOP_ONLY = {"ping"}


def _route_handlers(tree: ast.AST):
    """Yield (name, lineno, is_async, has_await) for every decorated route."""
    for node in ast.walk(tree):
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        decorators = []
        for d in node.decorator_list:
            try:
                decorators.append(ast.unparse(d))
            except Exception:  # noqa: BLE001 - unparse is best-effort here
                pass
        if not any(marker in d for d in decorators for marker in _ROUTE_DECORATORS):
            continue
        has_await = any(
            isinstance(n, (ast.Await, ast.AsyncWith, ast.AsyncFor))
            for n in ast.walk(node)
        )
        yield node.name, node.lineno, isinstance(node, ast.AsyncFunctionDef), has_await


class _SlowStore:
    """Store stand-in whose reads block like queries against a large DB."""

    def recent_events(self, limit=200):
        time.sleep(SLOW_DB_S)
        return []

    def stats_24h(self):
        time.sleep(SLOW_DB_S)
        return {}

    def subscribe(self, _cb):
        pass

    def unsubscribe(self, _cb):
        pass

    def __getattr__(self, _name):
        # Any other query the stats builder reaches for is equally slow.
        def _slow(*_a, **_kw):
            time.sleep(SLOW_DB_S)
            return {}
        return _slow


def main() -> int:
    c = Checks("dashboard routes must not block the event loop", expect_min=4)

    # --- 1. STATIC: no route is `async def` without an `await` ---
    tree = ast.parse(SERVER_PY.read_text(encoding="utf-8"))
    handlers = list(_route_handlers(tree))
    offenders = [(n, ln) for n, ln, is_async, has_await in handlers
                 if is_async and not has_await and n not in _LOOP_ONLY]
    c.check(f"found route handlers to inspect ({len(handlers)})", len(handlers) >= 50)
    c.check(
        "no route is 'async def' without an await -- such a body runs its "
        "blocking work directly on the event loop and stalls the whole API "
        "(offenders: "
        + (", ".join(f"{n} (L{ln})" for n, ln in offenders) if offenders else "none")
        + ")",
        not offenders,
    )

    # --- 2. BEHAVIOURAL: liveness stays answerable under a slow read ---
    try:
        import httpx
        from valkyrie.web import server as S
    except ImportError as exc:
        # The static check above already ran and is the load-bearing one.
        print(f"  (behavioural check skipped: dependency missing: {exc})")
        return c.finish()

    S.state.store = _SlowStore()
    S.state.start_time = time.time()
    app = S.create_app()

    async def run() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport,
                                     base_url="http://test") as client:
            slow = asyncio.create_task(client.get("/api/events"))
            await asyncio.sleep(0.05)          # let it get into its thread
            t0 = time.perf_counter()
            await client.get("/api/ping")
            ping_ms = (time.perf_counter() - t0) * 1000
            await slow
            c.check(
                f"/api/ping answered in {ping_ms:.0f}ms while a "
                f"{int(SLOW_DB_S * 1000)}ms store read was in flight "
                f"(blocking-on-loop would make it >= {int(SLOW_DB_S * 1000)}ms)",
                ping_ms < SLOW_DB_S * 1000 * 0.5,
            )

            # --- 3. Liveness must not QUEUE either ---
            # Offloading blocking work to the threadpool trades a stalled loop
            # for a bounded worker pool, so the probe has a second way to go
            # slow: waiting for a free worker. Saturate the pool well past its
            # default 40 workers and require /api/ping to stay instant, which
            # it can only do by running on the event loop itself.
            flood = [asyncio.create_task(client.get("/api/doh/status"))
                     for _ in range(60)]
            await asyncio.sleep(0.20)          # let them claim every worker
            t0 = time.perf_counter()
            await client.get("/api/ping")
            sat_ms = (time.perf_counter() - t0) * 1000
            await asyncio.gather(*flood, return_exceptions=True)
            c.check(
                f"/api/ping answered in {sat_ms:.0f}ms with 60 blocking "
                f"requests saturating the threadpool (a threadpool-dispatched "
                f"ping would queue behind them for ~{int(SLOW_DB_S * 1000)}ms)",
                sat_ms < SLOW_DB_S * 1000 * 0.5,
            )

    asyncio.run(run())
    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
