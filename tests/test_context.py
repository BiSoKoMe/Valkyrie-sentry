#!/usr/bin/env python3
"""AppContext service container + dependency injection into the web server (ADR-0008).

Verifies the context's defaults and introspection, and — end to end — that a
context injected via create_app(ctx=...) is what the dashboard routes actually
read (not a module-global set behind their back).
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
    from valkyrie.context import AppContext

    print("\n=== AppContext ===\n")

    print("[1] Defaults: nothing wired")
    ctx = AppContext()
    _check("all services None", all(v is None for v in (
        ctx.store, ctx.firewall, ctx.blocklist, ctx.intelligence, ctx.edr,
        ctx.mac_randomizer, ctx.zero_log, ctx.self_heal)))
    _check("components() all False", not any(ctx.components().values()))
    _check("start_time defaults 0.0", ctx.start_time == 0.0)

    print("\n[2] Introspection reflects wired services")
    ctx = AppContext(store=object(), edr=object(), web_port=8090)
    comps = ctx.components()
    _check("store reported wired", comps["store"] is True)
    _check("edr reported wired", comps["edr"] is True)
    _check("firewall reported not wired", comps["firewall"] is False)
    _check("repr lists wired services", "store" in repr(ctx) and "edr" in repr(ctx))

    print("\n[3] Dependency injection reaches the web routes")
    try:
        from starlette.testclient import TestClient
        import valkyrie.web.server as web
        from valkyrie.store import Store
    except Exception as exc:   # noqa: BLE001
        print(f"  [-] SKIP — web/test stack unavailable: {exc}")
    else:
        with tempfile.TemporaryDirectory() as td:
            # A context WITHOUT a store: the route must report 'store not ready'.
            empty_ctx = AppContext()
            app = web.create_app(empty_ctx)
            _check("create_app adopts the injected ctx", web.state is empty_ctx)
            from testclient_compat import make_client
            client = make_client(app, "127.0.0.1")
            _check("no-store ctx -> /api/events 503",
                   client.get("/api/events").status_code == 503)

            # A context WITH a store: the same route now serves from it.
            store = Store(db_path=Path(td) / "ctx.db")
            store.start()
            wired_ctx = AppContext(store=store, web_port=8090)
            app2 = web.create_app(wired_ctx)
            _check("second injection swaps the active ctx", web.state is wired_ctx)
            client2 = make_client(app2, "127.0.0.1")
            _check("wired ctx -> /api/events 200",
                   client2.get("/api/events").status_code == 200)
            store.stop()

    print("\n" + "=" * 48)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
