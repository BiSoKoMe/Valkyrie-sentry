#!/usr/bin/env python3
"""valkyrie/web/server.py's _quiet_proactor_reset_handler.

Windows' ProactorEventLoop logs a full traceback every time a loopback
client (the Electron app polling /api/* routes, a browser tab closing
mid-request) resets the TCP connection - "Exception in callback
_ProactorBasePipeTransport._call_connection_lost(None)" / ConnectionResetError.
The disconnect was already handled correctly; this is asyncio's own cleanup
racing itself, not an application error. Measured 411 of these in one live
service log, which is also 411 chances to bury a genuinely new traceback.

These checks never touch a real event loop or socket - they call the handler
directly with fake ``context`` dicts and a fake ``loop`` that records whether
its ``default_exception_handler`` was invoked, proving the filter is narrow:
it suppresses exactly the documented shape and nothing else.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks


class _FakeLoop:
    def __init__(self) -> None:
        self.default_calls: list[dict] = []

    def default_exception_handler(self, context: dict) -> None:
        self.default_calls.append(context)


def main() -> int:
    from valkyrie.web.server import _quiet_proactor_reset_handler

    c = Checks("quiet proactor connection-reset handler", expect_min=5)

    print("[1] the exact documented shape is suppressed")
    loop = _FakeLoop()
    _quiet_proactor_reset_handler(loop, {
        "message": "Exception in callback "
                   "_ProactorBasePipeTransport._call_connection_lost(None)",
        "exception": ConnectionResetError(10054, "forcibly closed"),
    })
    c.check("default_exception_handler was NOT called for the known-benign case",
            loop.default_calls == [])

    print("\n[2] ConnectionAbortedError in the same callback is also suppressed")
    loop2 = _FakeLoop()
    _quiet_proactor_reset_handler(loop2, {
        "message": "Exception in callback "
                   "_ProactorBasePipeTransport._call_connection_lost(None)",
        "exception": ConnectionAbortedError(10053, "aborted"),
    })
    c.check("ConnectionAbortedError variant suppressed too",
            loop2.default_calls == [])

    print("\n[3] a DIFFERENT exception type in the same callback is NOT hidden")
    loop3 = _FakeLoop()
    ctx3 = {
        "message": "Exception in callback "
                   "_ProactorBasePipeTransport._call_connection_lost(None)",
        "exception": RuntimeError("something actually broke"),
    }
    _quiet_proactor_reset_handler(loop3, ctx3)
    c.check("an unrelated exception still reaches the default handler",
            loop3.default_calls == [ctx3])

    print("\n[4] a ConnectionResetError from a DIFFERENT callback is NOT hidden")
    loop4 = _FakeLoop()
    ctx4 = {
        "message": "Exception in callback SomeOtherThing.other_method(None)",
        "exception": ConnectionResetError(10054, "forcibly closed"),
    }
    _quiet_proactor_reset_handler(loop4, ctx4)
    c.check("connection reset outside the documented callback still surfaces",
            loop4.default_calls == [ctx4])

    print("\n[5] a context with no exception at all is passed through untouched")
    loop5 = _FakeLoop()
    ctx5 = {"message": "some other loop diagnostic"}
    _quiet_proactor_reset_handler(loop5, ctx5)
    c.check("exception-less context reaches the default handler",
            loop5.default_calls == [ctx5])

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
