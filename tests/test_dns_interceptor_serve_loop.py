#!/usr/bin/env python3
"""valkyrie/dns_interceptor.py's DNSInterceptor._serve_loop() error handling.

Windows routinely surfaces an EARLIER reply's ICMP port-unreachable (the
destination stopped listening - a browser tab closed before the answer
arrived) as ConnectionResetError / WinError 10054 on the NEXT recvfrom() of
a UDP socket - a normal, per-packet condition for a connectionless "server",
unrelated to whatever packet actually raised it. The loop used to treat any
OSError as fatal and exit the thread entirely, killing DNS resolution for
the WHOLE MACHINE (127.0.0.1 is the configured DNS server) until the next
self-heal cycle - up to 30s later - noticed and restarted it. Confirmed live
via the self-heal event history in the owner's real database: dns_interceptor
flapped unhealthy->recovered several times within a couple of hours, always
in a single check cycle, always via a real stop()+start() the recovery path
actually performs.

These checks call ``_serve_loop`` directly and synchronously (no real thread,
no real socket, no real network) against a scripted fake socket whose
``recvfrom`` raises a pre-programmed sequence of exceptions, and prove three
properties: bounded transient errors do not kill the loop; unbounded errors
still do (a genuinely broken socket must not spin forever); and an error
raised after ``stop()`` already flipped ``_running`` False exits immediately,
as normal shutdown always has.
"""
from __future__ import annotations

import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks


class _ScriptedSocket:
    """recvfrom() pops and raises/calls the next scripted item."""

    def __init__(self, script: list) -> None:
        self._script = list(script)

    def recvfrom(self, bufsize: int):
        item = self._script.pop(0)
        if callable(item):
            item()
        raise item if isinstance(item, BaseException) else RuntimeError(
            "scripted item was neither an exception nor consumed by call")


def _make_interceptor():
    from valkyrie.dns_interceptor import DNSInterceptor
    # Bypass __init__ (needs a Store, BlocklistManager, etc.) - _serve_loop
    # only ever touches self._running and self._sock.
    obj = object.__new__(DNSInterceptor)
    return obj


def main() -> int:
    c = Checks("DNSInterceptor._serve_loop error resilience", expect_min=5)

    print("[1] a handful of consecutive transient OSErrors (the WinError "
          "10054 shape) do not kill the loop - it keeps consuming events, "
          "never breaking early")
    dns = _make_interceptor()
    dns._running = True
    script = [ConnectionResetError(10054, "forcibly closed")] * 5 + [socket.timeout()] * 2

    def _exhaust_then_stop():
        dns._running = False
        return OSError("script exhausted")

    fake = _ScriptedSocket(script)
    orig_recvfrom = fake.recvfrom

    def _recvfrom(bufsize):
        if not fake._script:
            dns._running = False
            raise OSError("script exhausted - stop() closed the socket")
        return orig_recvfrom(bufsize)

    fake.recvfrom = _recvfrom
    dns._sock = fake
    dns._serve_loop()
    c.check("all 7 scripted events were consumed - the loop never bailed "
            "early on a transient error", fake._script == [])

    print("\n[2] UNBOUNDED consecutive errors (a genuinely broken socket, "
          "never a real packet in between) still exit the loop - the fix "
          "must not trade a false death for an infinite spin")
    dns2 = _make_interceptor()
    dns2._running = True
    fake2 = _ScriptedSocket(
        [ConnectionResetError(10054, "forcibly closed")] * 30)
    dns2._sock = fake2
    dns2._serve_loop()
    c.check("the loop exited before exhausting all 30 (did not spin forever)",
            len(fake2._script) > 0)
    c.check("it exited at exactly the documented bound (21 consumed, 9 left)",
            len(fake2._script) == 9)

    print("\n[3] an OSError raised AFTER stop() already flipped _running "
          "False exits immediately - the ordinary shutdown path")
    dns3 = _make_interceptor()
    dns3._running = True

    def _stop_then_raise():
        dns3._running = False

    fake3 = _ScriptedSocket([_stop_then_raise])

    def _recvfrom3(bufsize):
        item = fake3._script.pop(0)
        item()
        raise OSError("socket closed by stop()")

    fake3.recvfrom = _recvfrom3
    dns3._sock = fake3
    dns3._serve_loop()
    c.check("exits on the very first iteration once _running is False",
            fake3._script == [])
    c.check("_running stayed False (stop() was not undone)",
            dns3._running is False)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
