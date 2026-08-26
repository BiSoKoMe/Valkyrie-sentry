#!/usr/bin/env python3
"""Host safety — Valkyrie must never strand the host's network (host_safety.py).

The keystone is [X]: it reproduces the exact 2026-08-23 failure (adapter pointed
at 127.0.0.1, no resolver answering) and proves the watchdog frees the host. The
rest pins the fail-safe bias: at every ambiguous branch the host gets its
network back, and interception is left in place only when the resolver is proven
alive.

Pure logic + a fake executor, so this runs fully offline and touches no real
adapter.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402
from valkyrie.host_safety import (  # noqa: E402
    decide_dns_action, is_loopback_redirect, DnsActionKind, DnsExecutor,
    DnsWatchdog,
)


class FakeAdapter:
    """A fake network adapter the watchdog can drive without touching the OS."""
    def __init__(self, servers=()):
        self.servers = tuple(servers)
        self.resolver_up = False
        self.set_calls = []
        self.reset_calls = 0

    def executor(self):
        return DnsExecutor(
            read_servers=lambda: self.servers,
            resolver_alive=lambda: self.resolver_up,
            set_servers=self._set,
            reset_auto=self._reset,
        )

    def _set(self, servers):
        self.servers = tuple(servers)
        self.set_calls.append(tuple(servers))
        return True

    def _reset(self):
        self.servers = ()          # () models automatic/DHCP
        self.reset_calls += 1
        return True


def main() -> int:
    c = Checks("host safety — never strand the network", expect_min=22)

    # ================================================================ [1]
    print("\n[1] loopback-redirect detection is ALL, not ANY")
    c.check("all-loopback is a redirect", is_loopback_redirect(("127.0.0.1",)))
    c.check("::1 is a redirect", is_loopback_redirect(("::1",)))
    c.check("mixed (loopback + public) is NOT a redirect — host still resolves",
            not is_loopback_redirect(("127.0.0.1", "8.8.8.8")))
    c.check("empty (automatic/DHCP) is NOT a redirect",
            not is_loopback_redirect(()))
    c.check("a real public server is NOT a redirect",
            not is_loopback_redirect(("1.1.1.1",)))

    # ================================================================ [X] KEYSTONE
    print("\n[X] THE 2026-08-23 STRAND: adapter on 127.0.0.1, resolver dead, "
          "an original was saved -> restore it")
    a = decide_dns_action(("127.0.0.1",), resolver_alive=False,
                          saved_original=("75.75.75.75", "75.75.76.76"))
    c.check("stranded host triggers a RESTORE", a.kind == DnsActionKind.RESTORE_ORIGINAL)
    c.check("restores the EXACT pre-redirect servers",
            a.servers == ("75.75.75.75", "75.75.76.76"))
    c.check("the reason names the strand", "stranded" in a.reason.lower())

    # ================================================================ [2]
    print("\n[2] stranded with NO saved original -> reset to automatic (DHCP)")
    a = decide_dns_action(("127.0.0.1",), resolver_alive=False, saved_original=None)
    c.check("no saved original -> RESET_TO_AUTO", a.kind == DnsActionKind.RESET_TO_AUTO)
    # and a saved original that is ITSELF loopback is not trustworthy -> auto
    a2 = decide_dns_action(("127.0.0.1",), resolver_alive=False,
                           saved_original=("127.0.0.1",))
    c.check("a loopback 'original' is not trusted; reset to auto instead",
            a2.kind == DnsActionKind.RESET_TO_AUTO)

    # ================================================================ [3]
    print("\n[3] routed through us AND resolver answering -> LEAVE (healthy)")
    a = decide_dns_action(("127.0.0.1",), resolver_alive=True,
                          saved_original=("1.1.1.1",))
    c.check("healthy interception is left alone", a.kind == DnsActionKind.LEAVE)

    # ================================================================ [4]
    print("\n[4] not routed through us -> LEAVE, and learn the real DNS if unseen")
    a = decide_dns_action(("1.1.1.1",), resolver_alive=False, saved_original=None)
    c.check("real DNS with nothing saved -> SAVE_ORIGINAL",
            a.kind == DnsActionKind.SAVE_ORIGINAL and a.servers == ("1.1.1.1",))
    a2 = decide_dns_action(("1.1.1.1",), resolver_alive=False,
                           saved_original=("1.1.1.1",))
    c.check("real DNS already saved -> LEAVE", a2.kind == DnsActionKind.LEAVE)
    a3 = decide_dns_action((), resolver_alive=False, saved_original=None)
    c.check("automatic DNS is safe -> LEAVE (nothing to save)",
            a3.kind == DnsActionKind.LEAVE)

    # ================================================================ [5]
    print("\n[5] WATCHDOG end-to-end: it heals a stranded host on a tick")
    adapter = FakeAdapter(servers=("1.1.1.1",))       # start healthy
    wd = DnsWatchdog(adapter.executor())
    wd.tick()                                          # learns the real DNS
    c.check("watchdog recorded the real DNS", wd.saved_original == ("1.1.1.1",))
    # now a (legacy build / crash) redirect happens and the resolver is dead:
    adapter.servers = ("127.0.0.1",)
    adapter.resolver_up = False
    wd.tick()
    c.check("watchdog restored the host's real DNS", adapter.servers == ("1.1.1.1",))
    c.check("a heal was counted", wd.heals == 1)

    # ================================================================ [6]
    print("\n[6] WATCHDOG heals even with NO knowledge (post-crash cold start)")
    # Fresh watchdog, host already stranded, nothing saved (prior process died).
    adapter = FakeAdapter(servers=("127.0.0.1",))
    adapter.resolver_up = False
    wd = DnsWatchdog(adapter.executor())
    wd.tick()
    c.check("cold watchdog resets a stranded host to automatic",
            adapter.reset_calls == 1 and adapter.servers == ())
    c.check("heal counted on cold rescue", wd.heals == 1)

    # ================================================================ [7]
    print("\n[7] WATCHDOG never acts on a HEALTHY interception")
    adapter = FakeAdapter(servers=("127.0.0.1",))
    adapter.resolver_up = True                         # resolver answering
    wd = DnsWatchdog(adapter.executor())
    wd.tick()
    c.check("healthy interception is untouched",
            adapter.set_calls == [] and adapter.reset_calls == 0)

    # ================================================================ [8]
    print("\n[8] graceful stop restores a safe state, idempotently")
    adapter = FakeAdapter(servers=("1.1.1.1",))
    wd = DnsWatchdog(adapter.executor())
    wd.tick()                                          # learn real DNS
    adapter.servers = ("127.0.0.1",)                   # redirected while running
    act = wd.restore_on_stop()
    c.check("stop restored the exact original", adapter.servers == ("1.1.1.1",)
            and act.kind == DnsActionKind.RESTORE_ORIGINAL)
    # calling again when already safe is a no-op
    act2 = wd.restore_on_stop()
    c.check("stop is idempotent when already safe", act2.kind == DnsActionKind.LEAVE)

    # ================================================================ [9]
    print("\n[9] a watchdog that cannot READ the adapter does nothing (no blind acts)")
    def _boom():
        raise OSError("adapter unreadable")
    ex = DnsExecutor(read_servers=_boom, resolver_alive=lambda: False,
                     set_servers=lambda s: True, reset_auto=lambda: True)
    wd = DnsWatchdog(ex)
    act = wd.tick()
    c.check("unreadable adapter -> LEAVE, never a blind reset",
            act.kind == DnsActionKind.LEAVE)

    # ================================================================ [10]
    print("\n[10] a failing executor never crashes the watchdog")
    def _fail(*_):
        raise OSError("netsh failed")
    ex = DnsExecutor(read_servers=lambda: ("127.0.0.1",),
                     resolver_alive=lambda: False,
                     set_servers=_fail, reset_auto=_fail)
    wd = DnsWatchdog(ex)
    try:
        wd.tick()
        c.check("watchdog survived an executor exception", True)
        c.check("the error was recorded, not raised", len(wd.status()["errors"]) >= 1)
    except Exception as exc:  # noqa: BLE001
        c.fail("watchdog survived an executor exception", repr(exc))
        c.fail("the error was recorded, not raised", "raised")

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
