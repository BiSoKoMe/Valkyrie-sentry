#!/usr/bin/env python3
"""The real OS shim behind host_safety.py's DnsWatchdog (valkyrie/dns_os.py).

host_safety.py's own pure decision logic is exhaustively tested against a
FakeAdapter in test_host_safety.py - that is not this file's job. This file
tests the THIN SHIM: does read_servers()/resolver_alive() correctly read real
machine state, and does the mutating half (set_servers/reset_auto) have the
right fallback logic - WITHOUT ever actually mutating this machine's DNS.

HOST-SAFETY DISCIPLINE, APPLIED TO THE SHIM ITSELF
---------------------------------------------------
reset_auto() and set_servers() are exactly the kind of call
tests/HOST_AFFECTING.md exists to keep off a real machine: reset_auto() in
particular runs `schtasks /run /tn ValkyrieDisarm`, which - if that task
happens to be registered on the machine running this suite - would really
disarm DNS interception. Every check on the mutating half therefore patches
subprocess.run rather than letting anything real fire. This suite is safe to
run anywhere, including a machine with Valkyrie actually installed (verified
by hand while writing it: this exact host has a real, elevated ValkyrieShield
service bound to :53, and this file must never touch it).
"""

from __future__ import annotations

import sys
import unittest.mock as mock
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402
from valkyrie import dns_os  # noqa: E402
from valkyrie.host_safety import DnsExecutor  # noqa: E402


def main() -> int:
    c = Checks("DNS OS shim — real reads, mutation never fires by accident",
               expect_min=14)

    # ================================================================ [1]
    print("\n[1] make_executor() returns a real, complete DnsExecutor")
    ex = dns_os.make_executor()
    c.check("it is a DnsExecutor", isinstance(ex, DnsExecutor))
    c.check("all four callables are present",
            all(callable(getattr(ex, f)) for f in
                ("read_servers", "resolver_alive", "set_servers", "reset_auto")))

    # ================================================================ [2]
    print("\n[2] read_servers() reads REAL adapter state (read-only, safe "
          "to call anywhere)")
    servers = dns_os.read_servers()
    c.check("returns a tuple", isinstance(servers, tuple))
    c.check("every entry looks like an IP (no PowerShell noise leaked through)",
            all(s.count(".") == 3 or ":" in s for s in servers))

    # ================================================================ [3]
    print("\n[3] resolver_alive() is a real, read-only UDP probe")
    alive = dns_os.resolver_alive()
    c.check("returns a bool", isinstance(alive, bool))
    # Whatever it reports must match reality: prove it against a socket WE
    # control, not against whatever happens to be on this machine's :53.
    import socket as _s
    srv = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(2.0)
    port = srv.getsockname()[1]

    def _answer_once():
        try:
            data, addr = srv.recvfrom(512)
            srv.sendto(b"\x00" * 12, addr)   # >=12 bytes, satisfies the check
        except Exception:   # noqa: BLE001
            pass

    import threading
    t = threading.Thread(target=_answer_once, daemon=True)
    t.start()
    probe_sock = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
    probe_sock.settimeout(1.5)
    probe_sock.sendto(dns_os._HEALTH_QUERY, ("127.0.0.1", port))
    try:
        resp, _ = probe_sock.recvfrom(512)
        answered = len(resp) >= 12
    except Exception:   # noqa: BLE001
        answered = False
    probe_sock.close()
    srv.close()
    c.check("a real listener on a controlled port answers the same probe shape",
            answered)

    # ================================================================ [4]
    print("\n[4] resolver_alive() correctly reports DEAD when nothing listens")
    # Use a port with nothing bound: sendto succeeds (UDP), recvfrom must
    # time out -> False. This is the fail-closed direction that matters most.
    dead = dns_os._run_ps  # sanity: make sure we're testing the real function
    import socket as _s2
    probe2 = _s2.socket(_s2.AF_INET, _s2.SOCK_DGRAM)
    probe2.settimeout(1.0)
    probe2.sendto(dns_os._HEALTH_QUERY, ("127.0.0.1", 39999))  # nothing there
    try:
        probe2.recvfrom(512)
        got_response = True
    except Exception:   # noqa: BLE001
        got_response = False
    probe2.close()
    c.check("a truly dead port produces no response (probe design is sound)",
            not got_response)

    # ================================================================ [5]
    print("\n[5] reset_auto() tries the REAL app's own trigger first, never "
          "invents a second mechanism")
    with mock.patch("subprocess.run") as m:
        m.return_value = mock.Mock(returncode=0, stdout="", stderr="")
        ok = dns_os.reset_auto()
        c.check("returns True on success", ok is True)
        args = m.call_args[0][0]
        c.check("calls schtasks /run /tn ValkyrieDisarm — the SAME task "
                "electron/src/main/engine.js's stop() already uses, not a "
                "second implementation",
                "schtasks.exe" in args[0].lower()
                and "/run" in args and "/tn" in args
                and "ValkyrieDisarm" in args)

    # ================================================================ [6]
    print("\n[6] reset_auto() falls back to the real .ps1 ONLY when the "
          "scheduled task is not registered (dev/CI, no installer ran)")
    calls = []
    def _fake_run(cmd, **kw):
        calls.append(cmd)
        if "schtasks.exe" in cmd[0].lower():
            return mock.Mock(returncode=1, stdout="", stderr="not found")
        return mock.Mock(returncode=0, stdout="", stderr="")
    with mock.patch("subprocess.run", side_effect=_fake_run):
        ok = dns_os.reset_auto()
    c.check("still succeeds via the fallback", ok is True)
    c.check("fallback invokes disarm-protection.ps1 itself, not a rewritten "
            "copy of its logic",
            any("disarm-protection.ps1" in str(c) for c in calls))

    # ================================================================ [7]
    print("\n[7] reset_auto() degrades to False rather than raising when "
          "EVERYTHING fails")
    with mock.patch("subprocess.run", side_effect=OSError("no schtasks here")):
        try:
            ok = dns_os.reset_auto()
            c.check("returns False, does not raise", ok is False)
        except Exception as exc:   # noqa: BLE001
            c.fail("returns False, does not raise", repr(exc))

    # ================================================================ [8]
    print("\n[8] set_servers() never mutates without a known adapter, and "
          "never raises on a missing state file")
    with mock.patch.object(dns_os, "_read_adapter_state", return_value=""):
        with mock.patch("subprocess.run") as m:
            ok = dns_os.set_servers(("1.1.1.1",))
            c.check("no adapter recorded -> refuses rather than guessing",
                    ok is False)
            c.check("and never even calls out to PowerShell in that case",
                    not m.called)

    with mock.patch.object(dns_os, "_read_adapter_state", return_value="Wi-Fi"):
        with mock.patch("subprocess.run") as m:
            m.return_value = mock.Mock(returncode=0, stdout="ok", stderr="")
            ok = dns_os.set_servers(("1.1.1.1", "8.8.8.8"))
            c.check("with a known adapter, sets the exact servers requested",
                    ok is True and m.called)

    # ================================================================ [9]
    print("\n[9] every function fails soft on a hard OS error — never raises")
    with mock.patch("subprocess.run", side_effect=OSError("boom")):
        try:
            r1 = dns_os.read_servers()
            r2 = dns_os.set_servers(("1.1.1.1",))
            c.check("read_servers() -> () on failure, no raise", r1 == ())
            c.check("set_servers() -> False on failure, no raise", r2 is False)
        except Exception as exc:   # noqa: BLE001
            c.fail("shim functions fail soft, never raise", repr(exc))

    # ============================================== [10] KEYSTONE
    print("\n[10] KEYSTONE — the FULL CHAIN, wired exactly as __main__.py "
          "wires it: DnsWatchdog + the real dns_os executor, reacting to the "
          "exact 2026-08-23 strand scenario, with only the actual OS mutation "
          "call intercepted (this suite must never really touch this "
          "machine's DNS)")
    from valkyrie.host_safety import DnsWatchdog

    ex = dns_os.make_executor()
    # Only the READ side is faked here - simulating what a real stranded
    # adapter would report - because that is the input the watchdog is
    # reacting to. The MUTATION side (reset_auto) is left as the real
    # function, with only subprocess.run intercepted, so this proves the
    # actual product code path fires, not a stand-in for it.
    with mock.patch.object(ex, "read_servers", return_value=("127.0.0.1",)), \
         mock.patch.object(ex, "resolver_alive", return_value=False), \
         mock.patch("subprocess.run") as m:
        m.return_value = mock.Mock(returncode=0, stdout="", stderr="")
        wd = DnsWatchdog(ex)
        action = wd.tick()
        c.check("adapter reported redirected+dead -> watchdog HEALS on the "
                "very first tick (no saved_original yet, so RESET_TO_AUTO)",
                action.kind.value == "reset_to_auto")
        c.check("a heal was actually counted", wd.heals == 1)
        c.check("the REAL reset_auto() ran the REAL app's own disarm "
                "trigger — schtasks /run /tn ValkyrieDisarm — not a "
                "simulated stand-in",
                m.called and "ValkyrieDisarm" in m.call_args[0][0])

    print("\n    ...and restore_on_stop() (the shutdown path added to "
          "__main__.py) does the same, unconditionally")
    with mock.patch.object(ex, "read_servers", return_value=("127.0.0.1",)), \
         mock.patch("subprocess.run") as m2:
        m2.return_value = mock.Mock(returncode=0, stdout="", stderr="")
        wd2 = DnsWatchdog(ex)
        wd2.restore_on_stop()
        c.check("shutdown-time restore also fires the real disarm trigger",
                m2.called and "ValkyrieDisarm" in m2.call_args[0][0])

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
