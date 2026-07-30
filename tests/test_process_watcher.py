"""Tests for process_watcher.py — the port -> process attribution table.

Why this module deserves its own tests: every DNS event Valkyrie records is
labelled with the process that made the query, and that label comes from here.
Downstream, *everything* treats it as ground truth — the EDR correlates on it,
behavioural rules key on parent/child names, the UI shows it to the analyst.
A wrong answer here is not a wrong answer in one place, it is a wrong answer
everywhere, presented with full confidence.

The bug this file was written around (verified, not assumed): `_refresh_loop`
had no exception guard. `_build_table()` reaches into psutil, /proc parsing and
Windows APIs, all of which raise transiently — a process exiting mid-enumeration
is completely routine. One such raise killed the refresh thread permanently,
froze the table at its last contents, and left `lookup()` confidently returning
whichever process happened to own that port at the moment of death, forever,
with nothing anywhere indicating it had stopped working.

That is the same shape as the frozen heartbeat found earlier in this codebase:
a background thread dying quietly and leaving a stale-but-plausible value that
reads as healthy. So the tests here assert both halves of the fix — the thread
must SURVIVE, and when data does go stale the module must ADMIT it rather than
answer from a frozen table.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks
import valkyrie.process_watcher as pw


def _thread_alive() -> bool:
    return any(t.name == "proc-watcher" and t.is_alive()
               for t in threading.enumerate())


def main() -> int:
    c = Checks("process watcher", expect_min=16)
    orig_build, orig_system = pw._build_table, pw._SYSTEM

    try:
        # ── The refresh thread must survive a raising table build ────────
        print("\n[1] REGRESSION: one exception must not kill the refresh thread")
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] in (2, 3):
                raise RuntimeError("psutil blew up mid-enumeration")
            return {("1.2.3.4", 1111):
                    pw.ProcessInfo(name=f"proc{calls['n']}.exe", pid=1, path="")}

        pw._build_table = flaky
        w = pw.ProcessWatcher()
        w.REFRESH_INTERVAL = 0.05
        w.STALE_AFTER = 5.0
        w.start()
        time.sleep(0.6)
        c.check("the refresh thread is still alive after two raises",
                _thread_alive())
        c.check(f"refreshes kept happening ({calls['n']} attempts)",
                calls["n"] > 3)
        st = w.status()
        c.check(f"the errors were COUNTED, not swallowed silently "
                f"({st['refresh_errors']} recorded)", st["refresh_errors"] >= 2)
        c.check("the last error is retained for diagnosis",
                "psutil blew up" in st["last_error"])
        c.check("attribution recovered to a fresh value after the failures",
                w.lookup("1.2.3.4", 1111).name != "proc1.exe")
        w.stop()

        # ── Stale data must be admitted, not served ─────────────────────
        print("\n[2] a frozen table must ADMIT it, not answer from stale data")
        pw._SYSTEM = "Linux"          # bypass the Windows heuristic fallback
        pw._build_table = lambda: {("1.2.3.4", 1111):
                                   pw.ProcessInfo(name="real.exe", pid=7, path="")}
        w2 = pw.ProcessWatcher()
        w2.REFRESH_INTERVAL = 0.05
        w2.STALE_AFTER = 0.3
        w2.start()
        c.check("a fresh table answers with the real process",
                w2.lookup("1.2.3.4", 1111).name == "real.exe")
        c.check("a fresh watcher reports running", w2.is_running() is True)
        c.check("a fresh watcher is not stale", w2.is_stale() is False)

        w2.stop()
        time.sleep(0.6)               # let it pass STALE_AFTER
        c.check("a frozen table is reported stale", w2.is_stale() is True)
        c.check("is_running() is False once data stops refreshing "
                "(so the watchdog can catch it)", w2.is_running() is False)
        c.check("lookup returns UNKNOWN rather than the stale process name",
                w2.lookup("1.2.3.4", 1111).name != "real.exe")

        # ── Lifecycle contract (needed by the component registry) ────────
        print("\n[3] lifecycle contract for the registry + watchdog")
        c.check("exposes start()", callable(getattr(w2, "start", None)))
        c.check("exposes stop()", callable(getattr(w2, "stop", None)))
        c.check("exposes is_running()", callable(getattr(w2, "is_running", None)))
        c.check("exposes status() for the registry",
                isinstance(w2.status(), dict))
        c.check("status() reports thread liveness and staleness separately",
                {"thread_alive", "stale", "entries"} <= set(w2.status()))

        # restart must actually recover it
        w2.start()
        time.sleep(0.2)
        c.check("start() after stop() recovers the watcher (watchdog recovery)",
                w2.is_running() is True)
        w2.stop()

        # ── start() must not explode if the first build fails ───────────
        print("\n[4] a failing first build must not break startup")

        def always_raises():
            raise RuntimeError("no permissions")

        pw._build_table = always_raises
        w3 = pw.ProcessWatcher()
        w3.REFRESH_INTERVAL = 0.05
        try:
            w3.start()
            started = True
        except Exception:
            started = False
        c.check("start() does not propagate a build failure", started)
        c.check("the failure is recorded", w3.status()["refresh_errors"] >= 1)
        c.check("lookup still returns something rather than raising",
                w3.lookup("9.9.9.9", 1) is not None)
        w3.stop()

    finally:
        pw._build_table, pw._SYSTEM = orig_build, orig_system

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
