"""Background threads must not die silently — enforced structurally.

This codebase has now produced the same bug four separate times: a worker
thread whose loop body was unguarded, so the first transient exception killed
it permanently while the subsystem went on *looking* healthy.

  * `self_test.HeartbeatMonitor`  — froze reporting "protected" forever.
  * `process_watcher._refresh_loop` — froze the port->process table, so every
    DNS event was attributed to whichever process held that port at death.
  * `zero_log._integrity_loop`    — stopped verifying log integrity while
    status() still answered "verified".
  * `fleet.agent._loop`           — endpoint silently dropped off fleet
    management; on the server it just looks like a quiet machine.

Each was found by reading one file. That does not scale and it does not stop
the fifth. So this file tests the INVARIANT two ways:

  1. STRUCTURALLY — every function used as a `threading.Thread(target=...)`
     must have its loop body guarded. This is an AST check over the whole
     package, so a NEW unguarded worker fails here the moment it is added,
     without anyone having to notice.
  2. BEHAVIOURALLY — the specific workers above are driven with a
     deliberately exploding work function and must keep running, keep
     counting the failures, and (where they report health) must refuse to
     claim a healthy state they cannot substantiate.

The second half matters because the first can be satisfied by a `try: ...
except: pass` that swallows everything and still leaves a dead subsystem.
"""

from __future__ import annotations

import ast
import pathlib
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks

_PKG = Path(__file__).resolve().parent.parent / "valkyrie"


def _thread_targets() -> dict[pathlib.Path, set[str]]:
    """Functions passed as threading.Thread(target=...) anywhere in valkyrie/."""
    out: dict[pathlib.Path, set[str]] = {}
    for p in _PKG.rglob("*.py"):
        if "__pycache__" in str(p):
            continue
        try:
            tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "Thread":
                for kw in n.keywords:
                    if kw.arg == "target":
                        name = getattr(kw.value, "attr", None) or getattr(kw.value, "id", None)
                        if name:
                            out.setdefault(p, set()).add(name)
    return out


def _unguarded_loops() -> list[str]:
    """Thread-target functions whose loop body has no exception handling."""
    bad: list[str] = []
    for p, names in _thread_targets().items():
        try:
            tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        for n in ast.walk(tree):
            if not (isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and n.name in names):
                continue
            for w in ast.walk(n):
                if isinstance(w, (ast.While, ast.For)):
                    inner = any(isinstance(s, ast.Try) for s in ast.walk(w))
                    outer = any(isinstance(a, ast.Try) for a in ast.walk(n)
                                if isinstance(a, ast.Try) and w in ast.walk(a))
                    if not (inner or outer):
                        rel = p.relative_to(_PKG.parent).as_posix()
                        bad.append(f"{rel}:{w.lineno} {n.name}()")
                    break
    return bad


def main() -> int:
    c = Checks("thread resilience", expect_min=10)

    # ── 1. STRUCTURAL: no worker loop may be unguarded ──────────────────
    print("\n[1] STRUCTURAL: every thread loop body is exception-guarded")
    targets = _thread_targets()
    total = sum(len(v) for v in targets.values())
    c.check(f"the scan found thread workers to check ({total} across "
            f"{len(targets)} files) — guards against a scan that silently "
            f"finds nothing", total >= 10)
    bad = _unguarded_loops()
    for b in bad:
        print(f"    UNGUARDED: {b}")
    c.check(f"no unguarded worker loop exists ({len(bad)} found)", not bad)

    # ── 2. BEHAVIOURAL: zero-log integrity checker ─────────────────────
    print("\n[2] zero-log integrity checker survives, and stays honest")
    import valkyrie.zero_log as zl
    z = zl.ZeroLogMode.__new__(zl.ZeroLogMode)
    z._store = None; z._hashes = {}; z._tampered = []; z._alert_callbacks = []
    z._stop_event = threading.Event(); z._active = True
    z._last_check = 0.0; z._integrity_errors = 0; z._last_integrity_error = ""
    attempts = {"n": 0}

    def _boom():
        attempts["n"] += 1
        raise OSError("file locked by another process")

    z._hash_sources = _boom
    old_interval = zl.INTEGRITY_CHECK_INTERVAL
    zl.INTEGRITY_CHECK_INTERVAL = 0.05
    try:
        z._check_thread = threading.Thread(target=z._integrity_loop, daemon=True)
        z._check_thread.start()
        time.sleep(0.5)
        alive = z._check_thread.is_alive()
        z._stop_event.set()
        c.check(f"the checker survived repeated raises ({attempts['n']} attempts)",
                alive and attempts["n"] > 2)
        c.check(f"failures were counted ({z._integrity_errors})",
                z._integrity_errors > 0)
        st = z.status()
        c.check(f"integrity does NOT claim 'verified' when nothing verified "
                f"(reports {st['integrity']!r})", st["integrity"] != "verified")
        c.check("status exposes the checker's own health",
                "checker_running" in st and "integrity_errors" in st)
    finally:
        zl.INTEGRITY_CHECK_INTERVAL = old_interval

    # ── 3. BEHAVIOURAL: DoH detector ───────────────────────────────────
    print("\n[3] DoH-bypass detector survives, counts, and restarts")
    import valkyrie.doh_detector as dd
    d = dd.DoHDetector(store=None)
    scans = {"n": 0}

    def _boom2():
        scans["n"] += 1
        raise OSError("psutil enumeration failed")

    d._scan = _boom2
    old_scan = dd.DOH_SCAN_INTERVAL
    dd.DOH_SCAN_INTERVAL = 0.05
    try:
        d.start()
        time.sleep(0.5)
        c.check(f"the scanner survived repeated raises ({scans['n']} attempts)",
                d.is_running() and scans["n"] > 2)
        c.check(f"failures were counted ({d._scan_errors})", d._scan_errors > 0)
        d.stop()
        time.sleep(0.2)
        c.check("stop() actually stops it", not d.is_running())
        d.start()
        time.sleep(0.1)
        # A Thread cannot be started twice; without a fresh one this raises,
        # and a watchdog whose recovery action is start() could never revive it.
        c.check("start() after stop() revives it (watchdog recovery works)",
                d.is_running())
        d.stop()
    finally:
        dd.DOH_SCAN_INTERVAL = old_scan

    # ── 4. BEHAVIOURAL: fleet agent keeps cycling through network errors ─
    print("\n[4] fleet agent survives a failing server")
    from valkyrie.fleet.agent import FleetAgent
    a = FleetAgent.__new__(FleetAgent)
    a._running = False; a._cycle_errors = 0; a._last_error = ""
    a._interval = 0.05
    cycles = {"n": 0}

    def _fail():
        cycles["n"] += 1
        raise ConnectionError("fleet server unreachable")

    a.send_heartbeat = _fail
    a.fetch_and_apply_policy = lambda: None
    a.fetch_and_run_commands = lambda: None
    a._running = True
    t = threading.Thread(target=a._loop, daemon=True)
    t.start()
    # _loop sleeps between cycles in fixed 0.5s slices (so stop() stays
    # responsive), which sets a floor of ~0.5s per cycle regardless of
    # _interval. Wait long enough for several cycles or this asserts nothing.
    time.sleep(1.8)
    a._running = False
    c.check(f"the agent kept cycling despite a dead server "
            f"({cycles['n']} attempts)", cycles["n"] > 2)
    c.check(f"cycle failures were counted ({a._cycle_errors})",
            a._cycle_errors > 0)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
