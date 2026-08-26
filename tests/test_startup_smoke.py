"""Does Valkyrie actually START? - the gap every other test leaves open.

`__main__.py` is 874 statements at ~8% coverage. It is the composition root:
the place where every subsystem is constructed, wired to the event bus,
registered with the component registry, and handed to the self-healing
watchdog. Nothing else in the suite executes `main()`.

That combination is the dangerous one. A NameError, a bad import, a wiring
mistake or an ordering bug in that file bricks the entire product - and every
other test in this repo still passes, because they all import modules directly
and never boot the thing. During one session this file's startup path was
edited repeatedly (a secret-permission sweep, a content-analysis worker, two
new watchdog registrations) and the only way to know it still ran was to boot
it by hand. This test is that manual check, made permanent.

SAFETY. This boots a real engine, so it is deliberately constrained:
  * `VALKYRIE_DATA_DIR` points at a throwaway temp directory, so it cannot
    read or corrupt the live install's database, keys or rules;
  * an ephemeral free port is used, so it cannot collide with a running
    instance on the default 8090;
  * `--no-dns --no-firewall --no-unbound` - it never touches system DNS,
    never installs a firewall rule, never starts a resolver. Those are the
    paths that have taken this machine offline before.
  * `--no-sysmon-setup` - sysmon_manager.install_or_verify() (ADR 0048) would
    otherwise attempt a REAL download-and-install of Sysmon on whatever host
    runs this suite every single time it boots the agent. That is a live
    system change with its own failure modes (see the ADR - a mainstream
    consumer AV can silently collide with it), and a unit-test smoke boot
    must never trigger it.
It is therefore safe on a developer workstation, which is the only reason it
can live in the default suite rather than the host-affecting exclusion list.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks, skip_file

_ROOT = Path(__file__).resolve().parent.parent
_BOOT_TIMEOUT = 60


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get(url: str, timeout: float = 3.0):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.load(r)


def main() -> int:
    c = Checks("startup smoke", expect_min=8)

    port = _free_port()
    td = tempfile.mkdtemp(prefix="valkyrie_smoke_")
    env = dict(os.environ, VALKYRIE_DATA_DIR=td,
               PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    cmd = [sys.executable, "-m", "valkyrie",
           "--no-dns", "--no-firewall", "--no-unbound", "--no-ui",
           "--no-sysmon-setup",
           "--web", "--web-port", str(port)]

    print(f"\nbooting an isolated engine on 127.0.0.1:{port}")
    print(f"  data dir: {td}")
    print("  host-affecting subsystems disabled (dns/firewall/unbound)\n")

    proc = subprocess.Popen(cmd, cwd=str(_ROOT), env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace")
    health = None
    try:
        deadline = time.time() + _BOOT_TIMEOUT
        while time.time() < deadline:
            if proc.poll() is not None:
                break                       # died during startup
            try:
                health = _get(f"http://127.0.0.1:{port}/api/health")
                break
            except Exception:
                time.sleep(1)

        if proc.poll() is not None:
            out = (proc.stdout.read() or "")[-3000:]
            print("ENGINE EXITED DURING STARTUP — output tail:")
            print(out)
            c.check("the engine survived startup", False)
            return c.finish()

        c.check("the engine came up and answered /api/health within "
                f"{_BOOT_TIMEOUT}s", health is not None)
        if health is None:
            return c.finish()

        # --- The composition root actually wired things together ---
        # LIVENESS IS NOT READINESS. The engine deliberately binds /api/health in
        # about a second and then warms subsystems up behind it, so asking for
        # the component list the instant health answers tests the architecture's
        # own design decision and calls it a failure. Poll until the registry
        # fills, with a bound - that asserts the real property ("everything gets
        # wired") without asserting a false one ("everything is wired instantly").
        print("[1] the component registry is populated")
        comps, items = {}, []
        _rdl = time.time() + 90
        while time.time() < _rdl:
            comps = _get(f"http://127.0.0.1:{port}/api/components") or {}
            items = comps.get("components", []) if isinstance(comps, dict) else (comps or [])
            if len(items) >= 5:
                break
            if proc.poll() is not None:
                break
            time.sleep(2)
        c.check("/api/components never reports 'disabled' while starting "
                "(a warming engine must not look like a switched-off feature)",
                isinstance(comps, dict) and comps.get("enabled") is not False)
        names = {x.get("name") for x in items}
        print(f"  {len(items)} components: {', '.join(sorted(n for n in names if n))}")
        c.check(f"components are registered ({len(items)} found)", len(items) >= 5)
        c.check("the store is registered and wired", "store" in names)
        c.check("the EDR engine is registered", "edr" in names)
        # Regression guard for this session's wiring: process_watcher had no
        # registry/watchdog presence at all before, so a dead refresh thread was
        # undetectable.
        c.check("process_watcher is registered (so the watchdog can see it)",
                "process_watcher" in names)

        # --- Nothing came up reporting a broken state ---
        print("\n[2] no component reports a hard failure")
        bad = [(x.get("name"), (x.get("health") or {}).get("state"))
               for x in items
               if (x.get("health") or {}).get("state") in ("error",)]
        for n, s in bad:
            print(f"  !! {n}: {s}")
        c.check(f"no component is in an error state ({len(bad)} bad)", not bad)

        # --- The API surface the UI depends on responds ---
        print("\n[3] the endpoints the desktop app polls actually answer")
        stats = _get(f"http://127.0.0.1:{port}/api/stats")
        c.check("/api/stats returns a payload", isinstance(stats, dict))
        c.check("/api/stats carries the fields the dashboard reads",
                {"dns_blocked", "protection_healthy"} <= set(stats))

        # --- And it did all that without a traceback ---
        print("\n[4] startup produced no traceback")
        proc.terminate()
        try:
            out = proc.communicate(timeout=15)[0] or ""
        except subprocess.TimeoutExpired:
            proc.kill()
            out = proc.communicate()[0] or ""
        c.check("no Python traceback anywhere in startup output",
                "Traceback (most recent call last)" not in out)
        if "Traceback (most recent call last)" in out:
            idx = out.find("Traceback (most recent call last)")
            print(out[idx:idx + 1500])

    finally:
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=10)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    return c.finish()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(skip_file("startup smoke", "interrupted"))
