"""Are the new capabilities actually DELIVERED in the real app, not just in
a mocked unit test? - the gap test_startup_smoke.py leaves open for
anything added after it.

Every test written for items 2-6 of the cybersecurity-analysis pass
(control_taxonomy, coverage, MTTD/MTTR, impact, asset_inventory)
constructs its own EdrEngine/AppContext/CoverageContext by hand, or patches
`valkyrie.web.server.state` directly. That proves the LOGIC is correct. It
cannot prove the WIRING is correct - that `__main__.py` actually
instantiates `AssetInventoryCollector` with the right constructor args,
that `AppContext` actually has an `asset_inventory` field, that
`valkyrie.edr.impact` actually imports cleanly inside the real process,
that the route decorators actually registered. A NameError or
AttributeError in any of that is invisible to a test that never goes
through the real composition root in `__main__.py` - which is exactly the
class of bug `test_startup_smoke.py`'s own docstring describes for
*earlier* wiring, and exactly the class of bug the "Final" step of that
pass (re-running `live_safe.py`) did NOT re-check: `live_safe.py` scores
Discovery-tactic detection only, using a REDUCED flag set, and never once
polled any of the five endpoints this file exists to check.

This boots ONE real, sandboxed engine (identical safety posture to
`test_startup_smoke.py` - throwaway data dir, ephemeral port, DNS/firewall/
resolver/Sysmon-install all disabled) and hits every endpoint those five
items added or changed, checking both that they answer and, where the
answer doesn't require a live incident, that the DATA is real and
non-trivial (asset-inventory finds actual software/drivers on this actual
host; that is a much stronger proof of delivery than any mock can give).

HONEST LIMITATION: the MTTD/MTTR and incidents(+impact) endpoints are only
checked for reachability and correct shape on an EMPTY store. Triggering a
real incident through the live HTTP-only interface would need either a
live DNS query (this boots with `--no-dns`, per the hard safety rules) or
firing a responder (forbidden outright). Their CONTENT correctness against
a real incident is covered by `test_mttd_mttr.py` / `test_impact.py`,
which build a real EdrEngine in-process (not through HTTP) specifically so
they can inject a detection safely. What this file adds on top is: those
code paths import and execute without crashing inside the actual booted
product, not just inside a test process that imported the modules by hand.
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


def _get(url: str, timeout: float = 5.0):
    """Return (body, status) for ANY response, including errors.

    This used to let urllib raise on a non-2xx, which made the returned `status`
    unreachable for exactly the cases worth asserting on. A 503 from a subsystem
    that was still warming up therefore surfaced as an unhandled HTTPError and
    took the whole file down, instead of being a value the test could check.
    """
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.load(r), r.status
    except urllib.error.HTTPError as e:
        try:
            return json.load(e), e.code
        except Exception:   # noqa: BLE001 — non-JSON error body
            return {}, e.code


def _get_ready(url: str, tries: int = 30, delay: float = 2.0,
               timeout: float = 5.0):
    """GET, retrying while the server says the subsystem is STILL STARTING.

    The engine binds /api/health in about a second and warms subsystems behind
    it, so a test that queries an endpoint the instant health answers is racing
    the architecture's own design. The server distinguishes the two states
    (`starting: true`), so wait on that rather than on a fixed sleep.
    """
    body, status = _get(url, timeout=timeout)
    for _ in range(tries):
        if status != 503 or not (isinstance(body, dict) and body.get("starting")):
            return body, status
        time.sleep(delay)
        body, status = _get(url, timeout=timeout)
    return body, status


def main() -> int:
    c = Checks("capability delivery (real boot, not a mock)", expect_min=15)

    port = _free_port()
    td = tempfile.mkdtemp(prefix="valkyrie_capdelivery_")
    env = dict(os.environ, VALKYRIE_DATA_DIR=td,
               PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    # Identical safety posture to test_startup_smoke.py: isolated data dir,
    # ephemeral port, DNS/firewall/resolver/Sysmon-install all disabled.
    # Endpoint telemetry (process/persistence/network/asset_inventory
    # collectors) and EDR are deliberately left ON -- they are exactly what
    # this file needs to actually exercise.
    cmd = [sys.executable, "-m", "valkyrie",
           "--no-dns", "--no-firewall", "--no-unbound", "--no-ui",
           "--no-sysmon-setup",
           "--web", "--web-port", str(port)]

    print(f"\nbooting an isolated engine on 127.0.0.1:{port}")
    print(f"  data dir: {td}")
    print("  host-affecting subsystems disabled (dns/firewall/unbound/sysmon-install)\n")

    proc = subprocess.Popen(cmd, cwd=str(_ROOT), env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace")
    base = f"http://127.0.0.1:{port}"
    try:
        health = None
        deadline = time.time() + _BOOT_TIMEOUT
        while time.time() < deadline:
            if proc.poll() is not None:
                break
            try:
                health, _ = _get(f"{base}/api/health")
                break
            except Exception:
                time.sleep(1)

        if proc.poll() is not None:
            out = (proc.stdout.read() or "")[-3000:]
            print("ENGINE EXITED DURING STARTUP — output tail:")
            print(out)
            c.check("the engine survived startup", False)
            return c.finish()

        c.check(f"the engine came up and answered /api/health within {_BOOT_TIMEOUT}s",
                health is not None)
        if health is None:
            return c.finish()

        # --- Item 2: control taxonomy ---
        print("[1] GET /api/controls/taxonomy (item 2)")
        body, status = _get_ready(f"{base}/api/controls/taxonomy")
        c.check("responds 200", status == 200)
        c.check("has categories + gaps", {"categories", "gaps"} <= set(body.keys()))
        cats = body.get("categories", {})
        c.check("all 7 IIBA categories present",
                {"preventive", "detective", "corrective", "deterrent",
                 "compensating", "directive", "recovery"} <= set(cats.keys()))
        c.check("decoys is classified deterrent in the LIVE registry, not "
                "just in the unit test's imported copy",
                any(x.get("name") == "decoys" for x in cats.get("deterrent", [])))

        # --- Item 3: coverage metric ---
        print("\n[2] GET /api/controls/coverage (item 3)")
        body, status = _get_ready(f"{base}/api/controls/coverage")
        c.check("responds 200", status == 200)
        c.check("has fraction_effective/counts/total/gaps",
                {"fraction_effective", "counts", "total", "gaps"} <= set(body.keys()))
        c.check("total matches a real, non-zero control count",
                isinstance(body.get("total"), int) and body["total"] > 0)
        c.check("fraction_effective is a real fraction in [0, 1]",
                0.0 <= body.get("fraction_effective", -1) <= 1.0)

        # --- Item 4: MTTD/MTTR ---
        print("\n[3] GET /api/edr/metrics/mttd-mttr (item 4)")
        body, status = _get_ready(f"{base}/api/edr/metrics/mttd-mttr")
        c.check("responds 200 (not 503 -- EDR is wired) and not a crash",
                status == 200)
        c.check("has mttd + mttr, each with n/total/median_seconds/p95_seconds",
                {"mttd", "mttr"} <= set(body.keys())
                and {"n", "total", "median_seconds", "p95_seconds"}
                    <= set(body.get("mttd", {}).keys()))
        # NOT asserting n==0: a real host's own background activity (a
        # LOLBin-shaped powershell invocation, this very test's loopback
        # HTTP traffic looking like a hardcoded-IP connection to
        # network_telemetry.py) can and does raise genuine incidents during
        # the ~30-60s this engine is up -- confirmed by inspecting
        # /api/edr/incidents below. That is Valkyrie working correctly on
        # organic telemetry, not a fixture leaking; asserting n==0 here
        # would be asserting something false about a live host, not a
        # useful regression guard.
        for _label, _m in (("mttd", body["mttd"]), ("mttr", body["mttr"])):
            c.check(f"{_label}.n is a non-negative int", isinstance(_m["n"], int) and _m["n"] >= 0)
            c.check(f"{_label} median is None iff n==0 (never a fabricated "
                    f"number for zero samples)",
                    (_m["n"] == 0) == (_m["median_seconds"] is None))
            if _m["n"] > 0:
                c.check(f"{_label} median_seconds is a real non-negative number",
                        isinstance(_m["median_seconds"], (int, float))
                        and _m["median_seconds"] >= 0)

        # --- Item 5: incident impact (reachability + shape only, see the ---
        # module docstring's HONEST LIMITATION -- no live incident exists) ---
        print("\n[4] GET /api/edr/incidents (item 5's impact field lives here)")
        body, status = _get_ready(f"{base}/api/edr/incidents")
        print(f"  DEBUG {len(body) if isinstance(body, list) else '?'} incident(s): "
              f"{json.dumps(body, indent=2)[:2000]}")
        c.check("responds 200 (edr/impact.py imports cleanly in the real "
                "process -- this is exactly the import that would NameError/"
                "ImportError if engine.py's `from . import impact` were broken)",
                status == 200)
        c.check("returns a list (empty on a fresh boot, which is expected --"
                " NOT proof impact.py's dispatch logic is correct, only that "
                "the endpoint and its imports are wired)",
                isinstance(body, list))

        # --- Item 6: asset inventory -- the strongest check here, because ---
        # it needs no live incident: real data on a real host, right now. ---
        print("\n[5] GET /api/asset-inventory (item 6)")
        _t0 = time.time()
        body, status = _get_ready(f"{base}/api/asset-inventory", timeout=45.0)
        print(f"  DEBUG asset-inventory took {time.time() - _t0:.1f}s")
        c.check("responds 200 (not 503 -- AssetInventoryCollector actually "
                "started: proves __main__.py's pre-init + AppContext field + "
                "endpoint_enabled wiring all actually work together)",
                status == 200)
        c.check("has counts/software/listening_ports/kernel_drivers",
                {"counts", "software", "listening_ports", "kernel_drivers"}
                <= set(body.keys()))
        counts = body.get("counts", {})
        c.check("REAL software found on THIS host (not a mock, not zero)",
                counts.get("software", 0) > 0)
        c.check("REAL kernel drivers found on THIS host (not a mock, not zero)",
                counts.get("kernel_drivers", 0) > 0)
        c.check("collector_running is True (the background poller actually "
                "started, not just importable)",
                body.get("collector_running") is True)

        # --- No traceback anywhere in startup/runtime output ---
        print("\n[6] no traceback anywhere in startup or request-handling output")
        proc.terminate()
        try:
            out = proc.communicate(timeout=15)[0] or ""
        except subprocess.TimeoutExpired:
            proc.kill()
            out = proc.communicate()[0] or ""
        c.check("no Python traceback anywhere in the engine's output",
                "Traceback (most recent call last)" not in out)
        if "Traceback (most recent call last)" in out:
            idx = out.find("Traceback (most recent call last)")
            print(out[idx:idx + 2000])

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
        raise SystemExit(skip_file("capability delivery", "interrupted"))
