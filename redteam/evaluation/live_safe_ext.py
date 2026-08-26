r"""Extension of live_safe.py's real-execution model to 3 more techniques
across 2 more tactics (Persistence, Execution/Defense-Evasion), for the
2026-08-25 pre-customer-validation security baseline. Reuses live_safe.py's
proven safety infrastructure (isolated engine instance, isolated temp data
dir, restricted flag set, bounded subprocess) rather than inventing new
execution machinery - see live_safe.py's own module docstring for why that
shape is safe to run outside a VM.

WHY EACH TECHNIQUE HERE IS SAFE TO RUN ON A REAL, CARED-ABOUT MACHINE
-----------------------------------------------------------------------
1. T1547.001 (Registry Run Key persistence): writes ONE value under
   HKCU\...\Run pointing at C:\Windows\System32\notepad.exe - a per-user,
   trivially reversible key pointing at a stock, harmless Windows binary
   that only does anything if a human manually logs off/on and it auto-runs
   notepad. Deleted immediately after the poll window. This is the exact
   mechanism Atomic Red Team's own T1547.001 Test #1 uses.
2. T1053.005 (Scheduled Task persistence): creates a ONE-TIME task
   (/SC ONCE) scheduled for 2099-12-31 - it structurally cannot fire before
   cleanup deletes it, so only the ARTIFACT of creation (what the detector
   is supposed to catch) exists, never an execution.
3. T1059.001 / T1027 (Encoded PowerShell): runs a single -EncodedCommand
   whose decoded payload is the literal string 'Get-Date' - it prints the
   current date and exits. No file writes, no network, no state change.

None of these touch Defender, the firewall, a real service, LSASS, shadow
copies, event logs, or create an OS-level account - the classes of atomic
this evaluation explicitly marks BLOCKED for host execution.
"""

from __future__ import annotations

import base64
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from redteam.evaluation.live_safe import (
    start_engine, stop_engine, _get, COMMAND_TIMEOUT_S,
)

RUN_KEY_PATH = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
RUN_KEY_VALUE = "ValkyrieAtomicTest"
RUN_KEY_TARGET = r"C:\Windows\System32\notepad.exe"
TASK_NAME = "ValkyrieAtomicTestTask"


@dataclass(frozen=True)
class ExtTechnique:
    id: str
    technique_id: str
    technique_name: str
    tactic: str
    setup_argv: tuple
    cleanup_argv: tuple
    why_safe: str


TECHNIQUES = (
    ExtTechnique(
        id="ext-persist-run-key", technique_id="T1547.001",
        technique_name="Boot or Logon Autostart Execution: Registry Run Keys",
        tactic="Persistence",
        setup_argv=("reg", "add", RUN_KEY_PATH, "/v", RUN_KEY_VALUE,
                    "/t", "REG_SZ", "/d", RUN_KEY_TARGET, "/f"),
        cleanup_argv=("reg", "delete", RUN_KEY_PATH, "/v", RUN_KEY_VALUE, "/f"),
        why_safe="HKCU-scoped (current user only), points at a stock Windows "
                 "binary (notepad.exe), never executes anything itself - "
                 "only runs if a human logs off/on, and is deleted before "
                 "that could happen.",
    ),
    ExtTechnique(
        id="ext-persist-scheduled-task", technique_id="T1053.005",
        technique_name="Scheduled Task/Job: Scheduled Task",
        tactic="Persistence",
        setup_argv=("schtasks", "/Create", "/TN", TASK_NAME, "/TR",
                    "cmd.exe /c exit", "/SC", "ONCE", "/SD", "12/31/2099",
                    "/ST", "23:59", "/F"),
        cleanup_argv=("schtasks", "/Delete", "/TN", TASK_NAME, "/F"),
        why_safe="One-time task scheduled 74 years in the future - "
                 "structurally cannot fire before it is deleted at the end "
                 "of this test.",
    ),
    ExtTechnique(
        id="ext-exec-powershell-encoded", technique_id="T1059.001",
        technique_name="Command and Scripting Interpreter: PowerShell (EncodedCommand)",
        tactic="Execution",
        setup_argv=("powershell.exe", "-NoProfile", "-NonInteractive",
                    "-EncodedCommand",
                    base64.b64encode("Get-Date".encode("utf-16-le")).decode("ascii")),
        cleanup_argv=(),
        why_safe="Decoded payload is the literal string 'Get-Date' - reads "
                 "the clock and exits. No file write, no network, no state "
                 "change.",
    ),
)


def _run_bounded(argv: tuple) -> tuple[int, str]:
    if not argv:
        return 0, ""
    print(f"    $ {' '.join(argv)}")
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=COMMAND_TIMEOUT_S, shell=False)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return -1, "TIMEOUT"


def _poll_for_incident(api_base: str, technique_id: str, started_at: float,
                       window_s: float = 30.0) -> dict:
    deadline = time.time() + window_s
    while time.time() < deadline:
        try:
            incidents = _get(api_base, "/api/edr/incidents?limit=100")
            items = incidents if isinstance(incidents, list) else incidents.get("incidents", [])
            for inc in items:
                tech = (inc.get("technique") or "")
                if technique_id in tech:
                    return {"captured": True, "incident_id": inc.get("id"),
                           "detector": inc.get("category"),
                           "severity": inc.get("severity"),
                           "latency_ms": (time.time() - started_at) * 1000,
                           "raw_technique_field": tech}
        except Exception as exc:
            print(f"      (poll error: {exc})")
        time.sleep(1.0)
    return {"captured": False, "incident_id": None, "detector": None,
           "severity": None, "latency_ms": None, "raw_technique_field": None}


def main() -> int:
    print("=== Live-safe extension: Persistence + Execution/Defense-Evasion ===")
    proc, api_base, data_dir = start_engine()
    results = []
    try:
        sensors = _get(api_base, "/api/sensors/status")
        print(f"[ENGINE] active sensors: {sensors}")
        # ROOT-CAUSE FINDING (this script's own first two attempts): /api/health
        # goes green BEFORE the endpoint-telemetry block (process/persistence/
        # network collectors) finishes initializing - a real readiness-signal
        # gap between "the web server answers" and "the collectors exist".
        # Confirmed directly: right after health-check success,
        # /api/telemetry/endpoint reported persistence_collector=False; only
        # by the END of a ~2-minute run did it read True. A fixed 25s guess
        # from health-check time was not reliably past that gap. Poll the
        # real readiness signal instead of guessing a delay.
        deadline = time.time() + 60
        ready = False
        while time.time() < deadline:
            try:
                st = _get(api_base, "/api/telemetry/endpoint")
                if st.get("persistence_running"):
                    ready = True
                    break
            except Exception:
                pass
            time.sleep(2)
        print(f"[ENGINE] persistence_collector running: {ready} "
             f"(waited {60 - max(0, deadline - time.time()):.0f}s)")
        if not ready:
            print("[ENGINE] WARNING: persistence_collector never came up within 60s - "
                 "Persistence-tactic results below are TEST/ENVIRONMENT failures, "
                 "not evidence about detection logic.")
        # PersistenceCollector ALSO needs its own first baseline snapshot
        # (startup_grace=5s) after the thread starts before a diff means
        # anything - now that we know the thread is actually running, wait
        # past that too.
        time.sleep(20)
        for t in TECHNIQUES:
            print(f"\n[{t.id}] {t.technique_id} {t.technique_name} ({t.tactic})")
            started = time.time()
            rc, out = _run_bounded(t.setup_argv)
            print(f"    setup rc={rc}")
            if rc not in (0, -1) and rc != 0:
                print(f"    setup output: {out[:500]}")
            result = _poll_for_incident(api_base, t.technique_id, started)
            result.update({"id": t.id, "technique_id": t.technique_id,
                          "technique_name": t.technique_name, "tactic": t.tactic,
                          "setup_rc": rc, "setup_output_tail": out[-500:]})
            results.append(result)
            print(f"    -> {'CAPTURED' if result['captured'] else 'MISSED'} "
                 f"(latency={result['latency_ms']})")
            if t.cleanup_argv:
                crc, cout = _run_bounded(t.cleanup_argv)
                print(f"    cleanup rc={crc}")
        try:
            endpoint_status_end = _get(api_base, "/api/telemetry/endpoint")
            print(f"\n[ENGINE] endpoint telemetry status (end of run): {endpoint_status_end}")
        except Exception as exc:
            print(f"\n[ENGINE] endpoint telemetry status (end of run): query failed ({exc})")
    finally:
        boot_output = stop_engine(proc)
        print("\n[ENGINE] full stdout/stderr:")
        print(boot_output[-6000:])

    print("\n=== RESULTS ===")
    for r in results:
        print(f"  {r['technique_id']:12} {r['tactic']:12} "
             f"{'CAPTURED' if r['captured'] else 'MISSED':8} "
             f"incident={r['incident_id']} sev={r['severity']} "
             f"latency_ms={r['latency_ms']}")

    import json
    out_path = Path(__file__).resolve().parent / "results" / \
        f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}__live_safe_ext.json"
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nwrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
