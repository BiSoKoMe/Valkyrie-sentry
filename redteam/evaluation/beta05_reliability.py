r"""Platform Beta 0.5 - Telemetry Reliability Qualification.

Implements exactly what docs/BETA_0_5_TELEMETRY_RELIABILITY.md predeclares -
that document is the spec, this file is the implementation; if they disagree,
this file has a bug. Answers a different question than Tier B
(docs/LIVE_FIRE_EVALUATION.md): not "does technique T get detected" but "can
Valkyrie stay alive and keep producing a trustworthy event stream under
repeated real activity for a meaningful period." No new detection rules, no
73-technique battery - detection score is a sanity signal here, never a
pass/fail gate.

Reuses existing, already-vetted-safe project paths rather than inventing a
new workload - see _ENGINE_FLAGS, _BENIGN_COMMANDS, PHASE_C_TECHNIQUE_IDS
below and the module docstring in redteam/evaluation/live_safe.py this
mirrors.

Modes:
    smoke       local-only, ~1 short cycle, NOT qualification evidence -
                syntax/API sanity only (the target environment for this
                qualification is a disposable windows-latest CI runner).
    dry-run     CI, ~5 minutes, validates the harness + artifact pipeline.
    fault-test  CI, boots with the debug fault collector, freezes it mid-run,
                proves DEGRADED then real-recovery-to-HEALTHY.
    soak        CI, the real 20-30 minute qualification run.

Usage:
    python redteam/evaluation/beta05_reliability.py --mode smoke
    python redteam/evaluation/beta05_reliability.py --mode dry-run
    python redteam/evaluation/beta05_reliability.py --mode fault-test
    python redteam/evaluation/beta05_reliability.py --mode soak --minutes 25
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))

RESULTS_DIR = Path(__file__).resolve().parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)

BOOT_TIMEOUT_S = 90
READY_TIMEOUT_S = 120           # additional time, after /api/health, to wait
                                # for /api/telemetry/watchdog overall=HEALTHY
SAMPLE_INTERVAL_S = 2.0

# Same baseline flags tierb-run-reusable.yml already uses and has already
# proven stable on this runner class (network layer off). --no-intelligence
# is kept off specifically because it is a documented, unrelated GIL-
# contention source (valkyrie_startup_deafness) - introducing it here would
# contaminate the telemetry-reliability signal this file exists to isolate.
_ENGINE_FLAGS = (
    "--no-dns", "--no-unbound", "--no-intelligence",
    "--no-firewall", "--no-tls", "--no-sysmon-setup", "--no-download-lists",
)

# Phase B / D / E: the exact bare, read-only, HARD-SAFETY-RULE-vetted
# commands redteam/evaluation/live_safe.py already runs outside a VM -
# reused verbatim rather than inventing a new "benign" workload.
_BENIGN_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("whoami",),
    ("systeminfo",),
    ("tasklist",),
    ("hostname",),
    ("ipconfig", "/all"),
    ("netstat", "-ano"),
    ("reg", "query", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"),
)

# Phase C: a small, already-proven-safe, non-destructive Tier B subset,
# chosen only because each one exercises a DIFFERENT collector this
# qualification instruments - never for technique coverage. See
# docs/LIVE_FIRE_EVALUATION.md and redteam/evaluation/catalog.py.
PHASE_C_TECHNIQUE_IDS = (
    "exec-powershell-encoded",   # T1059.001 - process_collector
    "persist-run-key",           # T1547.001 - persistence_collector
    "exec-wmic-process-call",    # T1047     - process_collector / WMI
)

COMMAND_TIMEOUT_S = 15


# =============================================================================
# Engine lifecycle
# =============================================================================

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get(api_base: str, path: str, timeout: float = 8.0):
    with urllib.request.urlopen(f"{api_base}{path}", timeout=timeout) as r:
        return json.load(r)


def _post(api_base: str, path: str, timeout: float = 8.0):
    req = urllib.request.Request(f"{api_base}{path}", method="POST", data=b"")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def start_engine(extra_env: dict | None = None) -> tuple[subprocess.Popen, str, str]:
    port = _free_port()
    data_dir = tempfile.mkdtemp(prefix="valkyrie_beta05_")
    env = dict(os.environ, VALKYRIE_DATA_DIR=data_dir,
               PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    if extra_env:
        env.update(extra_env)
    cmd = [sys.executable, "-m", "valkyrie", *_ENGINE_FLAGS,
           "--web", "--web-port", str(port)]
    print(f"[ENGINE] starting: {' '.join(cmd)}")
    print(f"[ENGINE] isolated data dir: {data_dir}")
    proc = subprocess.Popen(cmd, cwd=str(_ROOT), env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace")
    api_base = f"http://127.0.0.1:{port}"
    deadline = time.time() + BOOT_TIMEOUT_S
    while time.time() < deadline:
        if proc.poll() is not None:
            out = (proc.stdout.read() or "")[-4000:]
            raise RuntimeError(f"engine exited during startup:\n{out}")
        try:
            _get(api_base, "/api/health", timeout=3.0)
            print(f"[ENGINE] answering /api/health on {api_base}")
            return proc, api_base, data_dir
        except Exception:
            time.sleep(1)
    proc.terminate()
    raise RuntimeError(f"engine did not answer /api/health within {BOOT_TIMEOUT_S}s")


def stop_engine(proc: subprocess.Popen) -> str:
    if proc.poll() is not None:
        return proc.stdout.read() or ""
    proc.terminate()
    try:
        return proc.communicate(timeout=15)[0] or ""
    except subprocess.TimeoutExpired:
        proc.kill()
        return proc.communicate()[0] or ""


def wait_for_real_readiness(api_base: str, timeout_s: float = READY_TIMEOUT_S) -> dict:
    """Real readiness, not mere liveness: /api/health answering is not
    enough (that is exactly what looked fine during the historical
    deafness bug's first ~2 responses) - wait for the telemetry watchdog
    itself to report overall == HEALTHY."""
    deadline = time.time() + timeout_s
    last: dict = {}
    while time.time() < deadline:
        try:
            last = _get(api_base, "/api/telemetry/watchdog", timeout=5.0)
            sources = last.get("sources") or {}
            real_sources_ready = bool(sources) and all(
                src.get("available")
                and (src.get("status") or {}).get("running") is not False
                and float((src.get("status") or {}).get("last_poll_completed_at", 0) or 0) > 0
                for name, src in sources.items()
                if name != "debug_fault_collector"
            )
            loop_ready = bool((last.get("loop") or {}).get("beating"))
            if last.get("overall") == "HEALTHY" and real_sources_ready and loop_ready:
                print(f"[READY] watchdog reports HEALTHY: {last.get('sources', {}).keys()}")
                return last
        except Exception as exc:                      # noqa: BLE001
            last = {"error": str(exc)}
        time.sleep(2.0)
    raise RuntimeError(f"watchdog never reached HEALTHY within {timeout_s}s: {last}")


# =============================================================================
# Workload
# =============================================================================

def run_command(argv: tuple[str, ...]) -> None:
    print(f"  [EXEC] {' '.join(argv)}")
    try:
        subprocess.run(list(argv), capture_output=True, text=True,
                       timeout=COMMAND_TIMEOUT_S, shell=False,
                       encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        print(f"    !! timed out after {COMMAND_TIMEOUT_S}s")
    except FileNotFoundError as exc:
        print(f"    !! {exc}")


def run_benign_activity(duration_s: float, gap_s: float = 3.0) -> None:
    """Phase B / D / E's stimulus: ordinary process launches, harmless
    registry reads, and (via netstat) a look at real outbound connections -
    spaced out, never bursted."""
    deadline = time.time() + duration_s
    i = 0
    while time.time() < deadline:
        run_command(_BENIGN_COMMANDS[i % len(_BENIGN_COMMANDS)])
        i += 1
        time.sleep(gap_s)


def run_phase_c(api_base: str) -> bool:
    """Known telemetry-producing activity: the existing run_live_evaluation.ps1
    runner, filtered to PHASE_C_TECHNIQUE_IDS, against the already-running
    engine. Returns True if the script exited 0. Detection score is NOT the
    point here (see module docstring) - this just needs to genuinely exercise
    the process and persistence collectors with real deltas, not empty polls."""
    ps1 = _ROOT / "redteam" / "evaluation" / "run_live_evaluation.ps1"
    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if not pwsh or not ps1.exists():
        print(f"[PHASE C] SKIPPED - no PowerShell runner available "
              f"(pwsh={pwsh}, ps1_exists={ps1.exists()})")
        return False
    ids = ",".join(PHASE_C_TECHNIQUE_IDS)
    cmd = [pwsh, "-File", str(ps1), "-OnlyIds", ids,
           "-ApiBase", api_base, "-DetectWindowSeconds", "30", "-SkipDestructive"]
    print(f"[PHASE C] {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, cwd=str(_ROOT), timeout=300,
                                capture_output=True, text=True,
                                encoding="utf-8", errors="replace")
        print(result.stdout[-4000:])
        if result.returncode != 0:
            print(result.stderr[-2000:])
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("[PHASE C] run_live_evaluation.ps1 timed out")
        return False


# =============================================================================
# Continuous sampler
# =============================================================================

@dataclass
class Transition:
    ts: float
    kind: str            # "degraded" | "recovered"
    reasons: list = field(default_factory=list)


class Sampler:
    """Background thread sampling the running engine every SAMPLE_INTERVAL_S,
    independent of phase boundaries. Streams every sample to a JSONL file as
    it is taken (crash-proof, matching this project's Tier B convention) and
    keeps derived state a scoring pass reads afterward."""

    def __init__(self, api_base: str, out_path: Path) -> None:
        self._api_base = api_base
        self._out_path = out_path
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.current_phase = "A"
        self.samples: list[dict] = []
        self.transitions: list[Transition] = []
        self.health_failures = 0
        self.health_successes = 0
        self._prev_overall: str | None = None
        self._prev_reasons: list = []

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, daemon=True, name="beta05-sampler")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)

    def _loop(self) -> None:
        with open(self._out_path, "a", encoding="utf-8") as fh:
            while not self._stop.is_set():
                rec = self._sample_once()
                self.samples.append(rec)
                fh.write(json.dumps(rec, default=str) + "\n")
                fh.flush()
                self._stop.wait(SAMPLE_INTERVAL_S)

    def _sample_once(self) -> dict:
        now = time.time()
        rec: dict = {"t": now, "phase": self.current_phase}

        t0 = time.monotonic()
        try:
            _get(self._api_base, "/api/health", timeout=5.0)
            rec["health_ok"] = True
            rec["health_latency_s"] = time.monotonic() - t0
            self.health_successes += 1
        except Exception as exc:                       # noqa: BLE001
            rec["health_ok"] = False
            rec["health_error"] = str(exc)
            self.health_failures += 1

        try:
            wd = _get(self._api_base, "/api/telemetry/watchdog", timeout=5.0)
            rec["watchdog"] = wd
            overall = wd.get("overall")
            reasons = wd.get("degraded_reasons", [])
            if self._prev_overall == "HEALTHY" and overall == "DEGRADED":
                self.transitions.append(Transition(now, "degraded", reasons))
            elif self._prev_overall == "DEGRADED" and overall == "HEALTHY":
                self.transitions.append(Transition(now, "recovered", self._prev_reasons))
            self._prev_overall = overall
            self._prev_reasons = reasons
        except Exception as exc:                        # noqa: BLE001
            rec["watchdog"] = None
            rec["watchdog_error"] = str(exc)

        try:
            rec["causality_stats"] = _get(self._api_base, "/api/edr/causality/stats", timeout=5.0)
        except Exception as exc:                         # noqa: BLE001
            rec["causality_stats"] = None
            rec["causality_error"] = str(exc)

        try:
            rec["sensors_status"] = _get(self._api_base, "/api/sensors/status", timeout=5.0)
        except Exception as exc:                          # noqa: BLE001
            rec["sensors_status"] = None
            rec["sensors_error"] = str(exc)

        return rec


# =============================================================================
# Scoring - implements docs/BETA_0_5_TELEMETRY_RELIABILITY.md's predeclared
# PASS criteria. Each check is independent so a report can show which ones
# held even if the overall verdict is FAIL.
# =============================================================================

def _independent_stale_bound(interval: float) -> float:
    """A deliberately DIFFERENT bound from TelemetryWatchdog's own
    (interval * 4.0): interval * 5.0 + 5.0s. Not byte-identical logic, so a
    bug specific to the watchdog's own multiplier does not silently pass its
    own cross-check - this exists to verify the WIRING (real samples really
    reaching this harness), not to re-derive the same formula."""
    return interval * 5.0 + 5.0


def score(samples: list[dict], transitions: list[Transition],
         health_failures: int, health_successes: int,
         causality_before_c: int | None, causality_after_c: int | None,
         mode: str) -> dict:
    checks: dict[str, dict] = {}

    # 1. Zero silent collector deaths.
    dead = []
    for rec in samples:
        wd = rec.get("watchdog") or {}
        for name, src in (wd.get("sources") or {}).items():
            status = src.get("status")
            if status is not None and status.get("running") is False:
                dead.append((rec["t"], name))
    checks["no_silent_collector_deaths"] = {
        "pass": len(dead) == 0,
        "detail": dead[:10],
    }

    # 2. Zero periods where a collector is stale while watchdog says HEALTHY,
    #    recomputed independently (see _independent_stale_bound).
    contradictions = []
    for rec in samples:
        wd = rec.get("watchdog") or {}
        if wd.get("overall") != "HEALTHY":
            continue
        for name, src in (wd.get("sources") or {}).items():
            status = src.get("status")
            if not status:
                continue
            interval = float(status.get("poll_interval_s", 0) or 0)
            last_poll = float(status.get("last_poll_completed_at", 0) or 0)
            if interval <= 0 or last_poll <= 0:
                continue
            age = rec["t"] - last_poll
            if age > _independent_stale_bound(interval):
                contradictions.append((rec["t"], name, age))
    checks["no_stale_while_healthy"] = {
        "pass": len(contradictions) == 0,
        "detail": contradictions[:10],
    }

    # 3. Zero unexplained event-loop stalls beyond 5.0s.
    worst_stall = 0.0
    stalls = []
    for rec in samples:
        wd = rec.get("watchdog") or {}
        loop = wd.get("loop") or {}
        drift = float(loop.get("last_drift_seconds", 0) or 0)
        worst = float(loop.get("worst_drift_seconds", 0) or 0)
        worst_stall = max(worst_stall, worst)
        if drift > 5.0:
            stalls.append((rec["t"], drift))
    checks["no_unexplained_loop_stalls"] = {
        "pass": worst_stall <= 5.0,
        "detail": {"worst_drift_seconds": worst_stall, "stalls_over_5s": stalls[:10]},
    }

    # 4. Every wired collector must actually exist and complete repeated polls.
    #    "not_available" is not progress, and check 2 intentionally skips a
    #    missing status, so derive this independently rather than aliasing it.
    source_names = sorted({
        name
        for rec in samples
        for name in (((rec.get("watchdog") or {}).get("sources") or {}).keys())
        if name != "debug_fault_collector"
    })
    progress_detail = {}
    collectors_advance = bool(source_names)
    for name in source_names:
        observations = [
            ((rec.get("watchdog") or {}).get("sources") or {}).get(name) or {}
            for rec in samples
        ]
        available = [src for src in observations if src.get("available")]
        polls = {
            float((src.get("status") or {}).get("last_poll_completed_at", 0) or 0)
            for src in available
            if float((src.get("status") or {}).get("last_poll_completed_at", 0) or 0) > 0
        }
        ok = len(available) == len(observations) and len(polls) >= 2
        collectors_advance = collectors_advance and ok
        progress_detail[name] = {
            "available_samples": len(available),
            "total_samples": len(observations),
            "distinct_completed_polls": len(polls),
            "pass": ok,
        }
    checks["collectors_advance_throughout"] = {
        "pass": (collectors_advance
                 and checks["no_stale_while_healthy"]["pass"]
                 and checks["no_silent_collector_deaths"]["pass"]),
        "detail": progress_detail,
    }

    # 5. API stays responsive.
    checks["api_responsive"] = {
        "pass": health_failures == 0,
        "detail": {"failures": health_failures, "successes": health_successes},
    }

    # 6. Phase C causes measurable event-count progression (sanity signal,
    #    detection-agnostic). Only evaluated when both counts were captured.
    if causality_before_c is not None and causality_after_c is not None:
        checks["phase_c_advances_event_count"] = {
            "pass": causality_after_c > causality_before_c,
            "detail": {"before": causality_before_c, "after": causality_after_c},
        }
    else:
        checks["phase_c_advances_event_count"] = {
            "pass": True,
            "detail": "not measured this run (phase C skipped or counters unavailable)",
        }

    # 7. Fault-test only: a degraded-then-recovered pair was observed.
    if mode == "fault-test":
        has_degraded = any(t.kind == "degraded" for t in transitions)
        has_recovered = any(t.kind == "recovered" for t in transitions)
        checks["fault_detected_and_recovered"] = {
            "pass": has_degraded and has_recovered,
            "detail": [{"ts": t.ts, "kind": t.kind, "reasons": t.reasons} for t in transitions],
        }

    overall_pass = all(c["pass"] for c in checks.values())
    return {"overall": "PASS" if overall_pass else "FAIL", "checks": checks}


# =============================================================================
# Modes
# =============================================================================

def _write_summary(label: str, summary: dict) -> Path:
    ts = time.strftime("%Y%m%d_%H%M%S")
    path = RESULTS_DIR / f"beta05_{label}_{ts}.json"
    path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    print(f"\n[SUMMARY] written to {path}")
    return path


def run_smoke() -> int:
    """Local-only sanity pass. NOT qualification evidence - see the module
    docstring and docs/BETA_0_5_TELEMETRY_RELIABILITY.md's 'Why CI, not the
    local machine' section."""
    print("=" * 70)
    print("MODE: smoke -- LOCAL ONLY, NOT QUALIFICATION EVIDENCE")
    print("=" * 70)
    proc, api_base, data_dir = start_engine()
    try:
        wait_for_real_readiness(api_base, timeout_s=60)
        out = RESULTS_DIR / "beta05_smoke.jsonl"
        if out.exists():
            out.unlink()
        sampler = Sampler(api_base, out)
        sampler.start()
        sampler.current_phase = "A"
        time.sleep(6)
        sampler.current_phase = "B"
        run_benign_activity(10, gap_s=2.0)
        sampler.stop()
        result = score(sampler.samples, sampler.transitions,
                       sampler.health_failures, sampler.health_successes,
                       None, None, "smoke")
        print(json.dumps(result, indent=2, default=str))
        print("\n(This is a syntax/API sanity check only. It proves nothing "
              "about reliability under real CI scheduling.)")
        return 0
    finally:
        stop_engine(proc)
        shutil.rmtree(data_dir, ignore_errors=True)


def run_dry_run() -> int:
    print("=" * 70)
    print("MODE: dry-run -- CI, ~5 minutes, validates harness + artifacts")
    print("=" * 70)
    proc, api_base, data_dir = start_engine()
    try:
        wait_for_real_readiness(api_base)
        out = RESULTS_DIR / "beta05_dryrun.jsonl"
        if out.exists():
            out.unlink()
        sampler = Sampler(api_base, out)
        sampler.start()

        sampler.current_phase = "A"
        time.sleep(60)

        sampler.current_phase = "B"
        run_benign_activity(90)

        before_c = _get(api_base, "/api/edr/causality/stats", timeout=5.0)
        sampler.current_phase = "C"
        if not run_phase_c(api_base):
            raise RuntimeError("Phase C safe Tier B subset did not execute successfully")
        time.sleep(20)
        after_c = _get(api_base, "/api/edr/causality/stats", timeout=5.0)

        sampler.current_phase = "D"
        run_benign_activity(60)

        sampler.stop()
        result = score(sampler.samples, sampler.transitions,
                       sampler.health_failures, sampler.health_successes,
                       before_c.get("nodes"), after_c.get("nodes"), "dry-run")
        result["mode"] = "dry-run"
        result["evidence"] = False
        result["note"] = "Validates the harness itself, not reliability. Not a qualification pass/fail."
        _write_summary("dryrun", result)
        print(json.dumps(result, indent=2, default=str))
        return 0
    finally:
        stop_engine(proc)
        shutil.rmtree(data_dir, ignore_errors=True)


def run_fault_test() -> int:
    print("=" * 70)
    print("MODE: fault-test -- CI, proves the watchdog catches its target failure")
    print("=" * 70)
    proc, api_base, data_dir = start_engine(
        extra_env={"VALKYRIE_DEBUG_FAULT_COLLECTOR": "1"})
    try:
        wait_for_real_readiness(api_base)
        out = RESULTS_DIR / "beta05_faulttest.jsonl"
        if out.exists():
            out.unlink()
        sampler = Sampler(api_base, out)
        sampler.start()
        sampler.current_phase = "baseline"
        time.sleep(6)

        wd = _get(api_base, "/api/telemetry/watchdog", timeout=5.0)
        if wd.get("overall") != "HEALTHY":
            raise RuntimeError(f"expected HEALTHY before fault injection, got: {wd}")
        fic_status = wd["sources"].get("debug_fault_collector")
        if fic_status is None:
            raise RuntimeError("debug_fault_collector not wired - "
                               "VALKYRIE_DEBUG_FAULT_COLLECTOR did not take effect")
        interval = float(fic_status["status"]["poll_interval_s"])

        print("[FAULT] freezing debug_fault_collector")
        sampler.current_phase = "frozen"
        _post(api_base, "/api/debug/telemetry/fault?freeze=true", timeout=5.0)
        time.sleep(interval * 4.0 + 6.0)

        wd2 = _get(api_base, "/api/telemetry/watchdog", timeout=5.0)
        if wd2.get("overall") != "DEGRADED":
            raise RuntimeError(f"expected DEGRADED after freeze, got: {wd2}")
        print(f"[FAULT] confirmed DEGRADED: {wd2['degraded_reasons']}")

        print("[FAULT] unfreezing debug_fault_collector")
        sampler.current_phase = "recovering"
        _post(api_base, "/api/debug/telemetry/fault?freeze=false", timeout=5.0)
        time.sleep(6.0)

        wd3 = _get(api_base, "/api/telemetry/watchdog", timeout=5.0)
        if wd3.get("overall") != "HEALTHY":
            raise RuntimeError(f"expected HEALTHY after real recovery, got: {wd3}")
        print("[FAULT] confirmed real recovery to HEALTHY")

        sampler.stop()
        result = score(sampler.samples, sampler.transitions,
                       sampler.health_failures, sampler.health_successes,
                       None, None, "fault-test")
        result["mode"] = "fault-test"
        _write_summary("faulttest", result)
        print(json.dumps(result, indent=2, default=str))
        return 0 if result["overall"] == "PASS" else 1
    finally:
        stop_engine(proc)
        shutil.rmtree(data_dir, ignore_errors=True)


def run_soak(minutes: float) -> int:
    print("=" * 70)
    print(f"MODE: soak -- CI, {minutes:.0f}-minute qualification run")
    print("=" * 70)
    proc, api_base, data_dir = start_engine()
    try:
        wait_for_real_readiness(api_base)
        out = RESULTS_DIR / "beta05_soak.jsonl"
        if out.exists():
            out.unlink()
        sampler = Sampler(api_base, out)
        sampler.start()

        total_s = minutes * 60.0
        # Fixed A/B/C/D budgets per the predeclared spec; whatever remains
        # goes to phase E, floored at 0 so a short --minutes for testing
        # still runs end-to-end rather than going negative.
        a_s, b_s, c_settle_s, d_s = 150.0, 300.0, 300.0, 300.0
        e_s = max(0.0, total_s - (a_s + b_s + c_settle_s + d_s))

        sampler.current_phase = "A"
        time.sleep(a_s)

        sampler.current_phase = "B"
        run_benign_activity(b_s)

        before_c = _get(api_base, "/api/edr/causality/stats", timeout=5.0)
        sampler.current_phase = "C"
        if not run_phase_c(api_base):
            raise RuntimeError("Phase C safe Tier B subset did not execute successfully")
        elapsed = min(60.0, c_settle_s)
        time.sleep(elapsed)
        run_benign_activity(max(0.0, c_settle_s - elapsed))
        after_c = _get(api_base, "/api/edr/causality/stats", timeout=5.0)

        sampler.current_phase = "D"
        run_benign_activity(d_s)

        sampler.current_phase = "E"
        e_deadline = time.time() + e_s
        toggle = 0
        while time.time() < e_deadline:
            remaining = e_deadline - time.time()
            if toggle % 3 == 2 and remaining > 60:
                if not run_phase_c(api_base):
                    raise RuntimeError("Phase E safe Tier B subset did not execute successfully")
            else:
                run_benign_activity(min(90.0, max(1.0, remaining)))
            toggle += 1

        sampler.stop()
        result = score(sampler.samples, sampler.transitions,
                       sampler.health_failures, sampler.health_successes,
                       before_c.get("nodes"), after_c.get("nodes"), "soak")
        result["mode"] = "soak"
        result["minutes"] = minutes
        result["platform"] = platform.platform()
        _write_summary("soak", result)
        print(json.dumps(result, indent=2, default=str))
        return 0 if result["overall"] == "PASS" else 1
    finally:
        stop_engine(proc)
        shutil.rmtree(data_dir, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=["smoke", "dry-run", "fault-test", "soak"],
                    required=True)
    ap.add_argument("--minutes", type=float, default=25.0,
                    help="soak mode only: total qualification duration in minutes")
    args = ap.parse_args()

    if args.mode == "smoke":
        return run_smoke()
    if args.mode == "dry-run":
        return run_dry_run()
    if args.mode == "fault-test":
        return run_fault_test()
    return run_soak(args.minutes)


if __name__ == "__main__":
    raise SystemExit(main())
