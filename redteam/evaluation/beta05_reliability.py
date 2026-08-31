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
    contention  CI, same soak workload on one fresh runner, stopping at the
                first API timeout or stale transition and dumping attribution.
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


def _safe_get(api_base: str, path: str, timeout: float = 5.0) -> dict:
    """Like _get, but never raises - a before/after snapshot read that fails
    (the engine briefly or permanently unreachable, see Beta 0.5.5) must not
    crash the whole harness and discard every sample already collected."""
    try:
        return _get(api_base, path, timeout=timeout)
    except Exception:                              # noqa: BLE001
        return {}


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
    log_path = RESULTS_DIR / "beta05_engine.log"
    log_fh = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen(cmd, cwd=str(_ROOT), env=env,
                            stdout=log_fh, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace")
    proc._beta05_log_fh = log_fh  # type: ignore[attr-defined]
    proc._beta05_log_path = log_path  # type: ignore[attr-defined]
    api_base = f"http://127.0.0.1:{port}"
    deadline = time.time() + BOOT_TIMEOUT_S
    while time.time() < deadline:
        if proc.poll() is not None:
            log_fh.flush()
            out = log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
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
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    log_fh = getattr(proc, "_beta05_log_fh", None)
    if log_fh:
        log_fh.close()
    path = getattr(proc, "_beta05_log_path", None)
    return path.read_text(encoding="utf-8", errors="replace") if path else ""


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


def run_benign_activity(duration_s: float, gap_s: float = 3.0,
                        stop_event: threading.Event | None = None) -> None:
    """Phase B / D / E's stimulus: ordinary process launches, harmless
    registry reads, and (via netstat) a look at real outbound connections -
    spaced out, never bursted."""
    deadline = time.time() + duration_s
    i = 0
    while time.time() < deadline:
        if stop_event and stop_event.is_set():
            return
        run_command(_BENIGN_COMMANDS[i % len(_BENIGN_COMMANDS)])
        i += 1
        if stop_event:
            stop_event.wait(gap_s)
        else:
            time.sleep(gap_s)


# run_live_evaluation.ps1's OWN worst-case, not a guess: its readiness gate
# alone (-ReadyTimeoutSeconds, default 420) tolerates gaps and can legitimately
# take the full 420s before a single technique runs, plus up to
# -DetectWindowSeconds (30) per technique for all 3 PHASE_C_TECHNIQUE_IDS. A
# harness timeout shorter than that budget is a harness bug, not a reliability
# finding - run 3 of the 2026-08-30 soak hit exactly this: killed at 300s while
# still legitimately inside the script's own documented wait, discarding every
# sample the run had collected because the RuntimeError below used to escape
# uncaught. 600s leaves real margin over the 420 + 3*30 = 510s worst case.
PHASE_C_TIMEOUT_S = 600


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
        result = subprocess.run(cmd, cwd=str(_ROOT), timeout=PHASE_C_TIMEOUT_S,
                                capture_output=True, text=True,
                                encoding="utf-8", errors="replace")
        print(result.stdout[-4000:])
        if result.returncode != 0:
            print(result.stderr[-2000:])
        return result.returncode == 0
    except subprocess.TimeoutExpired as exc:
        # Print whatever the script had already written before the kill -
        # without this, a real "stuck in its own readiness gate" vs. "hung
        # mid-technique" distinction is unrecoverable after the fact (exactly
        # what run 3 above lost).
        print(f"[PHASE C] run_live_evaluation.ps1 timed out after "
              f"{PHASE_C_TIMEOUT_S}s - partial output follows:")
        if exc.stdout:
            print(exc.stdout[-4000:])
        if exc.stderr:
            print(exc.stderr[-2000:])
        return False


# =============================================================================
# Continuous sampler
# =============================================================================

@dataclass
class Transition:
    ts: float
    kind: str            # "degraded" | "recovered"
    reasons: list = field(default_factory=list)


# Reused psutil.Process handle per pid - psutil's cpu_percent() measures the
# interval SINCE ITS OWN LAST CALL on that same Process object, so creating a
# fresh Process() every sample would make every cpu_percent() reading
# meaningless (always the instantaneous-since-process-start average). One
# handle per pid across the whole run is required for this number to mean
# anything sampled continuously.
_ENGINE_PROC_HANDLES: dict[int, object] = {}


def _engine_process_stats(pid: int | None) -> dict | None:
    """Point-in-time resource snapshot of the engine process - memory,
    handles, threads, CPU. Beta 0.5.5 found the engine process itself can go
    completely unreachable mid-run; this exists to measure WHY (a resource
    trending toward a wall) instead of guessing, on every sample rather than
    only at the moment something already failed."""
    if not pid:
        return None
    try:
        import psutil
    except ImportError:
        return None
    try:
        proc = _ENGINE_PROC_HANDLES.get(pid)
        if proc is None:
            proc = psutil.Process(pid)
            _ENGINE_PROC_HANDLES[pid] = proc
        with proc.oneshot():
            return {
                "pid": proc.pid,
                "cpu_percent": proc.cpu_percent(),
                "rss": proc.memory_info().rss,
                "vms": proc.memory_info().vms,
                "threads": proc.num_threads(),
                "handles": proc.num_handles() if hasattr(proc, "num_handles") else None,
            }
    except Exception as exc:                          # noqa: BLE001
        # Includes psutil.NoSuchProcess - itself useful evidence: it means
        # the process had ALREADY exited by the time this sample ran, not
        # merely that it was slow to answer.
        return {"error": repr(exc)}


class Sampler:
    """Background thread sampling the running engine every SAMPLE_INTERVAL_S,
    independent of phase boundaries. Streams every sample to a JSONL file as
    it is taken (crash-proof, matching this project's Tier B convention) and
    keeps derived state a scoring pass reads afterward."""

    def __init__(self, api_base: str, out_path: Path, engine_pid: int | None = None,
                 stop_on_failure: bool = False) -> None:
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
        self._engine_pid = engine_pid
        self._stop_on_failure = stop_on_failure
        self.failure = threading.Event()
        self.first_failure: dict | None = None

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
                if self._stop_on_failure and self._failure_reason(rec):
                    self.first_failure = self._capture_failure(rec)
                    fh.write(json.dumps({"contention_failure": self.first_failure}, default=str) + "\n")
                    fh.flush()
                    self.failure.set()
                    return
                self._stop.wait(SAMPLE_INTERVAL_S)

    @staticmethod
    def _failure_reason(rec: dict) -> str | None:
        if not rec.get("health_ok"):
            return "api_health_failure"
        for name in ("watchdog", "causality", "sensors"):
            request = (rec.get("requests") or {}).get(name) or {}
            if not request.get("ok"):
                return f"api_{name}_failure"
        wd = rec.get("watchdog") or {}
        if wd.get("overall") == "DEGRADED":
            return "watchdog_degraded"
        return None

    def _capture_failure(self, rec: dict) -> dict:
        result = {"detected_at": time.time(), "phase": self.current_phase,
                  "reason": self._failure_reason(rec), "trigger_sample": rec}
        try:
            result["contention_endpoint"] = _get(
                self._api_base, "/api/telemetry/contention", timeout=5.0)
        except Exception as exc:
            result["contention_endpoint_error"] = repr(exc)
        # rec already carries a fresh engine_process reading from this same
        # sample cycle (see _sample_once) - reuse it rather than taking a
        # second, slightly later one.
        result["engine_process"] = rec.get("engine_process")
        return result

    def _timed_get(self, label: str, path: str) -> tuple[object | None, dict]:
        started_wall = time.time()
        started = time.monotonic()
        request = {"started_at": started_wall, "path": path}
        try:
            value = _get(self._api_base, path, timeout=5.0)
            request.update(ok=True, ended_at=time.time(),
                           duration_s=time.monotonic() - started)
            return value, request
        except Exception as exc:
            request.update(ok=False, ended_at=time.time(),
                           duration_s=time.monotonic() - started, error=repr(exc))
            return None, request

    def _sample_once(self) -> dict:
        now = time.time()
        rec: dict = {"t": now, "phase": self.current_phase}
        # Every sample, not only at failure time (Beta 0.5.5) - a resource
        # trending toward a wall should be visible in a clean run's own
        # data, not only reconstructable after the fact from one snapshot
        # taken at the moment something already broke.
        rec["engine_process"] = _engine_process_stats(self._engine_pid)

        rec["requests"] = {}
        health, rec["requests"]["health"] = self._timed_get("health", "/api/health")
        try:
            if health is None:
                raise RuntimeError(rec["requests"]["health"].get("error"))
            rec["health_ok"] = True
            rec["health_latency_s"] = rec["requests"]["health"]["duration_s"]
            self.health_successes += 1
        except Exception as exc:                       # noqa: BLE001
            rec["health_ok"] = False
            rec["health_error"] = str(exc)
            self.health_failures += 1

        try:
            wd, rec["requests"]["watchdog"] = self._timed_get(
                "watchdog", "/api/telemetry/watchdog")
            if wd is None:
                raise RuntimeError(rec["requests"]["watchdog"].get("error"))
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

        rec["causality_stats"], rec["requests"]["causality"] = self._timed_get(
            "causality", "/api/edr/causality/stats")
        if rec["causality_stats"] is None:
            exc = rec["requests"]["causality"].get("error")
            rec["causality_stats"] = None
            rec["causality_error"] = str(exc)

        rec["sensors_status"], rec["requests"]["sensors"] = self._timed_get(
            "sensors", "/api/sensors/status")
        if rec["sensors_status"] is None:
            exc = rec["requests"]["sensors"].get("error")
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
         mode: str, phase_c_failures: list[str] | None = None,
         engine_exit_code: int | None = None) -> dict:
    checks: dict[str, dict] = {}

    # The engine process disappearing entirely is a distinct, more
    # fundamental failure than any per-collector or per-request check can
    # see on its own (Beta 0.5.5) - checked directly against the subprocess.
    checks["engine_process_alive_throughout"] = {
        "pass": engine_exit_code is None,
        "detail": {"exit_code": engine_exit_code} if engine_exit_code is not None else {},
    }

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

    # A soak has no deliberate fault injection. Any DEGRADED sample therefore
    # means the watchdog observed a real reliability breach, even if the source
    # later recovered and accumulated many distinct polls overall. Eventual
    # recovery must not erase a minute-long persistence stall from the verdict.
    unexpected_degraded = []
    if mode != "fault-test":
        for rec in samples:
            wd = rec.get("watchdog") or {}
            if wd.get("overall") == "DEGRADED":
                unexpected_degraded.append(
                    (rec["t"], rec.get("phase"), wd.get("degraded_reasons", [])))
    checks["no_unexpected_degraded_intervals"] = {
        "pass": len(unexpected_degraded) == 0,
        "detail": unexpected_degraded[:20],
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
        healthy = [src for src in observations if src.get("healthy")]
        ok = (len(available) == len(observations)
              and len(healthy) == len(observations)
              and len(polls) >= 2)
        collectors_advance = collectors_advance and ok
        progress_detail[name] = {
            "available_samples": len(available),
            "total_samples": len(observations),
            "healthy_samples": len(healthy),
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

    # A Tier B subset invocation (phase C's own run, or its Phase E rerun)
    # that fails or times out is a real finding, but it must be SCORED, not
    # allowed to crash the harness and discard every sample already
    # collected - run 3 of the 2026-08-30 soak lost its entire evidence
    # trail to exactly this before this check existed.
    checks["phase_c_technique_execution_completed"] = {
        "pass": not phase_c_failures,
        "detail": phase_c_failures or [],
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
    return {
        "overall": "PASS" if overall_pass else "FAIL",
        "checks": checks,
        # Exploratory measurement, not yet a pass/fail gate (Beta 0.5.5) -
        # no real-data-backed threshold exists yet for what "trending toward
        # a wall" looks like for this engine on this runner class. Establish
        # bounds from what this actually reports across real runs, the same
        # way snapshot_budget/emit_budget were sized from measured numbers,
        # not guessed ahead of any data.
        "engine_resource_trend": _engine_resource_trend(samples),
    }


def _engine_resource_trend(samples: list[dict]) -> dict:
    points = [rec["engine_process"] for rec in samples
             if rec.get("engine_process") and "error" not in rec["engine_process"]]
    errors = [rec["engine_process"]["error"] for rec in samples
             if rec.get("engine_process") and "error" in rec["engine_process"]]
    if not points:
        return {"samples": 0, "errors": errors[:5]}

    def _series(key: str) -> list[int]:
        return [p[key] for p in points if p.get(key) is not None]

    def _summary(key: str) -> dict | None:
        vals = _series(key)
        if not vals:
            return None
        return {"first": vals[0], "last": vals[-1], "min": min(vals), "max": max(vals)}

    return {
        "samples": len(points),
        "errors": errors[:5],          # e.g. NoSuchProcess - itself evidence
        "rss_bytes": _summary("rss"),
        "handles": _summary("handles"),
        "threads": _summary("threads"),
    }


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
        sampler = Sampler(api_base, out, engine_pid=proc.pid)
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
        sampler = Sampler(api_base, out, engine_pid=proc.pid)
        sampler.start()

        before_c: dict = {}
        after_c: dict = {}
        phase_c_failures: list[str] = []
        unhandled_exception: str | None = None
        try:
            sampler.current_phase = "A"
            time.sleep(60)

            sampler.current_phase = "B"
            run_benign_activity(90)

            before_c = _safe_get(api_base, "/api/edr/causality/stats")
            sampler.current_phase = "C"
            if not run_phase_c(api_base):
                phase_c_failures.append("phase_c")
            time.sleep(20)
            after_c = _safe_get(api_base, "/api/edr/causality/stats")

            sampler.current_phase = "D"
            run_benign_activity(60)
        except Exception as exc:                     # noqa: BLE001
            unhandled_exception = f"{type(exc).__name__}: {exc}"
            print(f"[run_dry_run] unhandled exception during phase execution, "
                  f"scoring what was already collected: {unhandled_exception}")

        sampler.stop()
        engine_exit_code = proc.poll()
        result = score(sampler.samples, sampler.transitions,
                       sampler.health_failures, sampler.health_successes,
                       before_c.get("nodes"), after_c.get("nodes"), "dry-run",
                       phase_c_failures=phase_c_failures,
                       engine_exit_code=engine_exit_code)
        result["mode"] = "dry-run"
        result["evidence"] = False
        result["note"] = "Validates the harness itself, not reliability. Not a qualification pass/fail."
        if unhandled_exception:
            result["unhandled_exception"] = unhandled_exception
            result["overall"] = "FAIL"
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
        sampler = Sampler(api_base, out, engine_pid=proc.pid)
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


def run_soak(minutes: float, contention: bool = False) -> int:
    print("=" * 70)
    mode = "contention" if contention else "soak"
    print(f"MODE: {mode} -- CI, {minutes:.0f}-minute "
          f"{'first-failure attribution' if contention else 'qualification run'}")
    print("=" * 70)
    proc, api_base, data_dir = start_engine()
    try:
        wait_for_real_readiness(api_base)
        out = RESULTS_DIR / f"beta05_{mode}.jsonl"
        if out.exists():
            out.unlink()
        sampler = Sampler(api_base, out, engine_pid=proc.pid,
                          stop_on_failure=contention)
        sampler.start()
        # A Tier B subset failure/timeout is a scored finding
        # (phase_c_technique_execution_completed), never an uncaught
        # exception - the whole point is to keep every sample already
        # collected instead of discarding it (see PHASE_C_TIMEOUT_S's
        # docstring for the run that motivated this).
        phase_c_failures: list[str] = []
        before_c: dict = {}
        after_c: dict = {}
        unhandled_exception: str | None = None

        def pause(seconds: float) -> None:
            if contention:
                sampler.failure.wait(seconds)
            else:
                time.sleep(seconds)

        total_s = minutes * 60.0
        # Fixed A/B/C/D budgets per the predeclared spec; whatever remains
        # goes to phase E, floored at 0 so a short --minutes for testing
        # still runs end-to-end rather than going negative.
        a_s, b_s, c_settle_s, d_s = 150.0, 300.0, 300.0, 300.0
        e_s = max(0.0, total_s - (a_s + b_s + c_settle_s + d_s))

        # EVERYTHING below is wrapped: an engine that becomes briefly or
        # permanently unreachable mid-run (Beta 0.5.5 - a real, unexplained
        # finding, not a harness bug) must never crash this script and
        # discard every sample already collected. Whatever samples exist by
        # the time anything raises still get scored.
        try:
            sampler.current_phase = "A"
            pause(a_s)

            sampler.current_phase = "B"
            run_benign_activity(b_s, stop_event=sampler.failure if contention else None)

            if not (contention and sampler.failure.is_set()):
                before_c = _safe_get(api_base, "/api/edr/causality/stats")

            sampler.current_phase = "C"
            if not sampler.failure.is_set() and not run_phase_c(api_base):
                phase_c_failures.append("phase_c")
            elapsed = min(60.0, c_settle_s)
            pause(elapsed)
            run_benign_activity(max(0.0, c_settle_s - elapsed),
                                stop_event=sampler.failure if contention else None)
            if not sampler.failure.is_set():
                after_c = _safe_get(api_base, "/api/edr/causality/stats")

            sampler.current_phase = "D"
            run_benign_activity(d_s, stop_event=sampler.failure if contention else None)

            sampler.current_phase = "E"
            e_deadline = time.time() + e_s
            toggle = 0
            while time.time() < e_deadline and not sampler.failure.is_set():
                remaining = e_deadline - time.time()
                if toggle % 3 == 2 and remaining > 60:
                    if not run_phase_c(api_base):
                        phase_c_failures.append(f"phase_e_toggle_{toggle}")
                else:
                    run_benign_activity(min(90.0, max(1.0, remaining)),
                                        stop_event=sampler.failure if contention else None)
                toggle += 1
        except Exception as exc:                    # noqa: BLE001
            unhandled_exception = f"{type(exc).__name__}: {exc}"
            print(f"[run_soak] unhandled exception during phase execution, "
                  f"scoring what was already collected: {unhandled_exception}")

        sampler.stop()
        # Beta 0.5.5: the engine process disappearing entirely (not just one
        # collector or one API call) is a distinct, more fundamental failure
        # than anything the per-collector checks can see - checked directly
        # against the subprocess, not inferred from HTTP errors alone.
        engine_exit_code = proc.poll()
        result = score(sampler.samples, sampler.transitions,
                       sampler.health_failures, sampler.health_successes,
                       before_c.get("nodes"), after_c.get("nodes"), mode,
                       phase_c_failures=phase_c_failures,
                       engine_exit_code=engine_exit_code)
        result["mode"] = mode
        result["minutes"] = minutes
        result["platform"] = platform.platform()
        if unhandled_exception:
            result["unhandled_exception"] = unhandled_exception
            result["overall"] = "FAIL"
        if contention:
            result["first_failure"] = sampler.first_failure
            result["experiment_completed_without_failure"] = not sampler.failure.is_set()
        _write_summary(mode, result)
        print(json.dumps(result, indent=2, default=str))
        # Finding and preserving the failure is a successful attribution run.
        if contention:
            return 0 if sampler.first_failure is not None else 1
        return 0 if result["overall"] == "PASS" else 1
    finally:
        stop_engine(proc)
        shutil.rmtree(data_dir, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=["smoke", "dry-run", "fault-test", "contention", "soak"],
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
    if args.mode == "contention":
        return run_soak(args.minutes, contention=True)
    return run_soak(args.minutes)


if __name__ == "__main__":
    raise SystemExit(main())
