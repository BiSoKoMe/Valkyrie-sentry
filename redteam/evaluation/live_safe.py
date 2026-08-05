r"""Part 2 of ADR 0048 — the live-execution tier: real commands, on the real
host, scored against the REAL running EDR incident store. Tier A
(replay_harness.py) executes classifier functions directly on synthetic
probe_input; Tier B (run_live_evaluation.ps1) is a throwaway-VM exercise for
techniques too risky to run anywhere real. Neither ever answered the question
this file exists to answer: on THIS machine, right now, does an actual
`whoami.exe` process launched by an actual shell produce an actual incident
in the actual store, and how long does that take?

WHY THIS IS SAFE TO RUN OUTSIDE A VM
-------------------------------------
Every technique below is a bare, unmodified, read-only Windows diagnostic
command from a fixed allowlist (whoami, systeminfo, tasklist, ipconfig,
netstat, reg query, sc query, net view, net user, nltest /dclist, arp -a,
hostname) -- exactly the commands a Windows admin runs constantly with zero
side effects. `net user` is run bare (list), never with /add. `reg`/`sc` are
run with the QUERY verb only, never SET/DELETE/CREATE/START/STOP/CONFIG.
Every argv is a fixed tuple below -- there is no string formatting, no
shell=True, no user-controlled input reaching a shell. See `why_safe` on each
Technique for the specific justification.

This file does NOT touch Avast, Defender, any network adapter, DNS, the
firewall, or the (unsigned, must-not-load) valkyrie_km.sys kernel driver. It
starts Valkyrie itself with a fixed, hard-coded flag set that disables every
subsystem not needed to observe these techniques -- see `_ENGINE_FLAGS`.

TWO HONEST ARCHITECTURAL FACTS THIS FILE DOES NOT PAPER OVER
--------------------------------------------------------------
1. `native_audit.py` (ADR: commit d21c911) already gives this host a
   Sysmon-independent real-time command-line source: Security-log 4688, read
   by `etw/native_process.py`'s NativeProcessSensor, running the SAME
   classifier stack Sysmon EID 1 does. It stands down only when Sysmon is
   live. So "Sysmon stopped" on THIS host is not automatically "poller-only"
   -- it may be "native-4688 real-time, Sysmon-exclusive techniques (EID 8 /
   EID 10) unavailable". `run()` verifies which is actually true via
   `/api/sensors/status` and records it; it does not assume either way.
2. `process_telemetry.classify_discovery` deliberately never raises an
   incident for a single discovery command (Discovery is the one tactic
   where that is a guaranteed false-positive generator -- see
   `redteam/evaluation/catalog.py`'s `_RECON_BURST_NOTE`). systeminfo,
   tasklist, net view, and bare net user therefore have NO standalone
   capture path, by design -- credit for them can only ever come through the
   completed 'reconnaissance-burst' sequence incident. Scoring them
   "MISSED" for lacking a standalone incident would be measuring the harness's
   own misunderstanding, not the product. Each such Technique is tagged
   channel="burst_only" and scored against the shared burst incident, with
   that caveat carried into the report.

RUNNER SHAPE
------------
timestamp -> execute (bounded subprocess, argv logged before it runs) ->
poll GET /api/edr/incidents (bounded, never hangs) -> CAPTURED/MISSED +
latency_ms + detector + incident_id. Two isolated phases:
  Phase 1 (burst cluster): the 6 Discovery-tactic commands, run close
    together from this process so they share process lineage, so the
    reconnaissance-burst sequence (min_distinct=3 within 120s) gets a real
    chance to fire on REAL executions -- it has only ever been fed synthetic
    events before this.
  Phase 2 (no-path probes): the 6 commands with no Valkyrie code path at all
    (ipconfig, netstat, hostname, reg query, sc query, arp -a), run in
    isolation so a null result is cleanly attributable.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import median

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))

RESULTS_DIR = Path(__file__).resolve().parent / "results"
REPORT_PATH = Path(__file__).resolve().parent / "LIVE_SAFE_REPORT.md"
HISTORY_PATH = Path(__file__).resolve().parent / "LIVE_SAFE_HISTORY.md"

RUN_LABELS = ("poller_only", "sysmon")

BOOT_TIMEOUT_S = 60
COMMAND_TIMEOUT_S = 15          # bounded — a hung native tool cannot hang the runner
BURST_SETTLE_S = 45             # polling window after the last burst-cluster command
SOLO_SETTLE_S = 20              # polling window after each isolated no-path probe
POLL_INTERVAL_S = 1.0
BURST_COMMAND_GAP_S = 1.5       # spacing between burst-cluster commands


# =============================================================================
# The technique catalog — fixed argv only, drawn from the HARD SAFETY RULES
# allowlist (whoami, systeminfo, tasklist, ipconfig, netstat, reg QUERY,
# sc QUERY, net view, net user, nltest /dclist, arp -a, hostname). No string
# building, no shell=True — subprocess always receives this literal tuple.
# =============================================================================

@dataclass(frozen=True)
class LiveTechnique:
    id: str
    technique_id: str            # MITRE ATT&CK id
    technique_name: str
    argv: tuple                  # exact argv, executed with shell=False
    channel: str                 # standalone | burst_only | no_code_path
    why_safe: str
    catalog_ref: str = ""        # cross-ref into redteam/evaluation/catalog.py
    notes: str = ""

    def as_dict(self) -> dict:
        d = asdict(self)
        d["argv"] = list(self.argv)
        return d


# --- Phase 1: the reconnaissance-burst cluster (Discovery tactic) ----------
BURST_TECHNIQUES = (
    LiveTechnique(
        id="live-whoami-priv", technique_id="T1033",
        technique_name="System Owner/User Discovery (whoami /priv)",
        argv=("whoami", "/priv"), channel="burst_only",
        catalog_ref="disc-whoami-priv",
        why_safe="Reads the calling token's privilege list to stdout; no "
                  "argument to whoami mutates system state.",
        notes="Has its OWN named rule (behavioral_rules.py whoami-priv, LOW "
              "severity) but LOW does not clear the medium-severity incident "
              "gate in edr/engine.py -- so, like the bare-form Discovery "
              "commands below, this is only expected to surface via the "
              "reconnaissance-burst sequence, not as its own incident. "
              "Polled for both, in case that reading is wrong.",
    ),
    LiveTechnique(
        id="live-systeminfo", technique_id="T1082",
        technique_name="System Information Discovery",
        argv=("systeminfo",), channel="burst_only",
        catalog_ref="disc-systeminfo",
        why_safe="Built-in OS/hardware inventory dump to stdout; no write.",
    ),
    LiveTechnique(
        id="live-tasklist", technique_id="T1057",
        technique_name="Process Discovery",
        argv=("tasklist", "/v"), channel="burst_only",
        catalog_ref="disc-tasklist",
        why_safe="Lists running processes via the OS process snapshot API; "
                  "read-only.",
    ),
    LiveTechnique(
        id="live-net-view", technique_id="T1018",
        technique_name="Remote System Discovery (net view)",
        argv=("net", "view"), channel="burst_only",
        catalog_ref="disc-net-view",
        why_safe="Queries the local network browse list; a network READ, "
                  "issues no mutating request.",
    ),
    LiveTechnique(
        id="live-net-user", technique_id="T1087.001",
        technique_name="Account Discovery: Local Account (net user)",
        argv=("net", "user"), channel="burst_only",
        catalog_ref="disc-local-accounts",
        why_safe="Bare form ONLY, no /add -- lists local accounts, cannot "
                  "create one. behavioral_rules.py's account-creation rule "
                  "requires the literal '/add' token, absent here.",
    ),
    LiveTechnique(
        id="live-nltest-dclist", technique_id="T1482",
        technique_name="Domain Trust Discovery (nltest)",
        argv=("nltest", "/dclist"), channel="standalone",
        catalog_ref="disc-domain-trust",
        why_safe="Read-only domain-controller enumeration query. Fails "
                  "harmlessly with a usage/error message off-domain or "
                  "without a target; writes nothing either way.",
        notes="Has a named rule (nltest-domain, MEDIUM) which DOES clear "
              "the incident gate -- this is the one Discovery-tactic "
              "command with a real standalone-capture expectation.",
    ),
)

# --- Phase 2: commands with NO Valkyrie code path today ---------------------
# Verified by reading process_telemetry.py's _DISCOVERY_SOLO_BINS (only
# systeminfo.exe/tasklist.exe/whoami.exe) and _discovery_cmdline_technique
# (only nltest.exe and net.exe) plus behavioral_rules.py (no rule matches
# any of these). Included specifically to measure the gap honestly, not
# hidden because the expected answer is MISS.
NO_PATH_TECHNIQUES = (
    LiveTechnique(
        id="live-ipconfig", technique_id="T1016",
        technique_name="System Network Configuration Discovery (ipconfig)",
        argv=("ipconfig", "/all"), channel="no_code_path",
        why_safe="/all only displays adapter configuration; /release and "
                  "/renew (the mutating forms) are never used.",
        notes="No rule in behavioral_rules.py or process_telemetry.py "
              "recognizes ipconfig.exe at all.",
    ),
    LiveTechnique(
        id="live-netstat", technique_id="T1049",
        technique_name="System Network Connections Discovery (netstat)",
        argv=("netstat", "-ano"), channel="no_code_path",
        why_safe="Lists active connections/listening ports and owning "
                  "PIDs from the kernel's own connection table; a read.",
        notes="No rule recognizes netstat.exe.",
    ),
    LiveTechnique(
        id="live-hostname", technique_id="T1082",
        technique_name="System Information Discovery (hostname)",
        argv=("hostname",), channel="no_code_path",
        why_safe="Prints the computer name; takes no arguments that could "
                  "mutate anything.",
        notes="Distinct binary from systeminfo.exe -- NOT in "
              "_DISCOVERY_SOLO_BINS, so unlike systeminfo this contributes "
              "nothing to the burst sequence either.",
    ),
    LiveTechnique(
        id="live-reg-query", technique_id="T1012",
        technique_name="Query Registry (reg query)",
        argv=("reg", "query",
              r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"),
        channel="no_code_path",
        why_safe="QUERY verb only, against a key that ships on every "
                  "Windows install. ADD/DELETE/IMPORT/SAVE are never used.",
        notes="No rule recognizes reg.exe at all (the only reg.exe "
              "handling anywhere in this codebase is Valkyrie reading ITS "
              "OWN persistence-relevant keys, not classifying reg.exe "
              "invocations by other processes).",
    ),
    LiveTechnique(
        id="live-sc-query", technique_id="T1007",
        technique_name="System Service Discovery (sc query)",
        argv=("sc", "query", "eventlog"), channel="no_code_path",
        why_safe="QUERY verb only, against the built-in Windows Event Log "
                  "service. behavioral_rules.py's sc.exe rules require "
                  "'stop windefend' or a 'create' verb -- neither present.",
        notes="Deliberately queries 'eventlog', not Sysmon64/SysmonDrv, so "
              "this probe cannot be confused with this file's own Sysmon "
              "state verification (see verify_environment()).",
    ),
    LiveTechnique(
        id="live-arp", technique_id="T1016",
        technique_name="System Network Configuration Discovery (arp -a)",
        argv=("arp", "-a"), channel="no_code_path",
        why_safe="-a is the display flag; -d (delete) and -s (add static "
                  "entry) are never used.",
        notes="No rule recognizes arp.exe.",
    ),
)

ALL_TECHNIQUES = BURST_TECHNIQUES + NO_PATH_TECHNIQUES


# =============================================================================
# Command execution — every argv logged before it runs (HARD SAFETY RULE 6),
# shell=False always, bounded timeout always.
# =============================================================================

@dataclass
class ExecResult:
    argv: tuple
    ts_start: float              # time.time() — comparable to incident created_at
    ts_end: float
    returncode: int
    timed_out: bool = False


def run_command(argv: tuple) -> ExecResult:
    print(f"  [EXEC] {' '.join(argv)}")
    ts_start = time.time()
    try:
        p = subprocess.run(list(argv), capture_output=True, text=True,
                           timeout=COMMAND_TIMEOUT_S, shell=False,
                           encoding="utf-8", errors="replace")
        return ExecResult(argv, ts_start, time.time(), p.returncode)
    except subprocess.TimeoutExpired:
        return ExecResult(argv, ts_start, time.time(), -1, timed_out=True)
    except FileNotFoundError as exc:
        print(f"    !! {exc}")
        return ExecResult(argv, ts_start, time.time(), -2)


def run_readonly(argv: tuple, timeout: int = 15) -> tuple[int, str]:
    """Same discipline as run_command, for the environment-verification
    commands (sc query) — argv logged, bounded, never raises."""
    print(f"  [VERIFY] {' '.join(argv)}")
    try:
        p = subprocess.run(list(argv), capture_output=True, text=True,
                           timeout=timeout, shell=False,
                           encoding="utf-8", errors="replace")
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as exc:                       # noqa: BLE001
        return -1, f"{type(exc).__name__}: {exc}"


# =============================================================================
# Engine lifecycle — a fresh, isolated Valkyrie instance this file owns
# start-to-finish. Fixed flag set; nothing here is user-configurable, so the
# safety envelope cannot be narrowed by a bad CLI argument.
# =============================================================================

_ENGINE_FLAGS = (
    "--no-dns", "--no-firewall", "--no-unbound", "--no-ui",   # HARD SAFETY RULE 2/5
    "--no-sysmon-setup",     # HARD SAFETY RULE 1 — install_or_verify() can download+install
    "--no-download-lists",   # HARD SAFETY RULE 1 — external feeds are download-on-startup by default
    "--no-amsi",             # not needed for these techniques; minimizes surface touched
    "--no-ransomware-shield",
    "--no-intelligence",
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get(api_base: str, path: str, timeout: float = 8.0):
    with urllib.request.urlopen(f"{api_base}{path}", timeout=timeout) as r:
        return json.load(r)


def start_engine() -> tuple[subprocess.Popen, str, str]:
    port = _free_port()
    data_dir = tempfile.mkdtemp(prefix="valkyrie_live_safe_")
    env = dict(os.environ, VALKYRIE_DATA_DIR=data_dir,
               PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    cmd = [sys.executable, "-m", "valkyrie", *_ENGINE_FLAGS,
           "--web", "--web-port", str(port)]
    print(f"\n[ENGINE] starting: {' '.join(cmd)}")
    print(f"[ENGINE] isolated data dir: {data_dir}")
    proc = subprocess.Popen(cmd, cwd=str(_ROOT), env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace")
    api_base = f"http://127.0.0.1:{port}"
    deadline = time.time() + BOOT_TIMEOUT_S
    while time.time() < deadline:
        if proc.poll() is not None:
            out = (proc.stdout.read() or "")[-3000:]
            raise RuntimeError(f"engine exited during startup:\n{out}")
        try:
            _get(api_base, "/api/health", timeout=3.0)
            print(f"[ENGINE] healthy on {api_base}")
            return proc, api_base, data_dir
        except Exception:
            time.sleep(1)
    proc.terminate()
    raise RuntimeError(f"engine did not become healthy within {BOOT_TIMEOUT_S}s")


def stop_engine(proc: subprocess.Popen) -> str:
    if proc.poll() is not None:
        return proc.stdout.read() or ""
    proc.terminate()
    try:
        return proc.communicate(timeout=15)[0] or ""
    except subprocess.TimeoutExpired:
        proc.kill()
        return proc.communicate()[0] or ""


# =============================================================================
# Environment verification — "verify, do not assume". Uses only commands on
# the HARD SAFETY RULE 1 allowlist (sc QUERY) plus valkyrie.sysmon_manager's
# own already-vetted, read-only, fully-tested probe (never installs, never
# writes — see tests/test_sysmon_manager.py, 34/34 mocked-branch checks).
# =============================================================================

def verify_environment(run_label: str) -> dict:
    env: dict = {"run_label": run_label, "commands": []}

    for name, argv in (("sysmon64", ("sc", "query", "Sysmon64")),
                       ("sysmondrv", ("sc", "query", "SysmonDrv"))):
        rc, out = run_readonly(argv)
        env["commands"].append({"argv": list(argv), "returncode": rc, "output": out.strip()})
        env[f"sc_query_{name}"] = out.strip()

    # native_audit precheck — this file must never be the reason a write
    # happens. If this is already enabled (as ADR 0048 found it to be on
    # this host), enable_process_auditing() inside `main()`'s EDR startup
    # takes its "already enabled" fast path and performs no write at all;
    # if it is NOT already enabled, this run aborts before starting the
    # engine rather than silently letting it write the registry/audit policy.
    from valkyrie import native_audit
    already = native_audit.is_process_auditing_enabled()
    env["native_audit_already_enabled"] = already
    if not already:
        raise RuntimeError(
            "native_audit process-creation auditing is NOT already enabled "
            "on this host. Starting the engine would call "
            "native_audit.enable_process_auditing(), which WRITES a "
            "registry value and changes system audit policy — outside "
            "HARD SAFETY RULE 1 ('nothing that writes'). Refusing to start. "
            "(Read-only check only was performed; nothing was changed.)")

    # The authoritative Sysmon fact — read-only PowerShell queries inside
    # probe_sysmon(), the same function the running product uses to decide
    # its own degraded status (ADR 0048 commit 1e re-export shim).
    from valkyrie.sysmon_manager import probe_sysmon
    sysmon_env = probe_sysmon()
    env["probe_sysmon"] = sysmon_env.as_dict()

    if run_label == "sysmon":
        required_eids = (1, 3, 7, 8, 10)
        missing = [e for e in required_eids if not sysmon_env.provides(e)]
        if sysmon_env.service_state != "Running" or missing:
            raise RuntimeError(
                "RUN B requires a VERIFIED healthy Sysmon, not an assumed "
                "one. probe_sysmon() reports: service_state="
                f"{sysmon_env.service_state!r}, configured_eids="
                f"{list(sysmon_env.configured_eids)}, missing required "
                f"EIDs={missing}. Repair Sysmon via Avast's UI first, then "
                "re-run. (Nothing was changed by this check.)")
        print("[VERIFY] Sysmon confirmed healthy: service Running, "
              f"EIDs {required_eids} all present in active config.")
    else:
        if sysmon_env.present and sysmon_env.collection_live:
            print("[VERIFY] NOTE: Sysmon is actually live on this host right "
                  "now. run_label='poller_only' no longer describes reality — "
                  "re-check before trusting this run as the degraded baseline.")
        else:
            print(f"[VERIFY] Sysmon degraded as expected for this run "
                  f"(service_state={sysmon_env.service_state!r}, "
                  f"collection_live={sysmon_env.collection_live}).")

    return env


# =============================================================================
# Incident polling — bounded, never hangs.
# =============================================================================

def _parse_ts(ts: str) -> float:
    try:
        return datetime.fromisoformat(ts).timestamp()
    except ValueError:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()


def fetch_incidents(api_base: str) -> list[dict]:
    try:
        return _get(api_base, "/api/edr/incidents")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return []


def fetch_incident_detail(api_base: str, inc_id: str) -> dict:
    try:
        return _get(api_base, f"/api/edr/incidents/{inc_id}")
    except Exception:
        return {}


def poll_until(predicate, deadline: float, interval: float = POLL_INTERVAL_S):
    while True:
        result = predicate()
        if result is not None:
            return result
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval)


def _detector_of(api_base: str, inc: dict) -> tuple[str, str]:
    """(source, technique) of the incident's most relevant detection."""
    detail = fetch_incident_detail(api_base, inc["id"])
    dets = detail.get("detections") or []
    if not dets:
        return "", ""
    d = dets[-1]
    return str(d.get("source", "")), str(d.get("technique", ""))


# =============================================================================
# Result record + the two execution phases
# =============================================================================

@dataclass
class TechniqueResult:
    id: str
    technique_id: str
    technique_name: str
    argv: list
    channel: str
    executed: bool
    captured: bool
    latency_ms: float | None
    detector: str
    incident_id: str
    incident_title: str
    notes: str = ""


def _latency_ms(exec_ts: float, incident: dict) -> float:
    delta = (_parse_ts(incident["created_at"]) - exec_ts) * 1000.0
    return max(0.0, delta)


def run_burst_phase(api_base: str) -> list[TechniqueResult]:
    print("\n=== PHASE 1: reconnaissance-burst cluster "
          f"({len(BURST_TECHNIQUES)} distinct Discovery techniques) ===")
    baseline = {i["id"] for i in fetch_incidents(api_base)}
    execs: dict[str, ExecResult] = {}
    for i, tech in enumerate(BURST_TECHNIQUES):
        execs[tech.id] = run_command(tech.argv)
        if i < len(BURST_TECHNIQUES) - 1:
            time.sleep(BURST_COMMAND_GAP_S)
    cluster_start = min(e.ts_start for e in execs.values())

    settle_deadline = time.monotonic() + BURST_SETTLE_S
    print(f"[POLL] settling up to {BURST_SETTLE_S}s for the burst incident "
          "and any standalone captures...")

    def find_burst():
        for inc in fetch_incidents(api_base):
            if (inc["id"] not in baseline
                    and inc.get("category") == "attack_sequence"
                    and inc.get("title", "").startswith("Reconnaissance burst")
                    and _parse_ts(inc["created_at"]) >= cluster_start - 2):
                return inc
        return None

    def find_standalone(process_name: str):
        for inc in fetch_incidents(api_base):
            if (inc["id"] not in baseline
                    and inc.get("category") != "attack_sequence"
                    and inc.get("process_name", "").lower() == process_name.lower()
                    and _parse_ts(inc["created_at"]) >= cluster_start - 2):
                return inc
        return None

    burst_incident = poll_until(find_burst, settle_deadline)
    standalone_by_image: dict[str, dict] = {}
    if burst_incident is None:
        # Still worth a per-technique standalone sweep even if the burst
        # itself never completed (e.g. nltest-domain firing alone).
        for tech in BURST_TECHNIQUES:
            image = tech.argv[0]
            hit = poll_until(lambda im=image: find_standalone(im), settle_deadline)
            if hit:
                standalone_by_image[image] = hit
    else:
        print(f"[POLL] reconnaissance-burst incident CAPTURED: {burst_incident['id']}")
        for tech in BURST_TECHNIQUES:
            hit = find_standalone(tech.argv[0])
            if hit:
                standalone_by_image[tech.argv[0]] = hit

    results = []
    for tech in BURST_TECHNIQUES:
        ex = execs[tech.id]
        image = tech.argv[0]
        standalone = standalone_by_image.get(image)
        if standalone is not None:
            source, technique = _detector_of(api_base, standalone)
            results.append(TechniqueResult(
                tech.id, tech.technique_id, tech.technique_name,
                list(tech.argv), tech.channel, True, True,
                _latency_ms(ex.ts_start, standalone),
                source or "unknown", standalone["id"], standalone["title"],
                notes="captured as a STANDALONE incident"))
        elif burst_incident is not None:
            results.append(TechniqueResult(
                tech.id, tech.technique_id, tech.technique_name,
                list(tech.argv), tech.channel, True, True,
                _latency_ms(ex.ts_start, burst_incident),
                "edr.sequence", burst_incident["id"], burst_incident["title"],
                notes="captured via the shared reconnaissance-burst incident "
                      "only — no standalone capture exists for this "
                      "technique by design (see module docstring)"))
        else:
            results.append(TechniqueResult(
                tech.id, tech.technique_id, tech.technique_name,
                list(tech.argv), tech.channel, True, False, None,
                "", "", "", notes="neither a standalone incident nor the "
                                  "reconnaissance-burst incident appeared "
                                  f"within {BURST_SETTLE_S}s"))
    return results


def run_no_path_phase(api_base: str) -> list[TechniqueResult]:
    print(f"\n=== PHASE 2: no-code-path probes ({len(NO_PATH_TECHNIQUES)}) ===")
    results = []
    for tech in NO_PATH_TECHNIQUES:
        baseline = {i["id"] for i in fetch_incidents(api_base)}
        ex = run_command(tech.argv)
        image = tech.argv[0]
        deadline = time.monotonic() + SOLO_SETTLE_S

        def find():
            for inc in fetch_incidents(api_base):
                if (inc["id"] not in baseline
                        and inc.get("process_name", "").lower() == image.lower()):
                    return inc
            return None

        hit = poll_until(find, deadline)
        if hit is not None:
            source, technique = _detector_of(api_base, hit)
            print(f"  [!!] UNEXPECTED CAPTURE for {image}: {hit['title']}")
            results.append(TechniqueResult(
                tech.id, tech.technique_id, tech.technique_name,
                list(tech.argv), tech.channel, True, True,
                _latency_ms(ex.ts_start, hit), source or "unknown",
                hit["id"], hit["title"],
                notes="CAPTURED — contradicts the 'no code path' prediction; "
                      "reported as-is, not suppressed"))
        else:
            print(f"  [ ] {image}: no incident within {SOLO_SETTLE_S}s (as predicted)")
            results.append(TechniqueResult(
                tech.id, tech.technique_id, tech.technique_name,
                list(tech.argv), tech.channel, True, False, None,
                "", "", "", notes="no code path recognizes this command "
                                  "(verified, not assumed — see notes)"))
    return results


# =============================================================================
# Report generation
# =============================================================================

def _stats(results: list[TechniqueResult]) -> dict:
    captured = [r for r in results if r.captured]
    latencies = sorted(r.latency_ms for r in captured if r.latency_ms is not None)
    sources = {}
    for r in captured:
        sources[r.detector] = sources.get(r.detector, 0) + 1

    def _pctl(data, p):
        if not data:
            return None
        k = (len(data) - 1) * p
        f, c = int(k), min(int(k) + 1, len(data) - 1)
        return data[f] if f == c else data[f] + (data[c] - data[f]) * (k - f)

    return {
        "total": len(results),
        "captured": len(captured),
        "capture_rate": len(captured) / len(results) if results else 0.0,
        "latency_ms_median": median(latencies) if latencies else None,
        "latency_ms_p95": _pctl(latencies, 0.95),
        "detector_source_counts": sources,
    }


def write_json_result(run_label: str, env: dict, engine_meta: dict,
                      results: list[TechniqueResult], sensors_status: dict) -> Path:
    RESULTS_DIR.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    payload = {
        "tier": "live_safe",
        "run_label": run_label,
        "generated_at": ts,
        "environment": env,
        "engine": engine_meta,
        "sensors_status": sensors_status,
        "results": [asdict(r) for r in results],
        "summary": _stats(results),
    }
    path = RESULTS_DIR / f"{ts}__live_safe_{run_label}.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _latest_by_label(label: str) -> dict | None:
    candidates = sorted(RESULTS_DIR.glob(f"*__live_safe_{label}.json"))
    if not candidates:
        return None
    return json.loads(candidates[-1].read_text(encoding="utf-8"))


def _fmt_ms(v) -> str:
    return "—" if v is None else f"{v:.0f}"


def _table(results: list[dict]) -> str:
    lines = ["| Technique | Executed | Captured | Latency (ms) | Detector | Incident |",
             "|---|---|---|---:|---|---|"]
    for r in results:
        cap = "**CAPTURED**" if r["captured"] else "missed"
        lines.append(
            f"| {r['technique_id']} {r['technique_name']} | "
            f"`{' '.join(r['argv'])}` | {cap} | {_fmt_ms(r['latency_ms'])} | "
            f"{r['detector'] or '—'} | {r['incident_id'] or '—'} |")
    return "\n".join(lines)


def render_report() -> None:
    """Regenerates LIVE_SAFE_REPORT.md from whatever run(s) exist on disk —
    one baseline if only one label has run, both plus a DELTA section once
    poller_only and sysmon both exist."""
    poller = _latest_by_label("poller_only")
    sysmon = _latest_by_label("sysmon")

    parts = ["# Valkyrie Live-Safe Evaluation (ADR 0048, Part 2)\n",
             "Real read-only commands, executed on this host, scored against "
             "the real running EDR incident store. See "
             "`redteam/evaluation/live_safe.py` module docstring for the "
             "safety model and the two architectural caveats "
             "(native-4688-vs-poller, burst-only Discovery scoring).\n"]

    for label, data, title in (("poller_only", poller, "RUN A — degraded-Sysmon baseline"),
                               ("sysmon", sysmon, "RUN B — healthy-Sysmon baseline")):
        if data is None:
            parts.append(f"## {title}\n\n_not yet run_\n")
            continue
        s = data["summary"]
        parts.append(f"## {title}\n")
        parts.append(f"Generated: {data['generated_at']}  \n"
                     f"Capture rate: **{s['captured']}/{s['total']} "
                     f"({s['capture_rate']*100:.0f}%)**  \n"
                     f"Latency: median {_fmt_ms(s['latency_ms_median'])} ms, "
                     f"p95 {_fmt_ms(s['latency_ms_p95'])} ms  \n"
                     f"Detector sources: {s['detector_source_counts']}\n")
        env = data["environment"]
        parts.append(f"Sysmon at run time: service_state="
                     f"`{env['probe_sysmon']['service_state']}`, "
                     f"collection_live=`{env['probe_sysmon']['collection_live']}`, "
                     f"configured_eids=`{env['probe_sysmon']['configured_eids']}`  \n"
                     f"native_audit already enabled: "
                     f"`{env['native_audit_already_enabled']}`\n")
        parts.append(_table(data["results"]))
        parts.append("")

    if poller is not None and sysmon is not None:
        parts.append("## DELTA — the measured value of the Sysmon dependency\n")
        ps, ss = poller["summary"], sysmon["summary"]
        parts.append(f"Capture rate: {ps['captured']}/{ps['total']} "
                     f"({ps['capture_rate']*100:.0f}%) -> "
                     f"{ss['captured']}/{ss['total']} "
                     f"({ss['capture_rate']*100:.0f}%)  \n"
                     f"Median latency: {_fmt_ms(ps['latency_ms_median'])} ms -> "
                     f"{_fmt_ms(ss['latency_ms_median'])} ms  \n"
                     f"p95 latency: {_fmt_ms(ps['latency_ms_p95'])} ms -> "
                     f"{_fmt_ms(ss['latency_ms_p95'])} ms\n")
        by_id_a = {r["id"]: r for r in poller["results"]}
        by_id_b = {r["id"]: r for r in sysmon["results"]}
        lines = ["| Technique | Poller-only | Sysmon | Changed |",
                 "|---|---|---|---|"]
        for tid in by_id_a:
            a, b = by_id_a[tid], by_id_b.get(tid)
            if b is None:
                continue
            a_s = "CAPTURED" if a["captured"] else "missed"
            b_s = "CAPTURED" if b["captured"] else "missed"
            changed = "→ **gained**" if (not a["captured"] and b["captured"]) else \
                     ("→ **lost**" if (a["captured"] and not b["captured"]) else "same")
            lines.append(f"| {a['technique_id']} {a['technique_name']} | "
                        f"{a_s} | {b_s} | {changed} |")
        parts.append("\n".join(lines))

    REPORT_PATH.write_text("\n".join(parts) + "\n", encoding="utf-8")


def append_history_row(data: dict) -> None:
    header_needed = not HISTORY_PATH.exists()
    s = data["summary"]
    with HISTORY_PATH.open("a", encoding="utf-8") as f:
        if header_needed:
            f.write("# Live-safe evaluation history\n\n"
                    "One row per run. See LIVE_SAFE_REPORT.md for the latest "
                    "full report and delta.\n\n"
                    "| Timestamp (UTC) | Label | Captured | Total | Rate | "
                    "Median latency (ms) |\n|---|---|---|---|---|---|\n")
        f.write(f"| {data['generated_at']} | {data['run_label']} | "
                f"{s['captured']} | {s['total']} | {s['capture_rate']*100:.0f}% | "
                f"{_fmt_ms(s['latency_ms_median'])} |\n")


# =============================================================================
# Orchestration
# =============================================================================

def run(run_label: str) -> int:
    if run_label not in RUN_LABELS:
        print(f"error: run_label must be one of {RUN_LABELS}")
        return 2

    print(f"=== Live-safe evaluation — run_label={run_label} ===")
    env = verify_environment(run_label)   # raises RuntimeError to abort, on purpose

    proc, api_base, data_dir = start_engine()
    engine_meta = {"api_base": api_base, "data_dir": data_dir,
                   "flags": list(_ENGINE_FLAGS)}
    try:
        sensors_status = _get(api_base, "/api/sensors/status")
        print(f"[ENGINE] active sensors: {sensors_status}")

        results = run_burst_phase(api_base) + run_no_path_phase(api_base)

        out_path = write_json_result(run_label, env, engine_meta, results, sensors_status)
        print(f"\n[REPORT] wrote {out_path}")
    finally:
        boot_output = stop_engine(proc)
        if "Traceback (most recent call last)" in boot_output:
            idx = boot_output.find("Traceback (most recent call last)")
            print("\n[ENGINE] WARNING — traceback in engine output:")
            print(boot_output[idx:idx + 1500])

    data = json.loads(out_path.read_text(encoding="utf-8"))
    append_history_row(data)
    render_report()

    s = data["summary"]
    print(f"\n=== DONE: {s['captured']}/{s['total']} captured "
         f"({s['capture_rate']*100:.0f}%), "
         f"median latency {_fmt_ms(s['latency_ms_median'])} ms ===")
    print(f"Report: {REPORT_PATH}")
    return 0


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--run-label", required=True, choices=RUN_LABELS,
                    help="poller_only (RUN A, Sysmon degraded) or "
                         "sysmon (RUN B, Sysmon verified healthy)")
    args = ap.parse_args()
    try:
        return run(args.run_label)
    except RuntimeError as exc:
        print(f"\nABORTED: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
