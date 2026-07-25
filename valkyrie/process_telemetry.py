"""Process telemetry collector — endpoint visibility beyond DNS.

Valkyrie historically saw only DNS. This collector adds the first real endpoint
signal: it watches the process table and emits a normalized ``TelemetryEvent``
(category ``process``, activity ``exec``) for every newly-started process, with
lightweight, honest behavioral tagging.

Scope and honesty:
  * This is a **userland poller** (psutil), not a kernel sensor. It sees process
    starts on a short interval; a process that starts and exits between polls can
    be missed. Real-time, tamper-resistant capture (ETW on Windows, eBPF on
    Linux) is the next step — this collector is the portable seam those plug into
    and emits the same schema.
  * No privileges are required for the current user's processes; more are visible
    as root/admin. It degrades gracefully (does nothing) if psutil is absent or
    access is denied — it never raises into the caller.

The suspicious-process heuristics are deliberately small and explainable
(LOLBins, Office-spawns-shell, execution from temp/download dirs). They are a
starting point, not a replacement for a real detection-engineering pipeline, and
they say so.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, replace
from typing import Callable, Optional

from .behavioral_rules import classify_behavior
from .behavior_score import classify_anomaly
from .telemetry import (
    ACT_FLAGGED, ACT_OBSERVED, CAT_PROCESS,
    SEV_HIGH, SEV_INFO, SEV_LOW, SEV_MEDIUM, severity_rank, TelemetryEvent,
)

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False


# ---------------------------------------------------------------------------
# Behavioral heuristics (pure, unit-tested)
# ---------------------------------------------------------------------------

# Living-off-the-land binaries commonly abused to run attacker code while
# looking like normal system activity.
_LOLBINS = frozenset({
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe",
    "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "wmic.exe",
    "curl.exe", "schtasks.exe", "at.exe", "sc.exe",
})

# Office apps that should essentially never spawn a shell/script host — a classic
# macro-malware pattern.
_OFFICE = frozenset({
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
    "msaccess.exe",
})
_SHELLS = frozenset({
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "bash", "sh", "zsh",
})

# Path fragments that indicate execution from a low-trust, user-writable
# location. Matched against a separator-normalized path (backslashes -> slashes)
# so these forward-slash fragments catch both Windows and Unix paths.
_SUSPICIOUS_PATHS = (
    "/temp/", "/tmp/", "/downloads/",
    "/appdata/local/temp", "/windows/temp", "/var/tmp/",
)


def classify_process(name: str, path: str = "",
                     parent_name: str = "") -> tuple[str, list[str], str]:
    """Return (severity, labels, reason) for a process start.

    Pure and deterministic — the whole heuristic surface lives here so it can be
    unit-tested without touching the OS.
    """
    n = (name or "").lower()
    p = (path or "").lower().replace("\\", "/")   # normalize separators
    par = (parent_name or "").lower()

    severity = SEV_INFO
    labels: list[str] = []
    reasons: list[str] = []

    def _raise(to: str) -> None:
        nonlocal severity
        if severity_rank(to) > severity_rank(severity):
            severity = to

    if par in _OFFICE and n in _SHELLS:
        labels.append("office_child_shell")
        reasons.append(f"{par} spawned a shell/script host ({n})")
        _raise(SEV_HIGH)
    elif n in _LOLBINS:
        labels.append("lolbin")
        reasons.append(f"living-off-the-land binary ({n})")
        _raise(SEV_MEDIUM)

    if any(frag in p for frag in _SUSPICIOUS_PATHS):
        labels.append("suspicious_path")
        reasons.append("executable runs from a temp/download directory")
        _raise(SEV_MEDIUM if severity_rank(severity) < severity_rank(SEV_MEDIUM)
               else severity)
        if severity == SEV_INFO:
            _raise(SEV_LOW)

    return severity, labels, "; ".join(reasons)


# ---------------------------------------------------------------------------
# Command-line heuristics (pure, unit-tested). The command line is the single
# most valuable process-telemetry field: obfuscation, download cradles and
# hidden-window flags are the clearest signals of malicious LOLBin use.
# ---------------------------------------------------------------------------
_ENCODED_PS = ("-enc ", "-enc:", "-encodedcommand", "-ec ", " -e ")
_HIDDEN_FLAGS = ("-w hidden", "-windowstyle hidden", "-nop ", "-noprofile",
                 "-noni", "-noninteractive",
                 # WScript/CScript silent-batch mode ("wscript //b //nologo x.vbs")
                 # — a common way to run VBScript/JScript with no window or
                 # error prompts. Trailing space keeps this off URLs (`//blah`).
                 "//b ", "//nologo")
_DOWNLOAD_CRADLES = (
    "downloadstring", "downloadfile", "downloaddata", "invoke-expression",
    "iex(", "iex (", "iex ", "frombase64string", "net.webclient", "webclient",
    "start-bitstransfer", "bitstransfer", "invoke-webrequest", "invoke-restmethod",
    "certutil -urlcache", "certutil.exe -urlcache", "certutil -decode",
    "-decodehex", "wget http", "curl http", "wget.exe http", "curl.exe http",
)


def classify_cmdline(name: str, cmdline: str) -> tuple[str, list[str], str]:
    """Return (severity, labels, reason) from a process command line. Pure."""
    c = (cmdline or "").lower()
    severity = SEV_INFO
    labels: list[str] = []
    reasons: list[str] = []
    if not c:
        return severity, labels, ""

    def _raise(to: str) -> None:
        nonlocal severity
        if severity_rank(to) > severity_rank(severity):
            severity = to

    if any(t in c for t in _ENCODED_PS):
        labels.append("encoded_powershell")
        reasons.append("encoded/obfuscated command line")
        _raise(SEV_HIGH)
    if any(t in c for t in _DOWNLOAD_CRADLES):
        labels.append("download_cradle")
        reasons.append("in-memory download/execute cradle")
        _raise(SEV_HIGH)
    if any(t in c for t in _HIDDEN_FLAGS):
        labels.append("hidden_window")
        reasons.append("hidden / non-interactive execution flags")
        _raise(SEV_MEDIUM)
    return severity, labels, "; ".join(reasons)


@dataclass(frozen=True)
class ProcInfo:
    pid: int
    name: str
    path: str = ""
    ppid: int = 0
    parent_name: str = ""
    create_time: float = 0.0
    cmdline: str = ""
    parent_chain: tuple = ()      # (immediate parent, grandparent, …) names

    def key(self) -> tuple[int, float]:
        # pid alone is not unique over time (reused); pair with create_time.
        return (self.pid, round(self.create_time, 3))

    def to_event(self) -> TelemetryEvent:
        severity, labels, reason = classify_process(
            self.name, self.path, self.parent_name)
        csev, clabels, creason = classify_cmdline(self.name, self.cmdline)
        if severity_rank(csev) > severity_rank(severity):
            severity = csev
        labels = labels + clabels
        reason = "; ".join(r for r in (reason, creason) if r)

        # Behavioral IOA rule engine — the broad, MITRE-mapped content layer.
        # Its top hit's technique is carried explicitly so the EDR attaches the
        # exact ATT&CK id (and the kill-chain gets the exact tactic) rather than
        # inferring one from labels.
        technique = ""
        behavior = classify_behavior(self.name, self.parent_name,
                                     self.cmdline, self.path)
        if behavior is not None:
            if severity_rank(behavior["severity"]) > severity_rank(severity):
                severity = behavior["severity"]
            for lab in behavior["labels"]:
                if lab not in labels:
                    labels.append(lab)
            reason = "; ".join(r for r in (reason, behavior["reason"]) if r)
            technique = behavior["technique"]

        # Behavioral anomaly scorer — the *generalizing* layer. Where the rule
        # engine and classifiers key on known shapes, the nose scores intrinsic
        # wrongness (masquerade, obfuscation, impossible ancestry) and so catches
        # shapes no rule was written for. It only surfaces when it FIRES (crossed
        # its threshold), and defers to a rule's exact technique when one exists.
        anomaly = classify_anomaly(self.name, self.parent_name,
                                   self.cmdline, self.path)
        if anomaly is not None:
            if severity_rank(anomaly["severity"]) > severity_rank(severity):
                severity = anomaly["severity"]
            for lab in anomaly["labels"]:
                if lab not in labels:
                    labels.append(lab)
            reason = "; ".join(r for r in (reason, anomaly["reason"]) if r)
            if not technique:
                technique = anomaly["technique"]

        action = ACT_FLAGGED if severity_rank(severity) >= severity_rank(SEV_MEDIUM) \
            else ACT_OBSERVED
        return TelemetryEvent(
            category=CAT_PROCESS, activity="exec", action=action,
            ts=self.create_time or time.time(),
            actor_pid=self.pid, actor_name=self.name, actor_path=self.path,
            target={"path": self.path},
            severity=severity, reason=reason, source="process_collector",
            labels=labels,
            fields={"ppid": self.ppid, "parent_name": self.parent_name,
                    "cmdline": self.cmdline, "technique": technique,
                    "parent_chain": list(self.parent_chain)},
        )


def diff_snapshots(old: dict, new: dict) -> list[ProcInfo]:
    """Return processes present in ``new`` but not ``old`` (keyed by pid+ctime)."""
    return [info for k, info in new.items() if k not in old]


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class ProcessCollector:
    """Polls the process table and emits a TelemetryEvent per new process.

    ``emit`` is called with each ``TelemetryEvent`` (typically wired to
    ``bus.publish(ev.bus_message())``). The first poll establishes a baseline
    silently — only processes that appear *after* start are reported, so we don't
    flood the pipeline with every already-running process at launch.
    """

    def __init__(self, emit: Callable[[TelemetryEvent], None],
                 interval: float = 2.0) -> None:
        self._emit = emit
        self._interval = max(0.25, float(interval))
        # None = no baseline yet (a sentinel, not truthiness) so an empty first
        # snapshot is still a valid baseline rather than causing a re-seed.
        self._last: Optional[dict] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def available(self) -> bool:
        return _PSUTIL

    def snapshot(self) -> dict:
        """Return {key: ProcInfo} for currently-running processes.

        Never raises: per-process access errors are skipped, and an absent psutil
        yields an empty snapshot (collector effectively disabled).
        """
        out: dict = {}
        if not _PSUTIL:
            return out
        # Cache pid -> name to resolve parent names cheaply.
        names: dict[int, str] = {}
        try:
            procs = list(psutil.process_iter(["pid", "name", "ppid", "create_time"]))
        except Exception:
            return out
        for pr in procs:
            try:
                names[pr.info.get("pid", 0)] = (pr.info.get("name") or "")
            except Exception:
                pass
        for pr in procs:
            try:
                info = pr.info
                pid = int(info.get("pid", 0) or 0)
                ppid = int(info.get("ppid", 0) or 0)
                path = ""
                try:
                    path = pr.exe() or ""
                except Exception:
                    path = ""
                pi = ProcInfo(
                    pid=pid,
                    name=info.get("name") or "",
                    path=path,
                    ppid=ppid,
                    parent_name=names.get(ppid, ""),
                    create_time=float(info.get("create_time") or 0.0),
                )
                out[pi.key()] = pi
            except Exception:
                continue
        return out

    def _enrich(self, pi: "ProcInfo", pid_index: dict) -> "ProcInfo":
        """Add the command line and the parent-process name chain to a NEW
        process. Done only for fresh processes so the per-poll cost stays low
        (one cmdline() call per new process, not per process in the table)."""
        cmdline = ""
        if _PSUTIL:
            try:
                parts = psutil.Process(pi.pid).cmdline()
                cmdline = " ".join(parts) if parts else ""
            except Exception:
                cmdline = ""
        chain: list[str] = []
        seen: set[int] = set()
        ppid, depth = pi.ppid, 0
        while ppid and ppid not in seen and depth < 8:
            seen.add(ppid)
            depth += 1
            par = pid_index.get(ppid)
            if par is None:
                break
            chain.append(par.name)
            ppid = par.ppid
        return replace(pi, cmdline=cmdline, parent_chain=tuple(chain))

    def poll_once(self) -> int:
        """Take a snapshot, emit events for new processes, return the count.

        On the very first call it only seeds the baseline (returns 0).
        """
        new = self.snapshot()
        if self._last is None:
            self._last = new
            return 0
        fresh = diff_snapshots(self._last, new)
        self._last = new
        pid_index = {info.pid: info for info in new.values()}
        for pi in fresh:
            try:
                self._emit(self._enrich(pi, pid_index).to_event())
            except Exception:
                pass   # a bad emitter must never stop collection
        return len(fresh)

    def start(self) -> None:
        if self._running or not _PSUTIL:
            return
        self._last = self.snapshot()   # baseline; do not emit for existing procs
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="process-collector")
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def _loop(self) -> None:
        while self._running:
            time.sleep(self._interval)
            if not self._running:
                break
            try:
                self.poll_once()
            except Exception:
                pass
