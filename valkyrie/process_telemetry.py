"""Process telemetry collector - endpoint visibility beyond DNS.

Valkyrie historically saw only DNS. This collector adds the first real endpoint
signal: it watches the process table and emits a normalized ``TelemetryEvent``
(category ``process``, activity ``exec``) for every newly-started process, with
lightweight, honest behavioral tagging.

Scope and honesty:
  * This is a **userland poller** (psutil), not a kernel sensor. It sees process
    starts on a short interval; a process that starts and exits between polls can
    be missed. Real-time, tamper-resistant capture (ETW on Windows, eBPF on
    Linux) is the next step - this collector is the portable seam those plug into
    and emits the same schema.
  * No privileges are required for the current user's processes; more are visible
    as root/admin. It degrades gracefully (does nothing) if psutil is absent or
    access is denied - it never raises into the caller.

The suspicious-process heuristics are deliberately small and explainable
(LOLBins, Office-spawns-shell, execution from temp/download dirs). They are a
starting point, not a replacement for a real detection-engineering pipeline, and
they say so.
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, replace
from typing import Callable, Optional

from .behavioral_rules import classify_behavior
from .behavior_score import classify_anomaly
from .cmdline_normalize import normalize_cmdline
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

# Office apps that should essentially never spawn a shell/script host - a classic
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

    Pure and deterministic - the whole heuristic surface lives here so it can be
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
        # Temp/download execution ALONE is a weak signal: installers, updaters
        # and uninstallers run from there constantly. On real hardware this
        # false-positived on Valkyrie's OWN installer and on NSIS uninstallers
        # (Un_A.exe in ~nsu.tmp). So it only ESCALATES to medium when it
        # corroborates another signal (a LOLBin, an Office-spawned shell); on
        # its own it stays LOW - logged/observed, not an alerting incident. A
        # truly malicious binary from temp is virtually always accompanied by
        # one of those other tells or by the command-line/anomaly scorers.
        corroborated = bool(labels)      # office_child_shell or lolbin already set
        labels.append("suspicious_path")
        reasons.append("executable runs from a temp/download directory")
        _raise(SEV_MEDIUM if corroborated else SEV_LOW)

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
                 # - a common way to run VBScript/JScript with no window or
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


# ---------------------------------------------------------------------------
# Discovery-tactic labeling (pure, unit-tested). Deliberately INFO-only and
# NEVER escalates severity by itself: whoami/systeminfo/tasklist/net view/net
# user are each individually indistinguishable from routine administration
# (redteam/evaluation's disc-* findings - Discovery is architecturally the one
# ATT&CK tactic where firing an alerting incident on a single command is a
# guaranteed false-positive generator, per this project's own precision-over-
# aggression rule). The only thing this function does is attach a technique-
# tagged label; behavioral_sequences.py's 'reconnaissance-burst' rule is what
# actually raises an incident, and only once SEVERAL distinct ones appear from
# the same actor in a short window.
# ---------------------------------------------------------------------------
_DISCOVERY_SOLO_BINS = {
    "systeminfo.exe": "T1082 — System Information Discovery",
    "tasklist.exe":   "T1057 — Process Discovery",
    "whoami.exe":     "T1033 — System Owner/User Discovery",
    # Added 2026-08-05 after redteam/evaluation/live_safe.py RUN A measured
    # these as a VERIFIED gap (no code path at all, not a guess): ipconfig,
    # netstat, hostname. None of these has a mutating form worth excluding -
    # unlike reg/sc below, every ipconfig/netstat/hostname invocation is
    # equally a discovery read, so a solo-bin entry (unconditional on the
    # binary name) is correct here the same way it already is for
    # systeminfo/tasklist/whoami.
    "ipconfig.exe":   "T1016 — System Network Configuration Discovery",
    "netstat.exe":    "T1049 — System Network Connections Discovery",
    "hostname.exe":   "T1082 — System Information Discovery",
    # AdFind is the near-universal AD-recon tool in ransomware intrusions
    # (LockBit/Black Basta/Conti playbooks). It exists to enumerate Active
    # Directory, so - like the LOLBins above - it earns only an INFO discovery
    # label that FEEDS the recon-burst sequence; it never alerts alone, keeping
    # this name-based entry an honest supplement, not a standalone list-detector.
    "adfind.exe":     "T1087.002 — Account Discovery: Domain Account",
    # Round-2 (Akira/Medusa probe): built-in AD / session / network enumerators
    # every hands-on-keyboard intrusion reaches for. All read-only discovery, so
    # solo-bin INFO labels that feed the recon-burst, never standalone alerts.
    "dsquery.exe":    "T1087.002 — Account Discovery: Domain Account",
    "dsget.exe":      "T1087.002 — Account Discovery: Domain Account",
    "quser.exe":      "T1033 — System Owner/User Discovery",
    "qwinsta.exe":    "T1033 — System Owner/User Discovery",
    "arp.exe":        "T1016 — System Network Configuration Discovery",
    "route.exe":      "T1016 — System Network Configuration Discovery",
}

# reg.exe / sc.exe (added alongside the solo bins above) are NOT solo bins:
# 'reg add'/'reg delete' and 'sc create'/'sc stop' are real mutating actions,
# not discovery, and some of those already have their own alerting rules
# (behavioral_rules.py's sc.exe 'stop windefend' / 'create' rules) that must
# never be double-labeled as a mere INFO-level discovery command. Only the
# QUERY verb, and nothing else, earns the discovery label - same
# positive-keyword-AND-NOT-a-mutating-keyword shape as net.exe's 'net user'
# vs 'net user ... /add' below. \b word boundaries (not bare `in`) because
# 'query' must be the verb, not a substring of an unrelated key/service name.
_REG_MUTATING_VERBS = ("add", "delete", "import", "save", "restore",
                      "load", "unload", "copy", "export", "compare")
_SC_MUTATING_VERBS = ("create", "delete", "config", "start", "stop",
                     "pause", "continue", "failure", "sdset", "privs", "boot")


def _discovery_cmdline_technique(n: str, candidates: tuple) -> str:
    """The cmdline-shape half of classify_discovery - factored out so it can
    be evaluated against both the raw and de-obfuscated command line.

    `candidates` holds the raw lowercased cmdline, plus its normalized form
    when normalization actually changed anything. Both the POSITIVE match
    (a keyword appears) and the EXCLUSION check (a flag that hands the event
    to a different, already-alerting rule) are evaluated against every
    candidate - an obfuscated exclusion flag must not slip a duplicate,
    wrongly-labeled event past the exclusion any more than an obfuscated
    keyword should slip past the positive match.
    """
    if n == "nltest.exe":
        excluded = any(t in c for c in candidates for t in ("/dclist", "/domain_trusts"))
        if not excluded:
            # nltest WITH those flags already has its own real MEDIUM rule
            # (behavioral_rules.py nltest-domain) - don't double-label that case.
            return "T1482 — Domain Trust Discovery"
    elif n == "net.exe":
        if any("view" in c for c in candidates):
            return "T1018 — Remote System Discovery"
        add_present = any("/add" in c for c in candidates)
        if any("net group" in c for c in candidates) and not add_present:
            # 'net group' enumerates DOMAIN groups ("domain admins", "enterprise
            # admins") - a domain-account discovery distinct from local 'net
            # user'/'net localgroup'. /add is group creation, handled elsewhere.
            return "T1087.002 — Account Discovery: Domain Account"
        if any("net localgroup" in c for c in candidates) and not add_present:
            # 'net localgroup' (bare, or with a group name such as
            # 'administrators') enumerates LOCAL GROUP membership - MITRE's
            # own canonical example command for T1069.001. This used to be
            # folded into the same bucket as 'net user' below and returned
            # T1087.001 (Account Discovery) instead - a real live-fire
            # evaluation gap: the T1069.001 atomic test's exact command,
            # 'net localgroup administrators', already matched the old check
            # but under the wrong technique ID, so a live scorer that (per
            # this project's own rule) never credits a technique under the
            # wrong label never credited it. Checked before the bare 'net
            # user' case below since 'net localgroup' is the more specific
            # command shape.
            return "T1069.001 — Permission Groups Discovery: Local Groups"
        if any("net user" in c for c in candidates) and not add_present:
            # Bare listing only - /add is real account creation, already
            # covered (and alerted on) by behavioral_rules.py's own rules.
            return "T1087.001 — Account Discovery: Local Account"
        # 'net start' (bare) lists running services; 'net start <svc>' STARTS
        # one - a real mutating action, not discovery. Same "verb, and
        # nothing after it" shape as 'net accounts' below: net.exe's own
        # syntax puts the argument after the verb, so "is anything following
        # the verb" IS the discovery/mutating distinction, not a guessed
        # keyword. Added 2026-08-27 (redteam/evaluation confirmed generalization
        # gap: disc-service-net-start).
        if any(re.search(r"\bstart\s*$", c) for c in candidates):
            return "T1007 — System Service Discovery"
        # 'net accounts' (bare) displays the current password/lockout policy;
        # 'net accounts /minpwlen:N' (or any other switch) SETS it - mutating,
        # not discovery. Added 2026-08-27 (confirmed gap: disc-password-policy).
        if any(re.search(r"\baccounts\s*$", c) for c in candidates):
            return "T1201 — Password Policy Discovery"
    elif n == "reg.exe":
        query = any(re.search(r"\bquery\b", c) for c in candidates)
        mutating = any(re.search(rf"\b{v}\b", c) for c in candidates
                       for v in _REG_MUTATING_VERBS)
        if query and not mutating:
            return "T1012 — Query Registry"
    elif n == "sc.exe":
        query = any(re.search(r"\bquery\b", c) for c in candidates)
        mutating = any(re.search(rf"\b{v}\b", c) for c in candidates
                       for v in _SC_MUTATING_VERBS)
        if query and not mutating:
            return "T1007 — System Service Discovery"
    elif n == "schtasks.exe":
        # PowerShell/schtasks equivalent of the reg.exe/sc.exe "query verb,
        # not a mutating one" pattern above. Read-only task ENUMERATION
        # (T1007 in this catalog's own scheme - see disc-scheduled-tasks-query,
        # deliberately distinguished from the already-covered T1053.005 entry
        # which tests task CREATION via a different mechanism). Added 2026-08-27.
        query = any(re.search(r"\bquery\b", c) for c in candidates)
        mutating = any(re.search(rf"\b{v}\b", c) for c in candidates
                       for v in ("create", "delete", "change", "run", "end"))
        if query and not mutating:
            return "T1007 — System Service Discovery"
    elif n in ("powershell.exe", "pwsh.exe"):
        # RSAT ActiveDirectory-module recon cmdlets - the PowerShell equivalent
        # of dsquery/adfind (APT29, ransomware crews). Read-only enumeration, so
        # discovery labels that feed the recon-burst rather than alert alone.
        if any("get-adcomputer" in c for c in candidates):
            return "T1018 — Remote System Discovery"
        if any(g in c for c in candidates for g in
               ("get-aduser", "get-adgroup", "get-adgroupmember",
                "get-adobject", "get-adprincipalgroupmembership")):
            return "T1087.002 — Account Discovery: Domain Account"
        if any(g in c for c in candidates
               for g in ("get-addomain", "get-adtrust", "get-adforest")):
            return "T1482 — Domain Trust Discovery"
        # PowerShell-cmdlet equivalents of already-covered native-binary
        # discovery techniques (confirmed generalization gaps closed
        # 2026-08-27). Each cmdlet below is unconditionally read-only for
        # this purpose - unlike net.exe/reg.exe there is no same-name
        # mutating form to exclude (Set-Service/Start-Service etc. are
        # separate cmdlet names, so a substring match on the Get- form
        # cannot collide with a mutating one).
        if any("get-nettcpconnection" in c for c in candidates):
            return "T1049 — System Network Connections Discovery"
        if any("get-service" in c for c in candidates):
            return "T1007 — System Service Discovery"
        # Get-CimInstance alone is far too common (routine admin/monitoring
        # scripting) to match unconditionally - only the specific
        # antivirus-fingerprinting namespace query counts, mirroring how
        # 'net localgroup' (not bare 'net') earns its own specific label.
        if any("get-ciminstance" in c for c in candidates) and any(
                k in c for c in candidates
                for k in ("securitycenter2", "antivirusproduct")):
            return "T1518.001 — Security Software Discovery"
        # Get-ItemProperty/Get-Item are the PowerShell equivalent of
        # 'reg query', but reg.exe's own branch above is deliberately generic
        # (any query, any key = T1012) while this specific atomic tests
        # installed-software enumeration via the Uninstall registry key - so
        # this is scoped to that key, labeled to match the actual technique
        # under test (T1518) rather than the generic T1012 registry-read
        # label, the same way 'net localgroup' earns T1069.001 distinct from
        # bare 'net user's T1087.001.
        if any(g in c for c in candidates for g in
               ("get-itemproperty", "get-item ")) and any(
                "uninstall" in c for c in candidates):
            return "T1518 — Software Discovery"
    return ""


def classify_discovery(name: str, cmdline: str) -> tuple[str, list[str], str, str]:
    """Return (severity, labels, reason, technique) for a Discovery-tactic
    LOLBin invocation. Severity is ALWAYS SEV_INFO - see module note above."""
    n = (name or "").lower()
    c = (cmdline or "").lower()

    # Same "match raw AND normalized" discipline as behavioral_rules.
    # match_process - otherwise this weak-labeling path is trivially defeated
    # by the exact obfuscation classify_behavior already survives (found by
    # redteam/evaluation/evasion_harness.py: `net v^iew` / `net u^ser` evaded
    # this function while the already-normalized IOA rule engine did not).
    norm = normalize_cmdline(cmdline)
    nc = norm.text.lower() if norm.changed else c
    candidates = (c,) if nc == c else (c, nc)

    technique = _DISCOVERY_SOLO_BINS.get(n, "") or _discovery_cmdline_technique(n, candidates)

    if not technique:
        return SEV_INFO, [], "", ""
    return (SEV_INFO, ["discovery_command"],
            f"discovery command observed ({n})", technique)


@dataclass(frozen=True)
class ProcInfo:
    pid: int
    name: str
    path: str = ""
    ppid: int = 0
    parent_name: str = ""
    create_time: float = 0.0
    cmdline: str = ""
    parent_chain: tuple = ()      # (immediate parent, grandparent, ...) names

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

        # Behavioral IOA rule engine - the broad, MITRE-mapped content layer.
        # Its top hit's technique is carried explicitly so the EDR attaches the
        # exact ATT&CK id (and the kill-chain gets the exact tactic) rather than
        # inferring one from labels.
        technique = ""
        # Signature state is looked up here rather than inside the matcher so
        # the rule engine stays pure and I/O-free. Cached and revocation-free,
        # so this costs microseconds after the first sighting of a binary.
        try:
            from .signature import trust_of
            _sig = trust_of(self.path)
        except Exception:   # noqa: BLE001 — unknown signature must never break
            _sig = ""       # classification; rules keying on it fail closed
        behavior = classify_behavior(self.name, self.parent_name,
                                     self.cmdline, self.path, _sig)
        if behavior is not None:
            if severity_rank(behavior["severity"]) > severity_rank(severity):
                severity = behavior["severity"]
            for lab in behavior["labels"]:
                if lab not in labels:
                    labels.append(lab)
            reason = "; ".join(r for r in (reason, behavior["reason"]) if r)
            technique = behavior["technique"]

        # Behavioral anomaly scorer - the *generalizing* layer. Where the rule
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

        # Discovery-tactic weak labeling - the weakest tier, so it only fills
        # in a technique when nothing stronger already fired (a real rule/
        # anomaly hit always wins). See classify_discovery's module note.
        _, dlabels, dreason, dtechnique = classify_discovery(self.name, self.cmdline)
        for lab in dlabels:
            if lab not in labels:
                labels.append(lab)
        reason = "; ".join(r for r in (reason, dreason) if r)
        if not technique:
            technique = dtechnique

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
    silently - only processes that appear *after* start are reported, so we don't
    flood the pipeline with every already-running process at launch.
    """

    def __init__(self, emit: Callable[[TelemetryEvent], None],
                 interval: float = 2.0, emit_budget: float = 4.0) -> None:
        self._emit = emit
        self._base_interval = max(0.25, float(interval))
        self._interval = self._base_interval
        # None = no baseline yet (a sentinel, not truthiness) so an empty first
        # snapshot is still a valid baseline rather than causing a re-seed.
        self._last: Optional[dict] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        # Updated at the end of every poll_once() call, successful or not --
        # a reliability watchdog needs "is this collector still making
        # progress" (a thread can be alive but stuck inside a slow poll,
        # which is exactly the startup-deafness failure mode), not merely
        # "is the thread alive." See valkyrie/telemetry_watchdog.py.
        self.last_poll_completed_at: float = 0.0
        # See PersistenceCollector's identical field: counts a poll cycle
        # that raised all the way out to _loop()'s outer guard, the one
        # failure shape every per-item swallow inside poll_once() itself
        # cannot hide.
        self.exception_count: int = 0
        from .collector_diagnostics import PollDiagnostics
        self._diagnostics = PollDiagnostics()
        # See PersistenceCollector's identical field (docs/BETA_0_5_TELEMETRY_RELIABILITY.md
        # "Beta 0.5.3"): bounds the emit loop's wall-clock time so a slow/
        # contended ingest_telemetry() call (EdrStore's shared write lock
        # under concurrent load) cannot hold last_poll_completed_at hostage.
        # Entries not yet emitted when the budget expires are deferred to
        # the next poll's diff rather than dropped.
        self._emit_budget = max(1.0, float(emit_budget))
        self._truncated: list[str] = []

    def available(self) -> bool:
        return _PSUTIL

    # -- compensating-control hook (valkyrie/control_taxonomy.py) -----------
    #
    # This poller is Valkyrie's documented COMPENSATING control for the
    # Sysmon/ETW process-visibility sensors: when sensor_tamper.py detects
    # Sysmon has gone from healthy to unhealthy, it calls tighten() here to
    # actively substitute more frequent (lower-latency) userland polling for
    # the lost real-time kernel signal, instead of silently continuing at the
    # same cadence a healthy Sysmon never needed to compensate for anything.
    # restore_interval() reverts once Sysmon recovers. `_loop` reads
    # `self._interval` fresh every cycle, so this takes effect on the very
    # next sleep with no thread restart.
    def tighten(self, factor: float = 4.0) -> float:
        """Poll up to `factor`x more often (floored at 0.25s). Returns the
        new interval. Idempotent - calling it again while already tightened
        does not compound."""
        self._interval = max(0.25, self._base_interval / max(1.0, factor))
        return self._interval

    def restore_interval(self) -> float:
        """Revert to the configured baseline interval. Returns it."""
        self._interval = self._base_interval
        return self._interval

    def current_interval(self) -> float:
        return self._interval

    def snapshot(self) -> dict:
        """Return {key: ProcInfo} for currently-running processes.

        Never raises: per-process access errors are skipped, and an absent psutil
        yields an empty snapshot (collector effectively disabled).

        COST-BOUNDED (Beta 0.5.5/.6, docs/BETA_0_5_TELEMETRY_RELIABILITY.md):
        a live contention run measured this method's process_metadata stage
        taking ~3.8s under Phase C/E load, pushing the collector's whole poll
        cycle past its own stale bound (8s) while the engine's own resources
        stayed completely normal - ruling out resource exhaustion and
        pointing at real per-cycle cost instead. The cause: pr.exe() was
        called for EVERY currently-running process on EVERY poll, not only
        newly-appeared ones - O(all processes on the host), every 2 seconds,
        for a value (the executable path) that cannot change for a pid that
        was already seen. Reusing the prior poll's path for an already-known
        process instance turns this into O(new processes) instead.
        """
        out: dict = {}
        if not _PSUTIL:
            return out
        # Cache pid -> name to resolve parent names cheaply.
        names: dict[int, str] = {}
        try:
            with self._diagnostics.stage("process_iter"):
                procs = list(psutil.process_iter(["pid", "name", "ppid", "create_time"]))
        except Exception:
            return out
        known = self._last or {}
        with self._diagnostics.stage("process_metadata"):
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
                    create_time = float(info.get("create_time") or 0.0)
                    prior = known.get((pid, round(create_time, 3)))
                    if prior is not None:
                        # Same (pid, create_time) instance as last poll - the
                        # executable path of a live process cannot change, so
                        # skip the syscall entirely rather than repeating it
                        # for a process we already looked up.
                        path = prior.path
                    else:
                        try:
                            path = pr.exe() or ""
                        except Exception:
                            path = ""
                    pi = ProcInfo(pid=pid, name=info.get("name") or "", path=path,
                                  ppid=ppid, parent_name=names.get(ppid, ""),
                                  create_time=create_time)
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
        self._diagnostics.poll_started()
        try:
            new = self.snapshot()
            if self._last is None:
                self._last = new
                return 0
            with self._diagnostics.stage("diff_enrich_emit"):
                fresh = diff_snapshots(self._last, new)
                pid_index = {info.pid: info for info in new.values()}
                deadline = time.monotonic() + self._emit_budget
                budget_spent = False
                emitted_keys: set = set()
                for pi in fresh:
                    if budget_spent or time.monotonic() >= deadline:
                        budget_spent = True
                        continue
                    try:
                        self._emit(self._enrich(pi, pid_index).to_event())
                    except Exception:
                        pass
                    emitted_keys.add(pi.key())
                if budget_spent:
                    # Defer: keep any not-yet-emitted fresh process OUT of the
                    # new baseline so the next poll's diff rediscovers it,
                    # rather than a slow/contended emit holding this whole
                    # cycle (and last_poll_completed_at) hostage. Everything
                    # else in `new` (unchanged + already-emitted processes,
                    # and any that exited) still becomes the new baseline.
                    next_last = dict(new)
                    for pi in fresh:
                        if pi.key() not in emitted_keys:
                            next_last.pop(pi.key(), None)
                    self._last = next_last
                    self._truncated = self._truncated + ["diff_enrich_emit"]
                else:
                    self._last = new
                    self._truncated = []
            return len(emitted_keys)
        finally:
            # Recorded even on an early return or an exception path above, so
            # "no recent poll" only ever means "the thread stopped running,"
            # never "it happened to find nothing this cycle."
            self.last_poll_completed_at = time.time()
            self._diagnostics.poll_completed()

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

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def status(self) -> dict:
        return {
            "running": self.is_running(),
            "baseline_ready": self._last is not None,
            "poll_interval_s": self._interval,
            "last_poll_completed_at": self.last_poll_completed_at,
            "exception_count": self.exception_count,
            "truncated": list(self._truncated),
        } | self._diagnostics.status()

    def _loop(self) -> None:
        while self._running:
            time.sleep(self._interval)
            if not self._running:
                break
            try:
                self.poll_once()
            except Exception:
                self.exception_count += 1
