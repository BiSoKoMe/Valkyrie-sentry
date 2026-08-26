"""Multi-stage kill-chain correlation - turn isolated detections into one
scored attack chain.

The problem this solves (measured, not hypothetical): the base correlator in
store.find_open_incident groups detections by SAME category, so a single
intrusion shows up as several disconnected, individually-unremarkable
incidents -

    powershell.exe  encoded command      (execution)      -> incident A
    powershell.exe  DNS C2 beacon         (C2)             -> incident B
    powershell.exe  registry Run key      (persistence)    -> incident C

- none of which, alone, is confident enough to act on. A real attack IS the
sequence: the same actor moving across ATT&CK *tactics* in a short window.
This module scores that sequence.

Principle (straight from the directive): confidence rises only when multiple
INDEPENDENT signals agree. One tactic is business as usual; three distinct
tactics on one actor in four minutes is an attack. The score is a pure
function of the distinct tactics observed (+ a bump when the chain reaches a
high-impact tactic like encryption or exfiltration), so every number is
explainable and testable - there are no learned weights or opaque thresholds.

Honest boundaries:
  * Lineage is PID-based when the collector provides it (process_telemetry
    and Sysmon carry ppid/parent): a child process folds into its parent's
    chain via the parent->child PID edge. Where a detection has NO attributed
    PID (e.g. a DNS query the resolver couldn't map to a process), the actor
    NAME is the identity - precise where PIDs exist, best-effort where they
    don't. Two detections in different namespaces (one with a PID, one with
    only a name) will not merge; that residual gap is the honest limit of
    user-mode attribution.
  * This correlates detections that were ALREADY produced - it raises no new
    primary signal, only escalates confidence when independent detectors
    already agree. It cannot conjure a chain the sensors never saw.

Pure and deterministic (no clock reads inside scoring), so it is unit-tested
independently of the engine.
"""

from __future__ import annotations

import collections
import re
import threading
from typing import Optional

# ---------------------------------------------------------------------------
# Technique -> ATT&CK tactic. HONEST SCOPE: only the techniques Valkyrie
# actually emits (grepped from the codebase), so the map never implies
# coverage that doesn't exist. Sub-technique first, base as fallback.
# ---------------------------------------------------------------------------
TECHNIQUE_TACTIC: dict[str, str] = {
    "T1566":     "initial-access",       # Phishing
    "T1204":     "execution",            # User Execution
    "T1059":     "execution",            # Command & Scripting Interpreter
    "T1059.001": "execution",            # PowerShell
    "T1047":     "execution",            # WMI
    "T1053":     "persistence",          # Scheduled Task/Job
    "T1053.005": "persistence",          # Scheduled Task
    "T1037":     "persistence",          # Boot or Logon Initialization Scripts
    "T1037.001": "persistence",          # Logon Script (Windows)
    "T1543":     "persistence",          # Create/Modify System Process
    "T1543.003": "persistence",          # Windows Service
    "T1546.003": "persistence",          # WMI Event Subscription
    "T1547":     "persistence",          # Boot/Logon Autostart
    "T1547.001": "persistence",          # Registry Run Keys / Startup
    "T1574":     "persistence",          # Hijack Execution Flow
    "T1136":     "persistence",          # Create Account
    "T1136.001": "persistence",          # Create Local Account
    "T1505":     "persistence",          # Server Software Component
    "T1505.003": "persistence",          # Web Shell
    "T1490":     "impact",               # Inhibit System Recovery
    "T1055":     "defense-evasion",      # Process Injection
    "T1055.012": "defense-evasion",      # Process Hollowing
    "T1027":     "defense-evasion",      # Obfuscated Files or Information
    "T1140":     "defense-evasion",      # Deobfuscate/Decode
    "T1562":     "defense-evasion",      # Impair Defenses
    "T1562.001": "defense-evasion",      # Impair Defenses: Disable Tools
    "T1562.004": "defense-evasion",      # Impair Defenses: Disable/Modify Firewall
    "T1564":     "defense-evasion",      # Hide Artifacts
    "T1070":     "defense-evasion",      # Indicator Removal
    "T1070.001": "defense-evasion",      # Clear Windows Event Logs
    "T1218":     "defense-evasion",      # System Binary Proxy Execution
    "T1218.001": "defense-evasion",      # Compiled HTML File (hh.exe)
    "T1218.003": "defense-evasion",      # CMSTP
    "T1218.004": "defense-evasion",      # InstallUtil
    "T1218.005": "defense-evasion",      # Mshta
    "T1218.007": "defense-evasion",      # Msiexec
    "T1218.008": "defense-evasion",      # Odbcconf
    "T1218.009": "defense-evasion",      # Regsvcs/Regasm
    "T1218.010": "defense-evasion",      # Regsvr32
    "T1218.011": "defense-evasion",      # Rundll32
    "T1127":     "defense-evasion",      # Trusted Developer Utilities Proxy Execution
    "T1127.001": "defense-evasion",      # MSBuild
    "T1202":     "defense-evasion",      # Indirect Command Execution
    "T1216":     "defense-evasion",      # Signed Script Proxy Execution
    "T1220":     "defense-evasion",      # XSL Script Processing
    "T1548":     "privilege-escalation", # Abuse Elevation Control Mechanism
    "T1548.002": "privilege-escalation", # Bypass User Account Control
    "T1068":     "privilege-escalation", # Exploitation for Priv Esc (BYOVD driver)
    "T1562":     "defense-evasion",      # Impair Defenses
    "T1562.001": "defense-evasion",      # Disable or Modify Tools
    "T1562.002": "defense-evasion",      # Disable Windows Event Logging
    "T1562.004": "defense-evasion",      # Disable/Modify System Firewall
    "T1562.006": "defense-evasion",      # Indicator Blocking (ETW)
    "T1546":     "persistence",          # Event Triggered Execution
    "T1546.007": "persistence",          # Netsh Helper DLL
    "T1546.008": "persistence",          # Accessibility Features
    "T1546.010": "persistence",          # AppInit DLLs
    "T1546.012": "persistence",          # Image File Execution Options Injection
    "T1546.015": "persistence",          # Component Object Model Hijacking
    "T1547.004": "persistence",          # Winlogon Helper DLL
    "T1053.002": "persistence",          # Scheduled Task/Job: At
    "T1070.006": "defense-evasion",      # Timestomp
    "T1197":     "defense-evasion",      # BITS Jobs
    "T1036":     "defense-evasion",      # Masquerading
    "T1036.002": "defense-evasion",      # Right-to-Left Override
    "T1036.005": "defense-evasion",      # Match Legitimate Name or Location
    "T1036.007": "defense-evasion",      # Double File Extension
    "T1222":     "defense-evasion",      # File/Directory Permissions Modification
    "T1222.001": "defense-evasion",      # Windows File/Dir Permissions Mod
    "T1003":     "credential-access",    # OS Credential Dumping
    "T1003.001": "credential-access",    # LSASS Memory
    "T1003.002": "credential-access",    # Security Account Manager
    "T1003.003": "credential-access",    # NTDS
    "T1003.006": "credential-access",    # DCSync
    "T1558":     "credential-access",    # Steal or Forge Kerberos Tickets
    "T1558.001": "credential-access",    # Golden Ticket
    "T1558.003": "credential-access",    # Kerberoasting
    "T1550":     "lateral-movement",     # Use Alternate Authentication Material
    "T1550.002": "lateral-movement",     # Pass the Hash
    "T1550.003": "lateral-movement",     # Pass the Ticket
    "T1555":     "credential-access",    # Credentials from Password Stores
    "T1555.003": "credential-access",    # Credentials from Web Browsers
    "T1552":     "credential-access",    # Unsecured Credentials
    "T1552.001": "credential-access",    # Unsecured Credentials in Files
    "T1005":     "collection",           # Data from Local System
    "T1560":     "collection",           # Archive Collected Data
    "T1560.001": "collection",           # Archive via Utility (encrypted)
    "T1040":     "credential-access",    # Network Sniffing
    "T1098":     "persistence",          # Account Manipulation
    "T1553":     "defense-evasion",      # Subvert Trust Controls
    "T1553.006": "defense-evasion",      # Code Signing Policy Modification
    "T1112":     "defense-evasion",      # Modify Registry
    "T1620":     "defense-evasion",      # Reflective Code Loading
    "T1078":     "defense-evasion",      # Valid Accounts
    "T1021.006": "lateral-movement",     # Remote Services: WinRM
    "T1041":     "exfiltration",         # Exfiltration Over C2 Channel
    "T1033":     "discovery",            # System Owner/User Discovery
    "T1482":     "discovery",            # Domain Trust Discovery
    "T1082":     "discovery",            # System Information Discovery
    "T1057":     "discovery",            # Process Discovery
    "T1018":     "discovery",            # Remote System Discovery
    "T1087":     "discovery",            # Account Discovery
    "T1087.001": "discovery",            # Account Discovery: Local Account
    "T1046":     "discovery",            # Network Service Discovery (scan fan-out)
    "T1021":     "lateral-movement",     # Remote Services
    "T1021.002": "lateral-movement",     # SMB/Windows Admin Shares
    "T1570":     "lateral-movement",     # Lateral Tool Transfer
    "T1489":     "impact",               # Service Stop
    "T1105":     "command-and-control",  # Ingress Tool Transfer
    "T1071":     "command-and-control",  # Application Layer Protocol
    "T1071.004": "command-and-control",  # DNS
    "T1090":     "command-and-control",  # Proxy (port forwarding)
    "T1568":     "command-and-control",  # Dynamic Resolution
    "T1568.002": "command-and-control",  # DGA
    "T1572":     "command-and-control",  # Protocol Tunnelling
    "T1041":     "exfiltration",         # Exfil Over C2
    "T1048.003": "exfiltration",         # Exfil Over Alternative Protocol (DNS)
    "T1567":     "exfiltration",         # Exfil Over Web Service
    "T1567.002": "exfiltration",         # Exfil to Cloud Storage (rclone)
    "T1486":     "impact",               # Data Encrypted for Impact
    "T1485":     "impact",               # Data Destruction
    "T1561":     "impact",               # Disk Wipe
    "T1561.001": "impact",               # Disk Wipe: Content
    "T1569":     "execution",            # System Services
    "T1569.002": "execution",            # Service Execution (PsExec)
}

# Tactics whose presence makes a chain materially worse - the "objective"
# end of an intrusion. A chain that reaches one of these is escalated.
HIGH_IMPACT_TACTICS = frozenset({"credential-access", "exfiltration", "impact"})

# Per-detection severity -> an evidence-strength weight in (0, 1]. Added after
# a real, code-verified finding: this module used to count DISTINCT TACTICS
# with no regard for how strong the evidence behind each one was, so an
# INFO-level discovery label (process_telemetry.py's own comment: "Severity
# is ALWAYS SEV_INFO... never alerts alone") counted exactly the same as a
# critical LSASS-access detection. A realistic benign developer sequence -
# IDE terminal -> encoded PowerShell startup (SEV_LOW, explicitly a "context
# signal, not a detection" per behavioral_rules.py) -> MSBuild build step ->
# hostname.exe for a build log (SEV_INFO) - crossed 3 distinct tactics and
# scored "high" (0.75) under the old formula purely from three weak,
# individually-non-alerting signals. HIGH is intentionally worth the same as
# CRITICAL here: this is a per-detection EVIDENCE-STRENGTH weight, not a
# duplicate of score_chain's own high-impact-tactic bump (a different axis).
_SEVERITY_WEIGHT: dict[str, float] = {
    "info": 0.2, "low": 0.4, "medium": 0.7, "high": 1.0, "critical": 1.0,
}
_DEFAULT_SEVERITY_WEIGHT = 1.0   # unrecognized/missing severity: assume strong,
                                 # same as an unspecified `severity` argument -
                                 # never let a typo silently look like weak evidence.

# Human labels for explanations.
TACTIC_LABEL = {
    "initial-access": "Initial Access", "execution": "Execution",
    "persistence": "Persistence", "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion", "credential-access": "Credential Access",
    "discovery": "Discovery", "lateral-movement": "Lateral Movement",
    "collection": "Collection", "command-and-control": "Command & Control",
    "exfiltration": "Exfiltration", "impact": "Impact",
}

_TID_RE = re.compile(r"T1[0-9]{3}(?:\.[0-9]{3})?")


def extract_technique_id(text: str) -> str:
    """Pull a bare technique id out of a label like 'T1059.001 - PowerShell'."""
    m = _TID_RE.search(str(text or ""))
    return m.group(0) if m else ""


def tactic_for(technique: str) -> Optional[str]:
    """Map a technique id (or a full label) to its ATT&CK tactic, or None."""
    tid = extract_technique_id(technique)
    if not tid:
        return None
    if tid in TECHNIQUE_TACTIC:
        return TECHNIQUE_TACTIC[tid]
    base = tid.split(".")[0]
    return TECHNIQUE_TACTIC.get(base)


def score_chain(tactics: set[str], evidence_quality: float = 1.0,
                lineage_quality: float = 1.0, temporal_quality: float = 1.0
                ) -> tuple[float, str]:
    """Pure scoring: (confidence 0-1, severity). Explainable by construction.

    Structural score is unchanged: 0.25 per distinct tactic (2->0.50,
    3->0.75, 4->1.00), +0.15 if the chain reaches a high-impact tactic
    (cred-access / exfil / impact). That structural score is then scaled by
    three independent, honestly-named quality factors - each defaults to 1.0
    so a bare call with just a tactic set (as this module's own pure-mapping
    tests use) reproduces the exact old numbers:

      * evidence_quality: how strong the underlying detections actually are
        (1.0 = at least one high/critical-severity detection anchors this
        chain; lower = built only from low/info-tier signals). Distinct
        tactics agreeing is meaningful ONLY when the agreement is real
        evidence, not three informational labels.
      * lineage_quality: how much of the chain is directly-observed PID/PPID
        process lineage vs. a same-NAME-in-window guess (0.6 floor - a name
        match is still real correlation, just weaker than a verified edge).
      * temporal_quality: how tightly clustered the stages are inside the
        correlation window (1.0 near-simultaneous, 0.5 floor near the full
        window) - three tactics in five seconds is not the same claim as
        three tactics loosely spread across ten minutes.

    Severity bucketing is unchanged: >=0.9 critical, >=0.7 high, else medium.
    """
    n = len(tactics)
    score = 0.25 * n
    if tactics & HIGH_IMPACT_TACTICS:
        score += 0.15
    score = min(1.0, score)
    quality = max(0.0, min(1.0, evidence_quality)) * \
              max(0.0, min(1.0, lineage_quality)) * \
              max(0.0, min(1.0, temporal_quality))
    score = min(1.0, score * quality)
    severity = "critical" if score >= 0.9 else "high" if score >= 0.7 else "medium"
    return round(score, 3), severity


class KillChainCorrelator:
    """Lineage-aware sliding window of distinct ATT&CK tactics per attack.

    A "chain" is a connected component of process identities. Detections are
    linked into the same chain when they share a PID (same process, different
    tactic) or a parent->child PID edge (``ppid``), so an intrusion that walks
    ``powershell.exe -> rundll32.exe -> ...`` is scored as ONE attack instead of
    one-per-process. When PIDs are unavailable (e.g. a DNS detection with no
    attributed process), the actor NAME is the identity - precise where PIDs
    exist, best-effort where they don't.

    ``observe`` returns a chain summary only when a chain crosses into (or
    extends) a multi-tactic state, so the engine raises ONE correlated
    incident that grows, not a storm of alerts.
    """

    _MAX_CHAINS = 2048

    # Default matches the module's own stated principle above ("three distinct
    # tactics... is an attack") - a live VM run found the default had drifted to
    # 2, which raised "multi-stage attack" incidents against ordinary PowerShell
    # admin scripting and TiWorker.exe (Windows Modules Installer, a legitimate
    # OS component) purely from two loosely-related tactic labels inside the
    # 10-minute window. min_tactics remains a constructor parameter so callers
    # (and this module's own unit tests) can still exercise the mechanics at any
    # threshold; only the SHIPPED default was wrong.
    # A bare ppid edge to a parent that has NEVER itself been directly
    # observed doing anything (its own PID was never a `primary`) links at
    # most this many distinct children before it stops merging further ones
    # into the same chain. Found via this module's own validation suite: a
    # long-lived, high-fan-out, never-itself-flagged launcher (an IDE, a
    # shell, a service supervisor) spawns many genuinely independent,
    # unrelated short-lived sessions, each sharing that one ppid - and the
    # union-find below, with no cap, folded all of them into one
    # ever-growing "chain" purely because they share an inert ancestor. A
    # REAL attacker's dropper/orchestrator spawning a handful of direct
    # malicious children (the case this correlator exists to catch, see
    # test_killchain.py [2c]) stays well under this cap; it only kicks in
    # for the high-fan-out, nothing-ever-detected-on-the-parent-itself shape.
    _PARENT_FANOUT_CAP = 3

    # Two tactics inside this many seconds of each other are treated as
    # "essentially simultaneous" - no temporal discount at all. Below this,
    # jittering the clock by a couple of seconds (real telemetry timestamps,
    # not synthetic test values) must not make a genuinely instantaneous,
    # automated attack sequence score any differently. Only span BEYOND this
    # grace period counts against temporal_quality.
    _TEMPORAL_GRACE_SECONDS = 5.0

    def __init__(self, window_seconds: float = 600.0, min_tactics: int = 3) -> None:
        self._window = window_seconds
        self._min = min_tactics
        # chain id -> deque[(ts, tactic, technique, title, actor_name, severity, verified)]
        self._chains: dict[int, collections.deque] = {}
        # identity token ("pid:N" | "name:X") -> chain id (union-find, flattened)
        self._token_chain: dict[str, int] = {}
        # chain id -> frozenset of tactics last reported (emit only on growth)
        self._reported: dict[int, frozenset] = {}
        # every token that has ever been used as a PRIMARY (i.e. that process
        # was itself directly observed doing something) - lets the fan-out
        # cap tell "a malicious parent spawning children" apart from "a
        # bystander launcher that was never itself flagged".
        self._primaries: set[str] = set()
        # parent token -> set of distinct primary tokens linked through it,
        # for the fan-out cap above.
        self._parent_fanout: dict[str, set[str]] = {}
        self._next_cid = 1
        self._lock = threading.RLock()

    def observe(self, actor: str, technique: str, title: str, ts: float,
                pid: int = 0, ppid: int = 0, severity: str = "high") -> Optional[dict]:
        """Record one detection; return a chain summary dict if it forms or
        extends a multi-stage chain, else None.

        ``pid``/``ppid`` (when the collector knows them) link a child process
        to its parent's chain, and mark this step as VERIFIED lineage (vs. a
        same-name-in-window guess when ``pid`` is 0). ``severity`` is the
        real Detection's own severity - this is what lets the chain tell an
        anchoring critical-severity detection apart from three purely
        informational labels that happen to touch three different tactics.
        ``ts`` is a caller-supplied monotonic-style timestamp so scoring
        stays clock-free and testable. Callers that omit ``severity`` (this
        module's own pre-existing unit tests, and code paths that predate
        this parameter) get the same "assume strong evidence" default this
        module always implicitly used, so old behavior is unchanged unless a
        caller actively tells it otherwise.
        """
        tactic = tactic_for(technique)
        if not actor or tactic is None:
            return None                      # unattributable / unmapped -> no chain
        verified = pid > 0
        primary = f"pid:{pid}" if pid > 0 else f"name:{actor}"
        parent = f"pid:{ppid}" if ppid > 0 else None
        with self._lock:
            self._primaries.add(primary)
            # Fan-out cap: a parent token that was NEVER itself directly
            # observed as a primary (the "parent" process never did anything
            # detectable in this data) may only bootstrap-link a handful of
            # distinct children before it stops counting as a connecting
            # edge. See _PARENT_FANOUT_CAP's docstring for why.
            if parent is not None and parent not in self._primaries:
                fanout = self._parent_fanout.setdefault(parent, set())
                if primary in fanout or len(fanout) < self._PARENT_FANOUT_CAP:
                    fanout.add(primary)
                else:
                    parent = None            # saturated - this edge no longer merges
            tokens = [primary] + ([parent] if parent else [])
            cid = self._chain_for(tokens, ts)
            for tok in tokens:
                self._token_chain[tok] = cid
            dq = self._chains[cid]
            while dq and ts - dq[0][0] > self._window:
                dq.popleft()
            dq.append((ts, tactic, extract_technique_id(technique) or technique,
                       title, actor, severity, verified))
            tactics = {t for _, t, _, _, _, _, _ in dq}
            if len(tactics) < self._min:
                return None
            frozen = frozenset(tactics)
            if self._reported.get(cid) == frozen:
                return None                  # no NEW tactic since last report -> quiet
            self._reported[cid] = frozen
            steps = [{"tactic": t, "technique": tech, "title": ttl, "ts": t0,
                      "actor": act, "severity": sev, "verified": ver}
                     for (t0, t, tech, ttl, act, sev, ver) in dq]
            actors = list(dict.fromkeys(act for *_, act, _, _ in dq))   # unique, in order

            # Three independent quality factors (see score_chain's docstring)
            # computed from what THIS chain's own steps actually carry, never
            # guessed: evidence strength (does at least one real, non-trivial
            # detection anchor this chain, or is it built entirely from
            # low/info-tier context signals?), lineage verification (how much
            # of the chain is an observed PID/PPID edge vs. a name guess),
            # and temporal tightness (how much of the window the steps span).
            evidence_quality = max(
                (_SEVERITY_WEIGHT.get(s["severity"], _DEFAULT_SEVERITY_WEIGHT)
                 for s in steps), default=_DEFAULT_SEVERITY_WEIGHT)
            verified_count = sum(1 for s in steps if s["verified"])
            lineage_quality = 0.6 + 0.4 * (verified_count / len(steps))
            span = dq[-1][0] - dq[0][0]
            if span <= self._TEMPORAL_GRACE_SECONDS or self._window <= self._TEMPORAL_GRACE_SECONDS:
                temporal_quality = 1.0    # "essentially simultaneous" - no discount at all
            else:
                excess = span - self._TEMPORAL_GRACE_SECONDS
                full_range = self._window - self._TEMPORAL_GRACE_SECONDS
                temporal_quality = max(0.5, 1.0 - 0.5 * (excess / full_range))
        score, severity_bucket = score_chain(tactics, evidence_quality,
                                             lineage_quality, temporal_quality)
        ordered = [t for t in TACTIC_LABEL if t in tactics]
        return {
            "actor": actor,
            "actors": actors,
            "processes": len(actors),
            "tactics": ordered,
            "techniques": sorted({s["technique"] for s in steps}),
            "distinct_tactics": len(tactics),
            "score": score,
            "severity": severity_bucket,
            "reaches_objective": bool(tactics & HIGH_IMPACT_TACTICS),
            "steps": steps,
            "chain_id": cid,
            "quality": {"evidence": round(evidence_quality, 3),
                       "lineage": round(lineage_quality, 3),
                       "temporal": round(temporal_quality, 3)},
            "explanation": self._explain(actors, ordered, score, tactics,
                                         evidence_quality, lineage_quality,
                                         temporal_quality),
        }

    def _chain_for(self, tokens: list[str], now: float) -> int:
        """Resolve the chain id for these identity tokens, merging existing
        chains when a parent->child edge joins two of them. Called under lock."""
        found = sorted({self._token_chain[t] for t in tokens
                        if t in self._token_chain})
        if not found:
            if len(self._chains) >= self._MAX_CHAINS:
                self._evict(now)
            cid = self._next_cid
            self._next_cid += 1
            self._chains[cid] = collections.deque()
            return cid
        keep = found[0]
        for other in found[1:]:               # merge child+parent chains into one
            self._chains[keep].extend(self._chains.pop(other, ()))
            for tok, c in list(self._token_chain.items()):
                if c == other:
                    self._token_chain[tok] = keep
            self._reported.pop(other, None)
        if len(found) > 1:
            # merged deque is no longer time-ordered; sort so window eviction
            # (popleft of oldest) stays correct
            self._chains[keep] = collections.deque(sorted(self._chains[keep]))
            self._reported.pop(keep, None)    # force re-evaluation of the union
        return keep

    @staticmethod
    def _explain(actors: list[str], ordered: list[str], score: float,
                 tactics: set[str], evidence_quality: float = 1.0,
                 lineage_quality: float = 1.0, temporal_quality: float = 1.0) -> str:
        who = " → ".join(actors) if len(actors) > 1 else (actors[0] if actors else "an actor")
        chain = " → ".join(TACTIC_LABEL[t] for t in ordered)
        span = f"across {len(actors)} linked processes ({who})" if len(actors) > 1 else who
        base = (f"{len(tactics)} independent ATT&CK tactics {span}: {chain}. "
                f"Confidence {int(score * 100)}%.")
        if tactics & HIGH_IMPACT_TACTICS:
            hit = ", ".join(TACTIC_LABEL[t] for t in ordered if t in HIGH_IMPACT_TACTICS)
            base += f" Chain has reached a high-impact objective ({hit})."
        # Honest caveats - never let the confidence number stand alone when
        # something material pulled it down. Each names a real, checkable
        # reason (never a vague "might be wrong").
        caveats = []
        if evidence_quality < 0.7:
            caveats.append("the individual detections here are mostly low-severity "
                           "or informational on their own")
        if lineage_quality < 0.9:
            caveats.append("some of these processes are linked by name only, not a "
                           "directly observed parent-child relationship")
        if temporal_quality < 0.8:
            caveats.append("the stages are spread across a large part of the "
                           "correlation window rather than tightly clustered")
        if caveats:
            base += " Caveat: " + "; ".join(caveats) + "."
        return base

    def _evict(self, now: float) -> None:
        """Drop chains whose whole window has expired, plus their tokens
        (called under lock)."""
        stale = [cid for cid, dq in self._chains.items()
                 if not dq or now - dq[-1][0] > self._window]
        for cid in stale:
            self._drop(cid)
        if len(self._chains) >= self._MAX_CHAINS:      # still full -> oldest-touched
            oldest = sorted(self._chains.items(), key=lambda kv: kv[1][-1][0])
            for cid, _ in oldest[: len(self._chains) - self._MAX_CHAINS + 1]:
                self._drop(cid)

    def _drop(self, cid: int) -> None:
        self._chains.pop(cid, None)
        self._reported.pop(cid, None)
        for tok, c in list(self._token_chain.items()):
            if c == cid:
                self._token_chain.pop(tok, None)
