"""Multi-stage kill-chain correlation — turn isolated detections into one
scored attack chain.

The problem this solves (measured, not hypothetical): the base correlator in
store.find_open_incident groups detections by SAME category, so a single
intrusion shows up as several disconnected, individually-unremarkable
incidents —

    powershell.exe  encoded command      (execution)      → incident A
    powershell.exe  DNS C2 beacon         (C2)             → incident B
    powershell.exe  registry Run key      (persistence)    → incident C

— none of which, alone, is confident enough to act on. A real attack IS the
sequence: the same actor moving across ATT&CK *tactics* in a short window.
This module scores that sequence.

Principle (straight from the directive): confidence rises only when multiple
INDEPENDENT signals agree. One tactic is business as usual; three distinct
tactics on one actor in four minutes is an attack. The score is a pure
function of the distinct tactics observed (+ a bump when the chain reaches a
high-impact tactic like encryption or exfiltration), so every number is
explainable and testable — there are no learned weights or opaque thresholds.

Honest boundaries:
  * Lineage is PID-based when the collector provides it (process_telemetry
    and Sysmon carry ppid/parent): a child process folds into its parent's
    chain via the parent→child PID edge. Where a detection has NO attributed
    PID (e.g. a DNS query the resolver couldn't map to a process), the actor
    NAME is the identity — precise where PIDs exist, best-effort where they
    don't. Two detections in different namespaces (one with a PID, one with
    only a name) will not merge; that residual gap is the honest limit of
    user-mode attribution.
  * This correlates detections that were ALREADY produced — it raises no new
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
# Technique → ATT&CK tactic. HONEST SCOPE: only the techniques Valkyrie
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
    "T1543":     "persistence",          # Create/Modify System Process
    "T1543.003": "persistence",          # Windows Service
    "T1546.003": "persistence",          # WMI Event Subscription
    "T1547":     "persistence",          # Boot/Logon Autostart
    "T1547.001": "persistence",          # Registry Run Keys / Startup
    "T1574":     "persistence",          # Hijack Execution Flow
    "T1136":     "persistence",          # Create Account
    "T1136.001": "persistence",          # Create Local Account
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
    "T1218.005": "defense-evasion",      # Mshta
    "T1218.010": "defense-evasion",      # Regsvr32
    "T1218.011": "defense-evasion",      # Rundll32
    "T1197":     "defense-evasion",      # BITS Jobs
    "T1003":     "credential-access",    # OS Credential Dumping
    "T1003.001": "credential-access",    # LSASS Memory
    "T1003.002": "credential-access",    # Security Account Manager
    "T1003.003": "credential-access",    # NTDS
    "T1555":     "credential-access",    # Credentials from Password Stores
    "T1033":     "discovery",            # System Owner/User Discovery
    "T1482":     "discovery",            # Domain Trust Discovery
    "T1021":     "lateral-movement",     # Remote Services
    "T1021.002": "lateral-movement",     # SMB/Windows Admin Shares
    "T1105":     "command-and-control",  # Ingress Tool Transfer
    "T1071":     "command-and-control",  # Application Layer Protocol
    "T1071.004": "command-and-control",  # DNS
    "T1568":     "command-and-control",  # Dynamic Resolution
    "T1568.002": "command-and-control",  # DGA
    "T1572":     "command-and-control",  # Protocol Tunnelling
    "T1041":     "exfiltration",         # Exfil Over C2
    "T1048.003": "exfiltration",         # Exfil Over Alternative Protocol (DNS)
    "T1486":     "impact",               # Data Encrypted for Impact
}

# Tactics whose presence makes a chain materially worse — the "objective"
# end of an intrusion. A chain that reaches one of these is escalated.
HIGH_IMPACT_TACTICS = frozenset({"credential-access", "exfiltration", "impact"})

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
    """Pull a bare technique id out of a label like 'T1059.001 — PowerShell'."""
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


def score_chain(tactics: set[str]) -> tuple[float, str]:
    """Pure scoring: (confidence 0-1, severity). Explainable by construction.

    0.25 per distinct tactic (2→0.50, 3→0.75, 4→1.00), +0.15 if the chain
    reaches a high-impact tactic (cred-access / exfil / impact). Severity:
    >=0.9 critical, >=0.7 high, else medium.
    """
    n = len(tactics)
    score = 0.25 * n
    if tactics & HIGH_IMPACT_TACTICS:
        score += 0.15
    score = min(1.0, score)
    severity = "critical" if score >= 0.9 else "high" if score >= 0.7 else "medium"
    return round(score, 3), severity


class KillChainCorrelator:
    """Lineage-aware sliding window of distinct ATT&CK tactics per attack.

    A "chain" is a connected component of process identities. Detections are
    linked into the same chain when they share a PID (same process, different
    tactic) or a parent→child PID edge (``ppid``), so an intrusion that walks
    ``powershell.exe → rundll32.exe → …`` is scored as ONE attack instead of
    one-per-process. When PIDs are unavailable (e.g. a DNS detection with no
    attributed process), the actor NAME is the identity — precise where PIDs
    exist, best-effort where they don't.

    ``observe`` returns a chain summary only when a chain crosses into (or
    extends) a multi-tactic state, so the engine raises ONE correlated
    incident that grows, not a storm of alerts.
    """

    _MAX_CHAINS = 2048

    def __init__(self, window_seconds: float = 600.0, min_tactics: int = 2) -> None:
        self._window = window_seconds
        self._min = min_tactics
        # chain id → deque[(ts, tactic, technique, title, actor_name)]
        self._chains: dict[int, collections.deque] = {}
        # identity token ("pid:N" | "name:X") → chain id (union-find, flattened)
        self._token_chain: dict[str, int] = {}
        # chain id → frozenset of tactics last reported (emit only on growth)
        self._reported: dict[int, frozenset] = {}
        self._next_cid = 1
        self._lock = threading.RLock()

    def observe(self, actor: str, technique: str, title: str, ts: float,
                pid: int = 0, ppid: int = 0) -> Optional[dict]:
        """Record one detection; return a chain summary dict if it forms or
        extends a multi-stage chain, else None.

        ``pid``/``ppid`` (when the collector knows them) link a child process
        to its parent's chain. ``ts`` is a caller-supplied monotonic-style
        timestamp so scoring stays clock-free and testable.
        """
        tactic = tactic_for(technique)
        if not actor or tactic is None:
            return None                      # unattributable / unmapped → no chain
        primary = f"pid:{pid}" if pid > 0 else f"name:{actor}"
        parent = f"pid:{ppid}" if ppid > 0 else None
        tokens = [primary] + ([parent] if parent else [])
        with self._lock:
            cid = self._chain_for(tokens, ts)
            for tok in tokens:
                self._token_chain[tok] = cid
            dq = self._chains[cid]
            while dq and ts - dq[0][0] > self._window:
                dq.popleft()
            dq.append((ts, tactic, extract_technique_id(technique) or technique,
                       title, actor))
            tactics = {t for _, t, _, _, _ in dq}
            if len(tactics) < self._min:
                return None
            frozen = frozenset(tactics)
            if self._reported.get(cid) == frozen:
                return None                  # no NEW tactic since last report → quiet
            self._reported[cid] = frozen
            steps = [{"tactic": t, "technique": tech, "title": ttl, "ts": t0,
                      "actor": act} for (t0, t, tech, ttl, act) in dq]
            actors = list(dict.fromkeys(act for *_, act in dq))   # unique, in order
        score, severity = score_chain(tactics)
        ordered = [t for t in TACTIC_LABEL if t in tactics]
        return {
            "actor": actor,
            "actors": actors,
            "processes": len(actors),
            "tactics": ordered,
            "techniques": sorted({s["technique"] for s in steps}),
            "distinct_tactics": len(tactics),
            "score": score,
            "severity": severity,
            "reaches_objective": bool(tactics & HIGH_IMPACT_TACTICS),
            "steps": steps,
            "explanation": self._explain(actors, ordered, score, tactics),
        }

    def _chain_for(self, tokens: list[str], now: float) -> int:
        """Resolve the chain id for these identity tokens, merging existing
        chains when a parent→child edge joins two of them. Called under lock."""
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
                 tactics: set[str]) -> str:
        who = " → ".join(actors) if len(actors) > 1 else (actors[0] if actors else "an actor")
        chain = " → ".join(TACTIC_LABEL[t] for t in ordered)
        span = f"across {len(actors)} linked processes ({who})" if len(actors) > 1 else who
        base = (f"{len(tactics)} independent ATT&CK tactics {span}: {chain}. "
                f"Confidence {int(score * 100)}% — it rises with each distinct stage.")
        if tactics & HIGH_IMPACT_TACTICS:
            hit = ", ".join(TACTIC_LABEL[t] for t in ordered if t in HIGH_IMPACT_TACTICS)
            base += f" Chain has reached a high-impact objective ({hit})."
        return base

    def _evict(self, now: float) -> None:
        """Drop chains whose whole window has expired, plus their tokens
        (called under lock)."""
        stale = [cid for cid, dq in self._chains.items()
                 if not dq or now - dq[-1][0] > self._window]
        for cid in stale:
            self._drop(cid)
        if len(self._chains) >= self._MAX_CHAINS:      # still full → oldest-touched
            oldest = sorted(self._chains.items(), key=lambda kv: kv[1][-1][0])
            for cid, _ in oldest[: len(self._chains) - self._MAX_CHAINS + 1]:
                self._drop(cid)

    def _drop(self, cid: int) -> None:
        self._chains.pop(cid, None)
        self._reported.pop(cid, None)
        for tok, c in list(self._token_chain.items()):
            if c == cid:
                self._token_chain.pop(tok, None)
