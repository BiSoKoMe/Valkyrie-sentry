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
  * The actor key is the process NAME. True process-lineage (parent→child
    across powershell→rundll32→…) needs a consistent PID/parent map at the
    detection layer, which the user-mode sensors don't yet guarantee; naming
    is the pragmatic, honest key today and is noted as future work.
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
    "T1055":     "defense-evasion",      # Process Injection
    "T1055.012": "defense-evasion",      # Process Hollowing
    "T1027":     "defense-evasion",      # Obfuscated Files or Information
    "T1140":     "defense-evasion",      # Deobfuscate/Decode
    "T1562.001": "defense-evasion",      # Impair Defenses: Disable Tools
    "T1564":     "defense-evasion",      # Hide Artifacts
    "T1003":     "credential-access",    # OS Credential Dumping
    "T1003.001": "credential-access",    # LSASS Memory
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
    """Per-actor sliding window of distinct ATT&CK tactics.

    ``observe`` is fed every real detection; it returns a chain summary only
    when an actor crosses into (or extends) a multi-tactic chain, so the
    engine raises ONE correlated incident that grows, not a storm of alerts.
    """

    _MAX_ACTORS = 2048

    def __init__(self, window_seconds: float = 600.0, min_tactics: int = 2) -> None:
        self._window = window_seconds
        self._min = min_tactics
        # actor → deque[(ts, tactic, technique, title)]
        self._events: dict[str, collections.deque] = {}
        # actor → frozenset of tactics last reported (to emit only on growth)
        self._reported: dict[str, frozenset] = {}
        self._lock = threading.RLock()

    def observe(self, actor: str, technique: str, title: str,
                ts: float) -> Optional[dict]:
        """Record one detection for ``actor``; return a chain summary dict if
        this observation forms or extends a multi-stage chain, else None.

        ``ts`` is a caller-supplied monotonic-style timestamp (seconds), so
        scoring stays clock-free and testable.
        """
        tactic = tactic_for(technique)
        if not actor or tactic is None:
            return None                      # unattributable / unmapped → no chain
        with self._lock:
            dq = self._events.get(actor)
            if dq is None:
                if len(self._events) >= self._MAX_ACTORS:
                    self._evict(ts)
                dq = self._events[actor] = collections.deque()
            while dq and ts - dq[0][0] > self._window:
                dq.popleft()
            dq.append((ts, tactic, extract_technique_id(technique) or technique, title))
            tactics = {t for _, t, _, _ in dq}
            if len(tactics) < self._min:
                return None
            frozen = frozenset(tactics)
            if self._reported.get(actor) == frozen:
                return None                  # no NEW tactic since last report → quiet
            self._reported[actor] = frozen
            steps = [{"tactic": t, "technique": tech, "title": ttl, "ts": t0}
                     for (t0, t, tech, ttl) in dq]
        score, severity = score_chain(tactics)
        ordered = [t for t in TACTIC_LABEL if t in tactics]
        return {
            "actor": actor,
            "tactics": ordered,
            "techniques": sorted({s["technique"] for s in steps}),
            "distinct_tactics": len(tactics),
            "score": score,
            "severity": severity,
            "reaches_objective": bool(tactics & HIGH_IMPACT_TACTICS),
            "steps": steps,
            "explanation": self._explain(actor, ordered, score, tactics),
        }

    @staticmethod
    def _explain(actor: str, ordered: list[str], score: float,
                 tactics: set[str]) -> str:
        chain = " → ".join(TACTIC_LABEL[t] for t in ordered)
        base = (f"{len(tactics)} independent ATT&CK tactics on {actor}: {chain}. "
                f"Confidence {int(score * 100)}% — it rises with each distinct stage.")
        if tactics & HIGH_IMPACT_TACTICS:
            hit = ", ".join(TACTIC_LABEL[t] for t in ordered if t in HIGH_IMPACT_TACTICS)
            base += f" Chain has reached a high-impact objective ({hit})."
        return base

    def _evict(self, now: float) -> None:
        """Drop actors whose whole window has expired (called under lock)."""
        stale = [a for a, dq in self._events.items()
                 if not dq or now - dq[-1][0] > self._window]
        for a in stale:
            self._events.pop(a, None)
            self._reported.pop(a, None)
        if len(self._events) >= self._MAX_ACTORS:      # still full → oldest-touched
            oldest = sorted(self._events.items(), key=lambda kv: kv[1][-1][0])
            for a, _ in oldest[: len(self._events) - self._MAX_ACTORS + 1]:
                self._events.pop(a, None)
                self._reported.pop(a, None)
