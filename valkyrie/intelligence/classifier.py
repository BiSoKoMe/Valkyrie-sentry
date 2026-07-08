"""ThreatClassifier — combines all intelligence signals into one decision.

Inputs per query: behavioural anomaly score (anomaly.py), infrastructure
relatedness (threat_graph.py), and the legacy heuristics engine
(behavioral.py: entropy / rate / age).  The strongest signal drives the
decision:

    score >= ANOMALY_BLOCK_THRESHOLD (0.7)  → block
    score >= ANOMALY_FLAG_THRESHOLD  (0.4)  → flag
    otherwise                               → allow

Learning-period damping: while the baseline is still learning, a block
driven purely by anomaly signals is downgraded to a flag — the machine's
"normal" is not yet known, so behaviour-only blocking would be guessing.
Graph-driven blocks (shared infrastructure with confirmed threats) are
never damped.

Consistently clean domains (INTEL_GOOD_AFTER_ALLOWS clean allows in a
row) are promoted into IntelligenceMemory as known-good so future
queries take the O(1) fast path.
"""

from __future__ import annotations

import threading
from typing import Optional

from ..config import (
    ANOMALY_BLOCK_THRESHOLD,
    ANOMALY_FLAG_THRESHOLD,
    INTEL_GOOD_AFTER_ALLOWS,
)
from .anomaly import AnomalyDetector
from .baseline import BaselineLearner
from .memory import IntelligenceMemory
from .threat_graph import ThreatGraph


class ThreatClassifier:
    """Single decision point over all intelligence signals."""

    def __init__(
        self,
        baseline: BaselineLearner,
        anomaly: AnomalyDetector,
        threat_graph: ThreatGraph,
        memory: IntelligenceMemory,
        behavioral=None,                        # valkyrie.behavioral.BehavioralEngine
        block_threshold: float = ANOMALY_BLOCK_THRESHOLD,
        flag_threshold: float = ANOMALY_FLAG_THRESHOLD,
    ) -> None:
        self._baseline  = baseline
        self._anomaly   = anomaly
        self._graph     = threat_graph
        self._memory    = memory
        self._behavioral = behavioral
        self._block = block_threshold
        self._flag  = flag_threshold
        self._clean_streak: dict[str, int] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def classify(self, process: str, domain: str, timestamp: float,
                 payload: int = 0, ip: str = "") -> dict:
        """Return {"decision", "score", "reason", "signals"} for one query."""
        process = (process or "unknown").lower()
        domain  = domain.lower().rstrip(".")

        signals: dict[str, float] = {}

        a_score = self._anomaly.score(process, domain, timestamp, payload)
        signals["anomaly"] = round(a_score, 3)

        g_score = self._graph.is_related(domain, ip)
        signals["threat_graph"] = round(g_score, 3)

        b_score = 0.0
        b_reason = ""
        if self._behavioral is not None:
            try:
                b_score, b_reason = self._behavioral.score(domain, process)
            except Exception:
                b_score, b_reason = 0.0, ""
        signals["behavioral"] = round(b_score, 3)

        score = max(a_score, g_score, b_score)

        # Reason comes from whichever engine produced the deciding score
        if score <= 0:
            reason = ""
        elif score == g_score and g_score >= a_score and g_score >= b_score:
            reason = self._graph.explain(domain, ip)
        elif score == a_score and a_score >= b_score:
            reason = self._anomaly.explain(process, domain)
        else:
            reason = b_reason

        if score >= self._block:
            decision = "block"
        elif score >= self._flag:
            decision = "flag"
        else:
            decision = "allow"

        # Learning-period damping — anomaly-only blocks become flags
        if (decision == "block"
                and self._baseline.is_learning()
                and g_score < self._block):
            decision = "flag"
            reason = f"[learning] {reason}"

        self._track_clean_streak(domain, process, decision, score)

        return {
            "decision": decision,
            "score":    round(score, 3),
            "reason":   reason,
            "signals":  signals,
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _track_clean_streak(self, domain: str, process: str,
                            decision: str, score: float) -> None:
        """Promote consistently clean domains into known-good memory."""
        with self._lock:
            if decision != "allow" or score >= self._flag:
                self._clean_streak.pop(domain, None)
                return
            streak = self._clean_streak.get(domain, 0) + 1
            if streak >= INTEL_GOOD_AFTER_ALLOWS:
                self._clean_streak.pop(domain, None)
                promote = True
            else:
                self._clean_streak[domain] = streak
                promote = False
            # Bound the tracker so it cannot grow without limit
            if len(self._clean_streak) > 50_000:
                self._clean_streak.clear()
        if promote:
            self._memory.remember_good(domain, process)
