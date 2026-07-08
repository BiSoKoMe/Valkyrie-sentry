"""Valkyrie intelligence layer — self-learning threat detection.

The ``Intelligence`` hub wires the five learning components together and
is the single object the DNS pipeline and the web dashboard interact
with:

    baseline  — learns this machine's normal (BaselineLearner)
    anomaly   — behaviour-signature scoring (AnomalyDetector)
    graph     — threat infrastructure relations (ThreatGraph)
    memory    — remembered verdicts, fast path (IntelligenceMemory)
    classify  — combined decision (ThreatClassifier)

All state persists in the existing Store's SQLite database, so it
survives reboots — and correctly stays in RAM under zero-log mode.
Everything here is stdlib-only and works fully offline.
"""

from __future__ import annotations

import threading
import time
from typing import Optional

from .anomaly import AnomalyDetector
from .baseline import BaselineLearner
from .classifier import ThreatClassifier
from .memory import IntelligenceMemory
from .self_heal import SelfHealing
from .threat_graph import ThreatGraph

__all__ = [
    "AnomalyDetector",
    "BaselineLearner",
    "Intelligence",
    "IntelligenceMemory",
    "SelfHealing",
    "ThreatClassifier",
    "ThreatGraph",
]


class Intelligence:
    """Facade over the full intelligence stack for one Store."""

    def __init__(self, store, behavioral=None) -> None:
        self._store    = store
        self.baseline  = BaselineLearner(store)
        self.anomaly   = AnomalyDetector(self.baseline)
        self.graph     = ThreatGraph(store)
        self.memory    = IntelligenceMemory(store)
        self.classifier = ThreatClassifier(
            baseline     = self.baseline,
            anomaly      = self.anomaly,
            threat_graph = self.graph,
            memory       = self.memory,
            behavioral   = behavioral,
        )
        self._lock = threading.RLock()
        self._last_anomaly: dict = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        self.baseline.start()
        self.graph.start()
        self.memory.start()

    def stop(self) -> None:
        self.baseline.stop()

    # ------------------------------------------------------------------
    # Pipeline hooks (called from the DNS decision path)
    # ------------------------------------------------------------------

    def record(self, process: str, domain: str, timestamp: float,
               payload_size: int = 0) -> None:
        """Step 1 of the pipeline: observe.  Never raises."""
        try:
            self.baseline.record(process, domain, timestamp, payload_size)
        except Exception:
            pass

    def check_memory(self, domain: str, ip: str = "") -> Optional[str]:
        """Step 2: fast path — 'bad' / 'good' / None.  Never raises."""
        try:
            return self.memory.check(domain, ip)
        except Exception:
            return None

    def memory_reason(self, domain: str) -> str:
        try:
            return self.memory.reason_for(domain)
        except Exception:
            return ""

    def classify(self, process: str, domain: str, timestamp: float,
                 payload: int = 0) -> dict:
        """Step 3: full classification.  Never raises."""
        try:
            result = self.classifier.classify(process, domain, timestamp, payload)
        except Exception as exc:
            return {"decision": "allow", "score": 0.0,
                    "reason": f"classifier error: {exc}", "signals": {}}
        if result["decision"] in ("block", "flag"):
            with self._lock:
                self._last_anomaly = {
                    "domain":      domain,
                    "process":     process,
                    "decision":    result["decision"],
                    "score":       result["score"],
                    "explanation": result["reason"],
                    "at":          time.strftime("%H:%M:%S"),
                }
        return result

    def remember_block(self, domain: str, reason: str, ip: str = "") -> None:
        """Steps 5–6: a block happened — remember it and grow the graph."""
        try:
            self.memory.remember_bad(domain, ip, reason)
            self.graph.record_threat(domain, ip)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Introspection (CLI flags + dashboard)
    # ------------------------------------------------------------------

    def status(self) -> dict:
        mem = self.memory.stats()
        with self._lock:
            last = dict(self._last_anomaly)
        learning = self.baseline.is_learning()
        return {
            "mode":               "learning" if learning else "active",
            "learning":           learning,
            "learning_day":       self.baseline.learning_day(),
            "learning_days_total": int(self.baseline._learning_days),
            "threats_learned":    mem["threats_learned"],
            "safe_patterns":      mem["safe_patterns"],
            "baseline_processes": self.baseline.coverage(),
            "baseline_pairs":     self.baseline.pair_count(),
            "graph_threats":      self.graph.count(),
            "db_size_bytes":      mem["db_size_bytes"],
            "last_anomaly":       last,
        }

    def export(self) -> dict:
        data = self.memory.export_intelligence()
        data["baseline_processes"] = self.baseline.coverage()
        data["baseline_pairs"]     = self.baseline.pair_count()
        return data

    def reset_learning(self) -> None:
        self.baseline.reset()
