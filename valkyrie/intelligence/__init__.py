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
from .cooccurrence import CoOccurrenceTracker
from .memory import IntelligenceMemory
from .self_heal import SelfHealing
from .threat_graph import ThreatGraph

__all__ = [
    "AnomalyDetector",
    "BaselineLearner",
    "CoOccurrenceTracker",
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
        self._behavioral = behavioral
        self.baseline  = BaselineLearner(store)
        self.anomaly   = AnomalyDetector(self.baseline)
        self.graph     = ThreatGraph(store)
        self.memory    = IntelligenceMemory(store)
        # G2: co-occurrence never scores a domain already promoted to known-good.
        self.cooc      = CoOccurrenceTracker(
            exempt_fn=lambda d: self.memory.check(d) == "good"
        )
        self.classifier = ThreatClassifier(
            baseline     = self.baseline,
            anomaly      = self.anomaly,
            threat_graph = self.graph,
            memory       = self.memory,
            behavioral   = behavioral,
            cooccurrence = self.cooc,
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
        # Un-poison: any tracker the old duplicate-block bug learned as a THREAT
        # is purged from memory (memory.start) AND from the infrastructure graph
        # here, so trackers stop hard-blocking (deception is restored) and legit
        # sites stop "sharing infrastructure" with them. No manual cleanup.
        try:
            purged = self.graph.forget(getattr(self.memory, "purged_trackers", []))
            purged_pop = len(getattr(self.graph, "purged_popular", []) or [])
            # print(), not logging: this module has no logging.basicConfig
            # anywhere in the app, so a bare logging.getLogger().info() call is
            # silently dropped by the default WARNING-level root logger —
            # verified missing from a real run. print() is what the rest of this
            # file already uses for startup diagnostics (see print_signal_health
            # below); nssm redirects stdout to service_stdout.log, so this is
            # how an operator actually sees it.
            if purged:
                print(f"[intelligence] un-poisoned {purged} tracker(s) "
                      f"wrongly learned as threats")
            if purged_pop:
                print(f"[intelligence] un-poisoned {purged_pop} popular "
                      f"domain(s) wrongly recorded in the threat graph")
        except Exception:
            pass
        self.print_signal_health()

    # ------------------------------------------------------------------
    # Signal health audit (no silent failures — see PHASE 0)
    # ------------------------------------------------------------------

    def signal_health(self) -> list[dict]:
        """Aggregate ACTIVE/DISABLED status for every scoring signal in the
        stack, evaluated against the CURRENT baseline state.

        Grouped by engine. A DISABLED entry means the signal structurally
        cannot fire right now (learning gate, missing dependency, etc.) — it is
        surfaced rather than silently scoring 0.
        """
        rows: list[dict] = []
        for s in self.anomaly.signal_health():
            rows.append({"engine": "anomaly", **s})
        if self._behavioral is not None and hasattr(self._behavioral, "signal_health"):
            for s in self._behavioral.signal_health():
                rows.append({"engine": "behavioral", **s})
        else:
            rows.append({"engine": "behavioral", "signal": "(engine)",
                         "active": False,
                         "note": "DISABLED: no behavioral engine wired into intelligence"})
        # Threat-graph is a propagation signal: live, but scores > 0 only once a
        # related domain has already been blocked (nothing to propagate from at
        # a cold start).
        rows.append({"engine": "threat_graph", "signal": "infrastructure_relation",
                     "active": True,
                     "note": "fires only after a related domain has been blocked "
                             "(propagation signal, 0 at cold start)"})
        # Co-occurrence is FLAG-ONLY and temporal: needs >= COOC_MIN_ANCHORS
        # distinct first-party anchors learned over separate page loads.
        from ..config import COOC_MIN_ANCHORS
        rows.append({"engine": "cooccurrence", "signal": "third_party_ubiquity",
                     "active": True,
                     "note": f"FLAG-ONLY; needs >= {COOC_MIN_ANCHORS} distinct anchors "
                             f"(temporal — 0 on first contact / single-shot)"})
        return rows

    def print_signal_health(self) -> None:
        """Print a single ACTIVE/DISABLED audit line per signal at startup."""
        learning = self.baseline.is_learning()
        mode = (f"learning day {self.baseline.learning_day()}/"
                f"{int(self.baseline._learning_days)}" if learning else "active")
        print(f"[intelligence] signal health "
              f"(intelligence-only baseline, mode={mode}):")
        for r in self.signal_health():
            state = "ACTIVE  " if r["active"] else "DISABLED"
            print(f"  {state} {r['engine']:<12} {r['signal']:<22} {r['note']}")

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
        try:
            self.cooc.observe(process, domain, timestamp)
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
        """Steps 5–6: a block happened — remember it and grow the graph.

        A tracker/telemetry domain is NEVER learned as a threat: it is a privacy
        nuisance handled by the scanner + DECEIVE policy, and treating it as a
        threat both hard-blocks it forever (breaking deception) and makes legit
        sites 'share infrastructure' with it. Callers that hard-block a tracker
        (strict profiles) still get the block; it just isn't *remembered*.
        """
        try:
            from ..decision import reason_denotes_deceivable
            if reason_denotes_deceivable(reason):
                return
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
