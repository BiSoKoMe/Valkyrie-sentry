"""Test the intelligence layer - baseline, anomaly, threat graph, memory,
classifier.

Standalone script, no pytest required:

    python test_intelligence.py

Uses a temporary SQLite database; nothing touches data/.
All timing is synthetic so results are deterministic.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.store import Store
from valkyrie.intelligence.anomaly import AnomalyDetector
from valkyrie.intelligence.baseline import BaselineLearner
from valkyrie.intelligence.classifier import ThreatClassifier
from valkyrie.intelligence.memory import IntelligenceMemory
from valkyrie.intelligence.threat_graph import ThreatGraph

_TMP = Path(tempfile.mkdtemp(prefix="valkyrie_intel_test_"))
_PASS = 0
_FAIL = 0


def _store(name: str) -> Store:
    s = Store(db_path=_TMP / f"{name}.db")
    s.start()
    return s


def check(label: str, condition: bool, detail: str = "") -> None:
    global _PASS, _FAIL
    if condition:
        _PASS += 1
        print(f"  PASS  {label}")
    else:
        _FAIL += 1
        print(f"  FAIL  {label}  {detail}")


# ---------------------------------------------------------------------------
# 1. Baseline records and retrieves correctly
# ---------------------------------------------------------------------------

def test_baseline() -> None:
    print("\n[1] BaselineLearner — record / retrieve / persist")
    store = _store("baseline")
    learner = BaselineLearner(store, learning_days=0)
    learner.start()

    base = time.time() - 3600
    for i in range(10):
        learner.record("chrome.exe", "site.example.com", base + i * 60, 80)
    learner.record("chrome.exe", "cdn.example.net", base + 30, 90)

    profile = learner.get_baseline("chrome.exe")
    check("domains recorded", profile["domains"].get("site.example.com") == 10,
          f"got {profile['domains']}")
    check("timing learned (~60s gap)",
          50 <= profile["timing"].get("site.example.com", 0) <= 70,
          f"got {profile['timing']}")
    check("is_normal for repeated pair",
          learner.is_normal("chrome.exe", "site.example.com"))
    check("not normal for unseen pair",
          not learner.is_normal("chrome.exe", "never-seen.example.org"))
    check("process coverage counted", learner.coverage() == 1)

    # Persistence across a simulated restart
    written = learner.flush()
    check("flush wrote rows", written >= 2, f"wrote {written}")
    learner2 = BaselineLearner(store, learning_days=0)
    learner2.start()
    check("baseline survives restart",
          learner2.get_baseline("chrome.exe")["domains"].get("site.example.com") == 10)
    check("learning period respected (0 days → active)",
          not learner2.is_learning())
    store.stop()


# ---------------------------------------------------------------------------
# 2 + 3. Anomaly scoring - heartbeat HIGH, normal traffic LOW
# ---------------------------------------------------------------------------

def test_anomaly() -> None:
    print("\n[2] AnomalyDetector — simulated heartbeat scores HIGH")
    store = _store("anomaly")
    learner = BaselineLearner(store, learning_days=0)
    learner.start()

    detector = AnomalyDetector(
        learner,
        is_background_fn=lambda p: p == "telemetry_agent.exe",
        is_running_fn=lambda p: None,      # liveness unknown -> signal off
    )

    # Background process beaconing every 30s with identical tiny payloads
    base = time.time() - 600
    ts = base
    for i in range(8):
        ts = base + i * 30
        learner.record("telemetry_agent.exe", "beacon.tracker-corp.com", ts, 64)
    hb_score = detector.score("telemetry_agent.exe", "beacon.tracker-corp.com", ts, 64)

    check("heartbeat detected",
          detector.is_heartbeat("telemetry_agent.exe", "beacon.tracker-corp.com"))
    check(f"heartbeat scores HIGH (>=0.7): {hb_score}", hb_score >= 0.7)
    explanation = detector.explain("telemetry_agent.exe", "beacon.tracker-corp.com")
    check("explanation names the heartbeat", "heartbeat" in explanation, explanation)

    print("\n[3] AnomalyDetector — normal browsing scores LOW")
    gaps = [3, 47, 12, 200, 31, 88, 9]
    sizes = [300, 800, 1200, 400, 1500, 700, 950]
    ts = base
    for gap, size in zip(gaps, sizes):
        ts += gap
        learner.record("firefox.exe", "news.example.com", ts, size)
    normal_score = detector.score("firefox.exe", "news.example.com", ts, 640)
    check(f"normal traffic scores LOW (<0.4): {normal_score}", normal_score < 0.4)
    store.stop()


# ---------------------------------------------------------------------------
# 4. Threat graph links related domains
# ---------------------------------------------------------------------------

def test_threat_graph() -> None:
    print("\n[4] ThreatGraph — related infrastructure auto-flagged")
    store = _store("graph")
    graph = ThreatGraph(store)
    graph.start()

    graph.record_threat("telemetry.acme.com", "203.0.113.10")

    check("exact threat = 1.0",
          graph.is_related("telemetry.acme.com") == 1.0)
    rel = graph.is_related("analytics.acme.com")
    check(f"same base domain lands in flag band (0.4–0.7): {rel}",
          0.4 <= rel < 0.7)
    subnet = graph.is_related("cdn.other-corp.com", "203.0.113.99")
    check(f"same /24 subnet related (>=0.6): {subnet}", subnet >= 0.6)
    check("unrelated domain = 0.0",
          graph.is_related("wikipedia.org") == 0.0)

    # Persistence across restart
    graph2 = ThreatGraph(store)
    graph2.start()
    check("graph survives restart",
          graph2.is_related("analytics.acme.com") >= 0.4)
    store.stop()

    # Regression: a popular domain's own subdomain being "confirmed" must NEVER
    # poison its own base - live bug where a Microsoft delivery-optimization
    # host (array508.prod.do.dsp.mp.microsoft.com - "dsp" reads as ad-tech) got
    # recorded, and every subsequent microsoft.com query then "shared
    # infrastructure" with its own sibling subdomain and got flagged.
    print("\n[4b] a popular domain's subdomain must never self-poison its base")
    store3 = _store("graph_popular")
    graph3 = ThreatGraph(store3)
    graph3.start()
    graph3.record_threat("array508.prod.do.dsp.mp.microsoft.com", "20.1.2.3")
    check("record_threat refuses a popular-domain subdomain",
          graph3.is_related("array508.prod.do.dsp.mp.microsoft.com") == 0.0)
    check("microsoft.com itself does not 'share infrastructure' with itself",
          graph3.is_related("microsoft.com") == 0.0)
    check("a different microsoft.com subdomain is not flagged either",
          graph3.is_related("update.microsoft.com") == 0.0)
    # A REAL threat under a non-popular base still works normally (the guard
    # is popularity-specific, not a blanket "subdomains never relate").
    graph3.record_threat("telemetry.acme.com")
    check("a genuine non-popular threat still populates the base bucket",
          graph3.is_related("analytics.acme.com") >= 0.4)
    store3.stop()

    # Self-heal: an ALREADY-poisoned row (written by an older build, before this
    # guard existed) must be purged the moment a build with the fix starts.
    print("\n[4c] startup self-heal purges an already-poisoned popular domain")
    store4 = _store("graph_selfheal")
    ThreatGraph(store4).start()      # create the intel_threats schema only
    conn = store4.connection()
    conn.execute(
        "INSERT INTO intel_threats (domain, ip, base_domain, prefix, added) "
        "VALUES ('array508.prod.do.dsp.mp.microsoft.com', '', 'microsoft.com', '', '2026-01-01')"
    )
    conn.commit(); conn.close()
    graph4 = ThreatGraph(store4)     # simulates the NEXT (fixed-build) restart
    graph4.start()
    check("poisoned row purged on startup",
          "array508.prod.do.dsp.mp.microsoft.com" in graph4.purged_popular)
    check("microsoft.com is clean after self-heal",
          graph4.is_related("microsoft.com") == 0.0)
    store4.stop()


# ---------------------------------------------------------------------------
# 5. Memory persists across simulated restart
# ---------------------------------------------------------------------------

def test_memory() -> None:
    print("\n[5] IntelligenceMemory — verdicts persist and behave")
    store = _store("memory")
    mem = IntelligenceMemory(store)
    mem.start()

    mem.remember_bad("spy.example.com", ip="198.51.100.5", reason="heartbeat beacon")
    mem.remember_good("docs.python.org", process="firefox.exe")

    check("bad verdict", mem.check("spy.example.com") == "bad")
    check("subdomain of bad parent is bad",
          mem.check("deep.spy.example.com") == "bad")
    check("good verdict", mem.check("docs.python.org") == "good")
    check("unknown returns None", mem.check("unseen.example.net") is None)

    mem.remember_good("spy.example.com")     # must NOT downgrade
    check("bad never downgraded by remember_good",
          mem.check("spy.example.com") == "bad")

    # Simulated restart: fresh instance, same database
    mem2 = IntelligenceMemory(store)
    mem2.start()
    check("bad verdict survives restart", mem2.check("spy.example.com") == "bad")
    check("good verdict survives restart", mem2.check("docs.python.org") == "good")

    exported = mem2.export_intelligence()
    check("export contains the threat",
          "spy.example.com" in exported["threats"])
    stats = mem2.stats()
    check("stats counts", stats["threats_learned"] == 1 and stats["safe_patterns"] == 1,
          str(stats))
    store.stop()


# ---------------------------------------------------------------------------
# 6. Classifier - surveillance blocked, normal allowed, learning damped
# ---------------------------------------------------------------------------

def _stack(store: Store, learning_days: float):
    learner = BaselineLearner(store, learning_days=learning_days)
    learner.start()
    detector = AnomalyDetector(
        learner,
        is_background_fn=lambda p: p.startswith("svc_"),
        is_running_fn=lambda p: None,
    )
    graph = ThreatGraph(store)
    graph.start()
    mem = IntelligenceMemory(store)
    mem.start()
    clf = ThreatClassifier(learner, detector, graph, mem)
    return learner, detector, graph, mem, clf


def test_classifier() -> None:
    print("\n[6] ThreatClassifier — surveillance vs normal")
    store = _store("classifier")
    learner, _, graph, mem, clf = _stack(store, learning_days=0)

    # Surveillance signature: background svc, 30s metronome, tiny payloads
    base = time.time() - 600
    ts = base
    for i in range(8):
        ts = base + i * 30
        learner.record("svc_updater.exe", "collect.adnet-metrics.io", ts, 60)
    verdict = clf.classify("svc_updater.exe", "collect.adnet-metrics.io", ts, 60)
    check(f"surveillance blocked: {verdict['score']}",
          verdict["decision"] == "block", str(verdict))
    check("signals include anomaly", verdict["signals"].get("anomaly", 0) >= 0.7)

    # Normal signature: foreground browser, irregular timing, mixed payloads
    ts2 = base
    for gap, size in zip([5, 90, 22, 140, 61, 33], [400, 900, 1300, 500, 1100, 800]):
        ts2 += gap
        learner.record("firefox.exe", "python.org", ts2, size)
    verdict2 = clf.classify("firefox.exe", "python.org", ts2, 700)
    check(f"normal allowed: {verdict2['score']}",
          verdict2["decision"] == "allow", str(verdict2))

    # Threat-graph relation pushes a NEW domain into flag/block
    graph.record_threat("telemetry.acme.com")
    verdict3 = clf.classify("firefox.exe", "analytics.acme.com", ts2 + 10, 300)
    check(f"related infra at least flagged: {verdict3['decision']}",
          verdict3["decision"] in ("flag", "block"), str(verdict3))
    store.stop()

    # Learning-period damping: anomaly-only block becomes a flag
    print("\n[6b] Learning-period damping")
    store2 = _store("classifier_learning")
    learner2, _, _, _, clf2 = _stack(store2, learning_days=7)   # learning active
    ts3 = base
    for i in range(8):
        ts3 = base + i * 30
        learner2.record("svc_spy.exe", "ping.shady-corp.net", ts3, 48)
    verdict4 = clf2.classify("svc_spy.exe", "ping.shady-corp.net", ts3, 48)
    check("anomaly-only block damped to flag while learning",
          verdict4["decision"] == "flag", str(verdict4))
    check("reason marks learning mode", verdict4["reason"].startswith("[learning]"),
          verdict4["reason"])
    store2.stop()


# ---------------------------------------------------------------------------

def main() -> int:
    print("Valkyrie intelligence layer — test suite")
    print(f"(temp db dir: {_TMP})")
    try:
        test_baseline()
        test_anomaly()
        test_threat_graph()
        test_memory()
        test_classifier()
    finally:
        shutil.rmtree(_TMP, ignore_errors=True)

    print(f"\n{'='*50}")
    print(f"  {_PASS} passed, {_FAIL} failed")
    print(f"{'='*50}")
    return 1 if _FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
