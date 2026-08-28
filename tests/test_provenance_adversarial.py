"""Adversarial checks for the privacy/security provenance experiment.

These tests deliberately reorder observations, reuse a PID, omit a process
start, and generate a bounded event burst. They prove failure handling and
graph integrity only; they are not a substitute for a disposable-VM live run.
"""

from valkyrie.edr.causal_detect import CausalBaseline, MIN_OBSERVATIONS, MIN_SESSIONS
from valkyrie.edr.engine import EdrEngine
from valkyrie.store import Store
from valkyrie.telemetry import CAT_DNS, CAT_PRIVACY, CAT_PROCESS, TelemetryEvent


def _mature():
    return CausalBaseline(observations=MIN_OBSERVATIONS, sessions=MIN_SESSIONS)


def _process(pid, name, ts, *, ppid=0):
    return TelemetryEvent(category=CAT_PROCESS, activity="exec", ts=ts,
                          actor_pid=pid, actor_name=name,
                          source="process_collector", fields={"ppid": ppid})


def _privacy(pid=10, event_id="privacy-1"):
    return TelemetryEvent(
        category=CAT_PRIVACY, activity="outbound_observation", ts=10.0,
        actor_pid=pid, actor_name="chrome.exe", target={"domain": "tracker.example"},
        source="nyx.tls", fields={"artifact_kind": "nyx_leak", "event_id": event_id,
                                   "privacy_category": "identifier",
                                   "destination_host": "tracker.example",
                                   "first_party_origin": "publisher.example"})


def _dns(pid=11):
    return TelemetryEvent(category=CAT_DNS, activity="query", ts=11.0,
                          actor_pid=pid, actor_name="helper.exe",
                          target={"domain": "rare.example"}, source="test")


def _engine(tmp_path):
    store = Store(db_path=tmp_path / "provenance-adversarial.db")
    store.start()
    engine = EdrEngine(store)
    engine.start()
    engine._causal_baseline = _mature()
    return store, engine


def _close(store, engine):
    engine.stop()
    store.stop()


def _consequences(engine):
    return [i for i in engine.list_incidents()
            if i["category"] == "privacy_consequence"]


def test_reordered_privacy_then_egress_is_correlated_when_complete(tmp_path):
    store, engine = _engine(tmp_path)
    try:
        engine.ingest_telemetry(_process(10, "chrome.exe", 1.0))
        engine.ingest_telemetry(_process(11, "helper.exe", 2.0, ppid=10))
        engine.ingest_telemetry(_privacy())       # arrives before its consequence
        assert not _consequences(engine)
        engine.ingest_telemetry(_dns())
        assert len(_consequences(engine)) == 1
    finally:
        _close(store, engine)


def test_pid_reuse_does_not_join_old_descendant_to_new_privacy_event(tmp_path):
    store, engine = _engine(tmp_path)
    try:
        engine.ingest_telemetry(_process(10, "chrome.exe", 1.0))
        engine.ingest_telemetry(_process(11, "helper.exe", 2.0, ppid=10))
        engine.ingest_telemetry(_dns())
        # A new process instance reuses 10. Port attribution has no creation
        # time, so it must bind to the graph's newest 10 instance, not revive
        # the old browser lineage merely because its pid matches.
        engine.ingest_telemetry(_process(10, "chrome.exe", 20.0))
        engine.ingest_telemetry(_privacy())
        assert not _consequences(engine)
    finally:
        _close(store, engine)


def test_missing_parent_observation_suppresses_consequence(tmp_path):
    store, engine = _engine(tmp_path)
    try:
        # The helper causes an inferred parent. A privacy event on that inferred
        # parent must never become an autonomous consequence decision.
        engine.ingest_telemetry(_process(11, "helper.exe", 2.0, ppid=10))
        engine.ingest_telemetry(_dns())
        engine.ingest_telemetry(_privacy())
        assert not _consequences(engine)
    finally:
        _close(store, engine)


def test_event_storm_stays_bounded_and_does_not_duplicate_consequence(tmp_path):
    store, engine = _engine(tmp_path)
    try:
        engine.ingest_telemetry(_process(10, "chrome.exe", 1.0))
        engine.ingest_telemetry(_process(11, "helper.exe", 2.0, ppid=10))
        engine.ingest_telemetry(_privacy())
        for i in range(500):
            engine.ingest_telemetry(TelemetryEvent(
                category=CAT_DNS, activity="query", ts=20.0 + i,
                actor_pid=11, actor_name="helper.exe",
                target={"domain": f"burst-{i}.example"}, source="storm"))
        stats = engine.causality_stats()
        assert stats["nodes"] <= stats["capacity"]
        assert len(_consequences(engine)) <= 1
    finally:
        _close(store, engine)
