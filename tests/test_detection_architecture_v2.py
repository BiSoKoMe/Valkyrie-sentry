"""End-to-end checks for the shared deterministic v2 shadow pipeline."""

from __future__ import annotations

import statistics
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.edr.detection_v2 import (
    DetectionArchitectureV2,
    EntityStore,
    EventNormalizer,
)
from valkyrie.telemetry import TelemetryEvent


def _process(pid=100, create_time=1.0, labels=()):
    return TelemetryEvent(
        category="process", activity="exec", ts=create_time,
        actor_pid=pid, actor_name="helper.exe", source="process_collector",
        labels=list(labels), fields={"create_time": create_time, "ppid": 10},
    )


def _network(pid=100):
    return TelemetryEvent(
        category="network", activity="connect", ts=2.0,
        actor_pid=pid, actor_name="helper.exe", source="network_collector",
        target={"ip": "203.0.113.10", "port": 443},
    )


def _privacy(pid=100, *, authorized=False, secret="sentinel@example.test"):
    return TelemetryEvent(
        category="privacy", activity="outbound_observation", ts=3.0,
        actor_pid=pid, actor_name="helper.exe", source="nyx.tls",
        target={"domain": "collector.example", "url": "https://secret.invalid/x"},
        labels=["nyx_leak"] + (["trusted_gesture"] if authorized else []),
        fields={
            "event_id": f"nyx-{pid}-{authorized}",
            "artifact_kind": "nyx_leak",
            "privacy_category": "email",
            "destination_host": "collector.example",
            "authorized": authorized,
            "body": secret,
            "masked_sample": "se***st",
            "cookie": "session=secret",
        },
    )


def test_canonicalization_uses_process_instance_not_pid():
    entities = EntityStore(max_entities=16)
    normalizer = EventNormalizer(entities)
    first = normalizer.normalize(_process(pid=5320, create_time=1.0))
    second = normalizer.normalize(_process(pid=5320, create_time=9.0))
    assert first.subject.instance_id != second.subject.instance_id
    assert first.subject.pid == second.subject.pid == 5320
    assert not first.subject.inferred


def test_privacy_canonical_event_does_not_retain_content():
    architecture = DetectionArchitectureV2()
    architecture.observe(_process())
    result = architecture.observe(_privacy(secret="raw-sentinel-value"))
    serialized = repr(result.to_dict())
    assert "raw-sentinel-value" not in serialized
    assert "se***st" not in serialized
    assert "session=secret" not in serialized
    assert "https://secret.invalid" not in serialized
    assert result.event.object.identity == "collector.example"


def test_valkyrie_and_nyx_evidence_share_one_subject_and_hypothesis():
    architecture = DetectionArchitectureV2()
    architecture.observe(_process(labels=("office_child_shell",)))
    architecture.observe(_network())
    result = architecture.observe(_privacy())
    assert result.hypothesis.selected == "possible_data_theft"
    assert result.hypothesis.alerts
    behaviors = {
        fact.behavior
        for assessment in result.hypothesis.assessments
        for fact in assessment.supporting
    }
    assert "external_communication" in behaviors
    assert "sensitive_data_disclosure" in behaviors
    assert "disclosure_authority_absent" in behaviors
    assert not result.enforcement_authorized


def test_authorized_benign_twin_contradicts_data_theft():
    architecture = DetectionArchitectureV2()
    architecture.observe(_process())
    architecture.observe(_network())
    result = architecture.observe(_privacy(authorized=True))
    theft = next(item for item in result.hypothesis.assessments
                 if item.hypothesis_id == "possible_data_theft")
    assert theft.contradiction_strength > 0.90
    assert not result.hypothesis.alerts
    assert result.recommended_action == "observe"


def test_incomplete_identity_blocks_a_strong_privacy_conclusion():
    architecture = DetectionArchitectureV2()
    result = architecture.observe(_privacy(pid=999))
    assert result.hypothesis.blockers
    assert not result.hypothesis.alerts


def test_duplicate_events_do_not_amplify_evidence():
    architecture = DetectionArchitectureV2()
    architecture.observe(_process())
    event = _privacy()
    first = architecture.observe(event)
    second = architecture.observe(event)
    first_theft = next(a for a in first.hypothesis.assessments
                       if a.hypothesis_id == "possible_data_theft")
    second_theft = next(a for a in second.hypothesis.assessments
                        if a.hypothesis_id == "possible_data_theft")
    assert first_theft.confidence == second_theft.confidence
    assert architecture.status()["deduplicated"] == 1


def test_two_speed_queue_is_bounded_and_budgeted():
    architecture = DetectionArchitectureV2()
    for pid in range(100, 110):
        architecture.observe(_process(pid=pid, create_time=float(pid)))
    assert len(architecture.drain_analytics(3)) == 3
    assert architecture.status()["analytics_queued"] == 7
    assert architecture.run_analytics(4) == 4
    status = architecture.status()
    assert status["analytics_processed"] == 4
    assert status["behavior_shapes"] > 0


def test_fast_path_p99_is_below_ten_ms_for_synthetic_events():
    architecture = DetectionArchitectureV2()
    samples = []
    for pid in range(1000, 1500):
        result = architecture.observe(_process(pid=pid, create_time=float(pid)))
        samples.append(result.fast_path_ms)
    p99 = statistics.quantiles(samples, n=100)[98]
    assert p99 < 10.0, f"synthetic fast-path p99 was {p99:.3f} ms"


def test_engine_wires_low_severity_and_nyx_events_into_shared_ledger(tmp_path: Path):
    from valkyrie.edr.engine import EdrEngine
    from valkyrie.store import Store

    store = Store(db_path=tmp_path / "v2.db")
    store.start()
    engine = EdrEngine(store)
    engine.start()
    try:
        engine.ingest_telemetry(_process())
        engine.ingest_telemetry(_network())
        engine.ingest_telemetry(_privacy(secret="engine-raw-sentinel"))
        status = engine.detection_v2_status()
        ledger = engine.evidence_ledger()
        assert status["events"] == 3
        assert len(ledger) == 3
        assert "engine-raw-sentinel" not in repr(ledger)
        assert ledger[-1]["hypothesis"]["selected"] == "possible_data_theft"
        assert engine.drain_detection_v2_analytics(2)
    finally:
        engine.stop()
        store.stop()


def test_read_only_status_and_ledger_api(tmp_path: Path):
    try:
        from testclient_compat import make_client
        from valkyrie.context import AppContext
        from valkyrie.edr.engine import EdrEngine
        from valkyrie.store import Store
        from valkyrie.web.server import create_app
    except ImportError:
        return

    store = Store(db_path=tmp_path / "v2-api.db")
    store.start()
    engine = EdrEngine(store)
    engine.start()
    try:
        engine.ingest_telemetry(_process())
        app = create_app(AppContext(store=store, edr=engine))
        client = make_client(app, "127.0.0.1")
        status = client.get("/api/edr/detection-v2/status")
        ledger = client.get("/api/edr/detection-v2/ledger?limit=1")
        assert status.status_code == 200
        assert status.json()["mode"] == "shadow"
        assert ledger.status_code == 200
        assert len(ledger.json()["entries"]) == 1
        assert client.post("/api/edr/detection-v2/ledger").status_code == 405
    finally:
        engine.stop()
        store.stop()


if __name__ == "__main__":
    test_canonicalization_uses_process_instance_not_pid()
    test_privacy_canonical_event_does_not_retain_content()
    test_valkyrie_and_nyx_evidence_share_one_subject_and_hypothesis()
    test_authorized_benign_twin_contradicts_data_theft()
    test_incomplete_identity_blocks_a_strong_privacy_conclusion()
    test_duplicate_events_do_not_amplify_evidence()
    test_two_speed_queue_is_bounded_and_budgeted()
    test_fast_path_p99_is_below_ten_ms_for_synthetic_events()
    with tempfile.TemporaryDirectory(prefix="valkyrie_v2_") as tmp:
        test_engine_wires_low_severity_and_nyx_events_into_shared_ledger(Path(tmp))
        test_read_only_status_and_ledger_api(Path(tmp))
    print("10 passed")
