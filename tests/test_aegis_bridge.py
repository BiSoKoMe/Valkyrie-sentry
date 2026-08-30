"""valkyrie/aegis_bridge.py -- the CanonicalEvent -> ExposureObservation
translation boundary, tested against real DetectionArchitectureV2 output
(never hand-built ExposureObservation objects standing in for a real
event -- that would defeat the point of testing a translation boundary).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.aegis_bridge import UNAVAILABLE_CATEGORIES, translate_event, translate_session
from valkyrie.edr.detection_v2 import DetectionArchitectureV2
from valkyrie.telemetry import TelemetryEvent


def _process(pid=100, ts=1.0, labels=()):
    return TelemetryEvent(
        category="process", activity="exec", ts=ts, actor_pid=pid,
        actor_name="app.exe", source="process_collector", labels=list(labels),
        fields={"create_time": ts, "event_id": f"p-{pid}"})


def _network(pid=100, ts=2.0):
    return TelemetryEvent(
        category="network", activity="connect", ts=ts, actor_pid=pid,
        actor_name="app.exe", source="network_collector",
        target={"ip": "203.0.113.5", "domain": "dest.example"},
        fields={"event_id": f"n-{pid}"})


def _persistence(pid=100, ts=2.0):
    return TelemetryEvent(
        category="persistence", activity="registry_run_key", ts=ts, actor_pid=pid,
        actor_name="app.exe", source="persistence_collector",
        target={"location": r"HKCU\Software\Run\x"},
        fields={"event_id": f"r-{pid}"})


def test_a_purely_local_process_event_produces_no_observation():
    arch = DetectionArchitectureV2()
    result = arch.observe(_process(labels=["office_child_shell"]))
    assert translate_event(result.event) == ()


def test_a_persistence_event_produces_no_observation():
    # PERSISTENCE never reaches the wire either -- a registry write is
    # exactly as invisible to a network observer as a process launch.
    arch = DetectionArchitectureV2()
    result = arch.observe(_persistence())
    assert translate_event(result.event) == ()


def test_a_network_event_produces_a_destination_observation_with_provenance():
    arch = DetectionArchitectureV2()
    result = arch.observe(_network())
    observations = translate_event(result.event)
    assert len(observations) == 1
    obs = observations[0]
    assert obs.category == "DESTINATION"
    assert "n-100" in obs.provenance
    assert any("process:" in p for p in obs.provenance)


def test_a_network_event_with_no_domain_or_ip_produces_nothing():
    arch = DetectionArchitectureV2()
    bare = TelemetryEvent(category="network", activity="connect", ts=1.0,
                          actor_pid=100, actor_name="app.exe",
                          source="network_collector", fields={"event_id": "n-bare"})
    result = arch.observe(bare)
    assert translate_event(result.event) == ()


def test_a_privacy_event_produces_a_destination_observation():
    arch = DetectionArchitectureV2()
    priv = TelemetryEvent(
        category="privacy", activity="outbound_observation", ts=1.0, actor_pid=100,
        actor_name="app.exe", source="nyx.tls", target={"domain": "collector.example"},
        fields={"event_id": "x-1", "privacy_category": "identifier",
               "destination_host": "collector.example", "authorized": False})
    result = arch.observe(priv)
    observations = translate_event(result.event)
    assert len(observations) == 1
    assert observations[0].category == "DESTINATION"


def test_single_network_event_yields_no_timing_frequency_sequence():
    # These three categories require >=2 network-visible events for the
    # same subject -- a lone connection cannot honestly support them.
    arch = DetectionArchitectureV2()
    result = arch.observe(_network())
    session_obs = translate_session([result.event])
    categories = {o.category for o in session_obs}
    assert categories == {"DESTINATION"}


def test_two_network_events_for_the_same_subject_yield_timing_frequency_sequence():
    arch = DetectionArchitectureV2()
    r1 = arch.observe(_process())
    r2 = arch.observe(_network(ts=2.0))
    r3 = arch.observe(_network(ts=3.5))
    session_obs = translate_session([r1.event, r2.event, r3.event])
    categories = {o.category for o in session_obs}
    assert {"TIMING", "FREQUENCY", "SEQUENCE"} <= categories


def test_unavailable_categories_are_never_produced():
    arch = DetectionArchitectureV2()
    r1 = arch.observe(_process(labels=["office_child_shell"]))
    r2 = arch.observe(_network())
    r3 = arch.observe(_persistence())
    session_obs = translate_session([r1.event, r2.event, r3.event])
    produced_categories = {o.category for o in session_obs}
    assert produced_categories.isdisjoint(UNAVAILABLE_CATEGORIES)


def test_unavailable_categories_are_named_with_reasons():
    assert set(UNAVAILABLE_CATEGORIES) == {"VOLUME", "DIRECTION", "IDENTITY", "SESSION"}
    for category, reason in UNAVAILABLE_CATEGORIES.items():
        assert isinstance(reason, str) and len(reason) > 10


def test_observations_from_different_subjects_stay_in_separate_flows():
    arch = DetectionArchitectureV2()
    r1 = arch.observe(_network(pid=100, ts=1.0))
    r2 = arch.observe(_network(pid=200, ts=1.0))
    session_obs = translate_session([r1.event, r2.event])
    flow_ids = {o.flow_id for o in session_obs}
    assert len(flow_ids) == 2
    assert r1.event.subject.instance_id != r2.event.subject.instance_id
