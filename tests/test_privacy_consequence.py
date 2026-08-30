import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.edr.causal_detect import MIN_OBSERVATIONS, MIN_SESSIONS, CausalBaseline
from valkyrie.edr.consequence import score_privacy_consequence


def _sub(*, inferred=0, owner="chrome.exe", privacy_data=None):
    cgo = {"key": "1/1", "pid": 1, "name": owner, "parent_key": ""}
    child = {"key": "2/1", "pid": 2, "name": "helper.exe", "parent_key": "1/1"}
    return {"found": True, "cgo": cgo, "tree": [child], "chain": [cgo],
            "truncated": False, "evicted": 0, "inferred_nodes": inferred,
            "artifacts": [
                {"kind": "nyx_leak", "process": "chrome.exe", "data": privacy_data or
                 {"category": "identifier", "destination_host": "tracker.example"}},
                {"kind": "dns", "process": "helper.exe", "data": {"subject": "rare.example"}},
            ]}


def _mature():
    return CausalBaseline(observations=MIN_OBSERVATIONS, sessions=MIN_SESSIONS)


def test_fires_only_for_mature_complete_cross_layer_consequence():
    finding = score_privacy_consequence(_sub(), _mature())
    assert finding.fires
    assert finding.destination == "tracker.example"
    assert finding.network_destination == "rare.example"
    assert finding.privacy_categories == ("identifier",)
    assert "not prevented" in finding.reason


def test_rejects_immature_or_inferred_attribution():
    assert score_privacy_consequence(_sub(), CausalBaseline()).suppressed_by == "baseline_immature"
    assert score_privacy_consequence(_sub(inferred=1), _mature()).suppressed_by == "incomplete_provenance"


def test_routine_or_noninteractive_shapes_do_not_fire():
    baseline = _mature()
    for _ in range(20):
        baseline.add_artifact("helper.exe", "dns")
    assert score_privacy_consequence(_sub(), baseline).suppressed_by == "no_rare_descendant_egress"
    assert score_privacy_consequence(_sub(owner="msiexec.exe"), _mature()).suppressed_by == "non_interactive_owner"


def test_privacy_boundary_refuses_content_bearing_metadata():
    finding = score_privacy_consequence(_sub(privacy_data={
        "category": "identifier", "destination_host": "tracker.example", "body": "secret"}), _mature())
    assert not finding.fires
    assert finding.suppressed_by == "privacy_boundary_violation"


def test_engine_records_signal_and_only_seeds_future_dns_memory(tmp_path):
    from valkyrie.edr.engine import EdrEngine
    from valkyrie.store import Store
    from valkyrie.telemetry import CAT_DNS, CAT_PRIVACY, CAT_PROCESS, TelemetryEvent

    class Intel:
        def __init__(self): self.blocks = []
        def remember_block(self, destination, reason): self.blocks.append((destination, reason))

    store = Store(db_path=tmp_path / "consequence.db")
    store.start()
    intel = Intel()
    engine = EdrEngine(store, intelligence=intel)
    engine.start()
    try:
        engine._causal_baseline = _mature()
        engine.ingest_telemetry(TelemetryEvent(
            category=CAT_PROCESS, activity="exec", ts=1.0, actor_pid=10,
            actor_name="chrome.exe", source="process_collector"))
        engine.ingest_telemetry(TelemetryEvent(
            category=CAT_PROCESS, activity="exec", ts=2.0, actor_pid=11,
            actor_name="helper.exe", source="process_collector",
            fields={"ppid": 10}))
        engine.ingest_telemetry(TelemetryEvent(
            category=CAT_DNS, activity="query", ts=3.0, actor_pid=11,
            actor_name="helper.exe", target={"domain": "rare.example"},
            source="test"))
        engine.ingest_telemetry(TelemetryEvent(
            category=CAT_PRIVACY, activity="outbound_observation", ts=4.0,
            actor_pid=10, actor_name="chrome.exe", target={"domain": "tracker.example"},
            severity="low", source="nyx.tls", labels=["nyx_leak"],
            reason="Nyx observed a privacy category crossing a boundary",
            fields={"artifact_kind": "nyx_leak", "event_id": "nyx-test-1",
                    "privacy_category": "identifier",
                    "destination_host": "tracker.example",
                    "first_party_origin": "publisher.example",
                    "masked_sample": "ab***yz", "body": "must-not-retain"}))
        incidents = engine.list_incidents()
        assert any(i["category"] == "privacy_consequence" for i in incidents)
        # The experiment must not write directly to DNS intelligence. Any later
        # block is exclusively an explicit playbook action gated by decision and
        # authority, not an incidental consequence of graph scoring.
        assert not intel.blocks
        graph = engine.causality_subgraph(10)
        serialized = repr(graph)
        assert "ab***yz" not in serialized
        assert "must-not-retain" not in serialized
        incident = next(i for i in engine.list_incidents()
                        if i["category"] == "privacy_consequence")
        detail = engine.get_incident(incident["id"])
        assert any(t["kind"] == "decision" and t["data"]["action"] == "deceive"
                   for t in detail["timeline"])
    finally:
        engine.stop()
        store.stop()


def test_privacy_consequence_policy_escalates_only_in_stricter_profiles():
    from valkyrie.decision import Action, Profile, Signal, decide

    signal = Signal(category="privacy_consequence", severity="medium",
                    labels=("metadata_leakage",), entity="tracker.example")
    assert decide(signal, Profile.STANDARD).action == Action.DECEIVE
    assert decide(signal, Profile.HIGH_RISK).action == Action.BLOCK


def test_policy_gated_playbook_fails_closed_without_both_verdicts():
    from valkyrie.edr.playbooks import Playbook, PlaybookAction

    book = Playbook(
        id="privacy", min_severity="medium", categories=("privacy_consequence",),
        requires_policy_action="block", requires_authority_action="block",
        actions=[PlaybookAction("block_domain")])
    incident = {"severity": "medium", "category": "privacy_consequence"}
    assert not book.matches(incident, policy_action="deceive", authority_action="deceive")
    assert not book.matches(incident, policy_action="block", authority_action="alert")
    assert book.matches(incident, policy_action="block", authority_action="block")


def test_policy_gated_playbook_uses_persisted_incident_records():
    """The live bus payload is compact; the gate must use saved evidence, not
    assume its absence means permission. This exercises PlaybookEngine's actual
    subscription callback rather than Playbook.matches() in isolation."""
    from valkyrie.edr.playbooks import Playbook, PlaybookAction, PlaybookEngine

    class Edr:
        def __init__(self, authority):
            self.authority = authority
            self.calls = []

        def get_incident(self, incident_id):
            return {"timeline": [
                {"kind": "decision", "data": {"action": "block"}},
                {"kind": "authority", "data": {"action": self.authority}},
            ]}

        def respond(self, *args, **kwargs):
            self.calls.append((args, kwargs))

    book = Playbook(
        id="privacy", min_severity="medium", categories=("privacy_consequence",),
        requires_policy_action="block", requires_authority_action="block",
        actions=[PlaybookAction("block_domain")])
    payload = {"type": "incident", "incident": {
        "id": "inc-1", "severity": "medium", "category": "privacy_consequence",
        "entity": "tracker.example"}}

    allowed = Edr("block")
    engine = PlaybookEngine(allowed)
    engine._playbooks = [book]
    engine._on_incident(payload)
    assert len(allowed.calls) == 1
    assert allowed.calls[0][1]["dry_run"] is True

    refused = Edr("alert")
    engine = PlaybookEngine(refused)
    engine._playbooks = [book]
    engine._on_incident(payload)
    assert refused.calls == []


def test_playbook_first_response_is_not_suppressed_soon_after_boot():
    """A low monotonic clock is uptime, not evidence of a prior response."""
    from valkyrie.edr import playbooks as playbook_module
    from valkyrie.edr.playbooks import Playbook, PlaybookAction, PlaybookEngine

    class Edr:
        def __init__(self):
            self.calls = []

        def respond(self, *args, **kwargs):
            self.calls.append((args, kwargs))

    original_monotonic = playbook_module.time.monotonic
    try:
        playbook_module.time.monotonic = lambda: 12.0
        edr = Edr()
        engine = PlaybookEngine(edr)
        incident = {"id": "inc-fresh-boot", "entity": "tracker.example",
                    "severity": "high", "category": "privacy_consequence"}
        book = Playbook(id="fresh-boot", cooldown_seconds=300.0,
                        actions=[PlaybookAction("block_domain")])

        engine._run_playbook(book, incident)
        engine._run_playbook(book, incident)

        assert len(edr.calls) == 1
        assert engine.status()["suppressed_by_cooldown"] == 1
    finally:
        playbook_module.time.monotonic = original_monotonic


def test_tls_addon_emits_metadata_only_normalized_privacy_event():
    from valkyrie.nyx import Observation
    from valkyrie.tls_addon import ValkyrieAddon

    class Capture:
        def __init__(self): self.events = []
        def ingest_telemetry(self, event): self.events.append(event)

    addon = ValkyrieAddon.__new__(ValkyrieAddon)
    addon.edr = Capture()
    addon._resolve_causality_pid = lambda flow: (4321, "chrome.exe")
    addon._emit_nyx_observations(object(), [Observation(
        category="identifier", destination_host="tracker.example",
        first_party_origin="publisher.example", masked_sample="id***42",
        sentence="publisher.example sent your device identifier to tracker.example")])
    assert len(addon.edr.events) == 1
    event = addon.edr.events[0].to_dict()
    assert event["category"] == "privacy"
    assert event["fields"]["artifact_kind"] == "nyx_leak"
    assert event["fields"]["destination_host"] == "tracker.example"
    assert "masked_sample" not in event["fields"]
    assert "id***42" not in repr(event)


def test_privacy_event_retry_is_idempotent_in_the_graph(tmp_path):
    from valkyrie.edr.engine import EdrEngine
    from valkyrie.store import Store
    from valkyrie.telemetry import CAT_PRIVACY, TelemetryEvent

    store = Store(db_path=tmp_path / "retry.db")
    store.start()
    engine = EdrEngine(store)
    engine.start()
    try:
        event = TelemetryEvent(
            category=CAT_PRIVACY, activity="outbound_observation", actor_pid=42,
            actor_name="chrome.exe", target={"domain": "tracker.example"},
            source="nyx.tls", fields={"artifact_kind": "nyx_leak",
                                       "event_id": "retry-safe-1",
                                       "privacy_category": "identifier",
                                       "destination_host": "tracker.example"})
        engine.ingest_telemetry(event)
        engine.ingest_telemetry(event)
        node = engine._causality.node(42)
        assert node is not None
        assert len([a for a in node.artifacts if a.kind == "nyx_leak"]) == 1
    finally:
        engine.stop()
        store.stop()


if __name__ == "__main__":
    import inspect
    import tempfile

    tests = [value for name, value in list(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        if "tmp_path" in inspect.signature(test).parameters:
            with tempfile.TemporaryDirectory(prefix="valkyrie_privacy_") as tmp:
                test(Path(tmp))
        else:
            test()
    print(f"{len(tests)} passed")
