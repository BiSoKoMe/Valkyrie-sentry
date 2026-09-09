"""New API namespaces reuse real incident storage; no sensors or enforcement."""
from valkyrie.aegis import AegisInvestigator, NyxExposure
from valkyrie.edr.engine import EdrEngine
from valkyrie.edr.schema import Incident
from valkyrie.eventbus import EventBus
from valkyrie.store import Store


def test_case_identity_persists_and_exposure_alias_preserves_semantics(tmp_path):
    store = Store(db_path=tmp_path / "evidence.db")
    store.start()
    try:
        engine = EdrEngine(store)
        engine._edr.init_schema()
        incident = Incident(title="Controlled incident")
        engine._edr.save_incident(incident)
        aegis = AegisInvestigator(engine)
        assert [case["id"] for case in aegis.cases()] == [incident.id]
        assert aegis.case(incident.id) == engine.get_incident(incident.id)
        reopened = AegisInvestigator(EdrEngine(store))
        assert reopened.case(incident.id)["id"] == incident.id
        assert aegis.status()["independent_enforcement"] is False
        assert AegisInvestigator(
            engine, sensor_health_fn=lambda: {"healthy": True}
        ).status()["sensor_health"] == {"healthy": True}
        exposure = NyxExposure(engine)
        assert exposure.status() == engine.aegis_status()
        assert exposure.ledger() == engine.aegis_ledger()
        assert len(aegis.cases()) == 1
    finally:
        store.stop()


def test_namespaced_case_api_and_legacy_exposure_routes_agree(tmp_path, monkeypatch):
    from tests.testclient_compat import make_client
    from valkyrie.web import server
    store = Store(db_path=tmp_path / "api.db")
    store.start()
    try:
        engine = EdrEngine(store)
        engine._edr.init_schema()
        incident = Incident(title="Controlled API case")
        engine._edr.save_incident(incident)
        monkeypatch.setattr(server.state, "edr", engine)
        client = make_client(server.create_app(), "127.0.0.1")
        assert client.get("/api/v1/aegis/cases").json()["cases"][0]["id"] == incident.id
        assert client.get("/api/v1/aegis/status").status_code == 200
        assert client.get("/api/v1/aegis/status").json()["component"] == "aegis"
        assert client.get(f"/api/v1/aegis/cases/{incident.id}").json() == client.get(f"/api/edr/incidents/{incident.id}").json()
        assert client.get("/api/v1/aegis/cases/missing").status_code == 404
        assert client.get("/api/nyx/exposure/ledger").json() == client.get("/api/aegis/ledger").json()
        assert client.get("/api/nyx/exposure/status").json() == client.get("/api/aegis/status").json()
    finally:
        store.stop()


def test_status_without_a_sensor_health_source_says_so_explicitly(tmp_path):
    store = Store(db_path=tmp_path / "no-health.db")
    store.start()
    try:
        aegis = AegisInvestigator(EdrEngine(store))
        # An absent health source must read as UNKNOWN, never as "healthy" -
        # a case list with nothing open must not look identical whether
        # nothing happened or the sensors feeding it went silent.
        assert aegis.status()["sensor_health"] == {
            "overall": "UNKNOWN", "reason": "no sensor health source wired"}
    finally:
        store.stop()


def test_status_surfaces_a_degraded_sensor_health_source(tmp_path):
    store = Store(db_path=tmp_path / "degraded.db")
    store.start()
    try:
        degraded = {"overall": "DEGRADED", "degraded_reasons": ["persistence:stale"]}
        aegis = AegisInvestigator(EdrEngine(store), sensor_health_fn=lambda: degraded)
        assert aegis.status()["sensor_health"] == degraded
    finally:
        store.stop()


def test_status_reports_a_throwing_health_source_instead_of_hiding_it(tmp_path):
    store = Store(db_path=tmp_path / "throwing.db")
    store.start()
    try:
        def boom():
            raise RuntimeError("private watchdog internals must not leak")
        aegis = AegisInvestigator(EdrEngine(store), sensor_health_fn=boom)
        health = aegis.status()["sensor_health"]
        assert health["overall"] == "UNKNOWN"
        assert "private watchdog internals" not in str(health)
        assert "RuntimeError" in health["reason"]
    finally:
        store.stop()


def test_status_route_surfaces_the_wired_telemetry_watchdog(tmp_path, monkeypatch):
    from tests.testclient_compat import make_client
    from valkyrie.web import server
    store = Store(db_path=tmp_path / "route-health.db")
    store.start()
    try:
        engine = EdrEngine(store)
        engine._edr.init_schema()
        monkeypatch.setattr(server.state, "edr", engine)

        class _StubWatchdog:
            def status(self):
                return {"overall": "DEGRADED", "degraded_reasons": ["network_collector:stalled"]}

        monkeypatch.setattr(server.state, "telemetry_watchdog", _StubWatchdog(), raising=False)
        client = make_client(server.create_app(), "127.0.0.1")
        body = client.get("/api/v1/aegis/status").json()
        assert body["sensor_health"]["overall"] == "DEGRADED"
        assert "network_collector:stalled" in body["sensor_health"]["degraded_reasons"]
    finally:
        store.stop()


def test_failed_subscriber_is_counted_and_does_not_hide_other_delivery():
    bus = EventBus()
    received = []

    def broken(event):
        raise RuntimeError("private event must not enter diagnostic text")

    bus.subscribe(broken)
    bus.subscribe(received.append)
    bus.publish({"type": "telemetry"})
    assert received == [{"type": "telemetry"}]
    assert bus.stats() == {"published": 1, "delivered": 1, "failed": 1,
                           "subscribers": 2, "mode": "synchronous-best-effort"}
