"""The suite's public component boundary stays explicit and versioned."""

from valkyrie.capabilities import component_contract


def test_component_ownership_and_authority_are_unambiguous():
    contract = component_contract()
    components = {item["id"]: item for item in contract["components"]}
    assert contract["schema_version"] == 1
    assert set(components) == {"valkyrie", "nyx", "aegis"}
    assert components["valkyrie"]["role"] == "endpoint-detection-response"
    assert components["nyx"]["role"] == "outbound-privacy-defense"
    assert components["aegis"]["role"] == "local-investigation-correlation"
    assert components["aegis"]["independent_enforcement"] is False
    assert "unsigned-kernel-driver" in contract["excluded_from_release_claims"]


def test_callers_cannot_mutate_the_global_contract():
    first = component_contract()
    first["components"].clear()
    assert len(component_contract()["components"]) == 3


def test_capability_api_returns_the_same_contract():
    from tests.testclient_compat import make_client
    from valkyrie.web import server

    client = make_client(server.create_app(), "127.0.0.1")
    response = client.get("/api/v1/capabilities")
    assert response.status_code == 200
    assert response.json() == component_contract()
