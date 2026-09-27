"""The suite's public component boundary stays explicit and versioned."""

from pathlib import Path

from valkyrie.capabilities import component_contract

_REPO_ROOT = Path(__file__).resolve().parent.parent


def test_component_ownership_and_authority_are_unambiguous():
    contract = component_contract()
    components = {item["id"]: item for item in contract["components"]}
    assert contract["schema_version"] == 1
    assert set(components) == {"valkyrie", "nyx", "aegis", "warden"}
    assert components["valkyrie"]["role"] == "endpoint-detection-response"
    assert components["nyx"]["role"] == "outbound-privacy-defense"
    assert components["aegis"]["role"] == "local-investigation-correlation"
    assert components["warden"]["role"] == "network-presence-privacy"
    assert components["aegis"]["independent_enforcement"] is False
    assert components["warden"]["independent_enforcement"] is False
    assert "unsigned-kernel-driver" in contract["excluded_from_release_claims"]


def test_callers_cannot_mutate_the_global_contract():
    first = component_contract()
    first["components"].clear()
    assert len(component_contract()["components"]) == 4


def test_every_component_uses_the_same_enforcement_key():
    # independent_host_enforcement (NYX-only, pre-2026-09-11) vs
    # independent_enforcement (everyone else) was a schema inconsistency with
    # no consumer anywhere in the repo depending on the NYX-only spelling -
    # a silent drift a caller could trip on invisibly. All four components
    # must expose the same key.
    contract = component_contract()
    for item in contract["components"]:
        assert "independent_enforcement" in item, item["id"]
        assert "independent_host_enforcement" not in item, item["id"]


def test_every_evidence_path_actually_exists():
    # A test file (or route) cited as evidence for a capability claim that
    # does not exist would make the claim unverifiable by construction - the
    # exact "coverage that doesn't exist" failure the rest of this codebase
    # explicitly rejects elsewhere (see behavioral_rules.py's own honest-scope
    # comments). This does not run the evidence, only confirms it is real.
    contract = component_contract()
    for item in contract["components"]:
        for path in item["evidence"]:
            assert (_REPO_ROOT / path).is_file(), f"{item['id']}: {path}"


def test_capability_api_returns_the_same_contract():
    from tests.testclient_compat import make_client
    from valkyrie.web import server

    client = make_client(server.create_app(), "127.0.0.1")
    response = client.get("/api/v1/capabilities")
    assert response.status_code == 200
    assert response.json() == component_contract()
