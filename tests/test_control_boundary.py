"""HTTP trust boundary. Only a synthetic handler is invoked; no host actions."""
import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse
from tests.testclient_compat import make_client


@pytest.fixture
def boundary(monkeypatch):
    from valkyrie.web import server
    monkeypatch.setattr(server, "_CONTROL_TOKEN", "T" * 32)
    monkeypatch.setattr(server, "_CONTROL_TOKEN_PUBLISHED", True)
    app = server.create_app()
    received = []

    async def harmless(request: Request):
        received.append(request.method)
        return JSONResponse({"accepted": True})

    app.add_api_route("/api/test-control", harmless, methods=["POST", "PUT", "PATCH", "DELETE"])
    return server, app, received


@pytest.mark.parametrize("origin", [None, "null", "http://localhost", "https://untrusted.example"])
def test_loopback_cannot_bootstrap_secret(boundary, origin):
    _, app, _ = boundary
    headers = {} if origin is None else {"origin": origin}
    response = make_client(app, "127.0.0.1").get("/api/system/token", headers=headers)
    assert response.status_code == 403
    assert "T" * 32 not in response.text
    assert "token" not in response.json()


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_mutations_require_header_credential(boundary, method):
    _, app, received = boundary
    request = getattr(make_client(app, "127.0.0.1"), method)
    assert request("/api/test-control").status_code == 403
    assert request("/api/test-control?token=" + "T" * 32).status_code == 403
    assert received == []
    assert request("/api/test-control", headers={"x-valkyrie-token": "T" * 32}).status_code == 200
    assert received == [method.upper()]


def test_origin_peer_and_failed_credential_publication_deny_mutation(boundary, monkeypatch):
    server, app, received = boundary
    headers = {"x-valkyrie-token": "T" * 32}
    assert make_client(app, "192.0.2.5").post("/api/test-control", headers=headers).status_code == 403
    local = make_client(app, "127.0.0.1")
    assert local.post("/api/test-control", headers={**headers, "origin": "https://untrusted.example"}).status_code == 403
    monkeypatch.setattr(server, "_CONTROL_TOKEN_PUBLISHED", False)
    assert local.post("/api/test-control", headers=headers).status_code == 403
    assert received == []


def test_browser_observation_credential_cannot_authorize_control(boundary, monkeypatch):
    from unittest.mock import Mock
    server, app, received = boundary
    collector = Mock()
    collector.token_ok.side_effect = lambda value: value == "browser-only"
    collector.ingest.return_value = {"accepted": True}
    monkeypatch.setattr(server.state, "browser_context", collector)
    local = make_client(app, "127.0.0.1")
    headers = {"x-valkyrie-browser-token": "browser-only"}
    assert local.post("/api/browser/events", headers=headers, json={}).status_code == 202
    assert local.post("/api/test-control", headers=headers).status_code == 403
    assert local.post("/api/browser/events", json={}).status_code == 403
    assert received == []
