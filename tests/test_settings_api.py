"""GET/POST /api/v1/settings - the settings API that never existed before.

valkyrie/settings.py's whole override system (SPECS, load(), describe()) had
no HTTP path at all - confirmed by grepping the entire web server for SPECS/
CONFIG_OVERRIDES/settings before this route existed: zero hits. NYX_ACT (the
flagship "rewrite leaking data into fakes instead of only observing it"
behaviour) could only ever be turned on by hand-editing a settings file or an
environment variable and restarting the whole engine - no UI, no API. These
tests prove the new routes actually persist (survive a fresh settings.load(),
not just an in-memory change), validate the same way a hand-edited file
would, are gated the same as every other mutating route, and - the one
assertion that actually proves the flagship claim - that POSTing NYX_ACT is
visible to its real, live consumer without a process restart.
"""
from __future__ import annotations

import pytest
from tests.testclient_compat import make_client


@pytest.fixture
def api(monkeypatch, tmp_path):
    from valkyrie import config, settings as _settings
    from valkyrie.web import server

    monkeypatch.setattr(server, "_CONTROL_TOKEN", "T" * 32)
    monkeypatch.setattr(server, "_CONTROL_TOKEN_PUBLISHED", True)
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    # A successful POST calls setattr(config, key, val) directly (that is
    # the whole point - the change must be visible with no restart), not
    # through monkeypatch, so pytest's own undo would never see it. Register
    # every spec's CURRENT value with monkeypatch now so each one is
    # correctly restored after the test regardless of what a route mutates
    # it to, keeping every test in this file isolated from the others.
    for spec in _settings.SPECS:
        monkeypatch.setattr(config, spec.key, getattr(config, spec.key))
    app = server.create_app()
    client = make_client(app, "127.0.0.1")
    headers = {"x-valkyrie-token": "T" * 32}
    return config, client, headers, tmp_path


def _post(client, headers, key, value):
    return client.post("/api/v1/settings", headers=headers, json={"key": key, "value": value})


def test_get_lists_every_spec_with_its_current_value_and_source(api):
    _config, client, headers, _tmp = api
    r = client.get("/api/v1/settings")
    assert r.status_code == 200
    settings_by_key = {s["key"]: s for s in r.json()["settings"]}
    assert "NYX_ACT" in settings_by_key
    assert settings_by_key["NYX_ACT"]["source"] == "default"
    assert settings_by_key["NYX_ACT"]["live_without_restart"] is True
    # A restart-required setting must say so - the whole point of this field.
    assert settings_by_key["WEB_PORT"]["live_without_restart"] is False


def test_post_persists_and_survives_a_fresh_settings_load(api):
    from valkyrie import settings as _settings
    config, client, headers, tmp = api

    r = _post(client, headers, "RATE_MAX_QUERIES", 777)
    assert r.status_code == 200
    assert r.json()["value"] == 777

    # Not just an in-memory change: a BRAND NEW load() call, independent of
    # the running process's config module, must see it from disk.
    resolved, overrides = _settings.load({"RATE_MAX_QUERIES": 5000}, config_dir=tmp)
    assert resolved["RATE_MAX_QUERIES"] == 777
    assert any(o.key == "RATE_MAX_QUERIES" and o.value == 777 for o in overrides)

    # And the GET reflects it immediately in the same process too.
    r2 = client.get("/api/v1/settings")
    by_key = {s["key"]: s for s in r2.json()["settings"]}
    assert by_key["RATE_MAX_QUERIES"]["value"] == 777
    assert "config file" in by_key["RATE_MAX_QUERIES"]["source"]


def test_post_invalid_value_400s_with_the_configerror_message(api):
    _config, client, headers, _tmp = api
    r = _post(client, headers, "RATE_MAX_QUERIES", "not-a-number")
    assert r.status_code == 400
    assert "RATE_MAX_QUERIES" in r.json()["error"]


def test_post_unknown_key_400s_rather_than_writing_garbage_to_disk(api):
    _config, client, headers, tmp = api
    r = _post(client, headers, "NOT_A_REAL_SETTING", 1)
    assert r.status_code == 400
    assert not (tmp / "valkyrie.yaml").exists()


def test_post_without_a_valid_token_is_rejected_like_every_other_mutation(api):
    _config, client, _headers, tmp = api
    r = client.post("/api/v1/settings", json={"key": "NYX_ACT", "value": True})
    assert r.status_code == 403
    assert not (tmp / "valkyrie.yaml").exists()


def test_nyx_act_takes_effect_live_for_its_real_consumer_no_restart(api):
    # This is the assertion that actually proves the flagship claim: not
    # "the setting changed", but that tls_addon.py's real, live NYX_ACT read
    # (a deferred `from .config import NYX_ACT` inside the function body,
    # re-executed on every call) sees the new value with no process restart.
    config, client, headers, _tmp = api
    assert config.NYX_ACT is False

    r = _post(client, headers, "NYX_ACT", True)
    assert r.status_code == 200
    assert r.json() == {"key": "NYX_ACT", "value": True, "live_without_restart": True}

    # Simulate tls_addon.py's own read site exactly: a fresh deferred import.
    from valkyrie.config import NYX_ACT as live_read
    assert live_read is True
