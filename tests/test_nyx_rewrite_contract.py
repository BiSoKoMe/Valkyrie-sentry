"""In-memory request edits. No proxy, network, or user data."""
from valkyrie.nyx_rewrite import apply_rewrite


class Request:
    def __init__(self, fail_url=False):
        self._url = "https://tracker.example/?id=raw"
        self.raw_content = b"raw"
        self.headers = {"X-Id": "raw"}
        self.fail_url = fail_url

    @property
    def url(self):
        return self._url

    @url.setter
    def url(self, value):
        if self.fail_url:
            raise ValueError("sensitive URL must not enter diagnostics")
        self._url = value

    def set_content(self, value):
        self.raw_content = value


def rewrite(request):
    return apply_rewrite(request, url=request.url, body=request.raw_content,
                         headers=dict(request.headers), new_url="https://tracker.example/?id=fake",
                         new_body=b"fake", new_headers={"X-Id": "fake"})


def test_failed_url_does_not_hide_or_prevent_other_edits():
    request = Request(fail_url=True)
    result = rewrite(request)
    assert result.outcome == "partial"
    assert result.failed == ("url",)
    assert result.applied == ("body", "header")
    assert request.raw_content == b"fake" and request.headers["X-Id"] == "fake"
    assert "raw" in request.url
    assert "sensitive" not in repr(result)


def test_all_parts_must_be_applied_for_success():
    result = rewrite(Request())
    assert result.outcome == "applied" and not result.failed


def test_silent_body_setter_is_reported_as_partial():
    request = Request()
    request.set_content = lambda value: None
    result = rewrite(request)
    assert result.outcome == "partial" and result.failed == ("body",)


def test_addon_does_not_label_partial_edit_as_success(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock
    from valkyrie import config, nyx
    from valkyrie.tls_addon import ValkyrieAddon
    request = Request(fail_url=True)
    request.method = "POST"
    monkeypatch.setattr(config, "NYX_ACT", True)
    monkeypatch.setattr(nyx, "inspect_outbound", lambda **kw: [SimpleNamespace(sentence="disclosure observed")])
    monkeypatch.setattr(nyx, "fake_outbound", lambda *a: ("https://tracker.example/?id=fake", b"fake", ["identifier"]))
    monkeypatch.setattr(nyx, "fake_outbound_headers", lambda *a: ({"X-Id": "fake"}, ["identifier"]))
    addon = ValkyrieAddon.__new__(ValkyrieAddon)
    addon._emit_nyx_observations = Mock()
    addon._log = Mock()
    addon._nyx_observe(SimpleNamespace(request=request), "tracker.example", request.url, "browser")
    assert addon.nyx_diag["act_partial"] == 1
    assert addon.nyx_diag.get("act_succeeded", 0) == 0
    assert all(call.args[3] != "deceived" for call in addon._log.call_args_list)
