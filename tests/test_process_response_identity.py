"""Stale PID tests with a fully mocked psutil process; never terminate a process."""
import json
import sys
from types import SimpleNamespace
from unittest.mock import Mock

from valkyrie.edr.response import KillProcessResponder


def test_bare_pid_cannot_terminate():
    result = KillProcessResponder().execute("kill_process", "424242", dry_run=False, ctx=None)
    assert result[0] == "skipped" and "create_time" in result[1]


def test_stale_identity_is_refused_and_matching_identity_can_dispatch(monkeypatch):
    process = Mock()
    process.name.return_value = "test-workload.exe"
    process.create_time.return_value = 200.0
    monkeypatch.setitem(sys.modules, "psutil", SimpleNamespace(
        Process=Mock(return_value=process), NoSuchProcess=type("NoSuchProcess", (Exception,), {}),
        AccessDenied=type("AccessDenied", (Exception,), {}), TimeoutExpired=type("TimeoutExpired", (Exception,), {})))
    responder = KillProcessResponder()
    target = json.dumps({"pid": 424242, "create_time": 100.0})
    assert responder.execute("kill_process", target, dry_run=False, ctx=None)[0] == "skipped"
    process.terminate.assert_not_called()
    target = json.dumps({"pid": 424242, "create_time": 200.0})
    assert responder.execute("kill_process", target, dry_run=False, ctx=None)[0] == "succeeded"
    process.terminate.assert_called_once()
