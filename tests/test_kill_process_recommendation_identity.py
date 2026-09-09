"""End-to-end: a detection's process identity survives into a REAL kill.

response.py's KillProcessResponder correctly refuses to terminate a bare PID
for real (a PID alone can be reused by an unrelated process between detection
and action - see test_process_response_identity.py). But that refusal is only
as good as whatever built the recommended target: if the recommendation layer
(edr/investigate.py) never learned the sensor's observed process create_time,
EVERY real kill_process action from the one UI path that is actually wired to
it (the Electron investigation tab) would be refused as "ambiguous" forever,
with only the dry-run preview ever appearing to work. This test proves the
whole chain - a Detection carrying process_create_time in its details, through
Investigator._offline_report()'s recommended-action target, into
KillProcessResponder.execute(dry_run=False) - actually dispatches a real kill
when the sensor captured a create_time, and still correctly refuses when it
did not (no fabricated identity, ever).

Fully mocked psutil; nothing here can terminate a real process.
"""
from __future__ import annotations

import json
import sys
from types import SimpleNamespace
from unittest.mock import Mock

from valkyrie.edr.investigate import Investigator, _first_process_identity
from valkyrie.edr.response import KillProcessResponder
from valkyrie.edr.schema import Detection, Incident
from valkyrie.telemetry import CAT_PROCESS


def _mock_psutil(monkeypatch, create_time: float):
    process = Mock()
    process.name.return_value = "malicious.exe"
    process.create_time.return_value = create_time
    monkeypatch.setitem(sys.modules, "psutil", SimpleNamespace(
        Process=Mock(return_value=process), NoSuchProcess=type("NoSuchProcess", (Exception,), {}),
        AccessDenied=type("AccessDenied", (Exception,), {}), TimeoutExpired=type("TimeoutExpired", (Exception,), {})))
    return process


def _incident_and_detection(create_time: float | None) -> tuple[Incident, Detection]:
    inc = Incident(title="Suspicious process activity", severity="high",
                   status="open", category=CAT_PROCESS, process_name="malicious.exe")
    details = {"process_create_time": create_time} if create_time is not None else {}
    det = Detection(source="test", severity="high", category=CAT_PROCESS,
                    title="test detection", process_name="malicious.exe",
                    process_pid=424242, details=details)
    return inc, det


def _kill_target(inc: Incident, det: Detection) -> str:
    report = Investigator(edr_store=None)._offline_report(inc, [det])
    kills = [a for a in report["recommended_actions"] if a["action"] == "kill_process"]
    assert len(kills) == 1, "kill_process must be recommended exactly once for a process-category incident"
    return kills[0]["target"]


def test_first_process_identity_pairs_pid_and_create_time_from_the_same_detection():
    _, det = _incident_and_detection(create_time=555.5)
    identity = _first_process_identity([det])
    assert identity == {"pid": 424242, "create_time": 555.5}


def test_first_process_identity_is_none_with_no_pid_bearing_detection():
    assert _first_process_identity([]) is None


def test_recommended_target_carries_create_time_when_the_sensor_captured_one():
    inc, det = _incident_and_detection(create_time=1_700_000_000.0)
    target = _kill_target(inc, det)
    assert json.loads(target) == {"pid": 424242, "create_time": 1_700_000_000.0}


def test_recommended_target_is_a_bare_pid_when_the_sensor_never_captured_one():
    # Honest degradation, not a fabricated identity: the real action must
    # still be refused downstream (see next test), never silently allowed.
    inc, det = _incident_and_detection(create_time=None)
    target = _kill_target(inc, det)
    assert target == "424242"


def test_a_real_kill_actually_dispatches_when_the_recommendation_carried_create_time(monkeypatch):
    inc, det = _incident_and_detection(create_time=1_700_000_000.0)
    target = _kill_target(inc, det)
    process = _mock_psutil(monkeypatch, create_time=1_700_000_000.0)
    result = KillProcessResponder().execute("kill_process", target, dry_run=False, ctx=None)
    assert result[0] == "succeeded"
    process.terminate.assert_called_once()


def test_a_real_kill_is_still_refused_when_no_create_time_was_ever_observed(monkeypatch):
    inc, det = _incident_and_detection(create_time=None)
    target = _kill_target(inc, det)
    process = _mock_psutil(monkeypatch, create_time=1_700_000_000.0)
    result = KillProcessResponder().execute("kill_process", target, dry_run=False, ctx=None)
    assert result[0] == "skipped" and "create_time" in result[1]
    process.terminate.assert_not_called()
