import shutil

from valkyrie.collector_diagnostics import PollDiagnostics
from redteam.evaluation import beta05_reliability as reliability
from redteam.evaluation.beta05_reliability import Sampler


def test_poll_diagnostics_exposes_active_and_completed_stage():
    diagnostics = PollDiagnostics()
    diagnostics.poll_started()
    with diagnostics.stage("scheduled_tasks"):
        active = diagnostics.status()
        assert active["current_stage"] == "scheduled_tasks"
        assert active["poll_started_at"] > 0
    diagnostics.poll_completed()
    completed = diagnostics.status()
    assert completed["current_stage"] is None
    assert "scheduled_tasks" in completed["last_stage_durations_s"]
    assert completed["longest_poll_duration_s"] >= completed["last_poll_duration_s"]


def test_contention_mode_stops_on_any_api_failure_or_degraded():
    clean = {
        "health_ok": True,
        "requests": {name: {"ok": True} for name in
                     ("health", "watchdog", "causality", "sensors")},
        "watchdog": {"overall": "HEALTHY"},
    }
    assert Sampler._failure_reason(clean) is None
    timed_out = {**clean, "requests": {**clean["requests"],
                 "causality": {"ok": False}}}
    assert Sampler._failure_reason(timed_out) == "api_causality_failure"
    degraded = {**clean, "watchdog": {"overall": "DEGRADED"}}
    assert Sampler._failure_reason(degraded) == "watchdog_degraded"


def test_engine_output_is_not_an_undrained_pipe(monkeypatch, tmp_path):
    """A full Windows stdout pipe can block API and collector writers."""
    captured = {}

    class FakeProcess:
        pid = 123

        def poll(self):
            return None

    def fake_popen(*args, **kwargs):
        captured.update(kwargs)
        return FakeProcess()

    monkeypatch.setattr(reliability, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(reliability.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(reliability, "_get", lambda *_args, **_kwargs: {})
    process, _api, _data = reliability.start_engine()
    try:
        assert captured["stdout"] is not reliability.subprocess.PIPE
        assert getattr(captured["stdout"], "name", "").endswith("beta05_engine.log")
    finally:
        process._beta05_log_fh.close()
        shutil.rmtree(_data, ignore_errors=True)
