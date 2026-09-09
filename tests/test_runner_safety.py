"""Runner isolation, classification and real pytest coverage dispatch."""
from pathlib import Path
from types import SimpleNamespace

from tests import run_tests as runner


def test_unknown_test_is_not_assumed_safe():
    assert runner._category(Path("test_new_host_control.py")) == "unclassified"
    assert runner._category(Path("test_control_boundary.py")) == "isolated"
    assert runner._category(Path("test_dns.py")) == "integration"


def test_pytest_coverage_runs_assertions_and_uses_isolated_data(tmp_path, monkeypatch):
    source = tmp_path / "test_example.py"
    source.write_text("def test_example():\n    assert True\n")
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        assert Path(kwargs["env"]["VALKYRIE_DATA_DIR"]).is_dir()
        return SimpleNamespace(returncode=0, stdout="1 passed in 0.01s", stderr="")

    monkeypatch.setattr(runner.subprocess, "run", run)
    assert runner._run_one(source, 30, coverage=True)[0] == runner.OUTCOME_PASS
    assert calls[0][1:7] == ["-m", "coverage", "run", "--parallel-mode", "--source=valkyrie", "-m"]
    assert calls[0][7:] == ["pytest", str(source), "-q"]


def test_coverage_does_not_hide_failing_assertions(tmp_path, monkeypatch):
    source = tmp_path / "test_failure.py"
    source.write_text("def test_failure():\n    assert False\n")
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **kw:
                        SimpleNamespace(returncode=1, stdout="1 failed", stderr=""))
    assert runner._run_one(source, 30, coverage=True)[0] == runner.OUTCOME_FAIL


def test_direct_engine_boot_tests_require_a_disposable_host(monkeypatch):
    from tests import test_capability_delivery, test_startup_smoke

    monkeypatch.delenv("VALKYRIE_DISPOSABLE_TEST_HOST", raising=False)

    def unexpected_launch(*args, **kwargs):
        raise AssertionError("a workstation test must not launch the real engine")

    monkeypatch.setattr(runner.subprocess, "Popen", unexpected_launch)
    assert test_startup_smoke.main() == runner.EXIT_SKIP
    assert test_capability_delivery.main() == runner.EXIT_SKIP
