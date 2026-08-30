"""Platform Alpha is now a locked, known-good architectural baseline.

redteam/evaluation/baselines/platform_alpha_baseline.json is a committed
snapshot of platform_alpha_evidence_story.run()'s real output over the
fixed shared causal chain. Everything in that run is in-process and
deterministic -- no live host, no live network, no randomness -- so if this
exact test ever fails, the cause can ONLY be a change to Valkyrie's,
NYX's, or Aegis's reasoning code. It cannot be an environment or telemetry
flake, because none exists here. That is the whole point of freezing this
baseline before Platform Beta starts touching real hosts, real browsers,
and real network capture: once THOSE start producing failures, this test
is what tells you whether the reasoning layer regressed too, or whether the
failure is purely environmental.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam.evaluation.platform_alpha_evidence_story import run

_BASELINE_PATH = (Path(__file__).resolve().parent.parent
                 / "redteam" / "evaluation" / "baselines" / "platform_alpha_baseline.json")


def _load_baseline() -> dict:
    return json.loads(_BASELINE_PATH.read_text(encoding="utf-8"))


def _fresh() -> dict:
    return json.loads(json.dumps(run(), default=str))


def test_baseline_file_exists_and_is_valid_json():
    assert _BASELINE_PATH.exists(), "the frozen Platform Alpha baseline must be committed"
    baseline = _load_baseline()
    assert isinstance(baseline, dict) and baseline


def test_fresh_run_matches_the_frozen_baseline_exactly():
    baseline = _load_baseline()
    fresh = _fresh()
    assert fresh == baseline, (
        "Platform Alpha's real, in-process, deterministic evidence story "
        "changed. Since nothing in this test touches a live host, live "
        "network, or randomness, this can only be a reasoning-layer change "
        "in Valkyrie, NYX, or Aegis -- update the baseline deliberately "
        "(and explain why in the commit) if the change is intended, rather "
        "than silently accepting a new snapshot.")


def test_baseline_still_shows_the_three_way_divergence():
    # Re-assert the specific finding this baseline exists to protect, not
    # just byte-equality -- a baseline that matched itself but had quietly
    # lost its own point would be worse than useless.
    baseline = _load_baseline()
    assert baseline["valkyrie"]["hypothesis_isolated"]["selected"] == "suspicious_execution_chain"
    assert baseline["nyx"]["hypothesis_isolated"]["selected"] == "possible_data_theft"
    assert baseline["fused_decision"]["hypothesis"]["selected"] == "possible_data_theft"
    aegis = baseline["aegis"]["inference_hypotheses"]
    assert aegis["DESTINATION_DISCLOSURE"]["action"] == "alert"
    assert aegis["ACTIVITY_CLASSIFICATION"]["action"] == "alert"
    assert aegis["FLOW_LINKAGE"]["action"] != "alert"
    assert aegis["USER_LINKABILITY"]["action"] != "alert"
