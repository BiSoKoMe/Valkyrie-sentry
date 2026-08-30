"""Aegis 4: characterizing BUCKET-A from its own real Aegis 1A numbers, and
checking whether the planner would have been fooled by its intended effect
alone. Pulls live from aegis_1a_bucketing.run() rather than hardcoded
figures, so a change to that experiment is reflected here automatically.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam.evaluation.aegis_4_mechanism_characterization import (
    characterize_bucket_a,
    run,
)


def test_profile_distinguishes_intended_from_measured():
    profile = characterize_bucket_a()
    assert profile.intended_effect
    assert profile.measured_effects
    # intended_effect is free text; nothing here should equal a raw number,
    # confirming it is never mistaken for a measured value downstream.
    assert not any(str(v) == profile.intended_effect for v in
                  (e.measured_precision for e in profile.measured_effects))


def test_volume_is_measured_as_genuinely_weakened():
    profile = characterize_bucket_a()
    volume = next(e for e in profile.measured_effects if e.category == "VOLUME")
    assert volume.measured_precision < volume.baseline_precision
    assert not volume.is_new_signal


def test_sequence_is_recorded_as_a_new_signal_not_hidden():
    profile = characterize_bucket_a()
    sequence = next(e for e in profile.measured_effects if e.category == "SEQUENCE")
    assert sequence.is_new_signal
    assert sequence.measured_precision > 0.3   # a real, non-trivial replacement signal


def test_timing_and_destination_are_recorded_as_unchanged_not_omitted():
    profile = characterize_bucket_a()
    by_category = {e.category: e for e in profile.measured_effects}
    for category in ("TIMING", "DESTINATION"):
        assert by_category[category].baseline_precision == by_category[category].measured_precision


def test_numbers_are_pulled_live_from_the_real_experiment():
    from redteam.evaluation.aegis_1a_bucketing import run as run_1a
    profile = characterize_bucket_a()
    assert profile.bandwidth_overhead_pct == run_1a()["results"]["BUCKET-A"]["bandwidth_overhead_pct"]


def test_verification_reports_the_expected_mismatch():
    report = run()
    v = report["verification"]
    assert v["naive_planner_believes_solved"] is True
    assert v["measured_still_established"] is True
    assert v["mismatch"] is True
    assert v["weakened_categories_naively_claimed"] == ["VOLUME"]
    assert v["new_signal_categories_measured"] == ["SEQUENCE"]


def test_conclusion_text_matches_the_measured_mismatch():
    report = run()
    assert report["verification"]["mismatch"]
    assert report["conclusion"].startswith("MISMATCH")


def test_only_one_mechanism_is_characterized():
    report = run()
    assert report["mechanism_profile"]["name"].startswith("BUCKET-A")
    assert "BUCKET-B" not in str(report["mechanism_profile"])
    assert "BUCKET-C" not in str(report["mechanism_profile"])
    assert "BUCKET-D" not in str(report["mechanism_profile"])
