"""valkyrie/aegis_mechanism.py -- MechanismProfile and verify(), tested on
their own terms with small, hand-built profiles (the real BUCKET-A
characterization is tested separately in test_aegis_4_mechanism_characterization.py).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.aegis_exposure import ExposureObservation
from valkyrie.aegis_mechanism import ExposureEffect, MechanismProfile, naive_catalog_entry, verify


def _profile(**overrides) -> MechanismProfile:
    defaults = dict(
        name="TEST_MECH", intended_effect="weakens VOLUME",
        measured_effects=(
            ExposureEffect("VOLUME", "SINGLE", 1.0, 0.4),
        ),
        bandwidth_overhead_pct=10.0, latency_overhead_ms={}, compatibility_note="",
        repeatability_note="", evidence_class="test", source_experiment="test",
    )
    defaults.update(overrides)
    return MechanismProfile(**defaults)


def test_weakened_categories_ignores_new_signals():
    profile = _profile(measured_effects=(
        ExposureEffect("VOLUME", "SINGLE", 1.0, 0.3),
        ExposureEffect("SEQUENCE", "SINGLE", 0.0, 0.9, is_new_signal=True),
    ))
    assert profile.weakened_categories() == {"VOLUME"}
    assert profile.new_signal_categories() == {"SEQUENCE"}


def test_weakened_categories_ignores_small_changes():
    profile = _profile(measured_effects=(
        ExposureEffect("VOLUME", "SINGLE", 1.0, 0.9),   # small drop, below default threshold
    ))
    assert profile.weakened_categories() == frozenset()


def test_apply_to_updates_precision_and_adds_new_signals():
    scenario = (
        ExposureObservation("SINGLE", "VOLUME", "f1", precision=1.0),
        ExposureObservation("SINGLE", "DESTINATION", "f1", precision=1.0),
    )
    profile = _profile(measured_effects=(
        ExposureEffect("VOLUME", "SINGLE", 1.0, 0.3),
        ExposureEffect("SEQUENCE", "SINGLE", 0.0, 0.9, is_new_signal=True),
    ))
    result = profile.apply_to(scenario, "f1")
    by_category = {o.category: o for o in result}
    assert by_category["VOLUME"].precision == 0.3
    assert by_category["DESTINATION"].precision == 1.0   # untouched, preserved
    assert by_category["SEQUENCE"].precision == 0.9       # newly added


def test_apply_to_does_not_touch_other_flows():
    scenario = (
        ExposureObservation("SINGLE", "VOLUME", "f1", precision=1.0),
        ExposureObservation("SINGLE", "VOLUME", "f2", precision=1.0),
    )
    profile = _profile()
    result = profile.apply_to(scenario, "f1")
    f2 = next(o for o in result if o.flow_id == "f2")
    assert f2.precision == 1.0


def test_naive_catalog_entry_only_reflects_weakened_categories():
    profile = _profile(measured_effects=(
        ExposureEffect("VOLUME", "SINGLE", 1.0, 0.3),
        ExposureEffect("TIMING", "SINGLE", 1.0, 1.0),
        ExposureEffect("SEQUENCE", "SINGLE", 0.0, 0.9, is_new_signal=True),
    ))
    mech = naive_catalog_entry(profile, cost=1.0)
    assert mech.affected_categories == {"VOLUME"}


def test_verify_reports_mismatch_when_a_new_signal_keeps_the_hypothesis_alive():
    scenario = (ExposureObservation("SINGLE", "VOLUME", "f1", precision=1.0),)
    profile = _profile(measured_effects=(
        ExposureEffect("VOLUME", "SINGLE", 1.0, 0.2),   # weakened enough for a naive win
        ExposureEffect("SEQUENCE", "SINGLE", 0.0, 0.9, is_new_signal=True),  # but this survives
    ))
    result = verify(profile, scenario, "f1", "f1", "ACTIVITY_CLASSIFICATION")
    assert result["naive_planner_believes_solved"] is True
    assert result["measured_still_established"] is True
    assert result["mismatch"] is True


def test_verify_reports_no_mismatch_when_measurement_confirms_the_naive_view():
    scenario = (ExposureObservation("SINGLE", "VOLUME", "f1", precision=1.0),)
    profile = _profile(measured_effects=(
        ExposureEffect("VOLUME", "SINGLE", 1.0, 0.0),   # fully removed, nothing replaces it
    ))
    result = verify(profile, scenario, "f1", "f1", "ACTIVITY_CLASSIFICATION")
    assert result["naive_planner_believes_solved"] is True
    assert result["measured_still_established"] is False
    assert result["mismatch"] is False
