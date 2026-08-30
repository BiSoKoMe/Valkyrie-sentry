"""Aegis 1B -- information separation as a primitive, tested rather than
assumed. Pins the real (negative) finding: EXIT alone retains full
destination-driven linkability because it never needed identity in the
first place, and timing+size correlation re-links the separated views
despite incidental relay noise.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam.evaluation.aegis_1b_separation import run
from redteam.evaluation.aegis_ablation import FROZEN_MANIFEST_SHA256
from redteam.evaluation.aegis_baseline import build_corpus, manifest_hash


def test_corpus_still_matches_the_frozen_baseline():
    assert manifest_hash(build_corpus()) == FROZEN_MANIFEST_SHA256


def test_all_three_conditions_are_reported():
    report = run()
    assert set(report["conditions"]) == {
        "CONTROL", "SINGLE_INTERMEDIARY", "SEPARATED_KNOWLEDGE"}


def test_single_intermediary_is_structurally_identical_to_control():
    # The "obvious weakness" made empirical: a relay that sees both identity
    # and destination cannot be less informative than a single observer that
    # sees both -- confirmed as a number, not just asserted in prose.
    report = run()
    control = report["conditions"]["CONTROL"]["destination_linkability"]
    intermediary = report["conditions"]["SINGLE_INTERMEDIARY"]["destination_linkability"]
    assert control == intermediary


def test_exit_alone_keeps_full_destination_linkability():
    # The core, sobering finding: hiding identity from EXIT does nothing,
    # because EXIT's destination-overlap linkability never depended on
    # possessing an identity signal in the first place.
    report = run()
    control_acc = report["conditions"]["CONTROL"]["destination_linkability"]["balanced_accuracy"]
    exit_acc = report["conditions"]["SEPARATED_KNOWLEDGE"][
        "destination_linkability_at_exit"]["balanced_accuracy"]
    assert exit_acc == control_acc


def test_timing_size_correlation_relinks_the_separated_views():
    # The critical test the user specified: an informed observer re-links
    # ENTRY's view to EXIT's view of the same session using ONLY timing and
    # size, despite incidental relay noise. This is expected to succeed
    # (near-ceiling) given no decorrelation mechanism was added -- pinned as
    # a regression so this honest failure can't quietly disappear.
    report = run()
    relink = report["conditions"]["SEPARATED_KNOWLEDGE"]["relink_via_timing_size_correlation"]
    assert relink["relink_accuracy"] > 10 * relink["relink_random_chance"]


def test_verdict_reports_failure_when_relinking_succeeds():
    report = run()
    relink = report["conditions"]["SEPARATED_KNOWLEDGE"]["relink_via_timing_size_correlation"]
    if relink["relink_accuracy"] > 3 * relink["relink_random_chance"]:
        assert report["verdict"].startswith("FAILURE")


def test_does_not_claim_generalization_it_has_not_shown():
    report = run()
    assert report["generalizes_beyond_this_corpus"].startswith("No.")


def test_frozen_manifest_mismatch_raises():
    import redteam.evaluation.aegis_1b_separation as mod
    original = mod.FROZEN_MANIFEST_SHA256
    try:
        mod.FROZEN_MANIFEST_SHA256 = "0" * 64
        try:
            mod.run()
            assert False, "expected RuntimeError on manifest mismatch"
        except RuntimeError as exc:
            assert "baseline" in str(exc)
    finally:
        mod.FROZEN_MANIFEST_SHA256 = original


def test_honest_about_incidental_noise_vs_a_deliberate_mechanism():
    report = run()
    assert any("not a deliberate Aegis privacy mechanism" in note
              for note in report["limitations"])


if __name__ == "__main__":
    test_corpus_still_matches_the_frozen_baseline()
    test_all_three_conditions_are_reported()
    test_single_intermediary_is_structurally_identical_to_control()
    test_exit_alone_keeps_full_destination_linkability()
    test_timing_size_correlation_relinks_the_separated_views()
    test_verdict_reports_failure_when_relinking_succeeds()
    test_does_not_claim_generalization_it_has_not_shown()
    test_frozen_manifest_mismatch_raises()
    test_honest_about_incidental_noise_vs_a_deliberate_mechanism()
    print("9 passed")
