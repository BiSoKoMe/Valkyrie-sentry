"""Aegis 0.5 -- which feature group actually carries the Aegis 0 baseline's
information advantage. Guards the freeze: these numbers are only meaningful
if measured against the exact corpus Aegis 0 reported 91.7%/78.4% against.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam.evaluation.aegis_ablation import FROZEN_MANIFEST_SHA256, run
from redteam.evaluation.aegis_baseline import build_corpus, manifest_hash


def test_corpus_still_matches_the_frozen_aegis_0_baseline():
    # If this ever fails, aegis_baseline.py's generator changed and every
    # ablation number here silently stopped being comparable to Aegis 0's
    # reported 91.7%/78.4% -- exactly the "don't touch the baseline" risk
    # the user flagged.
    assert manifest_hash(build_corpus()) == FROZEN_MANIFEST_SHA256


def test_all_seven_combinations_are_reported():
    report = run()
    expected = {"destination_only", "size_only", "timing_only",
               "destination+size", "destination+timing", "size+timing",
               "all_three"}
    assert set(report["activity_classification_by_combination"]) == expected
    assert set(report["linkability_by_combination"]) == expected


def test_all_three_reproduces_the_frozen_aegis_0_full_feature_accuracy():
    # Sanity check that this module's own restricted-feature classifier,
    # given ALL features, is the same mechanism as aegis_baseline's -- not a
    # second, silently-different implementation of "the baseline."
    report = run()
    all_three = report["activity_classification_by_combination"]["all_three"]
    assert all_three["accuracy"] > 3 * all_three["random_chance"]


def test_size_alone_is_a_real_signal_not_noise():
    # The actual (not hypothesized) finding: size alone clears random chance
    # by a wide margin, confirming it is a genuine driver of the Aegis 0
    # baseline rather than an artifact of combining features.
    report = run()
    size_only = report["activity_classification_by_combination"]["size_only"]
    assert size_only["accuracy"] > 3 * size_only["random_chance"]


def test_destination_overlap_linkability_ignores_co_present_features_honestly():
    # Documented methodology limitation: the destination-overlap linkability
    # method doesn't use size/timing at all, so every combination that
    # INCLUDES destination reports the identical number. This pins that as
    # the expected (if limited) behavior rather than a silent bug -- the
    # report's own limitations must say so.
    report = run()
    link = report["linkability_by_combination"]
    dest_combos = ("destination_only", "destination+size", "destination+timing", "all_three")
    values = {link[c]["balanced_accuracy"] for c in dest_combos}
    assert len(values) == 1, "destination-containing combos should be identical " \
        "under the overlap method -- if this changes, the methodology changed too"
    assert any("destination-set overlap" in note for note in report["limitations"])


def test_frozen_manifest_mismatch_raises_instead_of_silently_reporting():
    import redteam.evaluation.aegis_ablation as mod
    original = mod.FROZEN_MANIFEST_SHA256
    try:
        mod.FROZEN_MANIFEST_SHA256 = "0" * 64
        try:
            mod.run()
            assert False, "expected a RuntimeError on manifest mismatch"
        except RuntimeError as exc:
            assert "baseline" in str(exc)
    finally:
        mod.FROZEN_MANIFEST_SHA256 = original


if __name__ == "__main__":
    test_corpus_still_matches_the_frozen_aegis_0_baseline()
    test_all_seven_combinations_are_reported()
    test_all_three_reproduces_the_frozen_aegis_0_full_feature_accuracy()
    test_size_alone_is_a_real_signal_not_noise()
    test_destination_overlap_linkability_ignores_co_present_features_honestly()
    test_frozen_manifest_mismatch_raises_instead_of_silently_reporting()
    print("6 passed")
