"""Aegis 1A -- deterministic size bucketing, tested against a naive AND a
retrained observer, in both a size-only and a full-feature profile. The
real finding here is negative for pure size bucketing (see
docs/AEGIS_1A_SIZE_BUCKETING.md) -- these tests pin the methodology's
honesty (frozen corpus, both observer profiles, the sequence-fingerprint
check), not a policy "winning."
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam.evaluation.aegis_1a_bucketing import FROZEN_MANIFEST_SHA256, POLICIES, run
from redteam.evaluation.aegis_baseline import build_corpus, manifest_hash


def test_corpus_still_matches_the_frozen_aegis_0_baseline():
    assert manifest_hash(build_corpus()) == FROZEN_MANIFEST_SHA256


def test_policies_were_defined_before_evaluation_four_of_them():
    names = {p.name for p in POLICIES}
    assert names == {"BUCKET-A", "BUCKET-B", "BUCKET-C", "BUCKET-D"}
    for policy in POLICIES:
        assert policy.boundaries == tuple(sorted(policy.boundaries))
        assert policy.boundaries[-1] >= 4_500_000  # covers the corpus's real max size


def test_every_policy_reports_both_observer_profiles():
    report = run()
    for name, result in report["results"].items():
        for key in ("naive_observer_accuracy", "retrained_observer_accuracy"):
            profiles = result[key]
            if name == "CONTROL":
                assert set(profiles) == {"size_only_observer", "full_feature_observer"}
            else:
                assert set(profiles) == {"size_only_observer", "full_feature_observer"}


def test_bucketing_never_shrinks_a_connection():
    # A bucket ceiling must never reveal a smaller value than the truth --
    # only equal or larger, or "hiding" the size would leak a lower bound.
    for policy in POLICIES:
        for size in (1, 300, 999, 1000, 1001, 50_000, 4_999_999, 6_000_000):
            assert policy.bucket(size) >= size


def test_retrained_observer_recovers_meaningfully_on_A_and_B():
    # The actual (negative-for-Aegis) finding: BUCKET-A and BUCKET-B's naive
    # accuracy drop is largely an illusion -- a retrained size-only observer
    # recovers most of it, and the full-feature observer barely notices at
    # all because destination/timing were never touched. Pinned as a
    # regression so this honest result can't quietly flip without review.
    report = run()
    for name in ("BUCKET-A", "BUCKET-B"):
        r = report["results"][name]
        assert r["retrained_observer_accuracy"]["size_only_observer"] > \
            r["naive_observer_accuracy"]["size_only_observer"]
        # A full-feature observer, which also has untouched destination and
        # timing, does not end up materially worse than CONTROL.
        control_full = report["results"]["CONTROL"]["naive_observer_accuracy"]["full_feature_observer"]
        assert r["retrained_observer_accuracy"]["full_feature_observer"] >= control_full - 0.10


def test_sequence_only_signal_can_exceed_raw_size_accuracy():
    # The user's specific concern, confirmed rather than assumed: with fine
    # enough buckets (BUCKET-B, BUCKET-C), the sequence of tiers alone is AT
    # LEAST as informative as the original size-only measurement -- hiding
    # exact bytes accomplished little because the discretized shape is
    # itself a fingerprint.
    report = run()
    control_size_only = report["results"]["CONTROL"]["naive_observer_accuracy"]["size_only_observer"]
    for name in ("BUCKET-B", "BUCKET-C"):
        assert report["results"][name]["sequence_only_accuracy"] >= control_size_only - 0.05


def test_bucket_d_costs_are_severe_and_documented_as_a_cautionary_case():
    report = run()
    d = report["results"]["BUCKET-D"]
    assert d["bandwidth_overhead_pct"] > 1000
    assert d["compatibility_concern"]["connections_flagged"] > 0


def test_frozen_manifest_mismatch_raises():
    import redteam.evaluation.aegis_1a_bucketing as mod
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


def test_honest_about_its_own_evidence_class_and_model_assumptions():
    report = run()
    assert report["evidence_class"] == "synthetic mechanism evaluation"
    assert not report["independent"]
    assert any("stated model" in note or "not a real measurement" in note
              for note in report["limitations"])
    assert any("heuristic proxy" in note for note in report["limitations"])


if __name__ == "__main__":
    test_corpus_still_matches_the_frozen_aegis_0_baseline()
    test_policies_were_defined_before_evaluation_four_of_them()
    test_every_policy_reports_both_observer_profiles()
    test_bucketing_never_shrinks_a_connection()
    test_retrained_observer_recovers_meaningfully_on_A_and_B()
    test_sequence_only_signal_can_exceed_raw_size_accuracy()
    test_bucket_d_costs_are_severe_and_documented_as_a_cautionary_case()
    test_frozen_manifest_mismatch_raises()
    test_honest_about_its_own_evidence_class_and_model_assumptions()
    print("9 passed")
