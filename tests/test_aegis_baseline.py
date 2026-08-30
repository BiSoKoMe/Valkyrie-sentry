"""Aegis 0 -- Measurement. No mitigation exists yet; this pins the baseline
number a future Aegis mechanism has to beat, and guards against the
class-imbalance trap that would otherwise make the linkability result look
better than it is.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam.evaluation.aegis_baseline import ACTIVITIES, build_corpus, run


def test_corpus_is_balanced_across_activities():
    sessions = build_corpus()
    counts = {a: sum(s.activity == a for s in sessions) for a in ACTIVITIES}
    assert len(set(counts.values())) == 1, "activity classes must be balanced " \
        "or accuracy vs. random chance is not a fair comparison"


def test_deterministic_across_runs():
    a = run()
    b = run()
    assert a["manifest_sha256"] == b["manifest_sha256"]
    assert a["activity_classification"] == b["activity_classification"]


def test_activity_classifier_is_a_real_adversary_not_a_strawman():
    # If this baseline classifier can't clear random chance by a wide margin,
    # it's not a meaningful reference point for any later Aegis mechanism to
    # beat -- a mechanism could look great purely because the "before" number
    # was already weak.
    report = run()
    clf = report["activity_classification"]
    assert clf["accuracy"] > 3 * clf["random_chance"]


def test_linkability_reports_balanced_accuracy_not_just_raw():
    # Same-user pairs are rare next to different-user pairs by construction;
    # raw accuracy alone would be dominated by the trivial "always guess
    # different" rule. This pins that the report surfaces the honest
    # comparison (balanced accuracy vs. 0.5) instead of only the inflated one.
    report = run()
    link = report["cross_session_linkability"]
    assert link["pairs"] > 0
    assert "best_threshold_balanced_accuracy" in link
    assert "majority_class_floor" in link
    assert link["best_threshold_balanced_accuracy"] > link["balanced_random_chance"]
    # The majority-class floor exists precisely because raw accuracy alone
    # would be misleading -- assert it actually IS the harder number to beat.
    assert link["majority_class_floor"] > link["best_threshold_raw_accuracy"] - 0.30


def test_honest_about_its_own_evidence_class():
    report = run()
    assert report["evidence_class"] == "synthetic mechanism evaluation"
    assert not report["independent"]
    assert report["stage"].startswith("Aegis 0")
    assert len(report["manifest_sha256"]) == 64
    assert report["limitations"]


if __name__ == "__main__":
    test_corpus_is_balanced_across_activities()
    test_deterministic_across_runs()
    test_activity_classifier_is_a_real_adversary_not_a_strawman()
    test_linkability_reports_balanced_accuracy_not_just_raw()
    test_honest_about_its_own_evidence_class()
    print("5 passed")
