"""Nyx enforcement scorecard: authorized/unauthorized/benign in one pass.

Individual leak categories are already unit-tested in test_nyx.py. This
harness asks the question the "next plan" essay calls Nyx's hardest problem:
does catching the unauthorized case ever break the authorized or benign
ones, across realistic workflow shapes -- login, checkout, upload,
messaging, sync, background telemetry, a cross-site embed -- in one
aggregate pass rather than one call at a time.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam.evaluation.nyx_scorecard import build_scenarios, score


def test_scenario_corpus_covers_all_three_expectation_classes():
    scenarios = build_scenarios()
    assert len(scenarios) >= 24
    assert len({s.scenario_id for s in scenarios}) == len(scenarios)
    kinds = {s.expect for s in scenarios}
    assert kinds == {"authorized", "unauthorized", "benign"}


def test_authorized_and_benign_flows_are_never_touched():
    report = score(build_scenarios())
    assert report["authorized_flow_unbroken_rate"] == 1.0
    assert report["benign_flow_unbroken_rate"] == 1.0


def test_unauthorized_fakeable_disclosures_are_deceived():
    report = score(build_scenarios())
    # Not every unauthorized scenario is fakeable (the tracking cookie is
    # deliberately observe-only), so this is a floor, not 100%.
    assert report["unauthorized_disclosure_deceived_rate"] >= 0.7


def test_tracking_cookie_never_enters_the_act_path():
    report = score(build_scenarios())
    assert report["cookie_never_entered_act_path"]


def test_no_raw_sentinel_value_survives_into_the_report():
    report = score(build_scenarios())
    assert not report["raw_value_retained_anywhere"]


def test_scorecard_is_honest_about_its_own_evidence_class():
    report = score(build_scenarios())
    assert report["evidence_class"] == "synthetic mechanism evaluation"
    assert not report["independent"]
    assert len(report["manifest_sha256"]) == 64
    assert report["limitations"]


def test_known_gaps_are_named_not_hidden_in_the_pass_rate():
    report = score(build_scenarios())
    gaps = {gap["scenario_id"]: gap for gap in report["structural_gaps"]}
    assert set(gaps) == {"gap-no-referer-context", "gap-header-only-identifier"}
    # No first-party context: Nyx stays silent by design -- not observed.
    assert not gaps["gap-no-referer-context"]["observed"]
    # Header-only identifier: Nyx observes it but cannot rewrite a header.
    assert gaps["gap-header-only-identifier"]["observed"]
    assert not gaps["gap-header-only-identifier"]["deceived"]


if __name__ == "__main__":
    test_scenario_corpus_covers_all_three_expectation_classes()
    test_authorized_and_benign_flows_are_never_touched()
    test_unauthorized_fakeable_disclosures_are_deceived()
    test_tracking_cookie_never_enters_the_act_path()
    test_no_raw_sentinel_value_survives_into_the_report()
    test_scorecard_is_honest_about_its_own_evidence_class()
    test_known_gaps_are_named_not_hidden_in_the_pass_rate()
    print("7 passed")
