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
    assert set(gaps) == {"gap-no-referer-context"}
    # No first-party context: Nyx stays silent by design -- not observed.
    assert not gaps["gap-no-referer-context"]["observed"]


def test_cross_site_authorized_flows_are_left_alone():
    # Regression (2026-09-24 disclosure gate): each of these carries an
    # id-shaped value to a DIFFERENT site, and each was rewritten by NYX_ACT
    # before -- breaking the sign-in, the emailed link, or the app's own
    # signed-in write. Authorized means untouched AND unreported.
    report = score(build_scenarios())
    by_id = {r["scenario_id"]: r for r in report["results"]}
    for sid in ("auth-oidc-token-exchange", "auth-oidc-authorize", "auth-oauth-callback",
                "auth-emailed-link", "auth-signed-in-backend"):
        assert by_id[sid]["request_unchanged"], sid
        assert by_id[sid]["observed_categories"] == (), sid


def test_fetch_metadata_closes_the_no_referer_gap_for_current_browsers():
    report = score(build_scenarios())
    result = next(r for r in report["results"]
                  if r["scenario_id"] == "unauth-no-referer-fetch-metadata")
    assert result["observed_categories"] == ("identifier",)
    assert result["faked_categories"] == ("identifier",)
    assert not result["raw_value_leaked"]


def test_uuid_in_an_asset_path_is_not_an_identifier():
    report = score(build_scenarios())
    result = next(r for r in report["results"] if r["scenario_id"] == "benign-uuid-asset-path")
    assert result["observed_categories"] == ()
    assert result["request_unchanged"]


def test_header_carried_identifier_is_now_deceived():
    # Regression: fake_outbound_headers() closes the gap this scorecard first
    # surfaced -- an identifier sent via a request header (a real tracker-SDK
    # pattern) used to be observed but never faked.
    report = score(build_scenarios())
    result = next(r for r in report["results"]
                 if r["scenario_id"] == "unauth-header-device-id")
    assert result["observed_categories"] == ("identifier",)
    assert result["faked_categories"] == ("identifier",)
    assert not result["raw_value_leaked"]


if __name__ == "__main__":
    test_scenario_corpus_covers_all_three_expectation_classes()
    test_authorized_and_benign_flows_are_never_touched()
    test_unauthorized_fakeable_disclosures_are_deceived()
    test_tracking_cookie_never_enters_the_act_path()
    test_no_raw_sentinel_value_survives_into_the_report()
    test_scorecard_is_honest_about_its_own_evidence_class()
    test_known_gaps_are_named_not_hidden_in_the_pass_rate()
    test_cross_site_authorized_flows_are_left_alone()
    test_fetch_metadata_closes_the_no_referer_gap_for_current_browsers()
    test_uuid_in_an_asset_path_is_not_an_identifier()
    test_header_carried_identifier_is_now_deceived()
    print("11 passed")
