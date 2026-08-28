from tools.provenance_demo import run_demo


def test_demo_exercises_guarded_consequence_and_retention_boundary():
    result = run_demo()

    assert result["mode"] == "synthetic, in-memory, local-only"
    assert result["causal_chain"] == ["chrome.exe", "helper.exe", "DNS rare.example"]
    assert result["observed"]["provenance_complete"]
    assert not result["observed"]["raw_content_retained"]
    assert result["decision"]["incident_category"] == "privacy_consequence"
    assert result["decision"]["standard_profile_action"] == "deceive"
    assert result["refusal"]["result"] == "privacy_boundary_violation"
    assert "decision" in result["evidence"]["timeline_kinds"]
