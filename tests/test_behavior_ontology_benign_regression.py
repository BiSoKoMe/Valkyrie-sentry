"""Benign regression cases for the canonical behaviors behavior_ontology.py
newly generalized into BehaviorEngine: security_control_tampering,
credential_access_attempt, discovery_activity, lateral_movement,
code_injection, obfuscated_execution, lolbin_proxy_execution,
destructive_impact, collection_staging.

Widening BehaviorEngine's vocabulary from 3 categories to 12 raises the
obvious risk this suite exists to check: did any of the 9 new categories
make Valkyrie convict on a single common, often-legitimate signal? Every
case here is one isolated event carrying exactly one new-category label, the
same shape a real single-instance benign action (an IT script, a signed
installer, an admin's one-off command) would produce.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.edr.detection_v2 import DetectionArchitectureV2
from valkyrie.telemetry import TelemetryEvent

_NEW_CATEGORIES_AND_REALISTIC_BENIGN_LABELS = {
    # canonical behavior -> a real raw label that maps to it, chosen from a
    # realistic ONE-OFF benign shape rather than an attack chain.
    "security_control_tampering": "defender_tamper",     # IT admin adjusting an AV exclusion
    "credential_access_attempt": "cred_store_list",       # admin tool listing cred stores
    "discovery_activity": "user_discovery",               # a lone `whoami`
    "lateral_movement": "lateral_wmic",                   # remote admin via WMI
    "code_injection": "dll_injection",                    # a legitimate injector (some AV/AV-adjacent tools do this)
    "obfuscated_execution": "encoded_powershell",          # a deployment script's encoded payload
    "lolbin_proxy_execution": "rundll32_proxy",           # a signed installer's COM registration
    "destructive_impact": "secure_wipe",                  # IT policy secure-erase of a retired disk
    "collection_staging": "collection_archive",           # a backup tool archiving files
}


def _single_event(labels):
    return TelemetryEvent(
        category="process", activity="exec", ts=1.0, actor_pid=100,
        actor_name="tool.exe", source="process_collector", labels=list(labels),
        fields={"create_time": 1.0, "event_id": "e-1"},
    )


def test_one_new_category_fact_alone_never_alerts():
    for canonical, label in _NEW_CATEGORIES_AND_REALISTIC_BENIGN_LABELS.items():
        arch = DetectionArchitectureV2()
        result = arch.observe(_single_event([label]))
        assert not result.hypothesis.alerts, (
            f"a single {canonical} fact ({label}) alone must not alert -- "
            f"detection_v2._HYPOTHESES requires >=2 supporting facts")
        assert result.recommended_action == "observe"


def test_trusted_maintenance_context_contradicts_a_new_category_even_with_two_facts():
    # Realistic shape: an IT admin's signed maintenance tool triggers TWO new
    # canonical facts (e.g. lists credential stores AND touches a security
    # control) in one action, which would otherwise clear minimum_support=2.
    # A trust signal alongside it must still keep this from alerting.
    arch = DetectionArchitectureV2()
    event = _single_event(["cred_store_list", "defender_tamper", "expected_maintenance"])
    result = arch.observe(event)
    assert not result.hypothesis.alerts, (
        "trusted maintenance context must contradict a two-fact new-category "
        "combination, not merely a single fact")


def test_two_new_categories_together_do_clear_the_bar_when_genuinely_untrusted():
    # The honest complement to the two tests above: TWO new-category facts,
    # with NO trust signal, is exactly the "independently weak signals
    # combine" shape detection_v2 exists to recognize -- confirms the
    # widened vocabulary still lets real corroborating evidence alert.
    arch = DetectionArchitectureV2()
    event = _single_event(["lsass_access", "defender_tamper"])
    result = arch.observe(event)
    assert result.hypothesis.alerts


if __name__ == "__main__":
    test_one_new_category_fact_alone_never_alerts()
    test_trusted_maintenance_context_contradicts_a_new_category_even_with_two_facts()
    test_two_new_categories_together_do_clear_the_bar_when_genuinely_untrusted()
    print("3 passed")
