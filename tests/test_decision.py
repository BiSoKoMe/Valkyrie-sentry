#!/usr/bin/env python3
"""Decision-policy tests (valkyrie/decision.py).

Every automated action must be explainable AND correct, so the policy is pinned
by scenario. These are the "every playbook has a simulated scenario" cases from
the validation-pipeline plan: each maps a realistic signal -> the action the
high-risk-user threat model requires, across profiles.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.decision import (
    Signal, Profile, Action, ThreatClass, Confidence, decide, classify_threat,
)

_fail = 0


def _check(label, got, want):
    global _fail
    ok = got == want
    if not ok:
        _fail += 1
    print(f"  [{'ok  ' if ok else 'FAIL'}] {label}: {getattr(got,'value',got)}"
          + ("" if ok else f"  (wanted {getattr(want,'value',want)})"))


def test_decoy_always_contains():
    print("[1] decoy access = instant CONTAIN, any profile")
    for prof in Profile:
        d = decide(Signal(category="process", severity="high",
                          labels=("decoy", "honeytoken"),
                          process_name="unknown.exe"), prof)
        _check(f"decoy/{prof.value}", d.action, Action.CONTAIN)
        _check(f"decoy/{prof.value} class", d.threat_class, ThreatClass.DECOY_TRIGGER)
        assert d.user_message and d.recommended_step   # must alert with guidance


def test_high_confidence_compromise_contains():
    print("[2] critical LSASS dump = CONTAIN")
    d = decide(Signal(category="process", severity="critical",
                      labels=("lolbin", "lsass_access", "credential_access"),
                      technique="T1003.001 — LSASS Memory",
                      process_name="rundll32.exe"))
    _check("lsass", d.action, Action.CONTAIN)
    _check("lsass conf", d.confidence, Confidence.HIGH)


def test_named_sequence_is_high():
    print("[3] completed attack_sequence = HIGH → CONTAIN")
    d = decide(Signal(category="attack_sequence", severity="high",
                      technique="T1105", process_name="powershell.exe"))
    _check("sequence conf", d.confidence, Confidence.HIGH)
    _check("sequence action", d.action, Action.CONTAIN)


def test_medium_compromise_blocks():
    print("[4] medium LOLBin = BLOCK (not kill the box)")
    d = decide(Signal(category="process", severity="medium", labels=("lolbin",),
                      process_name="cmd.exe"))
    _check("medium compromise", d.action, Action.BLOCK)


def test_telemetry_deceives_in_standard_blocks_in_highrisk():
    print("[5] telemetry: DECEIVE in Standard, BLOCK in High-Risk")
    sig = Signal(category="network", severity="low", labels=("telemetry", "analytics"),
                 process_name="app.exe", entity="metrics.vendor.com")
    _check("standard", decide(sig, Profile.STANDARD).action, Action.DECEIVE)
    _check("high_risk", decide(sig, Profile.HIGH_RISK).action, Action.BLOCK)
    _check("clean_room", decide(sig, Profile.CLEAN_ROOM).action, Action.BLOCK)


def test_sensitive_upload_blocks_and_alerts():
    print("[6] cloud backup of a sensitive working dir = BLOCK + alert")
    d = decide(Signal(category="network", severity="medium",
                      labels=("cloud_backup",), process_name="Dropbox.exe",
                      entity="dropbox.com", sensitive_path=True))
    _check("sensitive upload", d.action, Action.BLOCK)
    assert "confidential" in d.user_message.lower()


def test_surveillance_grades_by_confidence():
    print("[7] surveillance: high=CONTAIN, medium=BLOCK, low=ALERT")
    hi = decide(Signal(category="firewall_ip", severity="critical",
                       labels=("c2", "threat_intel_ip"), entity="45.9.148.1"))
    _check("surv high", hi.action, Action.CONTAIN)
    med = decide(Signal(category="intelligence", severity="medium",
                        labels=("beacon",), entity="rare.example"))
    _check("surv medium", med.action, Action.BLOCK)
    low = decide(Signal(category="anomaly", severity="low", entity="x.example"))
    _check("surv low", low.action, Action.ALERT)


def test_clean_room_escalates_medium():
    print("[8] Clean Room steps medium compromise BLOCK → CONTAIN")
    sig = Signal(category="process", severity="medium", labels=("lolbin",),
                 process_name="cmd.exe")
    _check("standard", decide(sig, Profile.STANDARD).action, Action.BLOCK)
    _check("clean_room", decide(sig, Profile.CLEAN_ROOM).action, Action.CONTAIN)


def test_never_downgrades_high_compromise():
    print("[9] no profile ever downgrades a high-confidence containment")
    sig = Signal(category="process", severity="critical", labels=("lsass_access",),
                 process_name="rundll32.exe")
    for prof in Profile:
        _check(f"{prof.value}", decide(sig, prof).action, Action.CONTAIN)


def test_low_noise_allows_in_standard():
    print("[10] low-confidence unclassified = ALLOW in Standard (no FP storm)")
    d = decide(Signal(category="other", severity="low", process_name="thing.exe"))
    _check("low other", d.action, Action.ALLOW)


def main() -> int:
    print("=" * 60)
    print("Decision-policy scenario tests")
    print("=" * 60)
    for fn in (test_decoy_always_contains, test_high_confidence_compromise_contains,
               test_named_sequence_is_high, test_medium_compromise_blocks,
               test_telemetry_deceives_in_standard_blocks_in_highrisk,
               test_sensitive_upload_blocks_and_alerts,
               test_surveillance_grades_by_confidence,
               test_clean_room_escalates_medium,
               test_never_downgrades_high_compromise,
               test_low_noise_allows_in_standard):
        fn()
    print("-" * 60)
    if _fail:
        print(f"{_fail} check(s) FAILED.")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
