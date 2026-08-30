"""Browser-extension integrity classification, with no browser or registry I/O."""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.browser_extension_integrity import classify_extension_change
from valkyrie.etw.sysmon import classify_sysmon
from valkyrie.etw.sysmon import SysmonSensor
from valkyrie.sysmon_manager import VALKYRIE_SYSMON_CONFIG


def test_lolbin_write_to_chrome_extension_store_is_high_confidence():
    extension_id = "abcdefghijklmnopabcdefghijklmnop"
    event = classify_extension_change(11, {
        "ProcessId": "41",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "TargetFilename": (
            rf"C:\Users\sam\AppData\Local\Google\Chrome\User Data\Default"
            rf"\Extensions\{extension_id}\1.0.0_0\manifest.json"),
    })
    assert event is not None
    assert event["severity"] == "high"
    assert event["activity"] == "extension_store_write"
    assert event["context"]["extension_id"] == extension_id
    assert "high_risk_writer" in event["labels"]
    assert "T1176.001" in event["technique"]


def test_browser_self_update_is_observed_without_incident_severity():
    event = classify_extension_change(11, {
        "ProcessId": "42",
        "Image": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        "TargetFilename": (
            r"C:\Users\sam\AppData\Local\Google\Chrome\User Data\Default"
            r"\Extensions\abcdefghijklmnopabcdefghijklmnop\1.0\manifest.json"),
    })
    assert event is not None
    assert event["severity"] == "info"
    assert "browser_managed_writer" in event["labels"]


def test_windows_group_policy_writer_is_observed_not_accused():
    event = classify_extension_change(13, {
        "ProcessId": "43",
        "Image": r"C:\Windows\System32\svchost.exe",
        "TargetObject": (
            r"HKLM\Software\Policies\Microsoft\Edge"
            r"\ExtensionInstallForcelist\1"),
        "Details": "do-not-retain-this-extension-id-or-update-url",
    })
    assert event is not None
    assert event["severity"] == "info"
    assert "trusted_policy_writer" in event["labels"]
    assert "Details" not in repr(event)
    assert event["context"]["extension_id"] == ""


def test_scripted_force_install_is_high_and_sysmon_wires_it_through():
    event = classify_sysmon(13, {
        "ProcessId": "44",
        "Image": r"C:\Windows\System32\reg.exe",
        "TargetObject": (
            r"HKLM\Software\Policies\Google\Chrome"
            r"\ExtensionInstallForcelist\1"),
        "Details": "abcdefghijklmnopabcdefghijklmnop;https://attacker.invalid/x.xml",
    })
    assert event is not None
    assert event["category"] == "asset"
    assert event["severity"] == "high"
    assert event["context"]["artifact_kind"] == "browser_extension"


def test_policy_rename_cannot_bypass_the_same_invariant():
    event = classify_sysmon(14, {
        "ProcessId": "47",
        "Image": r"C:\Users\sam\Downloads\policy-helper.exe",
        "TargetObject": (
            r"HKLM\Software\Policies\Microsoft\Edge"
            r"\ExtensionSettings"),
    })
    assert event is not None
    assert event["severity"] == "high"
    assert event["activity"] == "extension_policy_write"


def test_browser_name_outside_expected_install_path_is_not_trusted():
    event = classify_extension_change(11, {
        "ProcessId": "48",
        "Image": r"C:\Users\sam\Downloads\chrome.exe",
        "TargetFilename": (
            r"C:\Users\sam\AppData\Local\Google\Chrome\User Data\Default"
            r"\Extensions\abcdefghijklmnopabcdefghijklmnop\1.0\manifest.json"),
    })
    assert event is not None
    assert event["severity"] == "high"
    assert "browser_managed_writer" not in event["labels"]


def test_sysmon_emission_drops_registry_payload_but_keeps_provenance_metadata():
    classified = classify_sysmon(13, {
        "ProcessId": "46",
        "Image": r"C:\Windows\System32\reg.exe",
        "TargetObject": (
            r"HKLM\Software\Policies\Google\Chrome"
            r"\ExtensionInstallForcelist\1"),
        "Details": "secret-id;https://private.example/update.xml",
    })
    captured = []
    sensor = SysmonSensor()
    sensor.bind(captured.append)
    sensor._emit({"event_id": 13, "user_sid": "S-1-test"}, classified)
    assert len(captured) == 1
    emitted = captured[0].to_dict()
    assert emitted["fields"]["artifact_kind"] == "browser_extension"
    assert emitted["fields"]["browser_family"] == "chrome"
    assert "secret-id" not in repr(emitted)
    assert "private.example" not in repr(emitted)


def test_non_browser_secure_preferences_write_is_detected():
    event = classify_extension_change(11, {
        "ProcessId": "45",
        "Image": r"C:\Program Files\BackupCo\backup.exe",
        "TargetFilename": (
            r"C:\Users\sam\AppData\Local\Microsoft\Edge\User Data\Default"
            r"\Secure Preferences"),
    })
    assert event is not None
    assert event["severity"] == "medium"
    assert event["activity"] == "extension_preferences_write"


def test_unrelated_extension_directories_and_registry_are_ignored():
    assert classify_extension_change(11, {
        "Image": r"C:\Program Files\Microsoft VS Code\Code.exe",
        "TargetFilename": r"C:\Users\sam\.vscode\extensions\vendor.tool\manifest.json",
    }) is None
    assert classify_extension_change(13, {
        "Image": r"C:\Windows\System32\reg.exe",
        "TargetObject": r"HKCU\Software\Example\ExtensionSettings",
    }) is None


def test_shipped_sysmon_config_is_valid_and_collects_only_targeted_state():
    ET.fromstring(VALKYRIE_SYSMON_CONFIG)
    assert "\\ExtensionInstallForcelist" in VALKYRIE_SYSMON_CONFIG
    assert "\\ExtensionSettings" in VALKYRIE_SYSMON_CONFIG
    assert "\\Google\\Chrome\\User Data\\" in VALKYRIE_SYSMON_CONFIG
    assert "\\Microsoft\\Edge\\User Data\\" in VALKYRIE_SYSMON_CONFIG
    assert "\\Mozilla\\Firefox\\Profiles\\" in VALKYRIE_SYSMON_CONFIG
    assert "FileCreate onmatch=\"exclude\"" not in VALKYRIE_SYSMON_CONFIG


if __name__ == "__main__":
    checks = [
        value for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
    for check in checks:
        check()
    print(f"PASS: {len(checks)} browser-extension integrity checks")
