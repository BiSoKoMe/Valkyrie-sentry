"""Deterministic browser-extension integrity classification.

This module does not decide whether an extension is "good" or "bad" from a
store reputation list. It answers a narrower, locally provable question:
which process changed extension state, through which mechanism, and was that
writer consistent with normal browser or Windows policy management?

Only metadata is returned. Registry value contents, extension source code,
page content, cookies, and browsing history are never retained here.
"""

from __future__ import annotations

import re
from typing import Optional

from .telemetry import CAT_ASSET, SEV_HIGH, SEV_INFO, SEV_MEDIUM
from .trust import is_trusted_os_path


_CHROMIUM_STORES = (
    ("chrome", "\\google\\chrome\\user data\\"),
    ("edge", "\\microsoft\\edge\\user data\\"),
    ("brave", "\\bravesoftware\\brave-browser\\user data\\"),
    ("vivaldi", "\\vivaldi\\user data\\"),
    ("opera", "\\opera software\\"),
)
_FIREFOX_PROFILE = "\\mozilla\\firefox\\profiles\\"

_POLICY_ROOTS = (
    ("chrome", "\\software\\policies\\google\\chrome\\"),
    ("edge", "\\software\\policies\\microsoft\\edge\\"),
    ("brave", "\\software\\policies\\bravesoftware\\brave\\"),
    ("vivaldi", "\\software\\policies\\vivaldi\\"),
)
_POLICY_NAMES = ("\\extensioninstallforcelist", "\\extensionsettings")

_BROWSER_NAMES = frozenset({
    "chrome.exe", "msedge.exe", "brave.exe", "vivaldi.exe", "opera.exe",
    "firefox.exe",
})
_UPDATER_NAMES = frozenset({
    "googleupdate.exe", "googleupdaterservice.exe", "microsoftedgeupdate.exe",
    "braveupdate.exe", "vivaldiupdate.exe", "maintenanceservice.exe",
})
_POLICY_WRITERS = frozenset({
    "gpupdate.exe", "gpscript.exe", "svchost.exe", "omadmclient.exe",
    "deviceenroller.exe", "services.exe",
})
_SCRIPT_OR_LOLBIN_WRITERS = frozenset({
    "powershell.exe", "pwsh.exe", "cmd.exe", "reg.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "msbuild.exe", "installutil.exe",
})
_USER_WRITABLE = (
    "\\appdata\\", "\\temp\\", "\\downloads\\", "\\users\\public\\",
    "\\$recycle.bin\\", "\\perflogs\\",
)
_EXPECTED_BROWSER_PATHS = (
    "\\google\\chrome\\application\\",
    "\\microsoft\\edge\\application\\",
    "\\bravesoftware\\brave-browser\\application\\",
    "\\vivaldi\\application\\",
    "\\opera\\",
    "\\mozilla firefox\\",
    "\\google\\update\\",
    "\\microsoft\\edgeupdate\\",
    "\\braveupdate\\",
)

_CHROMIUM_ID_RE = re.compile(r"\\extensions\\([a-p]{32})(?:\\|$)", re.I)


def _norm(value: str) -> str:
    return (value or "").strip().strip('"').lower().replace("/", "\\")


def _name(path: str) -> str:
    return _norm(path).rsplit("\\", 1)[-1]


def _file_target(path: str) -> Optional[tuple[str, str, str]]:
    """Return (browser, change_kind, extension_id) for a relevant file."""
    low = _norm(path)
    browser = ""
    for candidate, marker in _CHROMIUM_STORES:
        if marker in low:
            browser = candidate
            break

    if browser:
        if "\\extensions\\" in low:
            match = _CHROMIUM_ID_RE.search(low)
            return browser, "extension_store_write", match.group(1) if match else ""
        leaf = low.rsplit("\\", 1)[-1]
        if leaf in ("preferences", "secure preferences"):
            return browser, "extension_preferences_write", ""

    if _FIREFOX_PROFILE in low:
        if "\\extensions\\" in low or low.endswith("\\extensions.json"):
            return "firefox", "extension_store_write", ""
    return None


def _registry_target(path: str) -> Optional[tuple[str, str, str]]:
    """Return (browser, change_kind, extension_id) for extension policy state."""
    low = _norm(path)
    if not any(name in low for name in _POLICY_NAMES):
        return None
    for browser, root in _POLICY_ROOTS:
        if root in low:
            # The terminal registry value name is an ordinal, not an extension
            # ID. The ID lives in Details, which we deliberately do not retain.
            return browser, "extension_policy_write", ""
    return None


def _browser_managed_writer(name: str, path: str) -> bool:
    n, p = _name(name), _norm(path)
    return (n in _BROWSER_NAMES | _UPDATER_NAMES
            and any(marker in p for marker in _EXPECTED_BROWSER_PATHS))


def _trusted_policy_writer(name: str, path: str) -> bool:
    return _name(name) in _POLICY_WRITERS and is_trusted_os_path(path)


def _high_risk_writer(name: str, path: str) -> bool:
    n, p = _name(name), _norm(path)
    return n in _SCRIPT_OR_LOLBIN_WRITERS or any(marker in p for marker in _USER_WRITABLE)


def classify_extension_change(event_id: int, data: dict) -> Optional[dict]:
    """Classify a Sysmon file/registry event that changes extension state.

    Returns TelemetryEvent-compatible keyword arguments, or ``None`` when the
    target is unrelated. This is intentionally pure so it can be tested without
    touching a real browser profile or registry hive.
    """
    eid = int(event_id)
    if eid == 11:
        target_path = str(data.get("TargetFilename", "") or "")
        target = _file_target(target_path)
        target_key = "path"
    elif eid in (12, 13, 14):
        target_path = str(data.get("TargetObject", "") or "")
        target = _registry_target(target_path)
        target_key = "location"
    else:
        return None

    if target is None:
        return None

    browser, change_kind, extension_id = target
    writer_path = str(data.get("Image", "") or "")
    writer_name = _name(writer_path)
    labels = ["browser_extension_change", "asset_change"]

    if change_kind == "extension_policy_write" and _trusted_policy_writer(
            writer_name, writer_path):
        severity = SEV_INFO
        labels.append("trusted_policy_writer")
        reason = f"Windows policy machinery changed {browser} extension policy"
    elif change_kind != "extension_policy_write" and _browser_managed_writer(
            writer_name, writer_path):
        severity = SEV_INFO
        labels.append("browser_managed_writer")
        reason = f"{browser} changed its own extension state"
    elif _high_risk_writer(writer_name, writer_path):
        severity = SEV_HIGH
        labels.extend(("unexpected_extension_writer", "high_risk_writer"))
        reason = (f"script, LOLBin, or user-writable process changed {browser} "
                  "extension state")
    else:
        severity = SEV_MEDIUM
        labels.append("unexpected_extension_writer")
        reason = f"non-browser process changed {browser} extension state"

    return {
        "category": CAT_ASSET,
        "activity": change_kind,
        "actor_pid": int(data.get("ProcessId", 0) or 0),
        "actor_name": writer_name,
        "actor_path": writer_path,
        "target": {target_key: target_path},
        "severity": severity,
        "labels": labels,
        "reason": reason,
        "technique": "T1176.001 - Browser Extensions",
        "context": {
            "artifact_kind": "browser_extension",
            "browser_family": browser,
            "extension_id": extension_id,
            "change_kind": change_kind,
            "attribution_confidence": "sysmon_process",
        },
    }
