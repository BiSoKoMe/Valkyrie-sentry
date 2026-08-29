# Browser Extension Integrity Experiment

## Research question

Can Valkyrie detect unauthorized browser-extension installation from local
provenance and state changes, without using a malicious-extension blocklist and
without retaining browser content?

## Why this matters

MITRE ATT&CK T1176.001 describes browser extensions as a persistence mechanism
that can read browser-entered information, change settings, and communicate in the
background. Its current detection guidance emphasizes extension installation or
configuration changes followed by abnormal process or network activity.

Chromium exposes machine policy through registry locations such as
`ExtensionInstallForcelist` and `ExtensionSettings`. These policies can install an
extension silently and grant permissions without normal user interaction. That
makes a policy change meaningful evidence, but not proof of malware. Enterprise
administration uses the same mechanism.

Primary references:

- [MITRE ATT&CK T1176.001: Browser Extensions](https://attack.mitre.org/techniques/T1176/001/)
- [MITRE ATT&CK T1176: Software Extensions](https://attack.mitre.org/techniques/T1176/)
- [Chrome Enterprise: ExtensionInstallForcelist](https://chromeenterprise.google/policies/extension-install-forcelist/)
- [Microsoft Edge extension policy reference](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-manage-extensions-ref-guide)
- [Microsoft Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [Microsoft Sysmon configuration guidance](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files)

## Implemented architecture

`valkyrie/browser_extension_integrity.py` is a deterministic, metadata-only
classifier. `valkyrie/etw/sysmon.py` invokes it for Sysmon file-create and registry
events. The shipped Sysmon configuration captures narrowly targeted evidence:

1. Writes under Chrome, Edge, Brave, Vivaldi, and Firefox extension stores.
2. Non-browser writes to Chromium `Preferences` and `Secure Preferences` files.
3. Registry changes under recognized browser `ExtensionInstallForcelist` and
   `ExtensionSettings` policy roots.

This audit also found that Valkyrie's BYOVD classifier consumed Sysmon DriverLoad
Event 6 while the shipped Sysmon configuration did not enable that event. The
configuration and coverage contract now enable and require DriverLoad. This fixes
a sensor-delivery defect; it does not create new BYOVD efficacy evidence.

The classifier then grades the writer:

- Browser or updater from an expected install location: observe at `info`.
- Trusted Windows policy machinery from an OS-owned location: observe at `info`.
- Unknown non-browser writer: flag at `medium`.
- Script host, LOLBin, or executable in a user-writable location: flag at `high`.

The result enters the causality graph as a `browser_extension` artifact. It can
therefore contribute to structural baseline learning and later provenance work.
The event is categorized as `asset`, not `persistence`, because Valkyrie's existing
default persistence playbook removes Run keys, services, tasks, and Startup files.
It cannot safely remove a browser extension or enterprise policy artifact.

## Privacy boundary

The detector retains only:

- writer PID, name, and path;
- target file or registry path;
- browser family;
- Chromium extension ID when it is present in the file path;
- change mechanism and attribution confidence.

It explicitly does not retain registry value data, update URLs, extension source,
page content, full URLs, cookies, form values, or keystrokes.

## Current evidence

`tests/test_browser_extension_integrity.py` covers:

- a PowerShell write into a Chrome extension store;
- a normal Chrome self-update;
- a trusted Windows Group Policy write;
- a scripted force-install registry change;
- a non-browser write to Edge `Secure Preferences`;
- exclusion of unrelated VS Code extension paths and unrelated registry keys;
- end-to-end Sysmon emission with registry payload-retention checks;
- XML well-formedness and narrow path coverage in the shipped Sysmon config.

Focused validation on 2026-08-29 passed 56 pytest checks plus all 36 checks in
`tests/test_sysmon_manager.py`.

## What this does not prove

- No extension was installed in a live isolated Windows VM.
- Sysmon configuration acceptance and event delivery are not yet live-verified.
- False-positive volume on managed enterprise browsers is not measured.
- A browser writing its own extension store is not assumed benign. It is retained
  as low-severity evidence because store compromise and malicious updates can use
  the normal browser writer.
- This does not inspect extension code or determine runtime intent.
- Existing Valkyrie-managed Sysmon installations do not yet receive automatic
  configuration migration. Fresh installations receive the new configuration.
- No automatic extension removal or policy rollback is implemented.

## Next hypothesis

A suspicious extension-state change followed by new browser egress should be more
precise than either event alone. The next isolated-VM experiment should measure
whether joining those events by browser family, profile, extension ID, time window,
and process provenance improves true positives without flagging ordinary extension
updates. Until that join is measured, this feature remains detection-only and
structurally validated.
