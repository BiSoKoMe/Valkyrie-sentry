# Valkyrie Security Engineering Increment

**Date:** 2026-08-29

**Scope:** Local browser-extension integrity and Sysmon delivery validation

**Status:** Implemented, locally tested, and mechanism-validated on a disposable Windows runner

## Executive summary

This increment did not attempt to add a large pile of malware signatures. It
selected one high-value visibility gap that fits Valkyrie's local provenance
model: unauthorized changes to browser-extension state.

Valkyrie can now observe targeted extension-store and browser-policy changes,
identify the process that made the change, grade that writer by provenance, and
attach the result to the causality graph. The detector is deterministic and runs
without AI, cloud lookup, or a malicious-extension blocklist.

The exact shipped Sysmon configuration was installed on a disposable Windows
GitHub Actions runner. Sysmon accepted the configuration and delivered three
targeted file events plus one targeted registry event. This proves sensor
delivery for the tested mechanisms. It does not prove malicious-extension
detection efficacy or an acceptable false-positive rate.

## Research performed

The implementation was grounded in primary sources:

- [MITRE ATT&CK T1176.001: Browser Extensions](https://attack.mitre.org/techniques/T1176/001/)
  describes extension installation as a persistence and collection mechanism.
- [MITRE ATT&CK T1176: Software Extensions](https://attack.mitre.org/techniques/T1176/)
  provides the broader extension-abuse model.
- [Chrome Enterprise ExtensionInstallForcelist](https://chromeenterprise.google/policies/extension-install-forcelist/)
  documents policy-driven extension installation.
- [Microsoft Edge extension-management reference](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-manage-extensions-ref-guide)
  documents Edge extension policy controls.
- [Microsoft Sysmon event reference](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
  defines the file, registry, driver, and process evidence Valkyrie consumes.
- [Microsoft Sysmon configuration guidance](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files)
  informed the narrowly scoped event configuration.
- [Microsoft ClickFix analysis](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/)
  was reviewed as an example of user-mediated execution where provenance is
  more useful than a single command string.
- [Atomic Red Team Windows matrix](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/Indexes/Matrices/windows-matrix.md)
  was reviewed to map safe future validation coverage.

The repository comparison found that imported Sigma rules already detected
Chromium command lines containing `--load-extension`. The actual missing layer
was state-change provenance: Valkyrie discarded most Sysmon file and registry
events unless they matched Startup-folder or classic autorun paths.

The audit also exposed a separate delivery defect. The existing BYOVD classifier
handled Sysmon DriverLoad Event 6, but Valkyrie's shipped Sysmon configuration did
not enable DriverLoad. That meant the classifier could exist while receiving no
production event. This increment corrected the configuration and its health
contract.

## What was added

### Deterministic extension-integrity classifier

`valkyrie/browser_extension_integrity.py` now recognizes:

- Chrome, Edge, Brave, Vivaldi, Opera, and Firefox extension-store writes;
- non-browser writes to Chromium `Preferences` and `Secure Preferences`;
- recognized `ExtensionInstallForcelist` and `ExtensionSettings` policy changes;
- Sysmon registry rename events, preventing a simple stage-and-rename bypass.

The classifier grades the writer rather than claiming that the changed extension
is malicious:

- expected browser or updater path: informational observation;
- trusted Windows policy writer: informational observation;
- unknown non-browser writer: medium severity;
- script host, LOLBin, or user-writable executable: high severity.

Process name alone is not trusted. For example, `chrome.exe` launched from a
Downloads directory is treated as high risk rather than as a browser self-update.

### Sysmon and provenance integration

`valkyrie/etw/sysmon.py` now passes targeted Event 11 and Events 12, 13, and 14
through the extension-integrity classifier.

`valkyrie/sysmon_manager.py` now:

- enables DriverLoad Event 6 for the existing BYOVD detector;
- captures only targeted browser-extension file paths;
- captures recognized browser extension-policy registry paths;
- filters normal browser preference writes at the sensor when possible;
- includes the new event sources in Sysmon health verification.

`valkyrie/edr/engine.py` treats `browser_extension` as a causal trigger. The
observation can therefore contribute to graph attribution and baseline learning.
It is categorized as an asset change, not persistence, because the current
persistence responder cannot safely remove extensions or enterprise policy.

### Privacy boundary

The new event retains only writer PID, writer name and path, target path, browser
family, safe extension ID when present in a file path, change type, and
attribution confidence.

It does not retain registry value payloads, update URLs, extension source code,
page content, full URLs, browsing history, cookies, form values, or keystrokes.

### Test and CI coverage

`tests/test_browser_extension_integrity.py` covers high-risk scripted writes,
normal browser self-writes, trusted policy writers, fake browser names in
user-writable paths, registry rename handling, privacy retention, false-positive
exclusions, Sysmon emission, and configuration structure.

The dedicated GitHub Actions workflow installs Microsoft-signed Sysmon only on a
disposable Windows runner. It refuses to replace a foreign Sysmon installation,
applies Valkyrie's exact configuration, generates inert extension-state changes,
checks event delivery, removes the test state, uninstalls Sysmon, and uploads a
small JSON evidence artifact.

## Evidence

- 43 focused pytest checks passed.
- 37 Sysmon manager checks passed.
- 19 sensor-tamper checks passed.
- Ruff fatal-error and undefined-name checks passed.
- Git diff whitespace checks passed.
- [GitHub Actions run 33269846059](https://github.com/BiSoKoMe/Valkyrie-sentry/actions/runs/33269846059)
  passed on Windows.
- Live evidence recorded 3 targeted FileCreate events and 1 targeted
  RegistryEvent while the Sysmon service remained running.
- Shipped Sysmon configuration SHA-256:
  `F2E88F620495C0BD9ABC4137B64CA6C8BECC69EFCE21FAE3DD5583E2CD7AFB36`.
- Rebuilt installer SHA-256:
  `3F44DD19E5AE52763023EBF70E675AC5A7A767C151D2AFEFEAFBFC2BC1CCF014`.

The first CI attempt failed safely before Sysmon installation because pytest was
not installed on the clean runner. The workflow was corrected to install pytest,
then rerun successfully. This is useful evidence that the validation environment
was genuinely clean rather than depending on packages installed on the developer
machine.

## What changed compared with prior Valkyrie

Before this increment, Valkyrie could detect some explicit unpacked-extension
command lines through imported Sigma content, but it had no dedicated local
provenance for extension-store or force-install-policy changes. It also had a
DriverLoad classifier whose required Sysmon event was absent from the shipped
configuration.

After this increment, targeted extension-state changes arrive as normalized,
metadata-only telemetry with writer attribution and graph integration. DriverLoad
delivery is also enabled and included in health checks.

## Limitations and refused claims

- The workflow did not install or execute a browser extension.
- The detector does not inspect extension code or infer runtime intent.
- A normal browser writer is not proof of safety. Store compromise and malicious
  updates can use the expected browser process.
- Enterprise policy changes can be legitimate. They are observed and attributed,
  not automatically removed.
- False-positive volume on normal and enterprise-managed browsers is not yet
  measured.
- Existing Valkyrie-managed Sysmon installations are not automatically migrated;
  fresh installations receive the new configuration.
- No automatic extension removal or policy rollback exists.
- The repository's global pytest discovery remains unhealthy because several
  legacy script-style test files call `sys.exit()` during import. Focused suites
  pass, but this test-collection debt should be fixed separately.
- This increment is not proof that Valkyrie matches CrowdStrike, Palo Alto, or
  another commercial EDR. It is one measured improvement in local provenance.

## Next hypothesis

The next experiment should join a suspicious extension-state change with new
browser egress and browser-context metadata inside a bounded time window. The
question is whether the combined causal chain improves precision over either
signal alone without flagging ordinary browser updates. Automatic response should
remain disabled until that experiment measures attribution error, false positives,
latency, and rollback behavior.
