# Valkyrie EDR Evaluation Report

**Tier:** A_replay  
**Generated:** 20260730T203810Z UTC  
**Git commit:** bce9f93  
**Catalog version:** 2026-07-30.2  
**Reproduce:** `PYTHONUTF8=1 python redteam/evaluation/replay_harness.py` (Tier A) or `redteam/evaluation/run_live_evaluation.ps1` (Tier B, VM only)

> **This is Tier A: classifier-input replay.** Real Valkyrie code was executed against synthetic inputs matching what each technique would produce. NO live attack ran. `attack_executed`, measured latency, and aggregate false-positive rate are honestly `null` throughout -- Tier A cannot produce them, and this report does not pretend otherwise. Scores here are gated by a source-verified judgment of whether each technique's detection path is reliably reachable live (see catalog.py), not by whether the Python call merely returned truthy. Tier B (`run_live_evaluation.ps1`, VM required) is what turns this into a live-attack answer.

## Scoring rules applied

- A miss is a miss. `CONDITIONAL` predictions are **not** credited as detected in the headline number -- only a confirmed, reliably-delivered `DETECT` counts.
- A detection whose category is a **user-defined DNS block** (`detection_category == 'user_rule'`) is excluded from the detected count and reported separately, per the evaluation brief.
  - None triggered this run.
- A rule firing under the **wrong technique label** (`known_mismatch`) is never credited, even if the underlying code executed without error.

## Overall

**25 / 40 techniques detected (62.5%)**

| Tactic | Detected | Total | % |
|---|---:|---:|---:|
| Execution | 5 | 7 | 71% |
| Persistence | 6 | 6 | 100% |
| Defense Evasion | 4 | 6 | 67% |
| Credential Access | 1 | 4 | 25% |
| Discovery | 1 | 6 | 17% |
| Lateral Movement | 1 | 3 | 33% |
| Command and Control | 5 | 5 | 100% |
| Impact | 2 | 3 | 67% |

**Explicitly out of scope:** 4 techniques, each with a stated reason (never silently dropped) -- see catalog.py `OUT_OF_SCOPE`.

## Per-test results

| Technique | Test | Tactic | Logic fires | Detected | Severity | Confidence | Delivery |
|---|---|---|:---:|:---:|---|---:|---|
| T1059.001 Command and Scripting Interpreter: Power | T1059.001 Test #2 (EncodedCommand) | Execution | yes | missed | medium | 0.55 | process_poll_2s_racy |
| T1059.003 Command and Scripting Interpreter: Windo | T1059.003 Test #1 (cmd spawned by Office) | Execution | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1218.005 System Binary Proxy Execution: Mshta | T1218.005 Test #1 (remote HTA) | Execution | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1218.010 System Binary Proxy Execution: Regsvr32  | T1218.010 Test #1 | Execution | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1218.011 System Binary Proxy Execution: Rundll32 | T1218.011 Test #1 | Execution | no | missed | info | 0.00 | realtime_etw |
| T1047 Windows Management Instrumentation (loca | T1047 Test #1 (wmic process call create) | Execution | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1204.002 User Execution: Malicious File (double-e | T1204.002 (manual masquerade construction) | Execution | yes | **DETECTED** | critical | 1.00 | realtime_etw |
| T1547.001 Boot or Logon Autostart Execution: Regis | T1547.001 Test #1 | Persistence | yes | **DETECTED** | medium | 0.55 | artifact_poll_15s |
| T1053.005 Scheduled Task/Job: Scheduled Task | T1053.005 Test #1 | Persistence | yes | **DETECTED** | high | 0.80 | artifact_poll_15s |
| T1543.003 Create or Modify System Process: Windows | T1543.003 Test #1 | Persistence | yes | **DETECTED** | medium | 0.55 | artifact_poll_15s |
| T1547.001 Boot or Logon Autostart Execution: Start | T1547.001 Test #9 (Startup folder) | Persistence | yes | **DETECTED** | medium | 0.55 | artifact_poll_15s |
| T1136.001 Create Account: Local Account | T1136.001 Test #1 (net user /add) | Persistence | yes | **DETECTED** | medium | 0.55 | realtime_etw |
| T1546.003 Event Triggered Execution: WMI Event Sub | T1546.003 Test #1 | Persistence | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1562.001 Impair Defenses: Disable or Modify Tools | T1562.001 Test #1 (Set-MpPreference -DisableRealtimeMonitoring) | Defense Evasion | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1070.001 Indicator Removal: Clear Windows Event L | T1070.001 Test #1 (wevtutil cl) | Defense Evasion | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1027 Obfuscated Files or Information: PowerSh | T1027 Test #3 | Defense Evasion | yes | missed | high | 0.80 | artifact_poll_15s |
| T1140 Deobfuscate/Decode Files or Information  | T1140 Test #1 | Defense Evasion | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1562.004 Impair Defenses: Disable or Modify Syste | T1562.004 Test #1 (netsh advfirewall set allprofiles state off) | Defense Evasion | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1055 Process Injection (CreateRemoteThread) | T1055.002 Test #1 | Defense Evasion | yes | missed | high | 0.80 | realtime_etw |
| T1003.001 OS Credential Dumping: LSASS Memory (com | T1003.001 Test #3 | Credential Access | yes | missed | high | 0.80 | realtime_etw |
| T1003.001 OS Credential Dumping: LSASS Memory (pro | T1003.001 Test #1 | Credential Access | yes | missed | high | 0.80 | realtime_etw |
| T1003.002 OS Credential Dumping: Security Account  | T1003.002 Test #1 (reg save HKLM\SAM) | Credential Access | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1555 Credentials from Password Stores | T1555.003 Test #1 (browser creds) | Credential Access | no | missed | info | 0.00 | realtime_etw |
| T1033 System Owner/User Discovery (whoami /pri | T1033 Test #1 | Discovery | no | missed | low | 0.30 | realtime_etw |
| T1082 System Information Discovery (systeminfo | T1082 Test #1 | Discovery | no | missed | info | 0.00 | no_code_path |
| T1057 Process Discovery (tasklist.exe) | T1057 Test #1 | Discovery | no | missed | info | 0.00 | no_code_path |
| T1018 Remote System Discovery (net view) | T1018 Test #1 | Discovery | no | missed | info | 0.00 | no_code_path |
| T1087.001 Account Discovery: Local Account (net us | T1087.001 Test #1 | Discovery | no | missed | info | 0.00 | process_poll_2s_racy |
| T1482 Domain Trust Discovery (nltest) | T1482 Test #1 | Discovery | yes | **DETECTED** | medium | 0.55 | realtime_etw |
| T1021.002 Remote Services: SMB/Windows Admin Share | T1021.002 Test #1 (self-target) | Lateral Movement | no | missed | info | 0.00 | process_poll_2s_racy |
| T1047 Windows Management Instrumentation (remo | T1047 Test #3 (wmic /node: remote, self-target) | Lateral Movement | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1570 Lateral Tool Transfer | T1570 (copy via admin share, self-target) | Lateral Movement | no | missed | info | 0.00 | no_code_path |
| T1071.004 Application Layer Protocol: DNS (query t | Custom -- DNS resolution to an EasyPrivacy-listed domain | Command and Control | yes | **DETECTED** | high | 0.70 | inline_request_path |
| T1071.004 Application Layer Protocol: DNS (DGA-gen | Custom -- algorithmically-generated C2 domain | Command and Control | yes | **DETECTED** | high | 0.80 | inline_request_path |
| T1071 Hardcoded-IP C2 (no DNS lookup at all) | Custom -- raw connect() to a threat-intel-flagged IP | Command and Control | yes | **DETECTED** | high | 0.80 | inline_request_path |
| T1071.004 DNS Tunneling / high-volume subdomain qu | Custom -- iodine/dnscat2-style query flood | Command and Control | yes | **DETECTED** | high | 0.75 | inline_request_path |
| T1105 Ingress Tool Transfer (certutil -urlcach | T1105 Test #1 | Command and Control | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1486 Data Encrypted for Impact (canary-direct | Custom -- rapid high-entropy overwrite of canary files (ransomware simulation) | Impact | yes | **DETECTED** | critical | 0.99 | purpose_built_watcher |
| T1490 Inhibit System Recovery (vssadmin delete | T1490 Test #1 | Impact | yes | **DETECTED** | critical | 0.95 | realtime_etw |
| T1489 Service Stop (targeting a security-relev | T1489 Test #1 -- IMPORTANT: target a DECOY service, never Valkyrie's own service, in any live run | Impact | no | missed | info | 0.00 | no_code_path |

## Missed techniques — root cause and required code change

### T1059.001 — Command and Scripting Interpreter: PowerShell  `exec-powershell-encoded`

- **Tactic:** Execution
- **Test:** T1059.001 Test #2 (EncodedCommand)
- **Predicted outcome:** CONDITIONAL
- **Root cause:** classify_powershell (etw/powershell.py) has TWO delivery paths with different reliability: real-time via PowerShell Script Block Logging (event 4104, enabled by provision.ps1), or the racy 2s process poll for the launching powershell.exe cmdline if 4104 logging is off. This entry is scored on the process-launch path; the 4104 path is a separate, more reliable signal this evaluation did not independently probe.
- **Code change required:** Confirm (during the VM pass) that PS Script Block Logging is actually being consumed end-to-end, not just enabled in Group Policy by provision.ps1 -- i.e. that something subscribes to the Microsoft-Windows-PowerShell/Operational log's event 4104 and calls classify_powershell on its ScriptBlockText. If that consumer does not exist yet, it is the single highest-value addition for the whole Execution tactic: PowerShell is the most common real-world delivery mechanism, and 4104 logging captures the deobfuscated script body, not just the launch command line.

### T1218.011 — System Binary Proxy Execution: Rundll32  `exec-rundll32-proxy`

- **Tactic:** Execution
- **Test:** T1218.011 Test #1
- **Predicted outcome:** DETECT
- **Root cause:** etw/sysmon.py's EID 1 (process creation) handler calls classify_process(name, path, parent) -- name/path/lineage only. It never calls classify_behavior() / match_process() from behavioral_rules.py, so the 32 named IOA rules (which contain exactly the patterns these techniques need: regsvr32 /i:, comsvcs.dll MiniDump, wevtutil cl, vssadmin delete shadows, Set-MpPreference -Disable*, reg save hklm\sam, nltest /domain_trusts, wmic /node:, certutil -urlcache) are reachable ONLY through process_telemetry.ProcInfo.to_event(), which is fed exclusively by a plain psutil poll on a 2.0-second interval (ProcessCollector, process_telemetry.py:258). Sysmon's own CommandLine field -- present in the raw ETW event -- is read for nothing else and discarded. Native one-shot commands exit in well under 2 seconds, so this poller loses the race for most of them, REGARDLESS OF WHETHER SYSMON IS INSTALLED, which is the counter-intuitive part: installing Sysmon does not fix this, because Sysmon's process-creation path was never connected to the rule engine that would use it.
- **Code change required:** In valkyrie/etw/sysmon.py, function classify_sysmon(), the `if eid == 1:` branch (~line 97): after computing `image`/`parent`, also read `cmdline = d.get('CommandLine', '')` and call `behavior = classify_behavior(_name(image), parent, cmdline, image)` from behavioral_rules.py (already imported project-wide; add the import to sysmon.py). If `behavior` is not None, raise `sev` to max(sev, behavior['severity']), merge behavior['labels'] into `labels`, and set `technique = behavior['technique']` on the returned dict (the `technique` field on EID 1 events is currently always ''). This single change gives real-time delivery -- independent of the 2s poller -- to all 32 rules on any host with Sysmon installed, which is exactly the provisioning redteam/provision.ps1 already sets up. It converts most of the 'affects' list above from MISS to a genuine DETECT on a Sysmon-equipped VM, and does not touch the bare-metal (no Sysmon) case, which honestly remains a gap without the kernel driver.

### T1027 — Obfuscated Files or Information: PowerShell -EncodedCommand  `evasion-encoded-powershell`

- **Tactic:** Defense Evasion
- **Test:** T1027 Test #3
- **Predicted outcome:** CONDITIONAL
- **Root cause:** classify_cmdline's encoded-PowerShell signal is reachable via TWO different call sites with different reliability: the racy 2s process poll (process_telemetry.ProcInfo.to_event) for a one-shot interactive launch, and the reliable 15s artifact-at-rest persistence scan (_persistence_severity) when the encoded command is stored IN a persistence location rather than run interactively. CONDITIONAL reflects that split: which path applies depends entirely on how the atomic delivers the encoded command.
- **Code change required:** Covered by the architectural EID1 fix for the interactive-launch case (classify_cmdline could be folded into the same EID1 wiring change, or called alongside classify_behavior since both take a cmdline string). No change needed for the persistence-artifact case -- it is already reliable.

### T1055 — Process Injection (CreateRemoteThread)  `evasion-process-injection`

- **Tactic:** Defense Evasion
- **Test:** T1055.002 Test #1
- **Predicted outcome:** CONDITIONAL
- **Root cause:** Sysmon EID 8 (CreateRemoteThread) IS wired directly to a real-time classifier in etw/sysmon.py -- this is NOT a wiring gap like the 32 IOA rules. The condition is binary and external: Sysmon must be installed. There is no fallback sensor -- the kernel driver that could provide one (driver/ valkyrie_km, docs/adr/0026) has never been compiled.
- **Code change required:** No code change to Valkyrie's classifier is needed -- the EID 8 handler is correct as written. The actual blocker is docs/adr/0026's kernel driver, which would give injection visibility without depending on Sysmon at all. Confirming this technique's real-world detection rate is entirely a Tier B question: does the VM have Sysmon installed and configured to log EID 8 (it is NOT logged by Sysmon's default config -- provision.ps1's sysmonconfig must explicitly enable CreateRemoteThread logging, which is high-volume and often excluded by default configs for noise reasons).

### T1003.001 — OS Credential Dumping: LSASS Memory (comsvcs MiniDump)  `cred-lsass-comsvcs`

- **Tactic:** Credential Access
- **Test:** T1003.001 Test #3
- **Predicted outcome:** CONDITIONAL
- **Root cause:** Sysmon EID 10 (ProcessAccess -> lsass.exe) is wired directly, real-time, independent of the poller -- genuinely the most reliable credential-access detection in the product on a Sysmon-equipped host. The cmdline rule (comsvcs-minidump) is ALSO racy on its own; EID 10 is what actually saves this technique.
- **Code change required:** No fix needed for the classifier. As with process injection, confirm Sysmon is configured to log EID 10 for lsass.exe specifically (Sysmon's default config typically DOES include an LSASS ProcessAccess rule since it's a well-known high-value signal, but provision.ps1's exact config should be checked rather than assumed).

### T1003.001 — OS Credential Dumping: LSASS Memory (procdump)  `cred-lsass-procdump`

- **Tactic:** Credential Access
- **Test:** T1003.001 Test #1
- **Predicted outcome:** CONDITIONAL
- **Root cause:** Identical to cred-lsass-comsvcs -- same EID 10 path, different tool.
- **Code change required:** Same as cred-lsass-comsvcs.

### T1555 — Credentials from Password Stores  `cred-browser-stores`

- **Tactic:** Credential Access
- **Test:** T1555.003 Test #1 (browser creds)
- **Predicted outcome:** DETECT
- **Root cause:** Named rule exists (T1555); racy poller only, and PowerShell Get-Content against a browser profile path has no independent real-time backstop the way LSASS access does.
- **Code change required:** Covered by the architectural fix for the process-launch case. A stronger fix specifically for browser credential stores: file-system watch (already partially present via the ransomware canary's file-monitoring machinery) on the small, well-known set of browser credential-store paths (Chrome/Edge 'Login Data', Firefox 'logins.json', etc.) -- an unexpected READ of one of these paths by a process other than the browser itself is a strong, specific signal independent of the launching command line.

### T1033 — System Owner/User Discovery (whoami /priv)  `disc-whoami-priv`

- **Tactic:** Discovery
- **Test:** T1033 Test #1
- **Predicted outcome:** DETECT
- **Root cause:** A named rule exists (T1033, LOW severity) -- the one Discovery technique with dedicated coverage before this evaluation. whoami.exe exits in single-digit milliseconds, so the racy poller reliably loses this race. This is the exact case the prior redteam/README.md already called 'LIKELY MISS'; this evaluation confirms it via source trace rather than intuition, and generalises it to every single-shot discovery command.
- **Code change required:** Covered by the architectural EID1 fix for the timing component. But note: LOW severity was likely chosen precisely because a lone `whoami /priv` is weak evidence on its own -- raising it to fire more aggressively as a standalone signal would reintroduce the FP risk the project's design principle argues against. The recon-burst ESP sequence fix (see disc-local-accounts) is the more consistent long-term answer: let whoami contribute a weak signal to a COMBINATION, rather than trying to make it fire reliably alone.

### T1082 — System Information Discovery (systeminfo.exe)  `disc-systeminfo`

- **Tactic:** Discovery
- **Test:** T1082 Test #1
- **Predicted outcome:** MISS
- **Root cause:** No rule exists for systeminfo.exe at all -- a genuine coverage hole, not a wiring hole.
- **Code change required:** See disc-local-accounts's fix -- part of the same recon-burst ESP sequence, not a standalone rule.

### T1057 — Process Discovery (tasklist.exe)  `disc-tasklist`

- **Tactic:** Discovery
- **Test:** T1057 Test #1
- **Predicted outcome:** MISS
- **Root cause:** No rule exists for tasklist.exe.
- **Code change required:** Same recon-burst ESP sequence fix.

### T1018 — Remote System Discovery (net view)  `disc-net-view`

- **Tactic:** Discovery
- **Test:** T1018 Test #1
- **Predicted outcome:** MISS
- **Root cause:** No rule exists for `net view`.
- **Code change required:** Same recon-burst ESP sequence fix.

### T1087.001 — Account Discovery: Local Account (net user)  `disc-local-accounts`

- **Tactic:** Discovery
- **Test:** T1087.001 Test #1
- **Predicted outcome:** MISS
- **Root cause:** See OVERBROAD_RULE_FINDINGS['net-user-add-overbroad'] -- the existing rule fires on this input, but as a MISLABELED T1136.001 hit, not as recognition of T1087.001 discovery. Separately: Discovery techniques that only ever READ state (whoami, systeminfo, tasklist, net view, net user with no argument) are architecturally the hardest tactic for any EDR that scores on process behaviour, because the commands themselves are indistinguishable from routine administration -- the entire category of 'single discovery command, alone, at medium+ severity' is a false-positive generator by construction, and Valkyrie's own precision-over-aggression design principle (documented in behavior_score.py's module docstring) argues against ever firing on one in isolation.
- **Code change required:** Do not add a HIGH/MEDIUM severity rule for any single discovery command -- that would trade a real detection gap for a real FP generator, which is the wrong trade for this product. Instead: add a WEAK, INFO-severity label ('discovery_command') to classify_process() for a small, curated set of discovery LOLBins (systeminfo.exe, tasklist.exe, net.exe view/user with no mutating args, nltest.exe, whoami.exe), and add a new ESP sequence rule to behavioral_sequences.py: fire (MEDIUM, 'reconnaissance burst') only when >= 3 DISTINCT discovery labels are observed from the SAME actor within a short window (e.g. 120s) -- mirroring the existing 'combination of weak signals' pattern already used for the anomaly scorer. A single `whoami` never fires anything; `whoami` + `systeminfo` + `net user` + `tasklist` inside two minutes does. This is consistent with the project's own stated design philosophy rather than a bolt-on.

### T1021.002 — Remote Services: SMB/Windows Admin Shares (PsExec)  `lat-psexec-smb`

- **Tactic:** Lateral Movement
- **Test:** T1021.002 Test #1 (self-target)
- **Predicted outcome:** CONDITIONAL
- **Root cause:** Named rule exists (T1021.002); racy poller only. CONDITIONAL rather than MISS because PsExec's remote service process tends to run longer than a bare native command. ALSO structurally limited to a single-VM evaluation the same way as the other Lateral Movement entries: a self-target run proves the tool/ service signature is recognised, not that cross-host movement is detected.
- **Code change required:** Covered by the architectural fix for the single-host signature. The cross-host gap is a test-infrastructure limitation, not a code fix -- see the Lateral Movement tactic note recommending a 2-VM topology for tier 4.

### T1570 — Lateral Tool Transfer  `lat-tool-transfer`

- **Tactic:** Lateral Movement
- **Test:** T1570 (copy via admin share, self-target)
- **Predicted outcome:** MISS
- **Root cause:** No rule exists for file-copy-to-admin-share patterns at all (`copy X \\host\C$\...`).
- **Code change required:** Add a rule to behavioral_rules.py: images=('cmd.exe', 'powershell.exe', 'robocopy.exe', 'xcopy.exe'), cmd_any=('\\\\','$\\') combined with a written-executable extension check on the destination -- technique T1570, severity MEDIUM (this pattern alone is common in legitimate IT admin work, so MEDIUM not HIGH, consistent with the project's precision-first stance). Same single-VM caveat as above for proving the cross-host case.

### T1489 — Service Stop (targeting a security-relevant service)  `impact-service-stop`

- **Tactic:** Impact
- **Test:** T1489 Test #1 -- IMPORTANT: target a DECOY service, never Valkyrie's own service, in any live run
- **Predicted outcome:** MISS
- **Root cause:** No rule exists for `sc stop` / `Stop-Service` / `Set-Service -StartupType Disabled` targeting security-relevant services at all.
- **Code change required:** Add a new rule to behavioral_rules.py's RULES tuple: images=('sc.exe','powershell.exe'), cmd_any=('stop', 'config start= disabled') combined with a curated set of security-service names (WinDefend, SecurityHealthService, Sysmon64, EventLog, wuauserv, and Valkyrie's own service name) checked as a substring of the full command line -- technique T1489, severity HIGH. Because this is a state-CHANGING action against a well-known, finite list of service names (not a generic pattern), it is also a good candidate for an artifact-at-rest check: a periodic (15s, alongside the persistence scan) query of each watched service's StartMode/State via Win32_Service, flagging any watched service that transitions from Running/Auto to Stopped/Disabled without a corresponding Valkyrie-initiated change. This is the one fix in this report that does not depend on the architectural Sysmon change at all, and is worth prioritizing precisely because it is independently reliable.

## Standalone findings (discovered by running the harness)

### net-user-add-overbroad

- **Discovered via:** Tier A replay of disc-local-accounts (T1087.001) -- the real classify_behavior() call returned a hit where the catalog's static-analysis prediction was 'no code path'.
- **Location:** `valkyrie/behavioral_rules.py, Rule('net-user-add', ...) cmd_any=('net user', 'net.exe user', 'net localgroup administrators')`
- **Problem:** Matches on the bare substring 'net user' with NO requirement for a mutating argument. `net user` alone (lists all local accounts -- routine, benign, and common) fires the identical MEDIUM-severity 'T1136.001 Create Local Account' incident as `net user backdoor P@ssw0rd123! /add` (an actual backdoor account). Same problem for `net localgroup administrators` (listing membership) vs `net localgroup administrators evilcorp /add` (adding to it).
- **Impact:** A real, live false-positive generator on any machine where routine administration includes listing local accounts or admin-group membership -- exactly the FP class this project's own stated design principle (precision over aggression, false positive is worse than a miss) argues hardest against, and it is currently shipping.
- **Code change:** Zero engine changes needed -- `Rule.cmd_all` (ALL substrings must be present) already exists in the dataclass (behavioral_rules.py line ~43) and is used by other rules in the same file; this rule simply used the wrong field. Replace the single net-user-add Rule (cmd_any=('net user', 'net.exe user', 'net localgroup administrators')) with two rules using cmd_all instead: Rule(..., cmd_all=('net user', '/add')) for account creation, and Rule(..., cmd_all=('net localgroup administrators', '/add')) for admin-group addition. A one-rule data change, no new code path, removes a live FP source without affecting recall on the real malicious case (every genuine T1136.001 atomic includes /add).

## The architectural fix (upgrades the largest number of misses at once)

**Wire Sysmon EID 1's CommandLine into the 32-rule IOA engine**

Affects: exec-mshta-remote, exec-regsvr32-squiblydoo, exec-rundll32-proxy, exec-wmic-process-call, evasion-clear-eventlogs, evasion-certutil-decode, evasion-firewall-disable, cred-sam-dump, disc-domain-trust, lat-wmi-remote, c2-ingress-tool-transfer, impact-shadow-delete

**Root cause:** etw/sysmon.py's EID 1 (process creation) handler calls classify_process(name, path, parent) -- name/path/lineage only. It never calls classify_behavior() / match_process() from behavioral_rules.py, so the 32 named IOA rules (which contain exactly the patterns these techniques need: regsvr32 /i:, comsvcs.dll MiniDump, wevtutil cl, vssadmin delete shadows, Set-MpPreference -Disable*, reg save hklm\sam, nltest /domain_trusts, wmic /node:, certutil -urlcache) are reachable ONLY through process_telemetry.ProcInfo.to_event(), which is fed exclusively by a plain psutil poll on a 2.0-second interval (ProcessCollector, process_telemetry.py:258). Sysmon's own CommandLine field -- present in the raw ETW event -- is read for nothing else and discarded. Native one-shot commands exit in well under 2 seconds, so this poller loses the race for most of them, REGARDLESS OF WHETHER SYSMON IS INSTALLED, which is the counter-intuitive part: installing Sysmon does not fix this, because Sysmon's process-creation path was never connected to the rule engine that would use it.

**Code change:** In valkyrie/etw/sysmon.py, function classify_sysmon(), the `if eid == 1:` branch (~line 97): after computing `image`/`parent`, also read `cmdline = d.get('CommandLine', '')` and call `behavior = classify_behavior(_name(image), parent, cmdline, image)` from behavioral_rules.py (already imported project-wide; add the import to sysmon.py). If `behavior` is not None, raise `sev` to max(sev, behavior['severity']), merge behavior['labels'] into `labels`, and set `technique = behavior['technique']` on the returned dict (the `technique` field on EID 1 events is currently always ''). This single change gives real-time delivery -- independent of the 2s poller -- to all 32 rules on any host with Sysmon installed, which is exactly the provisioning redteam/provision.ps1 already sets up. It converts most of the 'affects' list above from MISS to a genuine DETECT on a Sysmon-equipped VM, and does not touch the bare-metal (no Sysmon) case, which honestly remains a gap without the kernel driver.

**Effort:** Small, contained, single-file change; the hard part (the rule engine, the classify_behavior API) already exists and is tested. Needs a new test asserting EID 1 + a rule-matching cmdline produces a technique-tagged event, plus a regression check that EID 1 without Sysmon's CommandLine populated still degrades to the current name/path-only behaviour rather than raising.

## What this report cannot tell you

- Whether the attack **actually executed successfully** on a real system (Tier A has no attack to execute).
- **Measured** detection latency (Tier A has no live clock).
- Aggregate **false-positive rate** under real system load (see `tests/test_benign_corpus.py` and `tests/efficacy/harness.py` for this project's actual FP evidence instead of a fabricated number here).
- Whether Sysmon-dependent paths (T1055, T1003.001, and everything the architectural fix would newly cover) actually fire on a live, Sysmon-instrumented host -- confirmed only by Tier B.
- Lateral movement against a REAL second host -- this evaluation's lateral-movement entries are self-target simulations on one VM, which the report says explicitly rather than implying more coverage than exists.
