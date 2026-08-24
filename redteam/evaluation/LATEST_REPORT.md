# Valkyrie EDR Evaluation Report

**Tier:** B_live  
**Generated:** 20260811T071132Z UTC  
**Git commit:** 2b0a852  
**Catalog version:** 2026-07-30.2  
**Reproduce:** `PYTHONUTF8=1 python redteam/evaluation/replay_harness.py` (Tier A) or `redteam/evaluation/run_live_evaluation.ps1` (Tier B, VM only)

> **This is Tier B: live-fire.** Each technique was actually executed on the instrumented host and scored against the REAL running EDR's incident store -- `attack_executed`, measured `detection_latency_seconds`, the producing sensor (`matched_source`) and per-technique false positives are live observations, not predictions. Read the outcome breakdown below before the headline: a technique the host **blocked before it executed** (e.g. Defender killing a remote-scriptlet fetch) produced no attacker process for Valkyrie to observe and is NOT a Valkyrie detection failure -- it is reported separately from techniques that executed and were missed. The `predicted_tier_b` and static root-cause text carried per technique are the Tier A **prediction**, kept for comparison and labelled as such, never as a live observation.

## Scoring rules applied

- A miss is a miss. `CONDITIONAL` predictions are **not** credited as detected in the headline number -- only a confirmed, reliably-delivered `DETECT` counts.
- A `DETECT` whose catalog entry declares **host preconditions** (`requires`, e.g. `sysmon_eid8`) is credited only when those preconditions are verified **on the machine this run executed on**. The classifier firing is necessary but not sufficient: if the host cannot deliver the event, the detection cannot happen. Unmet preconditions are reported per technique with the reason, and the host snapshot is stored in the result file's `host_environment` so a score is never separable from the environment that produced it.
- A detection whose category is a **user-defined DNS block** (`detection_category == 'user_rule'`) is excluded from the detected count and reported separately, per the evaluation brief.
  - None triggered this run.
- A rule firing under the **wrong technique label** (`known_mismatch`) is never credited, even if the underlying code executed without error.

## Overall

**1 / 40 techniques detected (2.5%)**

### Outcome breakdown (live)

| Outcome | Count | Meaning |
|---|---:|---|
| detected | 1 | executed and a matching incident was raised |
| executed, missed | 33 | executed but no matching incident — a REAL detection gap |
| blocked before execution | 4 | the host (AV/OS) stopped the technique before it ran — no attacker process to observe, NOT a Valkyrie miss |
| not executed (no command) | 2 | the harness had no runnable command/atomic for this probe — a test-coverage gap, NOT a Valkyrie miss |

**Detection rate on techniques that actually executed: 1 / 34 = 2.9%**  (vs 1 / 40 = 2.5% over the full catalog).

| Tactic | Detected | Total | % |
|---|---:|---:|---:|
| Execution | 1 | 7 | 14% |
| Persistence | 0 | 6 | 0% |
| Defense Evasion | 0 | 6 | 0% |
| Credential Access | 0 | 4 | 0% |
| Discovery | 0 | 6 | 0% |
| Lateral Movement | 0 | 3 | 0% |
| Command and Control | 0 | 5 | 0% |
| Impact | 0 | 3 | 0% |

**Explicitly out of scope:** 4 techniques, each with a stated reason (never silently dropped) -- see catalog.py `OUT_OF_SCOPE`.

## Per-test results

| Technique | Test | Tactic | Outcome | Latency (s) | Sensor | Severity |
|---|---|---|:---:|---:|---|---|
| T1059.001 Command and Scripting Interpreter: Pow | T1059.001 Test #2 (EncodedCommand) | Execution | detected | 10.26 | — | critical |
| T1059.003 Command and Scripting Interpreter: Win | T1059.003 Test #1 (cmd spawned by Office) | Execution | not_executed_no_command | — | — | — |
| T1218.005 System Binary Proxy Execution: Mshta | T1218.005 Test #1 (remote HTA) | Execution | executed_missed | — | — | — |
| T1218.010 System Binary Proxy Execution: Regsvr3 | T1218.010 Test #1 | Execution | executed_missed | — | — | — |
| T1218.011 System Binary Proxy Execution: Rundll3 | T1218.011 Test #1 | Execution | executed_missed | — | — | — |
| T1047 Windows Management Instrumentation (lo | T1047 Test #1 (wmic process call create) | Execution | executed_missed | — | — | — |
| T1204.002 User Execution: Malicious File (double | T1204.002 (manual masquerade construction) | Execution | executed_missed | — | — | — |
| T1547.001 Boot or Logon Autostart Execution: Reg | T1547.001 Test #1 | Persistence | executed_missed | — | — | — |
| T1053.005 Scheduled Task/Job: Scheduled Task | T1053.005 Test #1 | Persistence | executed_missed | — | — | — |
| T1543.003 Create or Modify System Process: Windo | T1543.003 Test #1 | Persistence | executed_missed | — | — | — |
| T1547.001 Boot or Logon Autostart Execution: Sta | T1547.001 Test #9 (Startup folder) | Persistence | executed_missed | — | — | — |
| T1136.001 Create Account: Local Account | T1136.001 Test #1 (net user /add) | Persistence | executed_missed | — | — | — |
| T1546.003 Event Triggered Execution: WMI Event S | T1546.003 Test #1 | Persistence | executed_missed | — | — | — |
| T1562.001 Impair Defenses: Disable or Modify Too | T1562.001 Test #1 (Set-MpPreference -DisableRealtimeMonitoring) | Defense Evasion | executed_missed | — | — | — |
| T1070.001 Indicator Removal: Clear Windows Event | T1070.001 Test #1 (wevtutil cl) | Defense Evasion | executed_missed | — | — | — |
| T1027 Obfuscated Files or Information: Power | T1027 Test #3 | Defense Evasion | executed_missed | — | — | — |
| T1140 Deobfuscate/Decode Files or Informatio | T1140 Test #1 | Defense Evasion | executed_missed | — | — | — |
| T1562.004 Impair Defenses: Disable or Modify Sys | T1562.004 Test #1 (netsh advfirewall set allprofiles state off) | Defense Evasion | executed_missed | — | — | — |
| T1055 Process Injection (CreateRemoteThread) | T1055.002 Test #1 | Defense Evasion | executed_missed | — | — | — |
| T1003.001 OS Credential Dumping: LSASS Memory (c | T1003.001 Test #3 | Credential Access | executed_missed | — | — | — |
| T1003.001 OS Credential Dumping: LSASS Memory (p | T1003.001 Test #1 | Credential Access | blocked_before_execution | — | — | — |
| T1003.002 OS Credential Dumping: Security Accoun | T1003.002 Test #1 (reg save HKLM\SAM) | Credential Access | blocked_before_execution | — | — | — |
| T1555 Credentials from Password Stores | T1555.003 Test #1 (browser creds) | Credential Access | not_executed_no_command | — | — | — |
| T1033 System Owner/User Discovery (whoami /p | T1033 Test #1 | Discovery | executed_missed | — | — | — |
| T1082 System Information Discovery (systemin | T1082 Test #1 | Discovery | executed_missed | — | — | — |
| T1057 Process Discovery (tasklist.exe) | T1057 Test #1 | Discovery | executed_missed | — | — | — |
| T1018 Remote System Discovery (net view) | T1018 Test #1 | Discovery | executed_missed | — | — | — |
| T1087.001 Account Discovery: Local Account (net  | T1087.001 Test #1 | Discovery | executed_missed | — | — | — |
| T1482 Domain Trust Discovery (nltest) | T1482 Test #1 | Discovery | executed_missed | — | — | — |
| T1021.002 Remote Services: SMB/Windows Admin Sha | T1021.002 Test #1 (self-target) | Lateral Movement | executed_missed | — | — | — |
| T1047 Windows Management Instrumentation (re | T1047 Test #3 (wmic /node: remote, self-target) | Lateral Movement | executed_missed | — | — | — |
| T1570 Lateral Tool Transfer | T1570 (copy via admin share, self-target) | Lateral Movement | executed_missed | — | — | — |
| T1071.004 Application Layer Protocol: DNS (query | Custom -- DNS resolution to an EasyPrivacy-listed domain | Command and Control | executed_missed | — | — | — |
| T1071.004 Application Layer Protocol: DNS (DGA-g | Custom -- algorithmically-generated C2 domain | Command and Control | executed_missed | — | — | — |
| T1071 Hardcoded-IP C2 (no DNS lookup at all) | Custom -- raw connect() to a threat-intel-flagged IP | Command and Control | executed_missed | — | — | — |
| T1071.004 DNS Tunneling / high-volume subdomain  | Custom -- iodine/dnscat2-style query flood | Command and Control | executed_missed | — | — | — |
| T1105 Ingress Tool Transfer (certutil -urlca | T1105 Test #1 | Command and Control | blocked_before_execution | — | — | — |
| T1486 Data Encrypted for Impact (canary-dire | Custom -- rapid high-entropy overwrite of canary files (ransomware simulation) | Impact | blocked_before_execution | — | — | — |
| T1490 Inhibit System Recovery (vssadmin dele | T1490 Test #1 | Impact | executed_missed | — | — | — |
| T1489 Service Stop (targeting a security-rel | T1489 Test #1 -- IMPORTANT: in any LIVE run, stop a throwaway service RENAMED into the watched set (e.g. a dummy service named 'Sysmon64'), never the real WinDefend/EventLog and never Valkyrie's own service | Impact | executed_missed | — | — | — |

## Executed but missed — real detection gaps

These techniques ran to completion and Valkyrie raised no matching incident. This is the list to engineer against.

### T1218.005 — System Binary Proxy Execution: Mshta  `exec-mshta-remote`

- **Tactic:** Execution
- **Test:** T1218.005 Test #1 (remote HTA)
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — etw/sysmon.py's EID 1 (process creation) handler calls classify_process(name, path, parent) -- name/path/lineage only. It never calls classify_behavior() / match_process() from behavioral_rules.py, so the 32 named IOA rules (which contain exactly the patterns these techniques need: regsvr32 /i:, comsvcs.dll MiniDump, wevtutil cl, vssadmin delete shadows, Set-MpPreference -Disable*, reg save hklm\sam, nltest /domain_trusts, wmic /node:, certutil -urlcache) are reachable ONLY through process_telemetry.ProcInfo.to_event(), which is fed exclusively by a plain psutil poll on a 2.0-second interval (ProcessCollector, process_telemetry.py:258). Sysmon's own CommandLine field -- present in the raw ETW event -- is read for nothing else and discarded. Native one-shot commands exit in well under 2 seconds, so this poller loses the race for most of them, REGARDLESS OF WHETHER SYSMON IS INSTALLED, which is the counter-intuitive part: installing Sysmon does not fix this, because Sysmon's process-creation path was never connected to the rule engine that would use it.
- **Candidate code change (from Tier A analysis, verify against the live miss):** In valkyrie/etw/sysmon.py, function classify_sysmon(), the `if eid == 1:` branch (~line 97): after computing `image`/`parent`, also read `cmdline = d.get('CommandLine', '')` and call `behavior = classify_behavior(_name(image), parent, cmdline, image)` from behavioral_rules.py (already imported project-wide; add the import to sysmon.py). If `behavior` is not None, raise `sev` to max(sev, behavior['severity']), merge behavior['labels'] into `labels`, and set `technique = behavior['technique']` on the returned dict (the `technique` field on EID 1 events is currently always ''). This single change gives real-time delivery -- independent of the 2s poller -- to all 32 rules on any host with Sysmon installed, which is exactly the provisioning redteam/provision.ps1 already sets up. It converts most of the 'affects' list above from MISS to a genuine DETECT on a Sysmon-equipped VM, and does not touch the bare-metal (no Sysmon) case, which honestly remains a gap without the kernel driver.

### T1218.010 — System Binary Proxy Execution: Regsvr32 (Squiblydoo)  `exec-regsvr32-squiblydoo`

- **Tactic:** Execution
- **Test:** T1218.010 Test #1
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — etw/sysmon.py's EID 1 (process creation) handler calls classify_process(name, path, parent) -- name/path/lineage only. It never calls classify_behavior() / match_process() from behavioral_rules.py, so the 32 named IOA rules (which contain exactly the patterns these techniques need: regsvr32 /i:, comsvcs.dll MiniDump, wevtutil cl, vssadmin delete shadows, Set-MpPreference -Disable*, reg save hklm\sam, nltest /domain_trusts, wmic /node:, certutil -urlcache) are reachable ONLY through process_telemetry.ProcInfo.to_event(), which is fed exclusively by a plain psutil poll on a 2.0-second interval (ProcessCollector, process_telemetry.py:258). Sysmon's own CommandLine field -- present in the raw ETW event -- is read for nothing else and discarded. Native one-shot commands exit in well under 2 seconds, so this poller loses the race for most of them, REGARDLESS OF WHETHER SYSMON IS INSTALLED, which is the counter-intuitive part: installing Sysmon does not fix this, because Sysmon's process-creation path was never connected to the rule engine that would use it.
- **Candidate code change (from Tier A analysis, verify against the live miss):** In valkyrie/etw/sysmon.py, function classify_sysmon(), the `if eid == 1:` branch (~line 97): after computing `image`/`parent`, also read `cmdline = d.get('CommandLine', '')` and call `behavior = classify_behavior(_name(image), parent, cmdline, image)` from behavioral_rules.py (already imported project-wide; add the import to sysmon.py). If `behavior` is not None, raise `sev` to max(sev, behavior['severity']), merge behavior['labels'] into `labels`, and set `technique = behavior['technique']` on the returned dict (the `technique` field on EID 1 events is currently always ''). This single change gives real-time delivery -- independent of the 2s poller -- to all 32 rules on any host with Sysmon installed, which is exactly the provisioning redteam/provision.ps1 already sets up. It converts most of the 'affects' list above from MISS to a genuine DETECT on a Sysmon-equipped VM, and does not touch the bare-metal (no Sysmon) case, which honestly remains a gap without the kernel driver.

### T1218.011 — System Binary Proxy Execution: Rundll32  `exec-rundll32-proxy`

- **Tactic:** Execution
- **Test:** T1218.011 Test #1
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — etw/sysmon.py's EID 1 (process creation) handler calls classify_process(name, path, parent) -- name/path/lineage only. It never calls classify_behavior() / match_process() from behavioral_rules.py, so the 32 named IOA rules (which contain exactly the patterns these techniques need: regsvr32 /i:, comsvcs.dll MiniDump, wevtutil cl, vssadmin delete shadows, Set-MpPreference -Disable*, reg save hklm\sam, nltest /domain_trusts, wmic /node:, certutil -urlcache) are reachable ONLY through process_telemetry.ProcInfo.to_event(), which is fed exclusively by a plain psutil poll on a 2.0-second interval (ProcessCollector, process_telemetry.py:258). Sysmon's own CommandLine field -- present in the raw ETW event -- is read for nothing else and discarded. Native one-shot commands exit in well under 2 seconds, so this poller loses the race for most of them, REGARDLESS OF WHETHER SYSMON IS INSTALLED, which is the counter-intuitive part: installing Sysmon does not fix this, because Sysmon's process-creation path was never connected to the rule engine that would use it.
- **Candidate code change (from Tier A analysis, verify against the live miss):** In valkyrie/etw/sysmon.py, function classify_sysmon(), the `if eid == 1:` branch (~line 97): after computing `image`/`parent`, also read `cmdline = d.get('CommandLine', '')` and call `behavior = classify_behavior(_name(image), parent, cmdline, image)` from behavioral_rules.py (already imported project-wide; add the import to sysmon.py). If `behavior` is not None, raise `sev` to max(sev, behavior['severity']), merge behavior['labels'] into `labels`, and set `technique = behavior['technique']` on the returned dict (the `technique` field on EID 1 events is currently always ''). This single change gives real-time delivery -- independent of the 2s poller -- to all 32 rules on any host with Sysmon installed, which is exactly the provisioning redteam/provision.ps1 already sets up. It converts most of the 'affects' list above from MISS to a genuine DETECT on a Sysmon-equipped VM, and does not touch the bare-metal (no Sysmon) case, which honestly remains a gap without the kernel driver.

### T1047 — Windows Management Instrumentation (local process create)  `exec-wmic-process-call`

- **Tactic:** Execution
- **Test:** T1047 Test #1 (wmic process call create)
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — etw/sysmon.py's EID 1 (process creation) handler calls classify_process(name, path, parent) -- name/path/lineage only. It never calls classify_behavior() / match_process() from behavioral_rules.py, so the 32 named IOA rules (which contain exactly the patterns these techniques need: regsvr32 /i:, comsvcs.dll MiniDump, wevtutil cl, vssadmin delete shadows, Set-MpPreference -Disable*, reg save hklm\sam, nltest /domain_trusts, wmic /node:, certutil -urlcache) are reachable ONLY through process_telemetry.ProcInfo.to_event(), which is fed exclusively by a plain psutil poll on a 2.0-second interval (ProcessCollector, process_telemetry.py:258). Sysmon's own CommandLine field -- present in the raw ETW event -- is read for nothing else and discarded. Native one-shot commands exit in well under 2 seconds, so this poller loses the race for most of them, REGARDLESS OF WHETHER SYSMON IS INSTALLED, which is the counter-intuitive part: installing Sysmon does not fix this, because Sysmon's process-creation path was never connected to the rule engine that would use it.
- **Candidate code change (from Tier A analysis, verify against the live miss):** In valkyrie/etw/sysmon.py, function classify_sysmon(), the `if eid == 1:` branch (~line 97): after computing `image`/`parent`, also read `cmdline = d.get('CommandLine', '')` and call `behavior = classify_behavior(_name(image), parent, cmdline, image)` from behavioral_rules.py (already imported project-wide; add the import to sysmon.py). If `behavior` is not None, raise `sev` to max(sev, behavior['severity']), merge behavior['labels'] into `labels`, and set `technique = behavior['technique']` on the returned dict (the `technique` field on EID 1 events is currently always ''). This single change gives real-time delivery -- independent of the 2s poller -- to all 32 rules on any host with Sysmon installed, which is exactly the provisioning redteam/provision.ps1 already sets up. It converts most of the 'affects' list above from MISS to a genuine DETECT on a Sysmon-equipped VM, and does not touch the bare-metal (no Sysmon) case, which honestly remains a gap without the kernel driver.

### T1204.002 — User Execution: Malicious File (double-extension lure)  `exec-lure-doubleext`

- **Tactic:** Execution
- **Test:** T1204.002 (manual masquerade construction)
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — score_process (behavior_score.py) is reachable through the SAME path as the 32 IOA rules -- ProcInfo.to_event(), fed by the 2s poller -- so it inherits the identical timing dependency. The mitigating factor is behavioural, not architectural: a double-extension dropper typically does something after launch (drops a payload, opens a decoy document) rather than exiting immediately, which is why this is CONDITIONAL rather than a clean MISS.
- **Candidate code change (from Tier A analysis, verify against the live miss):** Covered by the architectural EID1 fix for the general case (wiring classify_behavior's cousin, score_process, into EID1 the same way would help here too -- consider adding it in the same change, since both functions take the same (image, parent, cmdline, path) shape). Until then, this technique's real reliability depends on payload behaviour after launch, which this evaluation cannot characterise from a synthetic replay.

### T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys  `persist-run-key`

- **Tactic:** Persistence
- **Test:** T1547.001 Test #1
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — valkyrie/persistence_telemetry.py:_persistence_severity via PersistenceCollector (15s artifact-at-rest scan)
- **Candidate code change (from Tier A analysis, verify against the live miss):** NOT YET DOCUMENTED -- flagging rather than inventing. Add a PER_TECHNIQUE['persist-run-key'] entry to root_cause.py.

### T1053.005 — Scheduled Task/Job: Scheduled Task  `persist-scheduled-task`

- **Tactic:** Persistence
- **Test:** T1053.005 Test #1
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — valkyrie/persistence_telemetry.py (scheduled task ASEP)
- **Candidate code change (from Tier A analysis, verify against the live miss):** NOT YET DOCUMENTED -- flagging rather than inventing. Add a PER_TECHNIQUE['persist-scheduled-task'] entry to root_cause.py.

### T1543.003 — Create or Modify System Process: Windows Service  `persist-new-service`

- **Tactic:** Persistence
- **Test:** T1543.003 Test #1
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — valkyrie/persistence_telemetry.py (service ASEP)
- **Candidate code change (from Tier A analysis, verify against the live miss):** NOT YET DOCUMENTED -- flagging rather than inventing. Add a PER_TECHNIQUE['persist-new-service'] entry to root_cause.py.

### T1547.001 — Boot or Logon Autostart Execution: Startup Folder  `persist-startup-folder`

- **Tactic:** Persistence
- **Test:** T1547.001 Test #9 (Startup folder)
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — valkyrie/persistence_telemetry.py (startup folder ASEP)
- **Candidate code change (from Tier A analysis, verify against the live miss):** NOT YET DOCUMENTED -- flagging rather than inventing. Add a PER_TECHNIQUE['persist-startup-folder'] entry to root_cause.py.

### T1136.001 — Create Account: Local Account  `persist-local-account`

- **Tactic:** Persistence
- **Test:** T1136.001 Test #1 (net user /add)
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — No artifact-at-rest scanner for local accounts, unlike registry Run keys / scheduled tasks / services / startup folder (all covered by persistence_telemetry.py's 15s poller). Detection depends entirely on catching `net.exe` alive during the 2s process poll; `net user ... /add` exits near-instantly.
- **Candidate code change (from Tier A analysis, verify against the live miss):** Add a fifth ASEP-style check to persistence_telemetry.py: PersistenceCollector already snapshot-diffs 4 location types every 15s (see _ACTIVITY_LABEL). Add a local-accounts snapshot using `net user` output (or, better, the Win32_UserAccount WMI class via `wmi` if already a dependency, or parsing `net user` -- diff the account-name set between polls the same way _run_key_specs() diffs registry values. A NEW account appearing between two 15s polls is itself the signal, independent of catching the creating process -- the same principle that makes the existing 4 ASEP checks reliable. This ALSO fixes T1087.001 Discovery's false-negative in the sense that it stops relying on catching the discovery command at all -- discovery of an account Valkyrie already knows about genuinely has no artifact to detect, which is a fair, honest limit rather than a gap (see the Discovery tactic note below).

### T1546.003 — Event Triggered Execution: WMI Event Subscription  `persist-wmi-subscription`

- **Tactic:** Persistence
- **Test:** T1546.003 Test #1
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — A named rule exists (wmi-event-consumer in behavioral_rules.py) and etw/wmi.py:classify_wmi exists, but whether a live WMI-Activity ETW consumer actually feeds classify_wmi in the running product was NOT confirmed end-to-end during this evaluation -- flagged as SOURCE_PARTIAL rather than asserted either way, unlike every source_confidence=CONFIRMED entry in this report.
- **Candidate code change (from Tier A analysis, verify against the live miss):** Before writing a fix, CONFIRM the wiring: grep for who actually calls classify_wmi() in etw/wmi.py's own module and trace it to a live event source the way this report traced classify_behavior. If no live caller exists, the fix is the same shape as the architectural one -- subscribe to the WMI-Activity operational log (or Sysmon's WmiEvent EIDs 19-21, if configured) and route __EventFilter / CommandLineEventConsumer creation into classify_wmi in real time rather than leaving it reachable only via the process poller catching wmic.exe alive.

### T1562.001 — Impair Defenses: Disable or Modify Tools (Defender)  `evasion-defender-disable`

- **Tactic:** Defense Evasion
- **Test:** T1562.001 Test #1 (Set-MpPreference -DisableRealtimeMonitoring)
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — Named rule exists (defender-disable). CONDITIONAL rather than MISS specifically because a PowerShell cmdlet invocation (Set-MpPreference) has a longer process lifetime than a bare native exe, AND PS Script Block Logging (if actually wired -- see exec-powershell-encoded above) gives a second, independent real-time path.
- **Candidate code change (from Tier A analysis, verify against the live miss):** Covered by the architectural EID1 fix for the process-launch path. For a real-time backstop independent of both that and PS logging: Defender's own state changes are queryable via Get-MpComputerStatus / the MSFT_MpComputerStatus WMI class -- a periodic (15s, alongside the persistence scan) check of AMRunningMode / RealTimeProtectionEnabled catches the STATE CHANGE itself, independent of catching the disabling process, exactly the artifact-at-rest pattern used elsewhere in this report's recommendations.

### T1070.001 — Indicator Removal: Clear Windows Event Logs  `evasion-clear-eventlogs`

- **Tactic:** Defense Evasion
- **Test:** T1070.001 Test #1 (wevtutil cl)
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — Named rule exists (`T1070.001`); no Sysmon EID backstop for `wevtutil cl` specifically -- there is no 'log cleared' Sysmon event Valkyrie currently consumes.
- **Candidate code change (from Tier A analysis, verify against the live miss):** Covered by the architectural fix for the racy-poller case. For a real-time backstop independent of that: consume Windows Security event 1102 ('The audit log was cleared') via the SAME wineventlog.py machinery already used elsewhere (valkyrie/etw/wineventlog.py:parse_event_xml) -- this event is generated by the OS itself at the moment of clearing, independent of catching wevtutil.exe alive.

### T1027 — Obfuscated Files or Information: PowerShell -EncodedCommand  `evasion-encoded-powershell`

- **Tactic:** Defense Evasion
- **Test:** T1027 Test #3
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — classify_cmdline's encoded-PowerShell signal is reachable via TWO different call sites with different reliability: the racy 2s process poll (process_telemetry.ProcInfo.to_event) for a one-shot interactive launch, and the reliable 15s artifact-at-rest persistence scan (_persistence_severity) when the encoded command is stored IN a persistence location rather than run interactively. CONDITIONAL reflects that split: which path applies depends entirely on how the atomic delivers the encoded command.
- **Candidate code change (from Tier A analysis, verify against the live miss):** Covered by the architectural EID1 fix for the interactive-launch case (classify_cmdline could be folded into the same EID1 wiring change, or called alongside classify_behavior since both take a cmdline string). No change needed for the persistence-artifact case -- it is already reliable.

### T1140 — Deobfuscate/Decode Files or Information (certutil -decode)  `evasion-certutil-decode`

- **Tactic:** Defense Evasion
- **Test:** T1140 Test #1
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — etw/sysmon.py's EID 1 (process creation) handler calls classify_process(name, path, parent) -- name/path/lineage only. It never calls classify_behavior() / match_process() from behavioral_rules.py, so the 32 named IOA rules (which contain exactly the patterns these techniques need: regsvr32 /i:, comsvcs.dll MiniDump, wevtutil cl, vssadmin delete shadows, Set-MpPreference -Disable*, reg save hklm\sam, nltest /domain_trusts, wmic /node:, certutil -urlcache) are reachable ONLY through process_telemetry.ProcInfo.to_event(), which is fed exclusively by a plain psutil poll on a 2.0-second interval (ProcessCollector, process_telemetry.py:258). Sysmon's own CommandLine field -- present in the raw ETW event -- is read for nothing else and discarded. Native one-shot commands exit in well under 2 seconds, so this poller loses the race for most of them, REGARDLESS OF WHETHER SYSMON IS INSTALLED, which is the counter-intuitive part: installing Sysmon does not fix this, because Sysmon's process-creation path was never connected to the rule engine that would use it.
- **Candidate code change (from Tier A analysis, verify against the live miss):** In valkyrie/etw/sysmon.py, function classify_sysmon(), the `if eid == 1:` branch (~line 97): after computing `image`/`parent`, also read `cmdline = d.get('CommandLine', '')` and call `behavior = classify_behavior(_name(image), parent, cmdline, image)` from behavioral_rules.py (already imported project-wide; add the import to sysmon.py). If `behavior` is not None, raise `sev` to max(sev, behavior['severity']), merge behavior['labels'] into `labels`, and set `technique = behavior['technique']` on the returned dict (the `technique` field on EID 1 events is currently always ''). This single change gives real-time delivery -- independent of the 2s poller -- to all 32 rules on any host with Sysmon installed, which is exactly the provisioning redteam/provision.ps1 already sets up. It converts most of the 'affects' list above from MISS to a genuine DETECT on a Sysmon-equipped VM, and does not touch the bare-metal (no Sysmon) case, which honestly remains a gap without the kernel driver.

### T1562.004 — Impair Defenses: Disable or Modify System Firewall  `evasion-firewall-disable`

- **Tactic:** Defense Evasion
- **Test:** T1562.004 Test #1 (netsh advfirewall set allprofiles state off)
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — Named rule exists; racy poller only.
- **Candidate code change (from Tier A analysis, verify against the live miss):** Covered by the architectural fix. A stronger, state-based backstop: Valkyrie's own firewall.py could periodically verify (alongside the persistence 15s poll) that the Windows Firewall service state matches what Valkyrie last set, the same pattern as the persistence ASEP scanner -- state drift detected at rest, not dependent on catching the process.

### T1055 — Process Injection (CreateRemoteThread)  `evasion-process-injection`

- **Tactic:** Defense Evasion
- **Test:** T1055.002 Test #1
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — Sysmon EID 8 (CreateRemoteThread) IS wired directly to a real-time classifier in etw/sysmon.py -- this is NOT a wiring gap like the 32 IOA rules. The condition is binary and external: Sysmon must be installed. There is no fallback sensor -- the kernel driver that could provide one (driver/ valkyrie_km, docs/adr/0026) has never been compiled.
- **Candidate code change (from Tier A analysis, verify against the live miss):** No code change to Valkyrie's classifier is needed -- the EID 8 handler is correct as written. The actual blocker is docs/adr/0026's kernel driver, which would give injection visibility without depending on Sysmon at all. Confirming this technique's real-world detection rate is entirely a Tier B question: does the VM have Sysmon installed and configured to log EID 8 (it is NOT logged by Sysmon's default config -- provision.ps1's sysmonconfig must explicitly enable CreateRemoteThread logging, which is high-volume and often excluded by default configs for noise reasons).

### T1003.001 — OS Credential Dumping: LSASS Memory (comsvcs MiniDump)  `cred-lsass-comsvcs`

- **Tactic:** Credential Access
- **Test:** T1003.001 Test #3
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — Sysmon EID 10 (ProcessAccess -> lsass.exe) is wired directly, real-time, independent of the poller -- genuinely the most reliable credential-access detection in the product on a Sysmon-equipped host. The cmdline rule (comsvcs-minidump) is ALSO racy on its own; EID 10 is what actually saves this technique.
- **Candidate code change (from Tier A analysis, verify against the live miss):** No fix needed for the classifier. As with process injection, confirm Sysmon is configured to log EID 10 for lsass.exe specifically (Sysmon's default config typically DOES include an LSASS ProcessAccess rule since it's a well-known high-value signal, but provision.ps1's exact config should be checked rather than assumed).

### T1033 — System Owner/User Discovery (whoami /priv)  `disc-whoami-priv`

- **Tactic:** Discovery
- **Test:** T1033 Test #1
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — A named rule exists (T1033, LOW severity) -- the one Discovery technique with dedicated coverage before this evaluation. whoami.exe exits in single-digit milliseconds, so the racy poller reliably loses this race. This is the exact case the prior redteam/README.md already called 'LIKELY MISS'; this evaluation confirms it via source trace rather than intuition, and generalises it to every single-shot discovery command.
- **Candidate code change (from Tier A analysis, verify against the live miss):** Covered by the architectural EID1 fix for the timing component. But note: LOW severity was likely chosen precisely because a lone `whoami /priv` is weak evidence on its own -- raising it to fire more aggressively as a standalone signal would reintroduce the FP risk the project's design principle argues against. The recon-burst ESP sequence fix (see disc-local-accounts) is the more consistent long-term answer: let whoami contribute a weak signal to a COMBINATION, rather than trying to make it fire reliably alone.

### T1082 — System Information Discovery (systeminfo.exe)  `disc-systeminfo`

- **Tactic:** Discovery
- **Test:** T1082 Test #1
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — No rule exists for systeminfo.exe at all -- a genuine coverage hole, not a wiring hole.
- **Candidate code change (from Tier A analysis, verify against the live miss):** See disc-local-accounts's fix -- part of the same recon-burst ESP sequence, not a standalone rule.

### T1057 — Process Discovery (tasklist.exe)  `disc-tasklist`

- **Tactic:** Discovery
- **Test:** T1057 Test #1
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — No rule exists for tasklist.exe.
- **Candidate code change (from Tier A analysis, verify against the live miss):** Same recon-burst ESP sequence fix.

### T1018 — Remote System Discovery (net view)  `disc-net-view`

- **Tactic:** Discovery
- **Test:** T1018 Test #1
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — No rule exists for `net view`.
- **Candidate code change (from Tier A analysis, verify against the live miss):** Same recon-burst ESP sequence fix.

### T1087.001 — Account Discovery: Local Account (net user)  `disc-local-accounts`

- **Tactic:** Discovery
- **Test:** T1087.001 Test #1
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — See OVERBROAD_RULE_FINDINGS['net-user-add-overbroad'] -- the existing rule fires on this input, but as a MISLABELED T1136.001 hit, not as recognition of T1087.001 discovery. Separately: Discovery techniques that only ever READ state (whoami, systeminfo, tasklist, net view, net user with no argument) are architecturally the hardest tactic for any EDR that scores on process behaviour, because the commands themselves are indistinguishable from routine administration -- the entire category of 'single discovery command, alone, at medium+ severity' is a false-positive generator by construction, and Valkyrie's own precision-over-aggression design principle (documented in behavior_score.py's module docstring) argues against ever firing on one in isolation.
- **Candidate code change (from Tier A analysis, verify against the live miss):** Do not add a HIGH/MEDIUM severity rule for any single discovery command -- that would trade a real detection gap for a real FP generator, which is the wrong trade for this product. Instead: add a WEAK, INFO-severity label ('discovery_command') to classify_process() for a small, curated set of discovery LOLBins (systeminfo.exe, tasklist.exe, net.exe view/user with no mutating args, nltest.exe, whoami.exe), and add a new ESP sequence rule to behavioral_sequences.py: fire (MEDIUM, 'reconnaissance burst') only when >= 3 DISTINCT discovery labels are observed from the SAME actor within a short window (e.g. 120s) -- mirroring the existing 'combination of weak signals' pattern already used for the anomaly scorer. A single `whoami` never fires anything; `whoami` + `systeminfo` + `net user` + `tasklist` inside two minutes does. This is consistent with the project's own stated design philosophy rather than a bolt-on.

### T1482 — Domain Trust Discovery (nltest)  `disc-domain-trust`

- **Tactic:** Discovery
- **Test:** T1482 Test #1
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — A named rule (T1482) exists but is reachable only via the racy 2s poller (nltest.exe exits fast). Requires a domain-joined host to test authentically.
- **Candidate code change (from Tier A analysis, verify against the live miss):** Covered by the architectural Sysmon-EID1 fix above; no additional change needed beyond that.

### T1021.002 — Remote Services: SMB/Windows Admin Shares (PsExec)  `lat-psexec-smb`

- **Tactic:** Lateral Movement
- **Test:** T1021.002 Test #1 (self-target)
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — Named rule exists (T1021.002); racy poller only. CONDITIONAL rather than MISS because PsExec's remote service process tends to run longer than a bare native command. ALSO structurally limited to a single-VM evaluation the same way as the other Lateral Movement entries: a self-target run proves the tool/ service signature is recognised, not that cross-host movement is detected.
- **Candidate code change (from Tier A analysis, verify against the live miss):** Covered by the architectural fix for the single-host signature. The cross-host gap is a test-infrastructure limitation, not a code fix -- see the Lateral Movement tactic note recommending a 2-VM topology for tier 4.

### T1047 — Windows Management Instrumentation (remote node)  `lat-wmi-remote`

- **Tactic:** Lateral Movement
- **Test:** T1047 Test #3 (wmic /node: remote, self-target)
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — Named rule exists; racy poller only. ALSO structurally limited to a single-VM evaluation: real lateral movement requires a second host, so even a perfect detection here only proves the tool signature is recognised, not that cross-host movement specifically is caught.
- **Candidate code change (from Tier A analysis, verify against the live miss):** Covered by the architectural fix for the single-host signature. The cross-host gap is a TEST-INFRASTRUCTURE limitation, not a code fix -- see the Lateral Movement tactic note recommending a 2-VM topology for tier 4.

### T1570 — Lateral Tool Transfer  `lat-tool-transfer`

- **Tactic:** Lateral Movement
- **Test:** T1570 (copy via admin share, self-target)
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — No rule exists for file-copy-to-admin-share patterns at all (`copy X \\host\C$\...`).
- **Candidate code change (from Tier A analysis, verify against the live miss):** Add a rule to behavioral_rules.py: images=('cmd.exe', 'powershell.exe', 'robocopy.exe', 'xcopy.exe'), cmd_any=('\\\\','$\\') combined with a written-executable extension check on the destination -- technique T1570, severity MEDIUM (this pattern alone is common in legitimate IT admin work, so MEDIUM not HIGH, consistent with the project's precision-first stance). Same single-VM caveat as above for proving the cross-host case.

### T1071.004 — Application Layer Protocol: DNS (query to a known tracker)  `c2-dns-tracker-domain`

- **Tactic:** Command and Control
- **Test:** Custom -- DNS resolution to an EasyPrivacy-listed domain
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — valkyrie/dns_interceptor.py:_decide -> site_scanner / blocklist (curated list, NOT a user-defined rule -- see scoring note)
- **Candidate code change (from Tier A analysis, verify against the live miss):** NOT YET DOCUMENTED -- flagging rather than inventing. Add a PER_TECHNIQUE['c2-dns-tracker-domain'] entry to root_cause.py.

### T1071.004 — Application Layer Protocol: DNS (DGA-generated domain)  `c2-dga-domain`

- **Tactic:** Command and Control
- **Test:** Custom -- algorithmically-generated C2 domain
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — valkyrie/dga.py:classify_dga -> dns_interceptor pipeline
- **Candidate code change (from Tier A analysis, verify against the live miss):** NOT YET DOCUMENTED -- flagging rather than inventing. Add a PER_TECHNIQUE['c2-dga-domain'] entry to root_cause.py.

### T1071 — Hardcoded-IP C2 (no DNS lookup at all)  `c2-hardcoded-ip`

- **Tactic:** Command and Control
- **Test:** Custom -- raw connect() to a threat-intel-flagged IP
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — valkyrie/network_telemetry.py:classify_connection -- explicitly designed for exactly this case
- **Candidate code change (from Tier A analysis, verify against the live miss):** NOT YET DOCUMENTED -- flagging rather than inventing. Add a PER_TECHNIQUE['c2-hardcoded-ip'] entry to root_cause.py.

### T1071.004 — DNS Tunneling / high-volume subdomain queries  `c2-dns-tunneling`

- **Tactic:** Command and Control
- **Test:** Custom -- iodine/dnscat2-style query flood
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — valkyrie/dns_tunnel.py:SubdomainFloodDetector
- **Candidate code change (from Tier A analysis, verify against the live miss):** NOT YET DOCUMENTED -- flagging rather than inventing. Add a PER_TECHNIQUE['c2-dns-tunneling'] entry to root_cause.py.

### T1490 — Inhibit System Recovery (vssadmin delete shadows)  `impact-shadow-delete`

- **Tactic:** Impact
- **Test:** T1490 Test #1
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — Named CRITICAL-severity rule exists; racy poller only, and if this atomic runs standalone (not chained after a ransomware encryption phase the canary already caught), a CRITICAL-severity technique may go completely unseen.
- **Candidate code change (from Tier A analysis, verify against the live miss):** Covered by the architectural fix as the primary improvement. Additionally: vssadmin/wbadmin/wmic shadowcopy delete all leave a durable, checkable artifact -- the shadow copy set itself is now empty. A periodic check (`vssadmin list shadows` parsed, or the VSS WMI provider) that detects an unexpected drop in shadow-copy count is an artifact-at-rest signal exactly like the persistence scanner, and would catch this even if the deleting process is never observed at all.

### T1489 — Service Stop (targeting a security-relevant service)  `impact-service-stop`

- **Tactic:** Impact
- **Test:** T1489 Test #1 -- IMPORTANT: in any LIVE run, stop a throwaway service RENAMED into the watched set (e.g. a dummy service named 'Sysmon64'), never the real WinDefend/EventLog and never Valkyrie's own service
- **Live observation:** executed, no matching incident within the detection window
- **Static (Tier A) prediction:** DETECT — No rule exists for `sc stop` / `Stop-Service` / `Set-Service -StartupType Disabled` targeting security-relevant services at all.
- **Candidate code change (from Tier A analysis, verify against the live miss):** Add a new rule to behavioral_rules.py's RULES tuple: images=('sc.exe','powershell.exe'), cmd_any=('stop', 'config start= disabled') combined with a curated set of security-service names (WinDefend, SecurityHealthService, Sysmon64, EventLog, wuauserv, and Valkyrie's own service name) checked as a substring of the full command line -- technique T1489, severity HIGH. Because this is a state-CHANGING action against a well-known, finite list of service names (not a generic pattern), it is also a good candidate for an artifact-at-rest check: a periodic (15s, alongside the persistence scan) query of each watched service's StartMode/State via Win32_Service, flagging any watched service that transitions from Running/Auto to Stopped/Disabled without a corresponding Valkyrie-initiated change. This is the one fix in this report that does not depend on the architectural Sysmon change at all, and is worth prioritizing precisely because it is independently reliable.

## Not a detection failure (reported for completeness)

- **T1059.003 Command and Scripting Interpreter: Windows Command Shell** (`exec-cmd-office-child`): not executed no command — the harness had no runnable command/atomic for this probe
- **T1003.001 OS Credential Dumping: LSASS Memory (procdump)** (`cred-lsass-procdump`): blocked before execution — the host (AV/OS) blocked it before the attacker process ran — `Exception calling "Start" with "0" argument(s): "Access is denied"`
- **T1003.002 OS Credential Dumping: Security Account Manager** (`cred-sam-dump`): blocked before execution — the host (AV/OS) blocked it before the attacker process ran — `This command cannot be run due to the error: Access is denied.`
- **T1555 Credentials from Password Stores** (`cred-browser-stores`): not executed no command — the harness had no runnable command/atomic for this probe
- **T1105 Ingress Tool Transfer (certutil -urlcache download)** (`c2-ingress-tool-transfer`): blocked before execution — the host (AV/OS) blocked it before the attacker process ran — `This command cannot be run due to the error: Access is denied.`
- **T1486 Data Encrypted for Impact (canary-directory encryption)** (`impact-ransomware-encrypt`): blocked before execution — the host (AV/OS) blocked it before the attacker process ran — `Object reference not set to an instance of an object.`

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
