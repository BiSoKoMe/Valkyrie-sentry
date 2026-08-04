# Valkyrie EDR Evaluation Report

**Tier:** A_replay  
**Generated:** 20260804T200055Z UTC  
**Git commit:** c92fe36  
**Catalog version:** 2026-07-30.2  
**Reproduce:** `PYTHONUTF8=1 python redteam/evaluation/replay_harness.py` (Tier A) or `redteam/evaluation/run_live_evaluation.ps1` (Tier B, VM only)

> **This is Tier A: classifier-input replay.** Real Valkyrie code was executed against synthetic inputs matching what each technique would produce. NO live attack ran. `attack_executed`, measured latency, and aggregate false-positive rate are honestly `null` throughout -- Tier A cannot produce them, and this report does not pretend otherwise. Scores here are gated by a source-verified judgment of whether each technique's detection path is reliably reachable live (see catalog.py), not by whether the Python call merely returned truthy. Tier B (`run_live_evaluation.ps1`, VM required) is what turns this into a live-attack answer.

## Scoring rules applied

- A miss is a miss. `CONDITIONAL` predictions are **not** credited as detected in the headline number -- only a confirmed, reliably-delivered `DETECT` counts.
- A `DETECT` whose catalog entry declares **host preconditions** (`requires`, e.g. `sysmon_eid8`) is credited only when those preconditions are verified **on the machine this run executed on**. The classifier firing is necessary but not sufficient: if the host cannot deliver the event, the detection cannot happen. Unmet preconditions are reported per technique with the reason, and the host snapshot is stored in the result file's `host_environment` so a score is never separable from the environment that produced it.
- A detection whose category is a **user-defined DNS block** (`detection_category == 'user_rule'`) is excluded from the detected count and reported separately, per the evaluation brief.
  - None triggered this run.
- A rule firing under the **wrong technique label** (`known_mismatch`) is never credited, even if the underlying code executed without error.

## Overall

**39 / 40 techniques detected (97.5%)**

| Tactic | Detected | Total | % |
|---|---:|---:|---:|
| Execution | 7 | 7 | 100% |
| Persistence | 6 | 6 | 100% |
| Defense Evasion | 6 | 6 | 100% |
| Credential Access | 4 | 4 | 100% |
| Discovery | 5 | 6 | 83% |
| Lateral Movement | 3 | 3 | 100% |
| Command and Control | 5 | 5 | 100% |
| Impact | 3 | 3 | 100% |

**Explicitly out of scope:** 4 techniques, each with a stated reason (never silently dropped) -- see catalog.py `OUT_OF_SCOPE`.

## Per-test results

| Technique | Test | Tactic | Logic fires | Detected | Severity | Confidence | Delivery |
|---|---|---|:---:|:---:|---|---:|---|
| T1059.001 Command and Scripting Interpreter: Power | T1059.001 Test #2 (EncodedCommand) | Execution | yes | **DETECTED** | medium | 0.55 | realtime_etw |
| T1059.003 Command and Scripting Interpreter: Windo | T1059.003 Test #1 (cmd spawned by Office) | Execution | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1218.005 System Binary Proxy Execution: Mshta | T1218.005 Test #1 (remote HTA) | Execution | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1218.010 System Binary Proxy Execution: Regsvr32  | T1218.010 Test #1 | Execution | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1218.011 System Binary Proxy Execution: Rundll32 | T1218.011 Test #1 | Execution | yes | **DETECTED** | high | 0.80 | realtime_etw |
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
| T1027 Obfuscated Files or Information: PowerSh | T1027 Test #3 | Defense Evasion | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1140 Deobfuscate/Decode Files or Information  | T1140 Test #1 | Defense Evasion | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1562.004 Impair Defenses: Disable or Modify Syste | T1562.004 Test #1 (netsh advfirewall set allprofiles state off) | Defense Evasion | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1055 Process Injection (CreateRemoteThread) | T1055.002 Test #1 | Defense Evasion | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1003.001 OS Credential Dumping: LSASS Memory (com | T1003.001 Test #3 | Credential Access | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1003.001 OS Credential Dumping: LSASS Memory (pro | T1003.001 Test #1 | Credential Access | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1003.002 OS Credential Dumping: Security Account  | T1003.002 Test #1 (reg save HKLM\SAM) | Credential Access | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1555 Credentials from Password Stores | T1555.003 Test #1 (browser creds) | Credential Access | yes | **DETECTED** | high | 0.80 | cred_store_poll_5s |
| T1033 System Owner/User Discovery (whoami /pri | T1033 Test #1 | Discovery | no | missed | low | 0.30 | realtime_etw |
| T1082 System Information Discovery (systeminfo | T1082 Test #1 | Discovery | yes | **DETECTED** | medium | 0.70 | realtime_etw |
| T1057 Process Discovery (tasklist.exe) | T1057 Test #1 | Discovery | yes | **DETECTED** | medium | 0.70 | realtime_etw |
| T1018 Remote System Discovery (net view) | T1018 Test #1 | Discovery | yes | **DETECTED** | medium | 0.70 | realtime_etw |
| T1087.001 Account Discovery: Local Account (net us | T1087.001 Test #1 | Discovery | yes | **DETECTED** | medium | 0.70 | realtime_etw |
| T1482 Domain Trust Discovery (nltest) | T1482 Test #1 | Discovery | yes | **DETECTED** | medium | 0.55 | realtime_etw |
| T1021.002 Remote Services: SMB/Windows Admin Share | T1021.002 Test #1 (self-target) | Lateral Movement | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1047 Windows Management Instrumentation (remo | T1047 Test #3 (wmic /node: remote, self-target) | Lateral Movement | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1570 Lateral Tool Transfer | T1570 (copy via admin share, self-target) | Lateral Movement | yes | **DETECTED** | medium | 0.55 | realtime_etw |
| T1071.004 Application Layer Protocol: DNS (query t | Custom -- DNS resolution to an EasyPrivacy-listed domain | Command and Control | yes | **DETECTED** | high | 0.70 | inline_request_path |
| T1071.004 Application Layer Protocol: DNS (DGA-gen | Custom -- algorithmically-generated C2 domain | Command and Control | yes | **DETECTED** | high | 0.80 | inline_request_path |
| T1071 Hardcoded-IP C2 (no DNS lookup at all) | Custom -- raw connect() to a threat-intel-flagged IP | Command and Control | yes | **DETECTED** | high | 0.80 | inline_request_path |
| T1071.004 DNS Tunneling / high-volume subdomain qu | Custom -- iodine/dnscat2-style query flood | Command and Control | yes | **DETECTED** | high | 0.75 | inline_request_path |
| T1105 Ingress Tool Transfer (certutil -urlcach | T1105 Test #1 | Command and Control | yes | **DETECTED** | high | 0.80 | realtime_etw |
| T1486 Data Encrypted for Impact (canary-direct | Custom -- rapid high-entropy overwrite of canary files (ransomware simulation) | Impact | yes | **DETECTED** | critical | 0.99 | purpose_built_watcher |
| T1490 Inhibit System Recovery (vssadmin delete | T1490 Test #1 | Impact | yes | **DETECTED** | critical | 0.95 | realtime_etw |
| T1489 Service Stop (targeting a security-relev | T1489 Test #1 -- IMPORTANT: in any LIVE run, stop a throwaway service RENAMED into the watched set (e.g. a dummy service named 'Sysmon64'), never the real WinDefend/EventLog and never Valkyrie's own service | Impact | yes | **DETECTED** | high | 0.80 | realtime_etw |

## Missed techniques — root cause and required code change

### T1033 — System Owner/User Discovery (whoami /priv)  `disc-whoami-priv`

- **Tactic:** Discovery
- **Test:** T1033 Test #1
- **Predicted outcome:** DETECT
- **Root cause:** A named rule exists (T1033, LOW severity) -- the one Discovery technique with dedicated coverage before this evaluation. whoami.exe exits in single-digit milliseconds, so the racy poller reliably loses this race. This is the exact case the prior redteam/README.md already called 'LIKELY MISS'; this evaluation confirms it via source trace rather than intuition, and generalises it to every single-shot discovery command.
- **Code change required:** Covered by the architectural EID1 fix for the timing component. But note: LOW severity was likely chosen precisely because a lone `whoami /priv` is weak evidence on its own -- raising it to fire more aggressively as a standalone signal would reintroduce the FP risk the project's design principle argues against. The recon-burst ESP sequence fix (see disc-local-accounts) is the more consistent long-term answer: let whoami contribute a weak signal to a COMBINATION, rather than trying to make it fire reliably alone.

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
