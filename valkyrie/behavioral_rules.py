"""Behavioral detection rules — Indicator-of-Attack (IOA) content engine.

CrowdStrike-style: detection is *content*, not code. Each rule is a small
declarative pattern over a process start (image, parent, command line, path)
that maps to a specific MITRE ATT&CK technique. Broadening coverage means
adding rules — data — not editing branches, and every rule is pure and
unit-tested with a benign control.

This is the endpoint-breadth layer the product was thin on: the older
`classify_process` / `classify_cmdline` heuristics catch a handful of PowerShell
patterns; this adds the LOLBin-proxy, credential-access, defense-evasion,
recovery-inhibition, discovery and lateral-movement command shapes that
Atomic Red Team actually exercises. Hits flow through the existing pipeline —
the collector attaches the rule's technique to the telemetry event, so the
EDR raises a detection and the kill-chain correlator scores it by tactic.

Precision discipline (the standing rule — a false positive erodes trust):
rules match SPECIFIC command shapes, not broad tokens; severities are tuned so
genuinely-ambiguous admin actions (schtasks, whoami) stay medium/low and the
unambiguous ones (vssadmin delete shadows, comsvcs MiniDump of lsass) are
high/critical. Benign controls in tests/test_behavioral_rules.py pin the FP
boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .cmdline_normalize import normalize_cmdline
from .telemetry import (SEV_CRITICAL, SEV_HIGH, SEV_LOW, SEV_MEDIUM,
                        severity_rank)


@dataclass(frozen=True)
class Rule:
    id: str
    technique: str                 # full ATT&CK label, e.g. "T1003.001 — LSASS Memory"
    severity: str
    label: str                     # short slug surfaced on the detection
    reason: str                    # human explanation
    images: tuple = ()             # process basenames this applies to (empty = any)
    images_not: tuple = ()         # process basenames to EXCLUDE (empty = none)
    parents: tuple = ()            # parent basenames (empty = any)
    cmd_all: tuple = ()            # ALL of these substrings must be present
    cmd_any: tuple = ()            # ANY of these substrings present
    path_any: tuple = ()           # ANY of these substrings in the image path

    def matches(self, image: str, parent: str, cmd: str, path: str) -> bool:
        if self.images and image not in self.images:
            return False
        if self.images_not and image in self.images_not:
            return False
        if self.parents and parent not in self.parents:
            return False
        if self.cmd_all and not all(t in cmd for t in self.cmd_all):
            return False
        if self.cmd_any and not any(t in cmd for t in self.cmd_any):
            return False
        if self.path_any and not any(t in path for t in self.path_any):
            return False
        # A rule with no POSITIVE condition never fires (guards against typos;
        # images_not alone is not enough — it must pair with a positive match).
        return bool(self.images or self.parents or self.cmd_all
                    or self.cmd_any or self.path_any)


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    label: str
    technique: str
    severity: str
    reason: str


_OFFICE = ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
           "msaccess.exe", "mspub.exe", "onenote.exe")
_SHELLS = ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
           "cscript.exe", "mshta.exe")

# ── The shipped IOA rule set ────────────────────────────────────────────────
# Grouped by tactic. Techniques are real ATT&CK ids; severities are tuned for
# precision. Extend by appending — no engine changes needed.
RULES: tuple = (
    # ─ Execution ─
    Rule("office-spawns-shell", "T1059 — Command & Scripting Interpreter", SEV_HIGH,
         "office_child_shell", "An Office application spawned a shell/script host",
         images=_SHELLS, parents=_OFFICE),
    Rule("wmic-process-call", "T1047 — Windows Management Instrumentation", SEV_HIGH,
         "wmic_process_call", "wmic used to create a process",
         images=("wmic.exe",), cmd_all=("process", "call", "create")),
    # Modern WMI process creation: PowerShell Invoke-CimMethod / Invoke-WmiMethod
    # against Win32_Process Create. wmic.exe is removed from Windows 11, so this
    # is how T1047 actually executes now — the wmic-only rule above misses it.
    # Matches the command shape on whatever host runs it (usually powershell.exe).
    Rule("wmi-cim-process-create", "T1047 — Windows Management Instrumentation", SEV_HIGH,
         "wmi_process_create", "WMI used to create a process (Win32_Process Create)",
         cmd_all=("win32_process",),
         cmd_any=("create", "invoke-cimmethod", "invoke-wmimethod")),
    # The ROBUST catch — needs no command line at all: WMI creates its child
    # under WmiPrvSE.exe, so ANY process born from WmiPrvSE (except WMI's own
    # internal helpers) is WMI-based execution. This fires even when the launch
    # command is base64-encoded/obfuscated (which hides "win32_process") and
    # regardless of what the payload is (calc, cmd, a dropped exe) — the cases
    # that slipped past a wmic-only or command-line-only rule. images_not keeps
    # WMI's legitimate internal helpers from tripping it.
    Rule("wmi-spawned-process", "T1047 — Windows Management Instrumentation", SEV_HIGH,
         "wmi_process_create", "A process was created by WMI (WmiPrvSE parent)",
         parents=("wmiprvse.exe",),
         images_not=("wmiprvse.exe", "wmiadap.exe", "scrcons.exe", "mofcomp.exe",
                     "wmic.exe", "unsecapp.exe")),
    Rule("mshta-remote", "T1218.005 — Mshta", SEV_HIGH,
         "mshta_exec", "mshta executed a remote or inline script",
         images=("mshta.exe",), cmd_any=("http://", "https://", "javascript:", "vbscript:")),
    Rule("regsvr32-scriptlet", "T1218.010 — Regsvr32 (Squiblydoo)", SEV_HIGH,
         "regsvr32_scriptlet", "regsvr32 loaded a remote scriptlet (Squiblydoo)",
         images=("regsvr32.exe",), cmd_any=("/i:http", "scrobj", "/i:https")),
    Rule("rundll32-proxy", "T1218.011 — Rundll32", SEV_HIGH,
         "rundll32_proxy", "rundll32 proxied script/remote execution",
         images=("rundll32.exe",),
         cmd_any=("javascript:", "http://", "https://", "mshtml", "url.dll,openurl")),
    # The other half of T1218.011, and the one the rule above missed: rundll32
    # loading a DLL from a USER-WRITABLE directory. Legitimate rundll32 use
    # loads DLLs out of System32/SysWOW64/Program Files — a signed OS binary
    # being pointed at C:\Users\Public\evil.dll,EntryPoint is the classic
    # "proxy execution to look like a trusted process" shape, and the exported
    # entry point after the comma is what a normal Windows operation never has
    # in those paths. Found by the red-team evaluation (exec-rundll32-proxy
    # replayed the DLL form, not the remote-script form, and nothing fired).
    Rule("rundll32-lowtrust-dll", "T1218.011 — Rundll32", SEV_HIGH,
         "rundll32_proxy", "rundll32 loaded a DLL from a user-writable directory",
         images=("rundll32.exe",), cmd_all=(".dll,",),
         cmd_any=("\\users\\public\\", "\\appdata\\", "\\temp\\", "\\downloads\\",
                  "\\programdata\\", "\\windows\\temp\\", "\\perflogs\\")),
    # LOW, not MEDIUM: "an executable ran from temp/downloads" is not by itself
    # an attack — installers, updaters and uninstallers do it constantly, and as
    # a standalone MEDIUM this false-positived on Valkyrie's own installer and on
    # NSIS uninstallers. At LOW it is observed and still contributes its label +
    # T1204 mapping when it CO-OCCURS with a real signal (a LOLBin, a download
    # cradle, an obfuscated command), but it no longer raises an incident alone.
    Rule("suspicious-path-exec", "T1204 — User Execution", SEV_LOW,
         "suspicious_path", "Executable ran from a temp/download directory",
         path_any=("\\temp\\", "\\downloads\\", "\\appdata\\local\\temp",
                   "\\windows\\temp")),

    # ─ Defense Evasion ─
    Rule("certutil-download", "T1105 — Ingress Tool Transfer", SEV_HIGH,
         "certutil_download", "certutil used to download a file",
         images=("certutil.exe",), cmd_any=("-urlcache", "-verifyctl", "-split")),
    Rule("certutil-decode", "T1140 — Deobfuscate/Decode", SEV_HIGH,
         "certutil_decode", "certutil used to decode an encoded payload",
         images=("certutil.exe",), cmd_any=("-decode", "-decodehex")),
    Rule("bitsadmin-transfer", "T1197 — BITS Jobs", SEV_MEDIUM,
         "bitsadmin_transfer", "bitsadmin used to transfer a file",
         images=("bitsadmin.exe",), cmd_any=("/transfer", "/addfile")),
    Rule("netsh-firewall-off", "T1562.004 — Disable/Modify System Firewall", SEV_HIGH,
         "firewall_disabled", "Windows firewall disabled via netsh",
         images=("netsh.exe",), cmd_all=("firewall", "off")),
    Rule("defender-disable", "T1562.001 — Impair Defenses: Disable Tools", SEV_HIGH,
         "defender_tamper", "Microsoft Defender protection disabled",
         cmd_any=("disablerealtimemonitoring", "set-mppreference -disable",
                  "sc stop windefend", "sc.exe stop windefend",
                  "add-mppreference -exclusionpath")),
    Rule("amsi-bypass", "T1562.001 — Impair Defenses: AMSI", SEV_HIGH,
         "amsi_bypass", "In-memory AMSI bypass pattern",
         cmd_any=("amsiinitfailed", "amsiutils", "[ref].assembly.gettype('system.management.automation.amsi")),
    Rule("clear-eventlog", "T1070.001 — Clear Windows Event Logs", SEV_HIGH,
         "eventlog_cleared", "Windows event logs cleared",
         cmd_any=("wevtutil cl", "wevtutil.exe cl", "clear-eventlog",
                  "clear-winevent", "limit-eventlog")),
    Rule("usn-journal-delete", "T1070 — Indicator Removal", SEV_HIGH,
         "usn_deleted", "USN change journal deleted (anti-forensics)",
         images=("fsutil.exe",), cmd_all=("usn", "deletejournal")),
    Rule("execpolicy-bypass", "T1059.001 — PowerShell (ExecutionPolicy Bypass)", SEV_MEDIUM,
         "execpolicy_bypass", "PowerShell execution policy bypassed",
         cmd_any=("-executionpolicy bypass", "-ep bypass", "-exec bypass")),

    # ─ Credential Access ─
    Rule("comsvcs-minidump", "T1003.001 — LSASS Memory (comsvcs MiniDump)", SEV_CRITICAL,
         "lsass_access", "rundll32 comsvcs.dll MiniDump of a process (LSASS dumping)",
         cmd_all=("comsvcs", "minidump")),
    Rule("procdump-lsass", "T1003.001 — LSASS Memory (procdump)", SEV_CRITICAL,
         "lsass_access", "procdump used against lsass",
         cmd_all=("lsass",), cmd_any=("procdump", "-ma ")),
    Rule("reg-save-hive", "T1003.002 — Security Account Manager", SEV_HIGH,
         "sam_dump", "Registry SAM/SYSTEM hive saved (credential theft)",
         images=("reg.exe",), cmd_all=("save",), cmd_any=("hklm\\sam", "hklm\\system", "hklm\\security")),
    Rule("ntdsutil-ifm", "T1003.003 — NTDS", SEV_HIGH,
         "ntds_dump", "ntdsutil IFM export (domain credential theft)",
         images=("ntdsutil.exe",), cmd_any=("ifm", "create full")),
    Rule("vaultcmd-creds", "T1555 — Credentials from Password Stores", SEV_MEDIUM,
         "vault_enum", "Windows Credential Manager enumerated",
         images=("vaultcmd.exe",), cmd_any=("/list", "/listcreds")),

    # ─ Persistence ─
    Rule("reg-add-runkey", "T1547.001 — Registry Run Keys / Startup", SEV_HIGH,
         "persistence_runkey", "Autostart Run key created via reg.exe",
         images=("reg.exe",), cmd_all=("add",),
         cmd_any=("\\currentversion\\run", "\\currentversion\\runonce",
                  "\\winlogon", "\\userinit")),
    Rule("schtasks-create", "T1053.005 — Scheduled Task", SEV_MEDIUM,
         "persistence_task", "Scheduled task created",
         images=("schtasks.exe",), cmd_any=("/create",)),
    Rule("sc-create-service", "T1543.003 — Windows Service", SEV_MEDIUM,
         "persistence_service", "New Windows service created",
         images=("sc.exe",), cmd_any=("create",)),
    # Two rules, not one, and cmd_all (ALL required) rather than cmd_any (ANY
    # of these). The single previous rule matched on the bare substring
    # "net user" / "net localgroup administrators" with no mutating verb
    # required, so `net user` alone -- listing accounts, completely routine
    # admin activity -- fired the identical MEDIUM "account created" incident
    # as `net user backdoor P@ss /add`. Found by the red-team evaluation
    # (redteam/evaluation/root_cause.py: net-user-add-overbroad) replaying
    # T1087.001 (Account Discovery) and getting a T1136.001 hit instead: the
    # rule couldn't tell "list" from "create". Requiring /add removes the
    # false positive without losing recall -- every genuine T1136.001 atomic
    # includes /add.
    Rule("net-user-add", "T1136.001 — Create Local Account", SEV_MEDIUM,
         "account_created", "Local account created via net user /add",
         cmd_all=("net user", "/add")),
    Rule("net-localgroup-admin-add", "T1136.001 — Create Local Account", SEV_MEDIUM,
         "account_created", "Account added to local Administrators group",
         cmd_all=("net localgroup administrators", "/add")),
    Rule("wmi-event-consumer", "T1546.003 — WMI Event Subscription", SEV_HIGH,
         "persistence_wmi", "WMI permanent event subscription (persistence)",
         cmd_any=("__eventfilter", "commandlineeventconsumer", "__filtertoconsumerbinding")),

    # ─ Impact (recovery inhibition — ransomware precursors) ─
    Rule("vssadmin-delete", "T1490 — Inhibit System Recovery", SEV_CRITICAL,
         "shadow_delete", "Volume shadow copies deleted (ransomware precursor)",
         cmd_all=("delete", "shadows"), cmd_any=("vssadmin", "wmic")),
    Rule("wbadmin-delete", "T1490 — Inhibit System Recovery", SEV_HIGH,
         "backup_delete", "Windows backup catalog deleted",
         images=("wbadmin.exe",), cmd_all=("delete",)),
    Rule("bcdedit-recovery-off", "T1490 — Inhibit System Recovery", SEV_HIGH,
         "recovery_disabled", "Boot recovery disabled via bcdedit",
         images=("bcdedit.exe",),
         cmd_any=("recoveryenabled no", "bootstatuspolicy ignoreallfailures")),
    # Stopping/disabling a security-relevant service is a common pre-attack or
    # ransomware-precursor step (kill the AV/EDR/logging before the real
    # payload runs). Two rules — not one cmd_any of "verb + service" pairs —
    # because "stop" (sc.exe/net.exe/Stop-Service) and "disabled" (sc config
    # .../Set-Service -StartupType Disabled) are different command shapes;
    # cmd_all pins the required verb token, cmd_any is the curated set of
    # security-relevant service names, so "sc query windefend" (no verb match)
    # and "net stop spooler" (verb matches, service does not) both stay clear.
    Rule("service-stop-security", "T1489 — Service Stop", SEV_HIGH,
         "security_service_stop", "A security-relevant service was stopped",
         images=("sc.exe", "net.exe", "powershell.exe", "pwsh.exe"),
         cmd_all=("stop",),
         cmd_any=("windefend", "securityhealthservice", "sysmon64", "sysmon",
                  "eventlog", "wuauserv", "valkyrie")),
    Rule("service-disable-security", "T1489 — Service Stop", SEV_HIGH,
         "security_service_stop", "A security-relevant service was disabled",
         images=("sc.exe", "powershell.exe", "pwsh.exe"),
         cmd_all=("disabled",),
         cmd_any=("windefend", "securityhealthservice", "sysmon64", "sysmon",
                  "eventlog", "wuauserv", "valkyrie")),

    # ─ Discovery ─
    Rule("nltest-domain", "T1482 — Domain Trust Discovery", SEV_MEDIUM,
         "domain_discovery", "Domain/DC enumeration via nltest",
         images=("nltest.exe",), cmd_any=("/dclist", "/domain_trusts")),
    Rule("whoami-priv", "T1033 — System Owner/User Discovery", SEV_LOW,
         "user_discovery", "Privilege/group enumeration via whoami",
         images=("whoami.exe",), cmd_any=("/priv", "/groups", "/all")),

    # ─ Lateral Movement ─
    Rule("psexec-remote", "T1021.002 — SMB/Admin Shares (PsExec)", SEV_HIGH,
         "lateral_psexec", "PsExec-style remote execution",
         cmd_any=("psexec \\\\", "psexec.exe \\\\", "paexec \\\\")),
    # The RECEIVING end, which the rule above cannot see. psexec-remote matches
    # the operator's outbound command — useful only on the machine the attacker
    # already controls. PSEXESVC.exe is the service binary PsExec drops and
    # starts on the TARGET, so its presence means someone moved laterally INTO
    # this host. That is the more valuable half of the signal for a defender:
    # it is evidence of an intrusion arriving, needs no command line at all
    # (matching on image name alone), and no legitimate software ships a
    # process by these names. PAExec/RemCom are the common PsExec clones.
    Rule("psexec-service-host", "T1021.002 — SMB/Admin Shares (PsExec)", SEV_HIGH,
         "lateral_psexec", "PsExec-style remote-execution service running on THIS host "
                            "(inbound lateral movement)",
         images=("psexesvc.exe", "paexec.exe", "remcomsvc.exe", "csexecsvc.exe")),
    Rule("wmic-remote-node", "T1047 — WMI (remote node)", SEV_HIGH,
         "lateral_wmic", "Remote command execution via wmic /node",
         images=("wmic.exe",), cmd_any=("/node:",)),
    # A UNC path (cmd_all pins the literal "\\\\") to a well-known ADMINISTRATIVE
    # share (C$/ADMIN$/IPC$/D$ — cmd_any) is the PsExec-era way to stage a tool
    # on a remote host. MEDIUM, not HIGH: legitimate IT admin work copies files
    # to admin shares too (per the redteam-evaluation lat-tool-transfer finding),
    # so this is a real but modest signal — a plain UNC path to a NORMAL share
    # (no $) never matches, which keeps ordinary file-server copies clear.
    Rule("lateral-tool-transfer", "T1570 — Lateral Tool Transfer", SEV_MEDIUM,
         "lateral_tool_transfer", "A file was copied to a remote administrative share",
         images=("cmd.exe", "powershell.exe", "pwsh.exe", "robocopy.exe", "xcopy.exe"),
         cmd_all=("\\\\",), cmd_any=("c$", "d$", "admin$", "ipc$")),
)


def match_process(image: str, parent: str, cmdline: str,
                  path: str = "") -> list[RuleHit]:
    """Return all rule hits for a process start, highest severity first. Pure.

    Rules are matched against the raw command line AND its de-obfuscated form
    (cmdline_normalize), and the hits are unioned. Matching BOTH is deliberate:
    normalization can then only ever ADD detections, so a rule that depends on
    raw syntax can never be broken by a normalizer change. Without this, every
    rule here is defeated by `n^et us^er /a^dd` — measured, 5 of 8 trivial
    obfuscations evaded the entire rule set.
    """
    im = (image or "").lower()
    par = (parent or "").lower()
    cmd = (cmdline or "").lower()
    pth = (path or "").lower().replace("/", "\\")

    seen: dict[str, RuleHit] = {}
    for r in RULES:
        if r.matches(im, par, cmd, pth):
            seen[r.id] = RuleHit(r.id, r.label, r.technique, r.severity, r.reason)

    norm = normalize_cmdline(cmdline)
    if norm.changed:
        ncmd = norm.text.lower()
        if ncmd != cmd:
            for r in RULES:
                if r.id not in seen and r.matches(im, par, ncmd, pth):
                    seen[r.id] = RuleHit(r.id, r.label, r.technique, r.severity,
                                         r.reason + " (recovered from an "
                                         "obfuscated command line)")

    hits = list(seen.values())
    hits.sort(key=lambda h: severity_rank(h.severity), reverse=True)
    return hits


def classify_behavior(image: str, parent: str, cmdline: str,
                      path: str = "") -> Optional[dict]:
    """Top-level convenience: the highest-severity hit as a dict the collector
    merges into a telemetry event, plus every label. None if nothing fired.

    Returns: {severity, labels, technique, reason} — technique is the top hit's
    ATT&CK id so the EDR/kill-chain get an exact tactic.

    Obfuscation is treated as evidence in its own right. A command line built
    with caret/backtick escaping, token-splitting quotes, character arithmetic
    or string concatenation has no legitimate reason to look that way, so it
    escalates a rule hit and — on its own — still reports MEDIUM/T1027. That
    keeps the "attacker obfuscated something we have no rule for" case visible
    instead of silent. Cosmetic normalization (whitespace, env vars) never
    triggers this; only the EVASIVE transform class does.
    """
    hits = match_process(image, parent, cmdline, path)
    norm = normalize_cmdline(cmdline)

    if not hits:
        if norm.obfuscated:
            return {
                "severity": SEV_MEDIUM,
                "technique": "T1027 — Obfuscated Files or Information",
                "labels": ["obfuscated_command"],
                "reason": ("command line uses evasion syntax with no functional "
                           "purpose (" + ", ".join(norm.obfuscation_signals) + ")"),
                "rule_ids": [],
                "normalized": norm.text,
            }
        return None

    top = hits[0]
    labels = list(dict.fromkeys(h.label for h in hits))
    reason = "; ".join(dict.fromkeys(h.reason for h in hits))
    severity = top.severity
    if norm.obfuscated:
        labels.append("obfuscated_command")
        reason += ("; obfuscated via " + ", ".join(norm.obfuscation_signals))
        # A known-bad command that was ALSO obfuscated is less ambiguous than
        # the same command typed plainly — an admin does not caret-escape.
        if severity_rank(severity) < severity_rank(SEV_HIGH):
            severity = SEV_HIGH
    return {
        "severity": severity,
        "technique": top.technique,
        "labels": labels,
        "reason": reason,
        "rule_ids": [h.rule_id for h in hits],
        "normalized": norm.text if norm.changed else "",
    }
