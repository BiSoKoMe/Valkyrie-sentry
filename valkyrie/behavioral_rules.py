"""Behavioral detection rules - Indicator-of-Attack (IOA) content engine.

CrowdStrike-style: detection is *content*, not code. Each rule is a small
declarative pattern over a process start (image, parent, command line, path)
that maps to a specific MITRE ATT&CK technique. Broadening coverage means
adding rules - data - not editing branches, and every rule is pure and
unit-tested with a benign control.

This is the endpoint-breadth layer the product was thin on: the older
`classify_process` / `classify_cmdline` heuristics catch a handful of PowerShell
patterns; this adds the LOLBin-proxy, credential-access, defense-evasion,
recovery-inhibition, discovery and lateral-movement command shapes that
Atomic Red Team actually exercises. Hits flow through the existing pipeline -
the collector attaches the rule's technique to the telemetry event, so the
EDR raises a detection and the kill-chain correlator scores it by tactic.

Precision discipline (the standing rule - a false positive erodes trust):
rules match SPECIFIC command shapes, not broad tokens; severities are tuned so
genuinely-ambiguous admin actions (schtasks, whoami) stay medium/low and the
unambiguous ones (vssadmin delete shadows, comsvcs MiniDump of lsass) are
high/critical. Benign controls in tests/test_behavioral_rules.py pin the FP
boundary.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .cmdline_normalize import normalize_cmdline
from .telemetry import (SEV_CRITICAL, SEV_HIGH, SEV_LOW, SEV_MEDIUM,
                        severity_rank)


@dataclass(frozen=True)
class Rule:
    id: str
    technique: str                 # full ATT&CK label, e.g. "T1003.001 - LSASS Memory"
    severity: str
    label: str                     # short slug surfaced on the detection
    reason: str                    # human explanation
    images: tuple = ()             # process basenames this applies to (empty = any)
    images_not: tuple = ()         # process basenames to EXCLUDE (empty = none)
    parents: tuple = ()            # parent basenames (empty = any)
    parents_not: tuple = ()        # parent basenames to EXCLUDE (empty = none)
    cmd_all: tuple = ()            # ALL of these substrings must be present
    cmd_any: tuple = ()            # ANY of these substrings present
    cmd_any2: tuple = ()           # a SECOND independent ANY-group, ANDed with
                                   # cmd_any - lets a rule require (any A) AND
                                   # (any B), e.g. (any download verb) AND (any
                                   # executable extension), which one cmd_any
                                   # alone cannot express.
    cmd_any3: tuple = ()           # a THIRD ANY-group, same rationale. Needed to
                                   # separate "wrote a payload INTO Startup" from
                                   # "ran normally FROM Startup": both mention the
                                   # folder and an executable extension, and only
                                   # the write VERB tells them apart.
    cmd_not: tuple = ()            # EXCLUSIONS - if any is present, do not fire.
                                   #
                                   # Every mature vendor rule is mostly exclusions;
                                   # Valkyrie had no way to express one, so its
                                   # rules were structurally more false-positive
                                   # prone than the content it wanted to import.
                                   #
                                   # DANGER, and the standard for adding one: an
                                   # exclusion is an attacker-visible bypass. If a
                                   # rule skips anything containing "\sysvol\",
                                   # an attacker who knows that hosts their payload
                                   # under a share called sysvol. So an exclusion
                                   # must key on something the attacker does NOT
                                   # control, or must be narrow enough that forging
                                   # it costs more than the detection is worth. An
                                   # exclusion that is trivially forgeable AND
                                   # guards a high-value signal must not be added
                                   # at all - accept the false positive or fix the
                                   # rule some other way.
    path_any: tuple = ()           # ANY of these substrings in the image path
    signed: str = ""               # required Authenticode state, "" = don't care
                                   #
                                   # "unsigned"     - verified as carrying none
                                   # "untrusted"    - signed but not acceptable
                                   #                  (revoked/expired/tampered)
                                   # "not_trusted"  - either of the above
                                   #
                                   # FAIL CLOSED: when the signature state is
                                   # UNKNOWN - a locked file, access denied, a
                                   # verification error - a rule keying on it
                                   # must NOT fire. Treating "we could not
                                   # check" as "unsigned" would let a transient
                                   # read failure manufacture a detection
                                   # against real software, which is the one
                                   # outcome this project never ships.

    def matches(self, image: str, parent: str, cmd: str, path: str,
                signature: str = "") -> bool:
        if self.images and image not in self.images:
            return False
        if self.images_not and image in self.images_not:
            return False
        if self.parents and parent not in self.parents:
            return False
        if self.parents_not and parent in self.parents_not:
            return False
        if self.cmd_all and not all(t in cmd for t in self.cmd_all):
            return False
        if self.cmd_any and not any(t in cmd for t in self.cmd_any):
            return False
        if self.cmd_any2:
            # Match cmd_any2 against the ARGUMENTS only - drop the leading
            # executable token - so a launcher basename (e.g. "powershell.exe")
            # cannot itself satisfy an ".exe" payload-extension check. This is
            # what makes "IWR ... -OutFile out.json" (benign) separable from
            # "IWR http://evil/a.exe" (a download cradle).
            _, _, _args = cmd.partition(" ")
            if not any(t in _args for t in self.cmd_any2):
                return False
        if self.cmd_any3 and not any(t in cmd for t in self.cmd_any3):
            return False
        # Exclusions are evaluated LAST and on the same normalised command line
        # the positive terms saw, so an exclusion cannot be smuggled past by the
        # obfuscation the normaliser already undoes.
        if self.cmd_not and any(t in cmd for t in self.cmd_not):
            return False
        if self.path_any and not any(t in path for t in self.path_any):
            return False
        if self.signed:
            sig = (signature or "").lower()
            # Fail closed: unknown/absent signature state never satisfies a
            # signature requirement.
            if sig in ("", "unknown"):
                return False
            if self.signed == "not_trusted":
                if sig not in ("unsigned", "untrusted"):
                    return False
            elif sig != self.signed:
                return False
        # A rule with no POSITIVE condition never fires (guards against typos;
        # images_not/cmd_not alone are not enough - they must pair with a
        # positive match).
        return bool(self.images or self.parents or self.cmd_all
                    or self.cmd_any or self.cmd_any2 or self.cmd_any3
                    or self.path_any or self.signed)


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

# Security-product service names that ransomware / EDR-killers stop or disable
# before detonating (T1489 / T1562.001). Curated set of major AV/EDR/logging
# services - broadened from real advisory data (Black Basta 'sc stop Sense' =
# Defender for Endpoint; LockBit 'net stop SamSs'). Substring-matched, so the
# required stop/disabled verb (cmd_all) is what keeps 'net stop spooler' clear.
_SECURITY_SERVICES = (
    "windefend", "securityhealthservice", "wscsvc", "sense", "wdnissvc",
    "wdfilter", "mpssvc", "sysmon64", "sysmon", "eventlog", "wuauserv",
    "samss", "sepmasterservice", "sophos", "csfalconservice", "csagent",
    "cylancesvc", "sentinelagent", "sentinelone", "mcafeeframework", "valkyrie",
)

# --- The shipped IOA rule set ---
# Grouped by tactic. Techniques are real ATT&CK ids; severities are tuned for
# precision. Extend by appending - no engine changes needed.
RULES: tuple = (
    # - Execution -
    Rule("office-spawns-shell", "T1059 — Command & Scripting Interpreter", SEV_HIGH,
         "office_child_shell", "An Office application spawned a shell/script host",
         images=_SHELLS, parents=_OFFICE),
    Rule("wmic-process-call", "T1047 — Windows Management Instrumentation", SEV_HIGH,
         "wmic_process_call", "wmic used to create a process",
         images=("wmic.exe",), cmd_all=("process", "call", "create")),
    # Modern WMI process creation: PowerShell Invoke-CimMethod / Invoke-WmiMethod
    # against Win32_Process Create. wmic.exe is removed from Windows 11, so this
    # is how T1047 actually executes now - the wmic-only rule above misses it.
    # Matches the command shape on whatever host runs it (usually powershell.exe).
    Rule("wmi-cim-process-create", "T1047 — Windows Management Instrumentation", SEV_HIGH,
         "wmi_process_create", "WMI used to create a process (Win32_Process Create)",
         cmd_all=("win32_process",),
         cmd_any=("create", "invoke-cimmethod", "invoke-wmimethod")),
    # The ROBUST catch - needs no command line at all: WMI creates its child
    # under WmiPrvSE.exe, so ANY process born from WmiPrvSE (except WMI's own
    # internal helpers) is WMI-based execution. This fires even when the launch
    # command is base64-encoded/obfuscated (which hides "win32_process") and
    # regardless of what the payload is (calc, cmd, a dropped exe) - the cases
    # that slipped past a wmic-only or command-line-only rule. images_not keeps
    # WMI's legitimate internal helpers from tripping it.
    Rule("wmi-spawned-process", "T1047 — Windows Management Instrumentation", SEV_HIGH,
         "wmi_process_create", "A process was created by WMI (WmiPrvSE parent)",
         parents=("wmiprvse.exe",),
         images_not=("wmiprvse.exe", "wmiadap.exe", "scrcons.exe", "mofcomp.exe",
                     "wmic.exe", "unsecapp.exe")),
    # DELIBERATELY NOT NARROWED. Elastic's corpus contains one benign exclusion
    # here - an app using `mshta vbscript:close(CreateObject(...).Popup(...))`
    # to show a notification. Excluding ".popup(" would clear that single false
    # positive and simultaneously hand every attacker a two-word bypass, because
    # the string costs nothing to add to a hostile command line. `mshta` running
    # inline vbscript:/javascript: is a high-value, hard-to-fake signal, so the
    # false positive is ACCEPTED rather than traded for a public bypass. Not
    # every finding should be fixed; this is what the exclusion standard on
    # Rule.cmd_not means in practice.
    Rule("mshta-remote", "T1218.005 — Mshta", SEV_HIGH,
         "mshta_exec", "mshta executed a remote or inline script",
         images=("mshta.exe",), cmd_any=("http://", "https://", "javascript:", "vbscript:")),
    Rule("regsvr32-scriptlet", "T1218.010 — Regsvr32 (Squiblydoo)", SEV_HIGH,
         "regsvr32_scriptlet", "regsvr32 loaded a remote scriptlet (Squiblydoo)",
         images=("regsvr32.exe",), cmd_any=("/i:http", "scrobj", "/i:https")),
    # `mshtml` as a bare token matched mshtml.dll,PrintHTML - printing a web page
    # - which Elastic's fleet exclusions show is ordinary user activity. The
    # actual proxy-execution vector is the RunHTMLApplication export, so key on
    # that instead. Not an exclusion: a narrower positive, which an attacker
    # cannot sidestep because RunHTMLApplication IS the technique.
    Rule("rundll32-proxy", "T1218.011 — Rundll32", SEV_HIGH,
         "rundll32_proxy", "rundll32 proxied script/remote execution",
         images=("rundll32.exe",),
         cmd_any=("javascript:", "http://", "https://", "url.dll,openurl",
                  "mshtml.dll,runhtmlapplication", "mshtml,runhtmlapplication")),
    # The other half of T1218.011, and the one the rule above missed: rundll32
    # loading a DLL from a USER-WRITABLE directory. Legitimate rundll32 use
    # loads DLLs out of System32/SysWOW64/Program Files - a signed OS binary
    # being pointed at C:\Users\Public\evil.dll,EntryPoint is the classic
    # "proxy execution to look like a trusted process" shape, and the exported
    # entry point after the comma is what a normal Windows operation never has
    # in those paths. Found by the red-team evaluation (exec-rundll32-proxy
    # replayed the DLL form, not the remote-script form, and nothing fired).
    # DROP ZONES, not application directories. The original list included bare
    # \appdata\ and \programdata\, which are where legitimate software INSTALLS
    # itself - Elastic's fleet exclusions caught WebEx
    # (\appdata\local\webex\...\atasctrl.dll,StartHostLauncher) and Admin By
    # Request (\programdata\fasttrack software\...\shellhelper32.dll,#1) doing
    # exactly this. A staging directory a payload is dropped into is the signal;
    # a vendor's install directory is not.
    Rule("rundll32-lowtrust-dll", "T1218.011 — Rundll32", SEV_HIGH,
         "rundll32_proxy", "rundll32 loaded a DLL from a user-writable directory",
         images=("rundll32.exe",), cmd_all=(".dll,",),
         cmd_any=("\\users\\public\\", "\\temp\\", "\\downloads\\",
                  "\\appdata\\local\\temp\\", "\\appdata\\roaming\\microsoft\\windows\\",
                  "\\windows\\temp\\", "\\perflogs\\", "\\$recycle.bin\\")),
    # LOW, not MEDIUM: "an executable ran from temp/downloads" is not by itself
    # an attack - installers, updaters and uninstallers do it constantly, and as
    # a standalone MEDIUM this false-positived on Valkyrie's own installer and on
    # NSIS uninstallers. At LOW it is observed and still contributes its label +
    # T1204 mapping when it CO-OCCURS with a real signal (a LOLBin, a download
    # cradle, an obfuscated command), but it no longer raises an incident alone.
    Rule("suspicious-path-exec", "T1204 — User Execution", SEV_LOW,
         "suspicious_path", "Executable ran from a temp/download directory",
         path_any=("\\temp\\", "\\downloads\\", "\\appdata\\local\\temp",
                   "\\windows\\temp")),

    # - Defense Evasion -
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
                  "add-mppreference -exclusionpath",
                  # Weakening expressed as "set value to the insecure number"
                  # rather than a -Disable* flag: cloud protection off, never
                  # submit samples. Generalizes past the -Disable vocabulary.
                  "mapsreporting 0", "mapsreporting:0", "-mapsreporting 0",
                  "submitsamplesconsent 2", "submitsamplesconsent:2")),
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
    # LOW, not MEDIUM, for the same reason as suspicious-path-exec: this is a
    # CONTEXT signal, not a detection. Elastic's fleet exclusions show
    # -ExecutionPolicy Bypass on winget's own updater, Windows Auto-Update
    # notifiers and Azure AD SSO logon scripts - it is how a large amount of
    # legitimate enterprise tooling invokes PowerShell at all. At LOW it still
    # carries its label and T1059.001 mapping when it CO-OCCURS with a real
    # signal, but it no longer raises an incident on its own.
    Rule("execpolicy-bypass", "T1059.001 — PowerShell (ExecutionPolicy Bypass)", SEV_LOW,
         "execpolicy_bypass", "PowerShell execution policy bypassed",
         cmd_any=("-executionpolicy bypass", "-ep bypass", "-exec bypass")),
    # Base64 -EncodedCommand payload. The label 'encoded_powershell' is also
    # set by process_telemetry.classify_cmdline (and maps to T1027 downstream),
    # but that leaves the Sysmon EID1 rule path with an empty `technique` field
    # unless the engine's label fallback happens to run -- so give the rule
    # engine its own technique tag (T1059.001) here, self-contained. Image-
    # gated to the PowerShell hosts and mirrors classify_cmdline's _ENCODED_PS
    # token set so the two never disagree. Precision: `-enc`/`-ec` on
    # powershell.exe's own command line is EncodedCommand; a bare `-e` is not
    # included (it collides with unrelated args).
    # LOW, and this one is safe to demote because it is REDUNDANT for the
    # malicious case: cmdline_normalize decodes the base64 before rules run, so
    # a hostile payload is caught by the rules that match its DECODED content
    # (verified: an encoded IEX download cradle fires ps-download-cradle-exec,
    # remote-download-iex, clickfix-run-dialog-exec and
    # remote-fetch-executable-generic). What is left when those do not fire is
    # an encoded command whose contents are benign - which is what Elastic's
    # exclusions are full of. So the encoding alone stays as context, and the
    # payload is what raises the incident.
    Rule("powershell-encoded-command", "T1059.001 — PowerShell (EncodedCommand)", SEV_LOW,
         "encoded_powershell", "PowerShell ran a base64 -EncodedCommand payload",
         images=("powershell.exe", "pwsh.exe"),
         cmd_any=("-enc ", "-enc:", "-encodedcommand", "-ec ")),

    # - Credential Access -
    # Both the named export ("comsvcs.dll MiniDump") and the ORDINAL form
    # ("comsvcs.dll,#24") which evades a "minidump" string match - #24 is the
    # MiniDump ordinal, used specifically to hide the technique.
    Rule("comsvcs-minidump", "T1003.001 — LSASS Memory (comsvcs MiniDump)", SEV_CRITICAL,
         "lsass_access", "rundll32 comsvcs.dll MiniDump of a process (LSASS dumping)",
         cmd_all=("comsvcs",), cmd_any=("minidump", "#24", ",#24", " #24")),
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

    # - Persistence -
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
    # Require the /add verb AND any of the net-invocation spellings. The old
    # cmd_all=("net user", "/add") matched `net user X /add` but SILENTLY MISSED
    # `net.exe user X /add` -- the form a real Sysmon EID1 CommandLine carries
    # ("net.exe user" has no "net user" substring) -- so the single most basic
    # persistence atomic evaded the rule live. cmd_any covers both spellings
    # (and the obfuscation normalizer folds `n^et us^er` back to `net user`),
    # while cmd_all=("/add",) keeps `net user` alone (listing) and `net view`
    # clear. Image-agnostic on purpose: the technique is just as real whether
    # net.exe is the process or a child of cmd.exe/powershell.exe.
    Rule("net-user-add", "T1136.001 — Create Local Account", SEV_MEDIUM,
         "account_created", "Local account created via net user /add",
         cmd_all=("/add",), cmd_any=("net user", "net.exe user", "net1 user")),
    Rule("net-localgroup-admin-add", "T1136.001 — Create Local Account", SEV_MEDIUM,
         "account_created", "Account added to local Administrators group",
         cmd_all=("localgroup", "administrators", "/add")),
    Rule("wmi-event-consumer", "T1546.003 — WMI Event Subscription", SEV_HIGH,
         "persistence_wmi", "WMI permanent event subscription (persistence)",
         cmd_any=("__eventfilter", "commandlineeventconsumer", "__filtertoconsumerbinding")),

    # - Impact (recovery inhibition - ransomware precursors) -
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
    # payload runs). Two rules - not one cmd_any of "verb + service" pairs -
    # because "stop" (sc.exe/net.exe/Stop-Service) and "disabled" (sc config
    # .../Set-Service -StartupType Disabled) are different command shapes;
    # cmd_all pins the required verb token, cmd_any is the curated set of
    # security-relevant service names, so "sc query windefend" (no verb match)
    # and "net stop spooler" (verb matches, service does not) both stay clear.
    Rule("service-stop-security", "T1489 — Service Stop", SEV_HIGH,
         "security_service_stop", "A security-relevant service was stopped",
         images=("sc.exe", "net.exe", "powershell.exe", "pwsh.exe"),
         cmd_all=("stop",),
         cmd_any=_SECURITY_SERVICES),
    Rule("service-disable-security", "T1489 — Service Stop", SEV_HIGH,
         "security_service_stop", "A security-relevant service was disabled",
         images=("sc.exe", "powershell.exe", "pwsh.exe"),
         cmd_all=("disabled",),
         cmd_any=_SECURITY_SERVICES),

    # - Discovery -
    Rule("nltest-domain", "T1482 — Domain Trust Discovery", SEV_MEDIUM,
         "domain_discovery", "Domain/DC enumeration via nltest",
         images=("nltest.exe",), cmd_any=("/dclist", "/domain_trusts")),
    Rule("whoami-priv", "T1033 — System Owner/User Discovery", SEV_LOW,
         "user_discovery", "Privilege/group enumeration via whoami",
         images=("whoami.exe",), cmd_any=("/priv", "/groups", "/all")),

    # - Lateral Movement -
    Rule("psexec-remote", "T1021.002 — SMB/Admin Shares (PsExec)", SEV_HIGH,
         "lateral_psexec", "PsExec-style remote execution",
         cmd_any=("psexec \\\\", "psexec.exe \\\\", "paexec \\\\")),
    # The RECEIVING end, which the rule above cannot see. psexec-remote matches
    # the operator's outbound command - useful only on the machine the attacker
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
    # share (C$/ADMIN$/IPC$/D$ - cmd_any) is the PsExec-era way to stage a tool
    # on a remote host. MEDIUM, not HIGH: legitimate IT admin work copies files
    # to admin shares too (per the redteam-evaluation lat-tool-transfer finding),
    # so this is a real but modest signal - a plain UNC path to a NORMAL share
    # (no $) never matches, which keeps ordinary file-server copies clear.
    # The loopback exclusion is semantic, not a concession: \\127.0.0.1\ADMIN$
    # and \\localhost\C$ are the LOCAL machine, so by definition no lateral
    # movement happened. Safe against forgery too - an attacker who reroutes
    # their transfer through loopback has not moved laterally either.
    Rule("lateral-tool-transfer", "T1570 — Lateral Tool Transfer", SEV_MEDIUM,
         "lateral_tool_transfer", "A file was copied to a remote administrative share",
         images=("cmd.exe", "powershell.exe", "pwsh.exe", "robocopy.exe", "xcopy.exe"),
         cmd_all=("\\\\",), cmd_any=("c$", "d$", "admin$", "ipc$"),
         cmd_not=("\\\\127.0.0.1\\", "\\\\localhost\\", "\\\\.\\", "\\\\::1\\")),

    # ---
    # Extended LOLBin / trusted-utility execution (T1218 family, T1127).
    # Each was a live MISS in the hard-adversarial corpus
    # (scratchpad/hard_redteam.py). Signatures pinned to the unmistakable
    # malicious argument shape so benign use of the same binary stays clear -
    # verified against a benign sibling per case.
    # ---
    Rule("mavinject-inject", "T1055.001 — Process Injection (mavinject)", SEV_HIGH,
         "dll_injection", "mavinject used to inject a DLL into a running process",
         images=("mavinject.exe", "mavinject32.exe"),
         cmd_any=("/injectrunning", "injectrunning")),
    Rule("installutil-exec", "T1218.004 — InstallUtil", SEV_HIGH,
         "lolbin_dotnet_exec", "InstallUtil used to execute a .NET assembly (uninstall bypass)",
         images=("installutil.exe",),
         cmd_any=("/logfile=", "/u ", "/u\t", "/logtoconsole")),
    # /U (unregister - runs the assembly's UnregisterClass, a code-exec vector)
    # OR an assembly loaded from a user-writable/temp path. Plain `regasm MyLib.dll`
    # registering a normally-pathed assembly (no /U) stays clear: every legit
    # regasm/regsvcs call operates on a .dll, so ".dll" alone is not a signal.
    Rule("regasm-regsvcs-exec", "T1218.009 — Regsvcs/Regasm", SEV_HIGH,
         "lolbin_dotnet_exec", "Regasm/Regsvcs used to execute a .NET assembly (unregister/temp-path)",
         # \programdata\ dropped for the same reason as rundll32-lowtrust-dll:
         # it is an application INSTALL root, not a staging directory, and
         # Elastic's exclusions show real installers registering assemblies from
         # under it. The genuine drop zones are kept.
         images=("regasm.exe", "regsvcs.exe"),
         cmd_any=("/u", "\\users\\public\\", "\\temp\\", "\\appdata\\local\\temp",
                  "\\downloads\\", "\\windows\\temp")),
    # The REGSVR action string is the DLL-loading vector; plain DSN configuration
    # (/a {CONFIGSYSDSN ...}) is routine, so match REGSVR specifically, not /a.
    Rule("odbcconf-regsvr", "T1218.008 — Odbcconf", SEV_HIGH,
         "lolbin_dll_exec", "odbcconf REGSVR action used to load a DLL",
         images=("odbcconf.exe",), cmd_any=("regsvr",)),
    Rule("cmstp-exec", "T1218.003 — CMSTP", SEV_HIGH,
         "lolbin_inf_exec", "CMSTP silent-install of an INF (proxy exec / UAC bypass)",
         images=("cmstp.exe",), cmd_any=("/s", "/ns", "/au")),
    # \SYSVOL\ is Group Policy software installation - present in every Active
    # Directory domain on earth, and the single highest-volume false positive
    # this rule can produce. Elastic ships this same exclusion to their fleet.
    #
    # It IS forgeable (an attacker could name a share "sysvol"), and that is
    # accepted deliberately rather than silently: forging it requires the
    # attacker to already control a reachable share AND get msiexec pointed at
    # it, while NOT forging it means alerting on routine domain administration
    # on every managed machine. The http/https/ftp arms are untouched.
    Rule("msiexec-remote", "T1218.007 — Msiexec (remote package)", SEV_HIGH,
         "lolbin_remote_msi", "msiexec installing a package from a remote/UNC source",
         images=("msiexec.exe",),
         cmd_any=("http://", "https://", "\\\\", "ftp://"),
         cmd_not=("\\sysvol\\",)),
    Rule("wuauclt-proxy", "T1218 — Signed Binary Proxy (wuauclt)", SEV_HIGH,
         "lolbin_proxy_exec", "wuauclt UpdateDeploymentProvider used to load a DLL",
         images=("wuauclt.exe",),
         cmd_any=("updatedeploymentprovider", "runhandlercomserver")),
    Rule("pcalua-proxy", "T1218 — Signed Binary Proxy (pcalua)", SEV_MEDIUM,
         "lolbin_proxy_exec", "Program Compatibility Assistant used to proxy-execute a binary",
         images=("pcalua.exe",), cmd_any=("-a",)),
    # forfiles /c runs a command per matched file - a real proxy-exec primitive,
    # but `forfiles /c "cmd /c del @file"` is also routine admin cleanup, so this
    # is LOW: a weak signal that contributes to a reconnaissance/exec sequence
    # rather than alerting on its own.
    Rule("forfiles-proxy", "T1059 — Command Execution Proxy (forfiles)", SEV_LOW,
         "lolbin_proxy_exec", "forfiles used to execute a command",
         images=("forfiles.exe",), cmd_any=("/c ", "/c\t")),
    Rule("hh-remote", "T1218.001 — Compiled HTML Help", SEV_MEDIUM,
         "lolbin_chm_exec", "hh.exe opened a remote CHM (compiled-HTML-help exec)",
         images=("hh.exe",), cmd_any=("http://", "https://", "ftp://")),
    Rule("msbuild-untrusted", "T1127.001 — MSBuild inline task", SEV_MEDIUM,
         "trusted_dev_exec", "MSBuild ran a project from a user-writable/temp path (inline-task exec)",
         images=("msbuild.exe",),
         cmd_any=("\\temp\\", "\\users\\public\\", "\\downloads\\",
                  "\\appdata\\local\\temp", "\\programdata\\", "\\windows\\temp")),
    # Squiblydoo where a shell WRAPS regsvr32 (image is cmd.exe/powershell.exe,
    # so the image-pinned regsvr32-scriptlet rule above can't see it): the
    # scriptlet COM object + a remote scriptlet path is unmistakable regardless
    # of which process carries the command line.
    Rule("scriptlet-remote-anyimage", "T1218.010 — Regsvr32 (Squiblydoo)", SEV_HIGH,
         "regsvr32_scriptlet", "Remote scriptlet (scrobj) load — image-agnostic catch",
         cmd_all=("scrobj",), cmd_any=("/i:http", "/i:https", "http://", "https://")),

    # - Credential access via alternate binaries -
    Rule("esentutl-cred-copy", "T1003 — Credential Store Copy (esentutl)", SEV_HIGH,
         "credential_copy", "esentutl used to copy a locked credential store (NTDS/SAM/VSS)",
         images=("esentutl.exe",),
         cmd_any=("ntds", "\\config\\sam", "/vss", "\\sam ", "sam.")),

    # - Recovery inhibition via alternate binary -
    Rule("diskshadow-script", "T1490 — Inhibit System Recovery (diskshadow)", SEV_HIGH,
         "shadow_manipulation", "diskshadow script mode (shadow-copy manipulation)",
         images=("diskshadow.exe",), cmd_any=("/s", "delete shadows")),

    # - WMI XSL script execution (Squiblytwo) -
    Rule("wmic-xsl", "T1220 — XSL Script Processing (WMIC)", SEV_HIGH,
         "wmic_xsl_exec", "WMIC /format with a remote XSL (Squiblytwo)",
         images=("wmic.exe",),
         cmd_any=("/format:http", "/format:\"http", "/format:'http", ".xsl")),

    # - PowerShell-native persistence (no cmd-line LOLBin; the cmdlet IS the IOA) -
    Rule("ps-new-service", "T1543.003 — Windows Service (New-Service)", SEV_MEDIUM,
         "persistence_service", "Service created via PowerShell New-Service",
         images=("powershell.exe", "pwsh.exe"), cmd_all=("new-service",)),
    Rule("ps-register-schtask", "T1053.005 — Scheduled Task (Register-ScheduledTask)", SEV_MEDIUM,
         "persistence_scheduled_task", "Scheduled task created via PowerShell Register-ScheduledTask",
         images=("powershell.exe", "pwsh.exe"),
         cmd_any=("register-scheduledtask", "new-scheduledtask")),

    # - PowerShell download cradle to an EXECUTABLE payload (T1105) -
    # (any download verb) AND (any executable-writing extension). Benign
    # IWR/curl to a .json/.txt/.zip data file stays clear - verified against a
    # benign `Invoke-WebRequest ... -OutFile out.json` sibling.
    Rule("ps-download-cradle-exec", "T1105 — Ingress Tool Transfer (PowerShell)", SEV_HIGH,
         "download_cradle", "PowerShell downloaded an executable payload",
         images=("powershell.exe", "pwsh.exe"),
         cmd_any=("invoke-webrequest", "iwr ", "invoke-restmethod", "irm ",
                  "start-bitstransfer", "downloadfile", "downloadstring",
                  "wget ", "curl "),
         cmd_any2=(".exe", ".dll", ".ps1", ".scr", ".bat", ".hta", ".vbs", ".jse")),

    # - UAC bypass: a known auto-elevating binary SPAWNS a shell (T1548.002) -
    # The no-argument fodhelper/computerdefaults case is a registry-hijack IOA
    # (handled by the registry sensor), not a command-line one - flagging the
    # bare launch would false-positive on legitimate Settings use. What IS
    # unambiguous on the process graph: one of these auto-elevators spawning a
    # command shell, which only happens as the bypass payload.
    Rule("uac-bypass-elevator-child", "T1548.002 — Bypass UAC (auto-elevator spawns shell)", SEV_HIGH,
         "uac_bypass", "A known auto-elevating binary spawned a command shell (UAC bypass)",
         images=("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"),
         parents=("fodhelper.exe", "computerdefaults.exe", "sdclt.exe",
                  "wsreset.exe", "slui.exe", "eventvwr.exe", "fltmc.exe")),

    # ---
    # Round 2 (2026-08-12): AV/log tampering, more LOLBins & credential
    # dumpers, registry-ASEP persistence. Each was a live MISS; benign
    # read-only siblings (wevtutil qe, reg query, Get-MpPreference, netsh
    # show, logman query) verified to stay clear.
    # ---
    # Defender exclusions of any kind - the classic "carve a hole then drop the
    # payload into it" step. Add-MpPreference WRITES; Get-MpPreference (read)
    # never matches.
    Rule("defender-exclusion", "T1562.001 — Impair Defenses: AV Exclusion", SEV_HIGH,
         "defender_tamper", "A Microsoft Defender exclusion was added",
         images=("powershell.exe", "pwsh.exe"),
         cmd_all=("add-mppreference",), cmd_any=("exclusion",)),
    # Defender disabled via policy registry keys.
    Rule("defender-disable-reg", "T1562.001 — Impair Defenses: Disable AV (registry)", SEV_HIGH,
         "defender_tamper", "Microsoft Defender disabled via a policy registry value",
         images=("reg.exe",), cmd_all=("add",),
         cmd_any=("disableantispyware", "disableantivirus",
                  "disablerealtimemonitoring", "tamperprotection",
                  "disablebehaviormonitoring", "disableioavprotection")),
    # Event Log channel disabled (wevtutil set-log /e:false) - blinds a channel
    # without the noisy "log cleared" (1102) event that `wevtutil cl` raises.
    Rule("wevtutil-disable-log", "T1562.002 — Disable Windows Event Logging", SEV_HIGH,
         "logging_tamper", "An event-log channel was disabled via wevtutil sl /e:false",
         images=("wevtutil.exe",), cmd_all=("sl", "/e:false")),
    # ETW trace stopped/deleted (logman) - kills a live telemetry source.
    Rule("logman-etw-stop", "T1562.006 — Indicator Blocking (ETW)", SEV_MEDIUM,
         "logging_tamper", "An ETW trace was stopped/deleted via logman",
         images=("logman.exe",), cmd_any=("stop", "delete"),
         cmd_any2=("-ets", "eventlog", "autologger", "-provider")),
    # Follina (msdt) - the ms-msdt / PCWDiagnostic diagnostic-tool exec vector.
    Rule("msdt-follina", "T1218 — MSDT (Follina)", SEV_HIGH,
         "lolbin_msdt_exec", "msdt invoked with a diagnostic-exec payload (Follina)",
         images=("msdt.exe",),
         cmd_any=("pcwdiagnostic", "ms-msdt", "it_launchmethod", "it_browseforfile")),
    # LOLBin downloaders.
    Rule("desktopimgdownldr-download", "T1105 — Ingress Tool Transfer (desktopimgdownldr)", SEV_HIGH,
         "download_cradle", "desktopimgdownldr used to fetch a remote file",
         images=("desktopimgdownldr.exe",), cmd_any=("lockscreenurl", "http")),
    Rule("certreq-download", "T1105 — Ingress Tool Transfer (certreq)", SEV_MEDIUM,
         "download_cradle", "certreq -Post to a remote HTTP endpoint",
         images=("certreq.exe",), cmd_all=("-post",),
         cmd_any=("http://", "https://")),
    Rule("finger-download", "T1105 — Ingress Tool Transfer (finger)", SEV_MEDIUM,
         "download_cradle", "finger.exe used as a download/exec channel",
         images=("finger.exe",), cmd_any=("@", "|")),
    # Alternate LSASS dumper by tool name (PID-based dumps are caught by the
    # Sysmon EID10 ProcessAccess sensor instead).
    Rule("createdump-lsass", "T1003.001 — LSASS Memory (createdump)", SEV_CRITICAL,
         "lsass_dump", "createdump used against LSASS",
         images=("createdump.exe",), cmd_any=("lsass",)),
    # Registry-ASEP persistence beyond Run keys.
    Rule("ifeo-debugger", "T1546.012 — Image File Execution Options Injection", SEV_HIGH,
         "persistence_ifeo", "A debugger was attached to a program via IFEO (persistence/priv-esc)",
         images=("reg.exe",),
         cmd_all=("image file execution options",), cmd_any=("debugger", "globalflag")),
    Rule("appinit-dlls", "T1546.010 — AppInit DLLs", SEV_HIGH,
         "persistence_appinit", "AppInit_DLLs modified (DLL loaded into every GUI process)",
         images=("reg.exe",), cmd_all=("add",), cmd_any=("appinit_dlls",)),
    Rule("netsh-helper-dll", "T1546.007 — Netsh Helper DLL", SEV_HIGH,
         "persistence_netsh", "A netsh helper DLL was registered (persistence)",
         images=("netsh.exe",), cmd_all=("add", "helper")),
    # Timestomping - setting a file's timestamps to blend in.
    Rule("timestomp-ps", "T1070.006 — Timestomp", SEV_MEDIUM,
         "indicator_removal", "File timestamps set via PowerShell (timestomp)",
         images=("powershell.exe", "pwsh.exe"),
         cmd_any=(".lastwritetime =", ".lastwritetime=", ".creationtime =",
                  ".creationtime=", ".lastaccesstime =", ".lastaccesstime=")),
    # Legacy at.exe scheduling - deprecated; scheduling a command is suspicious.
    Rule("at-schedule", "T1053.002 — Scheduled Task/Job: At", SEV_MEDIUM,
         "persistence_at", "A task was scheduled via the legacy at.exe",
         images=("at.exe",),
         cmd_any=("/interactive", "cmd", ".exe", ".bat", ".ps1", "\\", "/every")),

    # ---
    # Round 3 (2026-08-12): advanced credential access, fileless in-memory
    # execution, and high-value misc tradecraft. Image-AGNOSTIC where the
    # command-line string itself is the unmistakable IOA (these tools are
    # routinely renamed), so a renamed mimikatz.exe is caught by its module
    # names, not its filename. Benign siblings verified (Get-MpPreference,
    # Add-Type -AssemblyName, cipher /c, runas without /savecred, IRM GET).
    # ---
    # Mimikatz / DCSync / LSA dumping by unmistakable command string - renaming
    # the exe does not change what the operator must type.
    Rule("mimikatz-signatures", "T1003 — OS Credential Dumping (Mimikatz/DCSync)", SEV_CRITICAL,
         "credential_dumping", "Mimikatz / DCSync / LSA-dump command signature",
         cmd_any=("sekurlsa", "lsadump", "kerberos::", "dcsync", "invoke-mimikatz",
                  "::logonpasswords", "privilege::debug", "get-adreplaccount",
                  "lsadump::sam", "mimidrv", "rpc::")),
    # WDigest cleartext-credential caching re-enabled (a pre-dump setup step).
    Rule("wdigest-enable", "T1112 — Modify Registry (WDigest cleartext creds)", SEV_HIGH,
         "credential_access_setup", "WDigest UseLogonCredential enabled to cache cleartext creds",
         images=("reg.exe", "powershell.exe", "pwsh.exe"),
         cmd_any=("uselogoncredential",)),
    # Credential Manager UI / keymgr credential access.
    # LOW: rundll32 keymgr.dll,KRShowKeyMgr opens the Stored User Names and
    # Passwords DIALOG. It is a UI action a user performs deliberately, not an
    # automated credential-theft primitive - it cannot exfiltrate anything
    # without a human at the keyboard, which is why Elastic treat it as benign.
    # Kept as context (it is genuinely interesting next to other credential
    # signals) but it must not raise an incident when somebody opens Credential
    # Manager.
    Rule("keymgr-creds", "T1555 — Credentials from Password Stores (keymgr)", SEV_LOW,
         "credential_store_access", "Credential Manager accessed via keymgr.dll",
         images=("rundll32.exe",), cmd_any=("keymgr", "krshowkeymgr")),
    # Fileless: reflective .NET assembly load from bytes/base64 (in-memory, no
    # file on disk). Loading an assembly from a PATH is common and stays clear -
    # the byte/base64 source is the tell.
    Rule("reflective-assembly-load", "T1620 — Reflective Code Loading", SEV_HIGH,
         "reflective_load", "In-memory .NET assembly load from bytes/base64",
         images=("powershell.exe", "pwsh.exe"),
         cmd_any=("assembly]::load", "reflection.assembly]::load", "[appdomain]::"),
         cmd_any2=("frombase64string", "[byte[", "convert]::from", "readallbytes",
                   "downloaddata", "[system.io.")),
    # Base64-decode piped straight to Invoke-Expression - the canonical fileless
    # cradle. Decoding alone is fine; decode + IEX is not.
    Rule("decode-and-iex", "T1059.001 — PowerShell (decode + Invoke-Expression)", SEV_HIGH,
         "obfuscated_exec", "Base64-decoded content executed via Invoke-Expression",
         images=("powershell.exe", "pwsh.exe"),
         cmd_all=("frombase64string",), cmd_any=("iex", "invoke-expression", "| iex", "&(")),
    # In-memory C#/PInvoke compile via Add-Type -TypeDefinition. Add-Type
    # -AssemblyName (loading a framework assembly) is routine and stays clear.
    Rule("addtype-compile", "T1059.001 — PowerShell (in-memory compile)", SEV_MEDIUM,
         "inmemory_compile", "PowerShell compiled inline C#/PInvoke via Add-Type -TypeDefinition",
         images=("powershell.exe", "pwsh.exe"),
         cmd_all=("add-type",), cmd_any=("-typedefinition", "-memberdefinition")),
    # Wiping free space / a path with cipher /w destroys deleted-file recovery
    # (anti-forensics / pre-ransom). cipher /c (status) and /e /d stay clear.
    Rule("cipher-wipe", "T1485 — Data Destruction (cipher /w)", SEV_MEDIUM,
         "secure_wipe", "cipher /w used to wipe free space (anti-forensics)",
         images=("cipher.exe",), cmd_any=("/w",)),
    # Killing a security product's PROCESS by name (taskkill / Stop-Process).
    # Ordinary taskkill of a normal app never matches - the watched-name list is.
    Rule("kill-security-process", "T1562.001 — Impair Defenses: Kill Security Tool", SEV_HIGH,
         "defender_tamper", "A security product's process was force-killed",
         # Kill MECHANISM is generalized: taskkill, PowerShell Stop-Process, WMI
         # (process where ... delete / call terminate), and the classic ntsd -c q /
         # pskill / pssuspend - so switching the tool used to kill does not evade.
         cmd_any=("taskkill", "stop-process", "kill ", "/im ", "process where",
                  "call terminate", "process delete", "ntsd", "pskill",
                  "pssuspend"),
         cmd_any2=("msmpeng", "nissrv", "windefend", "securityhealthservice",
                   "mssense", "sense.exe", "senseir", "sensecncproxy",
                   "csfalcon", "csagent", "carbonblack", "cb.exe", "cylancesvc",
                   "cyoptics", "sentinelagent", "sentinelone", "sophos",
                   "savservice", "mcshield", "avp.exe", "ekrn", "bdagent",
                   "bdservicehost", "wrsa", "xagt", "sysmon", "sysmon64",
                   "procmon", "wireshark", "elastic-agent", "elastic-endpoint")),
    # Exfiltration: an HTTP client uploading a local file (-InFile / -Method Post
    # with a body file). A plain GET to fetch data (no upload) stays clear.
    Rule("exfil-http-upload", "T1041 — Exfiltration Over C2 Channel", SEV_HIGH,
         "exfiltration", "A local file was uploaded over HTTP (exfiltration)",
         images=("powershell.exe", "pwsh.exe", "curl.exe", "wget.exe"),
         cmd_any=("invoke-restmethod", "invoke-webrequest", "curl", "wget"),
         cmd_any2=("-infile", "-t ", "--upload-file", "-method post",
                   "-method put", "-f ", "--form", "file=@", "--data-binary")),
    # Remote WinRM session - dual-use (admins use it too), so MEDIUM: a real but
    # modest lateral-movement signal, consistent with the project's precision stance.
    Rule("winrm-lateral", "T1021.006 — Remote Services: WinRM", SEV_MEDIUM,
         "lateral_winrm", "Remote PowerShell/WinRM session to another host",
         images=("powershell.exe", "pwsh.exe"),
         cmd_any=("enter-pssession", "new-pssession", "invoke-command"),
         cmd_any2=("-computername", "-cn ", "-connectionuri", "-vmname")),
    # runas with /savecred reuses a stored credential without re-prompting - a
    # credential-abuse pattern; plain runas (interactive) stays clear.
    Rule("runas-savecred", "T1078 — Valid Accounts (runas /savecred)", SEV_MEDIUM,
         "stored_cred_abuse", "runas reused a stored credential (/savecred)",
         images=("runas.exe",), cmd_any=("/savecred",)),

    # ---
    # Round 4 (2026-08-12): Kerberos attacks, pass-the-hash, named credential
    # dumpers, more signed-binary-proxy LOLBins, COM hijack, port-forward,
    # BITS persistence. Command-string IOAs are image-agnostic (offensive tools
    # are routinely renamed). Benign siblings verified: setspn -L, portproxy
    # show, reg query CLSID, bitsadmin /list, extrac32 /Y, wsl --list.
    # ---
    # Kerberoasting / AS-REP roasting / ticket requests - Rubeus + the common
    # PowerShell/Impacket function names.
    Rule("kerberoast-tooling", "T1558.003 — Kerberoasting", SEV_HIGH,
         "kerberoasting", "Kerberoast / AS-REP roast / ticket-request tooling",
         cmd_any=("kerberoast", "asreproast", "invoke-kerberoast", "get-domainspnticket",
                  "getuserspns", "rubeus", "asktgt", "asktgs", "tgtdeleg", "/ptt",
                  "kerberos::golden", "kerberos::silver", "createnetonly")),
    # setspn -Q */* enumerates SPNs to pick roast targets; -L (list one account)
    # is routine admin and stays clear.
    Rule("setspn-query-all", "T1558.003 — SPN Discovery (setspn)", SEV_MEDIUM,
         "kerberoast_recon", "Domain-wide SPN enumeration via setspn -Q",
         images=("setspn.exe",), cmd_any=("-q", "/q")),
    # Pass-the-hash / overpass / SMB-exec tooling.
    Rule("pass-the-hash-tooling", "T1550.002 — Use Alternate Auth (PtH)", SEV_CRITICAL,
         "pass_the_hash", "Pass-the-hash / lateral auth-material reuse tooling",
         cmd_any=("sekurlsa::pth", "invoke-thehash", "invoke-smbexec",
                  "invoke-wmiexec", "-hashes ", "/ntlm:", "overpass")),
    # Named LSASS-dumping tools - matched by their known image names (a rename
    # falls back to the Sysmon EID10 ProcessAccess->lsass sensor).
    Rule("lsass-dumper-tool", "T1003.001 — LSASS Memory (known dumper)", SEV_CRITICAL,
         "lsass_dump", "A known LSASS-dumping tool was executed",
         images=("nanodump.exe", "handlekatz.exe", "dumpert.exe", "outflank-dumpert.exe",
                 "pypykatz.exe", "lsassy.exe", "mimidump.exe", "sqldumper.exe",
                 "safetykatz.exe", "sharpkatz.exe")),
    # Generic: any process writing a file named like an LSASS dump - catches a
    # renamed dumper by its output artefact.
    Rule("lsass-dump-artifact", "T1003.001 — LSASS Memory (dump artefact)", SEV_HIGH,
         "lsass_dump", "A process wrote an LSASS-dump-named file",
         cmd_any=("lsass.dmp", "lsass.bin", "lsass_dump", "lsassdump", "lsass.zip")),
    # WSL used to indirectly execute (Linux-side download/exec bypasses Win AV).
    Rule("wsl-indirect-exec", "T1202 — Indirect Command Execution (WSL)", SEV_MEDIUM,
         "wsl_exec", "WSL used to execute a command (indirect exec)",
         images=("wsl.exe",), cmd_any=("-e", "--exec", "-c ", "/bin/", "bash")),
    # extrac32 /C copies a file (LOLBin copy primitive); /Y-style cab extraction
    # stays clear.
    Rule("extrac32-copy", "T1218 — Signed Binary Proxy (extrac32)", SEV_MEDIUM,
         "lolbin_copy", "extrac32 used to copy a file (proxy)",
         images=("extrac32.exe",), cmd_any=("/c",)),
    Rule("ttdinject-launch", "T1218 — Signed Binary Proxy (ttdinject)", SEV_HIGH,
         "lolbin_proxy_exec", "ttdinject used to launch a process",
         images=("ttdinject.exe",), cmd_any=("/launch", "/clientparams")),
    Rule("presentationhost-exec", "T1218 — Signed Binary Proxy (PresentationHost)", SEV_MEDIUM,
         "lolbin_xbap_exec", "PresentationHost ran an XBAP/remote payload",
         images=("presentationhost.exe",),
         cmd_any=(".xbap", "http://", "https://", "\\users\\public", "\\temp\\")),
    Rule("syncappvpublishing-exec", "T1216 — Signed Script Proxy (SyncAppvPublishingServer)", SEV_HIGH,
         "lolbin_script_proxy", "SyncAppvPublishingServer ran an inline PowerShell payload",
         images=("syncappvpublishingserver.exe", "syncappvpublishingserver.vbs"),
         cmd_any=("(", "downloadstring", "iex", "new-object", ";")),
    # (verclsid intentionally NOT ruled: `verclsid /S /C {CLSID}` is exactly the
    # shell's own COM-approval check that Explorer runs constantly, so a
    # command-line rule on it is a false-positive generator - precision-first
    # says leave it to a parent-anomaly/sequence signal, not a standalone rule.)
    # COM hijack - writing a CLSID server path (InprocServer32/LocalServer32).
    Rule("com-hijack", "T1546.015 — Component Object Model Hijacking", SEV_HIGH,
         "persistence_com", "A COM server path was hijacked (CLSID InprocServer32/LocalServer32)",
         images=("reg.exe", "powershell.exe", "pwsh.exe"),
         cmd_any=("inprocserver32", "localserver32", "treatas"),
         cmd_any2=("\\clsid\\", "software\\classes")),
    # Port forwarding via netsh portproxy (pivoting / C2 relay).
    Rule("netsh-portproxy", "T1090 — Proxy: netsh portproxy", SEV_HIGH,
         "port_forward", "A port-forward was configured via netsh portproxy",
         images=("netsh.exe",), cmd_all=("portproxy", "add")),
    # BITS job persistence - SetNotifyCmdLine fires a command when a job completes.
    Rule("bits-persistence", "T1197 — BITS Jobs (persistence)", SEV_HIGH,
         "persistence_bits", "A BITS job was set to run a command (persistence)",
         images=("bitsadmin.exe",), cmd_any=("setnotifycmdline", "/setnotifyflags")),

    # --- Round 6: sensor self-defense, inhibit-recovery breadth, staging,
    #    persistence breadth, cred access, C2 tunneling, ingress, LOLBins ---

    # Sensor/EDR teardown - DELETING or UNLOADING the monitoring stack, not just
    # stopping it. service-stop/disable-security cover stop+disabled; this covers
    # the removal verbs (sc delete / Remove-Service) against the same protected
    # components. The verb group is ANDed with the component group (cmd_any2 is
    # matched against arguments, so the "sc"/"powershell" launcher can't satisfy
    # the component check). Generalizes: any security service, any of these verbs.
    Rule("service-delete-security", "T1562.001 — Impair Defenses: Remove Security Service", SEV_HIGH,
         "impair_defenses", "A security/monitoring service was deleted or removed",
         images=("sc.exe", "powershell.exe", "pwsh.exe"),
         cmd_any=("delete", "remove-service"),
         cmd_any2=("windefend", "securityhealthservice", "sysmondrv", "sysmon64",
                   "sysmon", "sense", "mssense", "wdfilter", "valkyrie",
                   "csagent", "cbdefense", "sentinelagent")),
    # Unloading a minifilter driver at runtime is a tamper primitive - the only
    # reason to `fltmc unload` is to blind a filter-driver sensor (Sysmon, EDR,
    # AV). fltmc listing/instances (the benign uses) never carry "unload".
    Rule("fltmc-unload", "T1562.001 — Impair Defenses: Unload Filter Driver", SEV_HIGH,
         "sensor_unload", "A filesystem minifilter driver was unloaded (sensor teardown)",
         images=("fltmc.exe",), cmd_all=("unload",)),
    # Sysmon uninstalling itself (`sysmon -u`) removes the driver + config. The
    # sensor tearing itself down is unambiguous - no benign self-uninstall in the
    # middle of an attack chain.
    Rule("sysmon-uninstall", "T1562.001 — Impair Defenses: Uninstall Sensor", SEV_HIGH,
         "sensor_uninstall", "Sysmon was invoked to uninstall itself",
         images=("sysmon.exe", "sysmon64.exe"),
         cmd_any=(" -u", " /u", "-u force", "uninstall")),

    # Inhibit recovery - shadow-copy destruction via the WMI/CIM paths that the
    # vssadmin-only rule (which requires the literal "shadows") misses. Covers
    # `wmic shadowcopy delete`, `Win32_Shadowcopy | %{$_.Delete()}`,
    # `Get-CimInstance Win32_ShadowCopy | Remove-CimInstance`. Enumerate-and-
    # destroy shadow copies is a ransomware hallmark with no benign analogue.
    Rule("shadowcopy-delete-wmi", "T1490 — Inhibit System Recovery (WMI/CIM shadow delete)", SEV_CRITICAL,
         "inhibit_recovery", "Volume shadow copies were deleted via WMI/CIM",
         cmd_any=("shadowcopy", "shadowcopies", "win32_shadowcopy"),
         cmd_any2=("delete", "remove-ciminstance", "remove-wmiobject", ".delete(")),

    # Persistence - LSA security/authentication/notification packages load a DLL
    # into LSASS at boot (SSP injection, e.g. mimilib). Writing these values is
    # domain-controller-grade config that never happens on a normal endpoint.
    Rule("lsa-package-persistence", "T1547.005 — Security Support Provider", SEV_HIGH,
         "persistence_lsa", "An LSA authentication/security package was registered",
         images=("reg.exe", "powershell.exe", "pwsh.exe"),
         cmd_any=("security packages", "authentication packages", "notification packages"),
         cmd_any2=("add", "set-itemproperty", "new-itemproperty")),
    # Persistence - screensaver hijack: pointing SCRNSAVE.EXE at an attacker
    # binary via reg makes it auto-run on idle. Users set screensavers through
    # the UI, not `reg add ... /v SCRNSAVE.EXE /d <path>`.
    Rule("screensaver-hijack", "T1546.002 — Screensaver", SEV_MEDIUM,
         "persistence_screensaver", "The screensaver executable was repointed via registry",
         images=("reg.exe", "powershell.exe", "pwsh.exe"),
         cmd_any=("scrnsave.exe",),
         cmd_any2=("add", "set-itemproperty", "new-itemproperty")),
    # Persistence - dropping an executable into a Startup autorun folder. Real
    # autorun locations only (Start Menu\Programs\Startup, shell:startup); .lnk
    # shortcuts (what installers legitimately drop) are excluded, executable
    # payload extensions are required.
    # A WRITE verb is now required. Without it the rule could not tell "dropped
    # a payload INTO Startup" (persistence) from "ran normally FROM Startup"
    # (every autorun on every machine, every boot) - both name the folder and
    # both name an executable extension. Elastic's exclusions caught the second
    # shape: cscript.exe running a .bat that already lived in Startup.
    Rule("startup-folder-drop", "T1547.001 — Startup Folder", SEV_HIGH,
         "persistence_startup", "An executable payload was written to a Startup folder",
         cmd_any=("start menu\\programs\\startup", "shell:startup"),
         cmd_any2=(".exe", ".bat", ".cmd", ".vbs", ".js", ".jse", ".ps1", ".scr", ".hta"),
         cmd_any3=("copy", "move", "xcopy", "robocopy", "out-file", "set-content",
                   "add-content", "new-item", "writealltext", "writeallbytes",
                   "downloadfile", "invoke-webrequest", "iwr ", "curl", "wget",
                   ">", "echo ", "certutil")),

    # Credential access - browser credential/cookie store theft. Copying the
    # named SQLite stores (Chrome/Edge "Login Data", Firefox logins.json/key4.db,
    # cookies) out of a profile is a credential-theft IOA; ordinary profile
    # backups don't name these specific files.
    # Copy-verb matched against the FULL command (it is often the launcher itself,
    # e.g. `robocopy ...`), the named credential store against the arguments - so
    # the verb-as-image case (robocopy/xcopy) is not lost to the arg-only check.
    Rule("browser-cred-theft", "T1555.003 — Credentials from Web Browsers", SEV_HIGH,
         "cred_browser", "A browser credential/cookie store was copied",
         cmd_any=("copy", "xcopy", "robocopy", "copy-item", "get-content",
                  "type ", "esentutl", "cp "),
         cmd_any2=("login data", "logins.json", "key4.db", "signons.sqlite",
                   "cookies.sqlite", "\\web data")),
    # Credential access - hunting secrets in files: recursive findstr/Select-String
    # for password/credential keywords. The recursive-search verb is ANDed with a
    # secret keyword, so ordinary recursive greps (for TODO, errors) stay clear.
    Rule("cred-hunt-files", "T1552.001 — Unsecured Credentials in Files", SEV_MEDIUM,
         "cred_hunt", "Recursive search of files for password/credential strings",
         cmd_any=("findstr /s", "findstr /is", "findstr /si", "select-string",
                  "-recurse -include", "gci -recurse", "get-childitem -recurse"),
         cmd_any2=("password", "passwd", "pwd=", "credential", "secret",
                   "apikey", "api_key", "connectionstring")),
    # Credential access - enumerating stored Windows credentials. Weak on its own
    # (admins use it), so LOW: feeds sequence correlation, doesn't auto-block.
    Rule("cmdkey-list", "T1555 — Credentials from Password Stores (cmdkey)", SEV_LOW,
         "cred_store_list", "Stored Windows credentials were enumerated (cmdkey /list)",
         images=("cmdkey.exe",), cmd_any=("/list", "/l ")),
    # Credential access - exporting saved WiFi profiles WITH the cleartext key.
    # `netsh wlan show profiles` is benign; export ... key=clear dumps passwords.
    Rule("wifi-password-export", "T1555 — Credentials from Password Stores (WiFi)", SEV_MEDIUM,
         "cred_wifi", "Saved WiFi profiles were exported with cleartext keys",
         images=("netsh.exe",), cmd_all=("wlan", "export"),
         cmd_any=("key=clear", "key = clear")),

    # Collection/staging - password-protected archive of data prior to exfil.
    # The add-verb is ANDed with a password flag (-hp / -p<pw>); ordinary
    # unprotected archiving (7z a backup.7z proj) and extraction (7z x) stay clear.
    Rule("archive-password-staging", "T1560.001 — Archive Collected Data (encrypted)", SEV_MEDIUM,
         "collection_archive", "Data was archived into a password-protected container",
         images=("rar.exe", "winrar.exe", "7z.exe", "7za.exe", "7zr.exe", "7zg.exe"),
         cmd_any=("a -", "a  -", " a "),
         cmd_any2=("-hp", "-p")),

    # Collection - archiving FROM a credential/secret store location. Added
    # 2026-08-24 after a breadth Tier B run showed Collection as the weakest
    # tactic. The FP problem is the whole difficulty here: a plain
    # `rar a backup.rar C:\Users\bob\Documents` is a LEGITIMATE backup and must
    # never be flagged (prime directive - never interfere with real work), which
    # is why archive-password-staging above keys on the password flag rather
    # than on archiving itself.
    #
    # This rule takes the OTHER honest discriminator: the SOURCE. No ordinary
    # backup targets a browser profile directory, an SSH/AWS key store, or the
    # credential vault - but staging-before-exfil does exactly that. Keying on
    # (archive tool) AND (a secret-bearing source path) is specific to the
    # attacker's shape, so ordinary archiving of Documents/Desktop/projects
    # stays completely clear.
    Rule("archive-credential-store", "T1560.001 — Archive Collected Data (credential store)",
         SEV_HIGH,
         "collection_archive_creds",
         "An archive tool was pointed at a credential/browser-profile store",
         images=("rar.exe", "winrar.exe", "7z.exe", "7za.exe", "7zr.exe",
                 "7zg.exe", "tar.exe", "zip.exe"),
         cmd_any=("a -", "a  -", " a ", "-c", "--create"),
         cmd_any2=(r"\appdata\local\google\chrome\user data",
                   r"\appdata\roaming\mozilla\firefox\profiles",
                   r"\appdata\local\microsoft\edge\user data",
                   r"\appdata\roaming\thunderbird",
                   r"\.ssh", r"\.aws", r"\.azure", r"\.kube",
                   r"\appdata\local\microsoft\credentials",
                   r"\appdata\roaming\microsoft\credentials",
                   r"\appdata\roaming\microsoft\protect")),

    # Collection - staging a COPY of a credential/browser store into a scratch
    # directory. The exfil-prep shape that precedes the archive above: attackers
    # copy the locked-open browser profile or key store somewhere writable first.
    # Same discriminator (the SOURCE is a secret store), so copying ordinary user
    # documents around - the thing people do all day - never trips it.
    # NOTE the deliberately NARROW cmd_any2 here: it names the actual
    # SECRET-BEARING ARTIFACTS, not the profile directory. An earlier draft
    # keyed on the Chrome profile path alone and the benign control
    # `copy "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Bookmarks" D:\bk`
    # tripped it - backing up bookmarks is legitimate work, and flagging it
    # would be exactly the interference the prime directive forbids. Keying on
    # "Login Data" / "Cookies" / "id_rsa" / "credentials" keeps the theft
    # shape and lets ordinary profile backup through.
    Rule("copy-credential-store", "T1005 — Data from Local System (credential store)",
         SEV_HIGH,
         "collection_copy_creds",
         "A credential store artifact was copied to another location",
         images=("cmd.exe", "xcopy.exe", "robocopy.exe", "powershell.exe", "pwsh.exe"),
         cmd_any=("copy", "xcopy", "robocopy", "copy-item", "cpi "),
         cmd_any2=(r"\login data", r"\web data", r"\cookies",
                   r"\key4.db", r"\logins.json", r"\signons.sqlite",
                   r"\.ssh\id_", r"\.aws\credentials", r"\.azure\credentials",
                   r"\appdata\roaming\microsoft\protect")),

    # C2 - reverse SSH/PuTTY tunnel (`-R remote:port`) turns the host into a
    # pivot/relay for the attacker. Restricted to ssh-family images so a generic
    # "-r" recursive flag elsewhere can't trip it.
    Rule("reverse-ssh-tunnel", "T1572 — Protocol Tunneling (reverse SSH)", SEV_MEDIUM,
         "c2_tunnel", "A reverse (remote-forward) SSH tunnel was opened",
         images=("ssh.exe", "plink.exe", "putty.exe"),
         cmd_any=(" -r ", " -r")),

    # Defense evasion - patching ETW from PowerShell by reflecting into the
    # tracing provider (blinds Script-Block/ETW logging). Near-zero benign use.
    Rule("etw-patch-reflection", "T1562.006 — Indicator Blocking (ETW patch)", SEV_HIGH,
         "impair_etw", "ETW tracing was patched via reflection (PSEtwLogProvider)",
         cmd_any=("psetwlogprovider", "etweventwrite",
                  "system.management.automation.tracing")),
    # Fileless C2 - remote download piped straight to Invoke-Expression, with NO
    # payload extension needed (the cradle that ps-download-cradle-exec's
    # extension check misses, e.g. `iwr http://x | iex`).
    Rule("remote-download-iex", "T1059.001 — PowerShell (remote download to IEX)", SEV_HIGH,
         "fileless_cradle", "Remote content downloaded and executed via Invoke-Expression",
         images=("powershell.exe", "pwsh.exe"),
         cmd_any=("invoke-webrequest", "iwr ", "invoke-restmethod", "irm ",
                  "downloadstring", "net.webclient"),
         cmd_any2=("iex", "invoke-expression", "| iex", ".invoke(")),
    # Ingress - native curl/wget fetching an executable payload to disk. Restricted
    # to curl/wget images with an executable/script extension so benign JSON/text
    # fetches (curl ... -o data.json) don't fire.
    Rule("curl-wget-download-exe", "T1105 — Ingress Tool Transfer (curl/wget)", SEV_MEDIUM,
         "ingress_curl", "curl/wget downloaded an executable payload",
         images=("curl.exe", "wget.exe"),
         cmd_any=("http://", "https://", "ftp://"),
         cmd_any2=(".exe", ".dll", ".scr", ".ps1", ".bat", ".hta", ".vbs", ".msi")),

    # LOLBins - signed/known binaries used as proxy executors. Each is niche
    # enough on an endpoint that image + the proxy argument is a precise IOA.
    Rule("msxsl-transform", "T1220 — XSL Script Processing (msxsl)", SEV_HIGH,
         "lolbin_msxsl", "msxsl ran an XSL transform (script proxy)",
         images=("msxsl.exe",), cmd_any=(".xsl", ".xml", "http://", "https://")),
    Rule("register-cimprovider-dll", "T1218 — Signed Binary Proxy (Register-CimProvider)", SEV_HIGH,
         "lolbin_cimprovider", "Register-CimProvider loaded a DLL",
         images=("register-cimprovider.exe",), cmd_any=("-path", ".dll")),
    Rule("scriptrunner-proxy", "T1218 — Signed Binary Proxy (ScriptRunner)", SEV_MEDIUM,
         "lolbin_scriptrunner", "ScriptRunner proxied command execution",
         images=("scriptrunner.exe",), cmd_any=("-appvscript",)),
    Rule("infdefaultinstall-inf", "T1218.007 — Msiexec/INF proxy (InfDefaultInstall)", SEV_MEDIUM,
         "lolbin_inf", "InfDefaultInstall executed an .inf (proxy install)",
         images=("infdefaultinstall.exe",), cmd_any=(".inf",)),
    Rule("xwizard-runwizard", "T1218 — Signed Binary Proxy (xwizard)", SEV_MEDIUM,
         "lolbin_xwizard", "xwizard ran a wizard/COM object (proxy exec)",
         images=("xwizard.exe",), cmd_any=("runwizard",)),
    Rule("dnscmd-plugin-dll", "T1543 — DNS server plugin DLL (dnscmd)", SEV_HIGH,
         "lolbin_dnscmd", "A DNS server-level plugin DLL was registered via dnscmd",
         images=("dnscmd.exe",), cmd_any=("serverlevelplugindll",)),

    # --- Round 7: env-var injection, boot tamper, log/audit evasion, account
    #    manipulation, service-reg persistence, lateral exec, capture ---

    # .NET profiler DLL injection (COR_PROFILER). Setting these env vars loads an
    # attacker DLL into every managed process - persistence + injection. The
    # write context (add/setx/.dll/CLSID) is required so reads don't fire.
    Rule("cor-profiler-hijack", "T1574.012 — COR_PROFILER Hijack", SEV_HIGH,
         "persistence_corprofiler", "A .NET COR_PROFILER environment hook was set",
         cmd_any=("cor_profiler", "cor_enable_profiling"),
         cmd_any2=("add", "setx", "set-itemproperty", "new-itemproperty",
                   "/d ", ".dll", "{", "clsid")),
    # Boot-configuration tamper that weakens code-integrity: enabling test-signing
    # or disabling integrity checks lets unsigned/malicious drivers load. (safeboot
    # is a DIFFERENT technique - see the safe-mode rule in the threat-informed
    # block below - so it is deliberately NOT bundled here anymore.)
    Rule("bcdedit-boot-tamper", "T1553.006 — Code Signing Policy Modification (bcdedit)", SEV_HIGH,
         "boot_tamper", "Boot config was altered to weaken code integrity",
         images=("bcdedit.exe",),
         cmd_any=("testsigning", "nointegritychecks", "disable_integrity_checks",
                  "loadoptions")),
    # PowerShell v2 downgrade - v2 predates AMSI and Script-Block logging, so
    # `-version 2` is run specifically to execute unlogged, un-scanned script.
    Rule("powershell-v2-downgrade", "T1562.001 — Impair Defenses: PowerShell downgrade", SEV_MEDIUM,
         "evade_ps_downgrade", "PowerShell was launched in v2 (no AMSI / script-block logging)",
         images=("powershell.exe", "pwsh.exe"),
         cmd_any=("-version 2", "-v 2", "-ver 2", "-version:2", "-v:2",
                  "-version 2.0")),
    # Audit-policy teardown - disabling success/failure auditing blinds the
    # Security log at the source. `auditpol /get` (read) never carries :disable.
    Rule("auditpol-disable", "T1562.002 — Disable Windows Event Logging (auditpol)", SEV_HIGH,
         "impair_audit", "Windows audit policy was disabled via auditpol",
         images=("auditpol.exe",), cmd_all=("/set",),
         cmd_any=(":disable", "/success:disable", "/failure:disable")),
    # Event-log tampering breadth - the PowerShell log cmdlets (Clear-EventLog,
    # Limit-EventLog to a tiny size to evict records). wevtutil cl / sl /e:false
    # are already covered by clear-eventlog / wevtutil-disable-log.
    Rule("ps-eventlog-tamper", "T1070.001 — Clear Windows Event Logs (PowerShell)", SEV_HIGH,
         "clear_eventlog_ps", "Event logs were cleared or shrunk via PowerShell",
         images=("powershell.exe", "pwsh.exe"),
         cmd_any=("clear-eventlog", "remove-eventlog", "limit-eventlog")),
    # Account manipulation - re-enabling a disabled account (classic for the
    # built-in Administrator/Guest) or clearing password expiry to keep a
    # backdoor account alive. Distinct from creation (net user /add).
    Rule("account-enable", "T1098 — Account Manipulation (enable / persist)", SEV_MEDIUM,
         "account_manip", "A user account was re-enabled or set never to expire",
         images=("net.exe", "net1.exe", "wmic.exe", "powershell.exe", "pwsh.exe"),
         cmd_any=("/active:yes", "passwordexpires=false", "passwordexpires=0",
                  "-passwordneverexpires", "enable-localuser", "enable-adaccount")),
    # Service install/hijack written straight to the registry (bypasses sc.exe):
    # an ImagePath/ServiceDll value under \Services points a service at a payload.
    # The write verb (add/set-itemproperty) is required so a query doesn't fire.
    Rule("service-imagepath-reg", "T1543.003 — Windows Service (registry ImagePath)", SEV_HIGH,
         "persistence_service_reg", "A service ImagePath/ServiceDll was written via registry",
         images=("reg.exe", "powershell.exe", "pwsh.exe"),
         cmd_any=("imagepath", "servicedll"),
         cmd_any2=("add", "set-itemproperty", "new-itemproperty")),
    # Lateral movement - winrs runs a command on a remote host over WinRM.
    Rule("winrs-lateral", "T1021.006 — Remote Services: WinRM (winrs)", SEV_MEDIUM,
         "lateral_winrs", "winrs executed a command on a remote host",
         images=("winrs.exe",), cmd_any=("-r:", "-r ", "-remote")),
    # Collection - host packet capture (netsh trace / pktmon) to sniff traffic.
    Rule("netsh-trace-capture", "T1040 — Network Sniffing (netsh trace)", SEV_MEDIUM,
         "capture_netsh", "A network capture was started via netsh trace",
         images=("netsh.exe",), cmd_all=("trace", "start")),
    Rule("pktmon-capture", "T1040 — Network Sniffing (pktmon)", SEV_MEDIUM,
         "capture_pktmon", "A network capture was started via pktmon",
         images=("pktmon.exe",), cmd_any=("start",)),

    # --- Round 9: UAC-bypass registry hijack, Defender-as-LOLBin, file hiding ---

    # UAC bypass - hijacking an auto-elevated handler by writing its command
    # under the per-user HKCU\...\Classes tree (which shadows HKLM for the
    # elevated process). The hijacked ProgIds are SYSTEM handlers (ms-settings ->
    # fodhelper/computerdefaults, mscfile -> eventvwr, exefile -> sdclt); a normal
    # app only ever registers its OWN ProgId, never these, so this is precise.
    Rule("uac-bypass-hijack", "T1548.002 — Bypass UAC (auto-elevate handler hijack)", SEV_HIGH,
         "uac_bypass_reg", "An auto-elevated handler's command was hijacked in HKCU Classes",
         images=("reg.exe", "powershell.exe", "pwsh.exe"),
         cmd_all=("classes",),
         cmd_any=("ms-settings\\shell", "mscfile\\shell", "exefile\\shell",
                  "\\folder\\shell\\open\\command", "delegateexecute")),
    # Defender's own MpCmdRun.exe abused as a download LOLBin (T1105) - it will
    # fetch any URL to disk, blending ingress into a signed AV binary.
    Rule("mpcmdrun-download", "T1105 — Ingress Tool Transfer (MpCmdRun)", SEV_HIGH,
         "lolbin_mpcmdrun", "Windows Defender MpCmdRun was used to download a file",
         images=("mpcmdrun.exe",), cmd_any=("-downloadfile", "downloadfile")),
    # Blinding Defender by deleting its signatures (T1562.001).
    Rule("defender-signature-removal", "T1562.001 — Impair Defenses: Remove AV Signatures", SEV_HIGH,
         "impair_av_defs", "Windows Defender signatures were removed",
         images=("mpcmdrun.exe",), cmd_any=("-removedefinitions", "removedefinitions")),
    # Hiding a payload with system+hidden attributes (T1564.001). Both +h and +s
    # on an executable/script is the malware-concealment shape; a bare +h on a
    # folder is not enough to fire.
    Rule("file-hide-attrib", "T1564.001 — Hidden Files and Directories", SEV_MEDIUM,
         "hide_file", "An executable was marked system+hidden via attrib",
         images=("attrib.exe",), cmd_all=("+h", "+s"),
         cmd_any2=(".exe", ".dll", ".scr", ".bat", ".vbs", ".ps1", ".js", ".cmd")),
    # A firewall ALLOW rule for a program living in a user-writable/staging path
    # (Public/Temp/AppData/Downloads) - opening the door for a dropped backdoor.
    # Installers add allow rules too, but for Program Files, not these paths.
    Rule("firewall-allow-payload", "T1562.004 — Disable/Modify Firewall (allow payload)", SEV_MEDIUM,
         "firewall_allow", "A firewall allow-rule was added for a payload in a staging path",
         images=("netsh.exe",), cmd_all=("advfirewall", "add", "allow"),
         cmd_any=("\\users\\public", "\\temp\\", "\\programdata\\",
                  "\\appdata\\", "\\downloads\\", "%temp%", "%public%")),
    # WMI event-subscription persistence compiled from a .mof via mofcomp - the
    # classic fileless-persistence install path (an alternative to the PowerShell
    # Set-WmiInstance form already covered by wmi-event-consumer).
    Rule("mofcomp-wmi-persistence", "T1546.003 — WMI Event Subscription (mofcomp)", SEV_MEDIUM,
         "persistence_mof", "A WMI MOF was compiled via mofcomp (event-subscription persistence)",
         images=("mofcomp.exe",), cmd_any=(".mof",)),

    # --- Round 14: offensive cred tooling, SYSTEM shell, hidden-window staging,
    #    registry recovery-inhibition ---

    # Named offensive credential/post-exploitation tools - the C#/PowerShell
    # tradecraft that dumps DPAPI, browser creds, and secrets. Image-agnostic
    # (matches the command signature) so a renamed binary still trips it.
    Rule("offensive-cred-tooling", "T1003 — OS Credential Dumping (offensive tooling)", SEV_HIGH,
         "cred_tool", "A known credential-theft tool signature was observed",
         cmd_any=("sharpdpapi", "sharpchrome", "sharpweb", "lazagne",
                  "gsecdump", "pwdump", "quarksdump", "dpapi::masterkey",
                  "dpapi::cred", "seatbelt", "sharphound", "certipy")),
    # PsExec (or paexec) launching a SYSTEM (-s) interactive/service process - a
    # local privilege-escalation-to-SYSTEM shell, distinct from remote \\host use.
    Rule("psexec-system", "T1569.002 — Service Execution (PsExec SYSTEM shell)", SEV_MEDIUM,
         "psexec_system", "PsExec launched a process as SYSTEM (-s)",
         images=("psexec.exe", "psexec64.exe", "paexec.exe"),
         cmd_any=(" -s ", " -s\t", "-s -i", "-s -d", "-s cmd", "-s powershell",
                  "-s -accepteula")),
    # Executing a payload from a user-writable staging path with a HIDDEN window
    # - the run-silently shape. The staging-path gate keeps a legitimate hidden
    # scheduled task (running from Program Files/Scripts) clear.
    Rule("hidden-window-staging-exec", "T1564.003 — Hidden Window (staged payload)", SEV_MEDIUM,
         "hidden_exec", "A payload in a staging path was run with a hidden window",
         cmd_any=("-windowstyle hidden", "-w hidden", "windowstyle hidden",
                  "-wstyle hidden"),
         cmd_any2=("\\users\\public", "\\temp\\", "\\appdata\\local\\temp",
                   "\\programdata\\", "\\downloads\\", "%temp%", "%public%")),
    # Inhibiting recovery via the registry: BootStatusPolicy set to ignore all
    # boot failures suppresses Windows' automatic repair (a ransomware precursor,
    # the registry twin of `bcdedit /set recoveryenabled no`).
    Rule("recovery-disable-reg", "T1490 — Inhibit System Recovery (registry)", SEV_MEDIUM,
         "inhibit_recovery_reg", "Automatic boot recovery was disabled via the registry",
         images=("reg.exe", "powershell.exe", "pwsh.exe"),
         cmd_any=("bootstatuspolicy",),
         cmd_any2=("3", "ignoreallfailures")),

    # --- Round 11: registry telemetry-disable, ASEP-DLL persistence, DCOM
    #    lateral, PS-history creds, disk destruction ---

    # Disabling a security-telemetry feature via the registry: AMSI for scripts
    # (AmsiEnable=0) or PowerShell Script-Block logging (=0). The DISABLE value
    # (set to 0) is required, so ENABLING the same policy (the benign/hardening
    # direction) stays clear.
    Rule("registry-telemetry-disable", "T1562.001 — Impair Defenses: Disable Telemetry (registry)", SEV_HIGH,
         "impair_telemetry_reg", "AMSI or PowerShell logging was disabled via the registry",
         images=("reg.exe", "powershell.exe", "pwsh.exe"),
         cmd_any=("amsienable", "enablescriptblocklogging",
                  "enablescriptblockinvocationlogging", "enablemodulelogging",
                  "enabletranscripting"),
         cmd_any2=("/d 0", "/d 0x0", "value 0", "-value 0", ":0", "/d 0 ")),
    # DLL-loading autostart extensibility points reached by writing the registry
    # directly: Print/Port Monitors, Time Providers, and the Winlogon Notify
    # subkey each load an attacker DLL at boot/logon. (Run keys, Winlogon
    # Shell/Userinit, LSA packages, AppInit, IFEO and Netsh helpers are covered
    # by their own rules.)
    Rule("registry-asep-dll", "T1547.010 — Port Monitors / Time Providers (registry ASEP)", SEV_HIGH,
         "persistence_asep_dll", "A boot/logon DLL autostart point was written in the registry",
         images=("reg.exe", "powershell.exe", "pwsh.exe"),
         cmd_any=("\\print\\monitors", "\\control\\print\\monitors",
                  "\\timeproviders\\", "\\winlogon\\notify"),
         cmd_any2=("add", "set-itemproperty", "new-itemproperty", ".dll")),
    # DCOM lateral movement - instantiating a remote-abusable COM object
    # (MMC20.Application, ShellWindows, ShellBrowserWindow, Excel) on another host
    # to run a command. The abused ProgIds have no benign remote-instantiation use.
    # The abused ProgIds (MMC20.Application, ShellBrowserWindow, ShellWindows) and
    # the MMC ExecuteShellCommand method have no benign local use, so the token
    # alone is the signal - no argument gate needed (which also keeps it firing on
    # a no-space single-token PowerShell expression, where arg-splitting is empty).
    Rule("dcom-lateral", "T1021.003 — Remote Services: DCOM", SEV_MEDIUM,
         "lateral_dcom", "A DCOM-abusable COM object was instantiated (lateral movement)",
         cmd_any=("mmc20.application", "shellbrowserwindow", "shellwindows",
                  "executeshellcommand")),
    # Credential access - reading the PowerShell console history, which routinely
    # contains typed secrets (passwords, connection strings, tokens).
    Rule("ps-history-creds", "T1552.001 — Credentials in PowerShell History", SEV_MEDIUM,
         "cred_ps_history", "The PowerShell console history file was read",
         cmd_any=("consolehost_history", "psreadline\\consolehost")),

    # Impact - destroying a volume: format with the auto-confirm /y (or /q quick)
    # flag runs unattended, the wiper shape rather than an interactive admin format.
    Rule("format-volume", "T1561.001 — Disk Wipe: Content", SEV_MEDIUM,
         "disk_format", "A volume was formatted unattended (format /y)",
         images=("format.com", "format.exe"),
         cmd_any=("/y",)),
    # Impact - recursive force-delete targeting a user-data tree (wiper / anti-
    # recovery). LOW: `del /s /q` is also ordinary cleanup, so this only feeds
    # sequence correlation and never auto-blocks on its own.
    Rule("mass-file-delete", "T1485 — Data Destruction (recursive delete)", SEV_LOW,
         "destroy_files", "Recursive force-delete of a user-data tree",
         cmd_any=("del /f", "del /s", "erase /s", "erase /f", "rd /s"),
         cmd_any2=("\\users\\", "\\documents", "\\desktop", "\\appdata\\",
                   "\\onedrive")),

    # --- Threat-informed additions ---
    # Grounded in the Red Canary 2025 Threat Detection Report top-10 (the most
    # prevalent techniques seen in confirmed real-world intrusions) cross-
    # referenced against this rule set's existing coverage - NOT synthetic
    # scenarios. These fill verified gaps, not hypothetical ones.
    #
    # T1036.005 Masquerading - a core Windows binary that only EVER launches
    # from System32/SysWOW64, seen running from a user-writable directory.
    # Expressed positively (bad LOCATION) rather than "not System32", so
    # legitimate alternate system paths (WinSxS, servicing, SysWOW64) can never
    # false-positive; only an unambiguous location (svchost/lsass/explorer under
    # \AppData or \Temp) fires. path is the image's on-disk location, populated
    # by the Sysmon EID1 collector; when path is unknown the rule simply stays
    # silent (no FP).
    Rule("masquerade-system-binary-location",
         "T1036.005 — Masquerading: Match Legitimate Name or Location", SEV_HIGH,
         "masquerade_syspath",
         "Core Windows system binary running from a user-writable directory",
         images=("svchost.exe", "lsass.exe", "services.exe", "csrss.exe",
                 "wininit.exe", "winlogon.exe", "smss.exe", "spoolsv.exe",
                 "taskhostw.exe", "dllhost.exe", "conhost.exe", "sihost.exe",
                 "ctfmon.exe", "rundll32.exe", "regsvr32.exe", "explorer.exe"),
         path_any=("\\appdata\\", "\\temp\\", "\\downloads\\",
                   "\\users\\public\\", "\\$recycle.bin")),

    # T1204.004 Malicious Copy-and-Paste ("ClickFix") - the standout 2025
    # initial-access vector: a user is social-engineered into pasting a command
    # into the Run dialog (Win+R launches via explorer.exe). The launched
    # interpreter is therefore a child of explorer AND carries download / base64
    # / hidden-window markers that an ordinary double-click never would. The
    # malicious-marker ANY-group is what separates this from the benign
    # "explorer started powershell" case, keeping the FP boundary tight.
    Rule("clickfix-run-dialog-exec",
         "T1204.004 — User Execution: Malicious Copy and Paste", SEV_HIGH,
         "clickfix_paste_exec",
         "Script interpreter spawned from the Run dialog with download/hidden markers",
         images=("powershell.exe", "pwsh.exe", "mshta.exe", "cmd.exe",
                 "wscript.exe", "cscript.exe"),
         parents=("explorer.exe",),
         cmd_any=("-enc", "-encodedcommand", "frombase64string",
                  "-w hidden", "-windowstyle hidden",
                  "iwr ", "invoke-webrequest", "iex ", "invoke-expression",
                  "curl ", "certutil", "bitsadmin",
                  "mshta http", "http://", "https://")),

    # Gaps found by running Volt Typhoon's real CISA-documented LOTL commands
    # through this classifier (AA24-038A) - 7/11 already hit; these close two of
    # the misses. Real adversary tradecraft, not synthetic.
    #
    # T1087.002 Domain Account Discovery - bulk Active Directory export via the
    # built-in LOTL tools ldifde/csvde (Volt Typhoon + many ransomware
    # affiliates). `-f <file>` is the tool writing the directory out to a file.
    # MEDIUM: legitimate AD migrations use these too, so it informs/sequences
    # rather than auto-blocks, per the precision rule.
    Rule("ldifde-csvde-ad-export",
         "T1087.002 — Account Discovery: Domain Account (AD export)", SEV_MEDIUM,
         "ad_bulk_export", "Bulk Active Directory export via ldifde/csvde",
         images=("ldifde.exe", "csvde.exe"),
         cmd_any=("-f ",)),

    # T1003.003 NTDS - exfiltration of the raw AD database file. This is the
    # payoff of the "vssadmin create shadow -> copy ntds.dit out of the snapshot"
    # route that the ntdsutil-IFM rule doesn't cover. Any command line that
    # NAMES ntds.dit is doing this: administrators reach the DB through ntdsutil,
    # never by handling the raw file, so naming it is a high-fidelity,
    # near-zero-FP signal - and being tool-agnostic it catches copy / esentutl
    # /y / robocopy / PowerShell Copy-Item alike.
    Rule("ntds-dit-file-access",
         "T1003.003 — NTDS (raw ntds.dit access/copy)", SEV_HIGH,
         "ntds_file_theft",
         "Direct access or copy of the raw AD database file (ntds.dit)",
         cmd_any=("ntds.dit",)),

    # From the ransomware-affiliate advisories (LockBit AA23-075A, Black Basta
    # AA24-131A, ALPHV, Play), via a cross-report probe of real commands.
    #
    # T1490 - 'vssadmin/wmic resize shadowstorage /maxsize=<tiny>' silently
    # discards existing shadow copies by shrinking their storage below what they
    # need: the same recovery-inhibition goal as 'delete shadows', a different
    # verb the delete-rule misses. Backups grow or leave storage default, never
    # shrink it to a floor, so 'resize shadowstorage' is a high-fidelity precursor.
    Rule("vssadmin-resize-shadowstorage",
         "T1490 — Inhibit System Recovery (shadow storage resize)", SEV_HIGH,
         "shadow_delete",
         "Shadow-copy storage resized down (silently discards shadow copies)",
         images=("vssadmin.exe", "wmic.exe"),
         cmd_all=("resize", "shadowstorage")),

    # T1485 - 'cipher /w:<path>' overwrites free space, destroying deleted-file
    # remnants: an anti-forensics / data-destruction wipe. /w is the wipe mode;
    # cipher's status (/c) and encrypt-decrypt (/e /d) uses never carry /w.
    Rule("cipher-freespace-wipe",
         "T1485 — Data Destruction (free-space wipe)", SEV_MEDIUM,
         "freespace_wipe", "Free-space wipe via cipher /w (anti-forensics)",
         images=("cipher.exe",),
         cmd_any=("/w:", "/w ")),

    # T1567.002 - rclone is the near-universal ransomware exfil tool (LockBit,
    # Black Basta, ALPHV): copy/sync of local data to a cloud 'remote:' before
    # encryption. The tell is a transfer verb (cmd_any) AND a remote target /
    # bulk-transfer flag (cmd_any2, matched against ARGS) - which separates real
    # exfil from a benign local 'rclone copy c:\a c:\b'. MEDIUM: rclone has
    # legitimate backup uses, so it informs/sequences rather than auto-blocks.
    Rule("rclone-cloud-exfil",
         "T1567.002 — Exfiltration to Cloud Storage (rclone)", SEV_MEDIUM,
         "cloud_exfil", "Bulk data transfer to a remote via rclone",
         images=("rclone.exe",),
         cmd_any=("copy", "sync", "move"),
         cmd_any2=("mega:", "b2:", "s3:", "drive:", "gdrive:", "dropbox:",
                   "remote:", "sftp:", "ftp:", "onedrive:", "pcloud:",
                   "--config", "--transfers", "--max-age")),

    # From the Akira/Medusa/Snatch advisories (CISA AA24-109A, AA25-071A) +
    # Huntress reporting, via a round-2 real-command probe.
    #
    # T1562.009 - reboot into Safe Mode so third-party AV/EDR services never
    # start, then run the encryptor "blind." Snatch/AvosLocker pioneered it,
    # Akira adopted it in 2025. `bcdedit ... safeboot` is the on-disk tell.
    Rule("bcdedit-safe-mode-boot",
         "T1562.009 — Impair Defenses: Safe Mode Boot", SEV_HIGH,
         "safe_mode_boot",
         "Boot configured for Safe Mode (starts the host without security services)",
         images=("bcdedit.exe",),
         cmd_any=("safeboot", "safebootalternateshell")),

    # T1021.001 - enable inbound RDP by flipping fDenyTSConnections to 0 (Medusa
    # and most hands-on-keyboard ransomware, to move laterally / re-enter). The
    # /d 0 value is the enabling direction; disabling RDP writes 1, so this stays
    # off legitimate "turn RDP off" administration. MEDIUM (admins do enable RDP).
    Rule("rdp-enable-registry",
         "T1021.001 — Remote Services: RDP (enabled via registry)", SEV_MEDIUM,
         "rdp_enabled", "Inbound RDP enabled via the fDenyTSConnections registry value",
         images=("reg.exe", "powershell.exe", "pwsh.exe"),
         cmd_all=("fdenytsconnections",),
         cmd_any=("/d 0", "value 0", "value:0", "-value 0", " 0 -force")),

    # T1485 - SysInternals sdelete used to securely wipe (free space / recursive):
    # anti-forensics and, on a share, destruction. sdelete is a legitimate tool,
    # so MEDIUM and gated on the wipe flags (-z zero free space, -c clean, -s
    # recurse, -p passes) rather than any invocation.
    Rule("sdelete-secure-wipe",
         "T1485 — Data Destruction (secure delete)", SEV_MEDIUM,
         "secure_wipe", "Secure/overwrite deletion via sdelete",
         images=("sdelete.exe", "sdelete64.exe"),
         cmd_any=(" -z", " -c", " -s", " -p", "/z", "/s")),

    # T1222.001 - mass take-ownership / ACL grant across a tree, the "make every
    # file writable so the encryptor can touch it" step (and a way to lock the
    # owner out). Recursive takeown, or icacls granting broad rights over a tree.
    # MEDIUM: admins run these too, so it informs/sequences rather than blocks.
    Rule("mass-acl-takeover",
         "T1222.001 — File and Directory Permissions Modification", SEV_MEDIUM,
         "mass_acl_change", "Recursive ownership/permission change over a file tree",
         images=("takeown.exe", "icacls.exe"),
         cmd_any=(" /r", "/grant"),
         cmd_any2=(" /r", " /t", "everyone", ":f", "grant")),

    # --- Adaptive-hardening: LSASS credential-theft behavioral class ---
    # An adversarial variant sweep of "obtain lsass memory" (17 implementations)
    # found 3 evasions with ONE root cause: the prior rules key on specific
    # tools/verbs (procdump, -ma, comsvcs, artifact names), so a dump INTENT
    # phrased with an un-enumerated vocabulary slipped. This generalizes the
    # intent - LSASS as the named target AND any member of a broad memory-dump
    # verb family, tool-agnostic. FP-safe by requiring BOTH: 'tasklist lsass'
    # (no verb) and 'procdump -ma notepad' (no lsass) both stay clear. Novel
    # tools that target lsass purely by PID with novel wording carry no cmdline
    # tell and are caught at RUNTIME by the Sysmon EID10 ProcessAccess->lsass
    # sensor (etw/sysmon.py) - the true tool-agnostic backstop for this class.
    Rule("lsass-memory-dump-generic",
         "T1003.001 — LSASS Memory (generic dump intent)", SEV_CRITICAL,
         "lsass_dump", "A command expresses a memory dump targeting LSASS",
         cmd_all=("lsass",),
         cmd_any=("dump", "-ma ", "fullmemdmp", "comsvcs", "writeprocessmemory",
                  "readprocessmemory", "minidumpwritedump", "createdump",
                  "-w ", "procexp")),

    # rdrleakdiag.exe (signed MS LOLBin) doing a FULL memory dump - its
    # LOLBAS-documented abuse is dumping lsass BY PID, so its command line
    # carries no 'lsass' string. Keyed on the tool + the full-dump flag: the
    # behavioral tell the other rules cannot see.
    Rule("rdrleakdiag-memory-dump",
         "T1003.001 — LSASS Memory (rdrleakdiag full dump)", SEV_HIGH,
         "lsass_dump", "rdrleakdiag full-memory dump (process-memory theft LOLBin)",
         images=("rdrleakdiag.exe",),
         cmd_any=("/fullmemdmp", "/memdmp", "fullmemdmp")),

    # --- Adaptive-hardening: download-cradle behavioral class (T1105) ---
    # A variant sweep of "fetch a remote payload" found 2 evasions with one root
    # cause: the per-tool rules (certutil/bitsadmin/curl/...) key on tool NAME and
    # a fixed verb set, so a RENAMED tool (cu.exe -urlcache) and a novel download
    # METHOD (WebClient.DownloadData) slipped. This generalizes on the *shape*:
    # a download METHOD (any of a broad family) AND an executable/script payload
    # extension in the arguments - independent of the tool's name. FP-safe
    # because it requires BOTH: fetching a .json/.html (no exe ext) and hashing
    # a local a.exe ('certutil -hashfile', no download verb) both stay clear.
    # A renamed curl/wget using only a bare '-o URL' carries no distinctive verb
    # and is caught at RUNTIME by the network-connection layer (Sysmon EID3 /
    # network_score) - the tool-agnostic backstop for this class.
    Rule("remote-fetch-executable-generic",
         "T1105 — Ingress Tool Transfer (generic download cradle)", SEV_HIGH,
         "download_cradle",
         "A download method fetched an executable/script payload (tool-agnostic)",
         cmd_any=("urlcache", "-outfile", "downloadfile", "downloaddata",
                  "downloadstring", "downloadfileasync", "openread",
                  "/transfer ", "invoke-webrequest", "iwr ",
                  "start-bitstransfer", "urldownloadtofile"),
         # NB: '.js' is deliberately excluded - as a bare substring it collides
         # with '.json' (a benign IWR target). '.jse'/'.wsf' keep JScript-family
         # payload coverage without the false positive. (Caught by the benign
         # 'Invoke-WebRequest ...releases.json' control - precision > recall.)
         cmd_any2=(".exe", ".dll", ".ps1", ".psm1", ".scr", ".bat", ".cmd",
                   ".hta", ".vbs", ".vbe", ".jse", ".wsf", ".msi",
                   ".sct", ".jar")),

    # --- Adaptive-hardening: impair-defenses class (T1562.001) ---
    # Disabling a security service via the REGISTRY (Start=4 = disabled) rather
    # than 'sc config ... start= disabled' - bypasses the string-based 'disabled'
    # match. Generalized on the shape: a Services\<name> key + the Start value +
    # 4, gated to the security-service family so ordinary service config is clear.
    Rule("service-disable-registry-start",
         "T1562.001 — Impair Defenses: Disable Service (registry Start=4)", SEV_HIGH,
         "security_service_stop",
         "A security service was disabled via its registry Start value (=4)",
         images=("reg.exe", "powershell.exe", "pwsh.exe"),
         cmd_all=("\\services\\", "start"),
         cmd_any=_SECURITY_SERVICES,
         cmd_any2=("/d 4", "/d 0x4", " 4 /f", "value 4", "-value 4",
                   "start' -value 4", "start\" 4")),

    # --- Adaptive-hardening: persistence class (T1547/T1037/T1546) ---
    # The per-mechanism rules key on the `reg add` WRITE tool, so writing the
    # same autostart value via PowerShell (Set-/New-ItemProperty) evaded. These
    # generalize on the autostart LOCATION + any registry-write mechanism, so
    # switching the writing tool no longer bypasses. 'reg query'/'Get-Item...'
    # (reads) carry no write verb and stay clear.
    Rule("persistence-runkey-generic",
         "T1547.001 — Registry Run Keys / Startup (any write tool)", SEV_HIGH,
         "persistence_runkey",
         "A Run/RunOnce autostart key was written (tool-agnostic)",
         cmd_all=("currentversion\\run",),
         cmd_any=("reg add", "set-itemproperty", "new-itemproperty", "set-item ",
                  "reg import")),
    Rule("persistence-winlogon-generic",
         "T1547.004 — Winlogon Helper (Shell/Userinit, any write tool)", SEV_HIGH,
         "persistence_winlogon",
         "Winlogon Shell/Userinit autostart modified (tool-agnostic)",
         cmd_all=("\\winlogon",),
         cmd_any=("reg add", "set-itemproperty", "new-itemproperty", "set-item "),
         cmd_any2=("shell", "userinit", "taskman")),
    Rule("persistence-logon-script",
         "T1037.001 — Boot or Logon Init Scripts (logon script)", SEV_HIGH,
         "persistence_logon_script",
         "Logon-script persistence via UserInitMprLogonScript",
         cmd_all=("userinitmprlogonscript",),
         cmd_any=("reg add", "set-itemproperty", "new-itemproperty", "/d ",
                  "-value")),
    Rule("persistence-powershell-profile",
         "T1546.013 — Event Triggered Execution: PowerShell Profile", SEV_HIGH,
         "persistence_ps_profile",
         "Persistence written into a PowerShell profile",
         cmd_any=("add-content", "set-content", "out-file", "tee-object",
                  ">>"),
         cmd_any2=("$profile", "_profile.ps1", "windowspowershell\\profile")),
    Rule("persistence-silent-process-exit",
         "T1546.012 — Image File Execution Options (SilentProcessExit)", SEV_HIGH,
         "persistence_ifeo",
         "SilentProcessExit monitor-process persistence",
         cmd_all=("silentprocessexit",),
         cmd_any=("reg add", "set-itemproperty", "new-itemproperty",
                  "monitorprocess", "/d ")),

    # --- Script hosts (T1059.005 / T1059.007) ---------------------------
    # Found by Tier B on 2026-08-25: `wscript.exe C:\Users\Public\evil.vbs`
    # raised nothing at all. A bare script-host invocation was genuinely
    # uncovered unless the script's own contents happened to trip another rule.
    #
    # SCOPED TO DROP ZONES, AND DELIBERATELY NOT TO %TEMP%. The obvious version
    # of this rule ("script host running a script from a writable path") would
    # fire on installers constantly: MSI custom actions execute from
    # C:\Windows\Installer, and Elastic's fleet exclusions contain real benign
    # examples such as an uninstaller .vbs under AppData\Roaming. Public\ and
    # Downloads\ are different - software does not install itself from them, so
    # a script host reaching into one is the drop-and-run shape rather than a
    # setup routine.
    Rule("scripthost-dropzone-script", "T1059.005 — Visual Basic / Script Host",
         SEV_HIGH, "scripthost_dropzone",
         "A Windows script host executed a script from a drop-zone directory",
         images=("wscript.exe", "cscript.exe", "mshta.exe"),
         cmd_any=(".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta"),
         cmd_any2=("\\users\\public\\", "\\downloads\\", "\\$recycle.bin\\",
                   "\\perflogs\\")),

    # The other half, and the stronger signal: a script host started BY a
    # document or a browser. Word does not legitimately launch wscript, whatever
    # path the script sits in - that is the macro/attachment delivery chain, so
    # no path constraint is needed and none is applied.
    Rule("scripthost-from-document", "T1059.005 — Visual Basic / Script Host",
         SEV_HIGH, "scripthost_document_child",
         "A document or browser process launched a Windows script host",
         images=("wscript.exe", "cscript.exe"),
         parents=("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                  "msaccess.exe", "onenote.exe", "visio.exe",
                  "acrord32.exe", "acrobat.exe",
                  "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
                  "opera.exe", "iexplore.exe",
                  "7zfm.exe", "winrar.exe")),
    # explorer.exe is deliberately ABSENT from that list. It is the shell, so
    # every double-clicked script has it as a parent - including an
    # administrator's own. Including it would have made this rule fire on
    # ordinary script use, which is the same over-reach the drop-zone scoping
    # above exists to avoid. A script launched from Explorer is covered by the
    # drop-zone rule when it lives somewhere it should not.

    # --- Code-signature state (T1036 / T1553) ---------------------------
    # These are the rules that GENERALISE rather than enumerate. Every other
    # rule in this file describes WHAT a process did and can be evaded by doing
    # something slightly different; these describe WHAT THE BINARY IS, which an
    # attacker cannot change cheaply. They cost nothing to evaluate (cached) and
    # they cover payloads nobody has written a rule for yet.
    #
    # All of them fail closed on UNKNOWN signature state - see Rule.signed.

    # The single highest-confidence signature rule available. A genuine
    # svchost.exe/lsass.exe/services.exe is ALWAYS catalog-signed by Microsoft;
    # Windows will not boot otherwise. So an executable carrying one of these
    # names that does not verify is not a false positive waiting to happen - it
    # is a payload wearing a system binary's name, which is among the oldest and
    # most reliable malware behaviours there is.
    Rule("masquerade-unsigned-system-binary",
         "T1036.005 — Masquerading: Match Legitimate Name or Location",
         SEV_CRITICAL, "masquerade_system_binary",
         "A process is using a core Windows binary's name but the file is not "
         "signed by Microsoft — a payload impersonating a system process",
         images=("svchost.exe", "lsass.exe", "services.exe", "csrss.exe",
                 "wininit.exe", "winlogon.exe", "smss.exe", "spoolsv.exe",
                 "dwm.exe", "taskhostw.exe", "explorer.exe", "conhost.exe",
                 "rundll32.exe", "regsvr32.exe", "ctfmon.exe", "sihost.exe",
                 "searchindexer.exe", "wuauclt.exe", "lsm.exe", "audiodg.exe"),
         signed="not_trusted"),

    # A signature that is PRESENT but unacceptable - revoked, expired, or a
    # digest that no longer matches the file. Distinct from unsigned and much
    # louder: unsigned software is everywhere and mostly benign, whereas a
    # broken signature means the binary was tampered with after signing, or was
    # signed with a certificate somebody revoked. Both are deliberate acts.
    Rule("tampered-or-revoked-signature",
         "T1553 — Subvert Trust Controls", SEV_HIGH,
         "signature_untrusted",
         "The executable carries a signature that does not verify — tampered "
         "after signing, or signed with a revoked/distrusted certificate",
         signed="untrusted"),

    # LOW on purpose. Unsigned binaries running from temp/download directories
    # are the normal shape of a dropped payload - AND the normal shape of a
    # developer's own build output, an installer's staged uninstaller, and every
    # portable tool anyone has ever downloaded. On this machine specifically the
    # owner compiles unsigned binaries constantly. So it is carried as CONTEXT
    # that sharpens a real detection sitting next to it, and never raises an
    # incident by itself.
    Rule("unsigned-binary-from-drop-zone",
         "T1204 — User Execution", SEV_LOW, "unsigned_drop_zone",
         "An unsigned executable ran from a staging directory",
         signed="unsigned",
         path_any=("\\users\\public\\", "\\appdata\\local\\temp\\",
                   "\\downloads\\", "\\windows\\temp\\", "\\perflogs\\",
                   "\\$recycle.bin\\", "\\programdata\\microsoft\\windows\\"
                   "start menu\\programs\\startup\\")),
)


# ---------------------------------------------------------------------------
# IMPORTED RULES — public vendor and community detection content
# ---------------------------------------------------------------------------
# Detection content from elastic/protections-artifacts (Elastic 2.0) and SigmaHQ
# (DRL 1.1), each rule having survived the import funnel in valkyrie/edr/
# elastic_import.py and sigma_import.py: per-rule licence, exact
# expressibility, never-drop-a-conjunct, dead-rule, false-positive and duplicate
# gates.
#
# Kept in a SEPARATE list from RULES on purpose. Valkyrie's own coverage and
# borrowed coverage must stay countable apart, or "how many techniques do we
# detect" quietly becomes a number nobody can attribute - which is the
# fake-parity failure this project refuses to ship. RULES stays the native
# corpus; ALL_RULES is what actually gets evaluated.
#
# Both licences require attribution wherever matches are displayed, so each
# imported rule carries its source and upstream id in `reason`. Do not strip it.
IMPORTED_RULES_PATH = Path(__file__).resolve().parent / "defaults" / "imported_rules.json"

_IMPORTED_FIELDS = ("images", "images_not", "parents", "parents_not",
                    "cmd_all", "cmd_any", "cmd_any2", "cmd_any3", "cmd_not",
                    "path_any")


def load_imported_rules(path: Optional[Path] = None) -> tuple:
    """Load the shipped imported ruleset. Fail-soft, and never raises.

    A missing or damaged file means Valkyrie runs on its native rules alone -
    degraded, but working. An import corpus must never be able to take the
    engine down; borrowed content is a supplement, not a dependency.
    """
    target = Path(path) if path else IMPORTED_RULES_PATH
    out: list = []
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
        for d in data.get("rules", []):
            try:
                out.append(Rule(
                    id=str(d["id"]), technique=str(d.get("technique") or "unmapped"),
                    severity=str(d.get("severity") or SEV_MEDIUM),
                    label=str(d.get("label") or "imported"),
                    reason=str(d.get("reason") or ""),
                    **{f: tuple(d.get(f) or ()) for f in _IMPORTED_FIELDS}))
            except Exception:   # noqa: BLE001 — one bad rule must not lose the rest
                continue
    except Exception:   # noqa: BLE001
        return ()
    return tuple(out)


IMPORTED_RULES: tuple = load_imported_rules()

# What the engine actually evaluates. Native first, so a native rule's hit is
# the one recorded when both cover the same behaviour.
ALL_RULES: tuple = RULES + IMPORTED_RULES


def match_process(image: str, parent: str, cmdline: str,
                  path: str = "", signature: str = "") -> list[RuleHit]:
    """Return all rule hits for a process start, highest severity first. Pure.

    Rules are matched against the raw command line AND its de-obfuscated form
    (cmdline_normalize), and the hits are unioned. Matching BOTH is deliberate:
    normalization can then only ever ADD detections, so a rule that depends on
    raw syntax can never be broken by a normalizer change. Without this, every
    rule here is defeated by `n^et us^er /a^dd` - measured, 5 of 8 trivial
    obfuscations evaded the entire rule set.
    """
    im = (image or "").lower()
    par = (parent or "").lower()
    cmd = (cmdline or "").lower()
    pth = (path or "").lower().replace("/", "\\")

    sig = (signature or "").lower()

    seen: dict[str, RuleHit] = {}
    for r in ALL_RULES:
        if r.matches(im, par, cmd, pth, sig):
            seen[r.id] = RuleHit(r.id, r.label, r.technique, r.severity, r.reason)

    norm = normalize_cmdline(cmdline)
    if norm.changed:
        ncmd = norm.text.lower()
        if ncmd != cmd:
            # ALL_RULES, not RULES. Iterating only the native corpus here meant
            # the 109 imported rules got the raw pass and never the
            # de-obfuscated one - so `c^ertoc -LoadDLL` evaded every imported
            # rule while the native rules recovered it. Borrowed content has to
            # inherit the anti-evasion property, or importing it quietly ships a
            # second, weaker rule engine alongside the real one.
            for r in ALL_RULES:
                if r.id not in seen and r.matches(im, par, ncmd, pth, sig):
                    seen[r.id] = RuleHit(r.id, r.label, r.technique, r.severity,
                                         r.reason + " (recovered from an "
                                         "obfuscated command line)")

    hits = list(seen.values())
    hits.sort(key=lambda h: severity_rank(h.severity), reverse=True)
    return hits


def classify_behavior(image: str, parent: str, cmdline: str,
                      path: str = "", signature: str = "") -> Optional[dict]:
    """Top-level convenience: the highest-severity hit as a dict the collector
    merges into a telemetry event, plus every label. None if nothing fired.

    Returns: {severity, labels, technique, reason} - technique is the top hit's
    ATT&CK id so the EDR/kill-chain get an exact tactic.

    Obfuscation is treated as evidence in its own right. A command line built
    with caret/backtick escaping, token-splitting quotes, character arithmetic
    or string concatenation has no legitimate reason to look that way, so it
    escalates a rule hit and - on its own - still reports MEDIUM/T1027. That
    keeps the "attacker obfuscated something we have no rule for" case visible
    instead of silent. Cosmetic normalization (whitespace, env vars) never
    triggers this; only the EVASIVE transform class does.
    """
    hits = match_process(image, parent, cmdline, path, signature)
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
        # the same command typed plainly - an admin does not caret-escape.
        if severity_rank(severity) < severity_rank(SEV_HIGH):
            severity = SEV_HIGH
    return {
        "severity": severity,
        "technique": top.technique,
        # EVERY matched technique, highest-severity first, deduped. A single
        # action can legitimately be more than one ATT&CK technique (e.g.
        # `sc stop WinDefend` is BOTH T1489 Service Stop AND T1562.001 Impair
        # Defenses); `technique` keeps the single top pick for back-compat, but
        # the incident and the SOC analyst should see all of them, not have the
        # rule-ordering coin-flip silently drop the others.
        "all_techniques": list(dict.fromkeys(h.technique for h in hits)),
        "labels": labels,
        "reason": reason,
        "rule_ids": [h.rule_id for h in hits],
        "normalized": norm.text if norm.changed else "",
    }
