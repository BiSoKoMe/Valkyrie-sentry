"""Root cause and concrete code fix for every miss, plus standalone findings
discovered by running the harness rather than by reading source alone.

Keyed by catalog technique `id` (not `technique_id` -- several techniques
appear more than once with different delivery/probe context, and the fix is
often specific to which entry point is broken).

Each entry cites the exact file and function to change. "Concrete" is the bar:
no entry here should be vaguer than something a contributor could start
implementing from directly.
"""

from __future__ import annotations

# =============================================================================
# THE ARCHITECTURAL FIX -- upgrades the largest number of misses at once
# =============================================================================

ARCHITECTURAL_FIX = {
    "title": "Wire Sysmon EID 1's CommandLine into the 32-rule IOA engine",
    "affects": [
        "exec-mshta-remote", "exec-regsvr32-squiblydoo", "exec-rundll32-proxy",
        "exec-wmic-process-call", "evasion-clear-eventlogs",
        "evasion-certutil-decode", "evasion-firewall-disable",
        "cred-sam-dump", "disc-domain-trust", "lat-wmi-remote",
        "c2-ingress-tool-transfer", "impact-shadow-delete",
    ],
    "root_cause": (
        "etw/sysmon.py's EID 1 (process creation) handler calls "
        "classify_process(name, path, parent) -- name/path/lineage only. It "
        "never calls classify_behavior() / match_process() from "
        "behavioral_rules.py, so the 32 named IOA rules (which contain "
        "exactly the patterns these techniques need: regsvr32 /i:, "
        "comsvcs.dll MiniDump, wevtutil cl, vssadmin delete shadows, "
        "Set-MpPreference -Disable*, reg save hklm\\sam, nltest "
        "/domain_trusts, wmic /node:, certutil -urlcache) are reachable "
        "ONLY through process_telemetry.ProcInfo.to_event(), which is fed "
        "exclusively by a plain psutil poll on a 2.0-second interval "
        "(ProcessCollector, process_telemetry.py:258). Sysmon's own "
        "CommandLine field -- present in the raw ETW event -- is read for "
        "nothing else and discarded. Native one-shot commands exit in well "
        "under 2 seconds, so this poller loses the race for most of them, "
        "REGARDLESS OF WHETHER SYSMON IS INSTALLED, which is the "
        "counter-intuitive part: installing Sysmon does not fix this, "
        "because Sysmon's process-creation path was never connected to the "
        "rule engine that would use it."
    ),
    "code_change": (
        "In valkyrie/etw/sysmon.py, function classify_sysmon(), the `if eid "
        "== 1:` branch (~line 97): after computing `image`/`parent`, also "
        "read `cmdline = d.get('CommandLine', '')` and call "
        "`behavior = classify_behavior(_name(image), parent, cmdline, "
        "image)` from behavioral_rules.py (already imported project-wide; "
        "add the import to sysmon.py). If `behavior` is not None, raise "
        "`sev` to max(sev, behavior['severity']), merge behavior['labels'] "
        "into `labels`, and set `technique = behavior['technique']` on the "
        "returned dict (the `technique` field on EID 1 events is currently "
        "always ''). This single change gives real-time delivery -- "
        "independent of the 2s poller -- to all 32 rules on any host with "
        "Sysmon installed, which is exactly the provisioning "
        "redteam/provision.ps1 already sets up. It converts most of the "
        "'affects' list above from MISS to a genuine DETECT on a "
        "Sysmon-equipped VM, and does not touch the bare-metal (no Sysmon) "
        "case, which honestly remains a gap without the kernel driver."
    ),
    "estimated_effort": "Small, contained, single-file change; the hard part "
        "(the rule engine, the classify_behavior API) already exists and is "
        "tested. Needs a new test asserting EID 1 + a rule-matching cmdline "
        "produces a technique-tagged event, plus a regression check that "
        "EID 1 without Sysmon's CommandLine populated still degrades to the "
        "current name/path-only behaviour rather than raising.",
}

# =============================================================================
# Standalone findings NOT fixed by the architectural change
# =============================================================================

PER_TECHNIQUE = {

    "exec-powershell-encoded": {
        "root_cause": (
            "classify_powershell (etw/powershell.py) has TWO delivery paths "
            "with different reliability: real-time via PowerShell Script "
            "Block Logging (event 4104, enabled by provision.ps1), or the "
            "racy 2s process poll for the launching powershell.exe cmdline "
            "if 4104 logging is off. This entry is scored on the process-"
            "launch path; the 4104 path is a separate, more reliable signal "
            "this evaluation did not independently probe."
        ),
        "code_change": (
            "Confirm (during the VM pass) that PS Script Block Logging is "
            "actually being consumed end-to-end, not just enabled in Group "
            "Policy by provision.ps1 -- i.e. that something subscribes to "
            "the Microsoft-Windows-PowerShell/Operational log's event 4104 "
            "and calls classify_powershell on its ScriptBlockText. If that "
            "consumer does not exist yet, it is the single highest-value "
            "addition for the whole Execution tactic: PowerShell is the "
            "most common real-world delivery mechanism, and 4104 logging "
            "captures the deobfuscated script body, not just the launch "
            "command line."
        ),
    },

    "exec-cmd-office-child": {
        "root_cause": (
            "classify_process's office-parent/shell-child rule is reachable "
            "only via the racy 2s poller (same as the 32 IOA rules, but "
            "this one lives in process_telemetry.py directly rather than "
            "behavioral_rules.py, so the architectural EID1 fix does not "
            "help it -- EID1 already calls classify_process, just not "
            "classify_behavior). The saving grace noted in the catalog is "
            "that a real payload cmd.exe from Office usually stays alive "
            "longer than a bare LOLBin invocation, giving the poller a "
            "better chance -- hence CONDITIONAL, not MISS."
        ),
        "code_change": (
            "This one is ALREADY reachable from Sysmon EID1 today (unlike "
            "the 32 IOA rules) because classify_process is what EID1 calls. "
            "No code change is required for the office-parent/shell-child "
            "signal specifically -- its reliability is a genuine timing "
            "question to confirm in Tier B, not a wiring gap to fix."
        ),
    },

    "exec-lure-doubleext": {
        "root_cause": (
            "score_process (behavior_score.py) is reachable through the "
            "SAME path as the 32 IOA rules -- ProcInfo.to_event(), fed by "
            "the 2s poller -- so it inherits the identical timing "
            "dependency. The mitigating factor is behavioural, not "
            "architectural: a double-extension dropper typically does "
            "something after launch (drops a payload, opens a decoy "
            "document) rather than exiting immediately, which is why this "
            "is CONDITIONAL rather than a clean MISS."
        ),
        "code_change": (
            "Covered by the architectural EID1 fix for the general case "
            "(wiring classify_behavior's cousin, score_process, into EID1 "
            "the same way would help here too -- consider adding it in the "
            "same change, since both functions take the same "
            "(image, parent, cmdline, path) shape). Until then, this "
            "technique's real reliability depends on payload behaviour "
            "after launch, which this evaluation cannot characterise from "
            "a synthetic replay."
        ),
    },

    "persist-wmi-subscription": {
        "root_cause": (
            "A named rule exists (wmi-event-consumer in behavioral_rules.py) "
            "and etw/wmi.py:classify_wmi exists, but whether a live "
            "WMI-Activity ETW consumer actually feeds classify_wmi in the "
            "running product was NOT confirmed end-to-end during this "
            "evaluation -- flagged as SOURCE_PARTIAL rather than asserted "
            "either way, unlike every source_confidence=CONFIRMED entry in "
            "this report."
        ),
        "code_change": (
            "Before writing a fix, CONFIRM the wiring: grep for who "
            "actually calls classify_wmi() in etw/wmi.py's own module and "
            "trace it to a live event source the way this report traced "
            "classify_behavior. If no live caller exists, the fix is the "
            "same shape as the architectural one -- subscribe to the "
            "WMI-Activity operational log (or Sysmon's WmiEvent EIDs 19-21, "
            "if configured) and route __EventFilter / "
            "CommandLineEventConsumer creation into classify_wmi in real "
            "time rather than leaving it reachable only via the process "
            "poller catching wmic.exe alive."
        ),
    },

    "evasion-defender-disable": {
        "root_cause": (
            "Named rule exists (defender-disable). CONDITIONAL rather than "
            "MISS specifically because a PowerShell cmdlet invocation "
            "(Set-MpPreference) has a longer process lifetime than a bare "
            "native exe, AND PS Script Block Logging (if actually wired -- "
            "see exec-powershell-encoded above) gives a second, independent "
            "real-time path."
        ),
        "code_change": (
            "Covered by the architectural EID1 fix for the process-launch "
            "path. For a real-time backstop independent of both that and "
            "PS logging: Defender's own state changes are queryable via "
            "Get-MpComputerStatus / the MSFT_MpComputerStatus WMI class -- "
            "a periodic (15s, alongside the persistence scan) check of "
            "AMRunningMode / RealTimeProtectionEnabled catches the STATE "
            "CHANGE itself, independent of catching the disabling process, "
            "exactly the artifact-at-rest pattern used elsewhere in this "
            "report's recommendations."
        ),
    },

    "evasion-process-injection": {
        "root_cause": (
            "Sysmon EID 8 (CreateRemoteThread) IS wired directly to a "
            "real-time classifier in etw/sysmon.py -- this is NOT a wiring "
            "gap like the 32 IOA rules. The condition is binary and "
            "external: Sysmon must be installed. There is no fallback "
            "sensor -- the kernel driver that could provide one (driver/ "
            "valkyrie_km, docs/adr/0026) has never been compiled."
        ),
        "code_change": (
            "No code change to Valkyrie's classifier is needed -- the EID 8 "
            "handler is correct as written. The actual blocker is "
            "docs/adr/0026's kernel driver, which would give injection "
            "visibility without depending on Sysmon at all. Confirming this "
            "technique's real-world detection rate is entirely a Tier B "
            "question: does the VM have Sysmon installed and configured to "
            "log EID 8 (it is NOT logged by Sysmon's default config -- "
            "provision.ps1's sysmonconfig must explicitly enable "
            "CreateRemoteThread logging, which is high-volume and often "
            "excluded by default configs for noise reasons)."
        ),
    },

    "cred-lsass-comsvcs": {
        "root_cause": (
            "Sysmon EID 10 (ProcessAccess -> lsass.exe) is wired directly, "
            "real-time, independent of the poller -- genuinely the most "
            "reliable credential-access detection in the product on a "
            "Sysmon-equipped host. The cmdline rule (comsvcs-minidump) is "
            "ALSO racy on its own; EID 10 is what actually saves this "
            "technique."
        ),
        "code_change": (
            "No fix needed for the classifier. As with process injection, "
            "confirm Sysmon is configured to log EID 10 for lsass.exe "
            "specifically (Sysmon's default config typically DOES include "
            "an LSASS ProcessAccess rule since it's a well-known high-value "
            "signal, but provision.ps1's exact config should be checked "
            "rather than assumed)."
        ),
    },

    "cred-lsass-procdump": {
        "root_cause": "Identical to cred-lsass-comsvcs -- same EID 10 path, "
            "different tool.",
        "code_change": "Same as cred-lsass-comsvcs.",
    },

    "disc-whoami-priv": {
        "root_cause": (
            "A named rule exists (T1033, LOW severity) -- the one Discovery "
            "technique with dedicated coverage before this evaluation. "
            "whoami.exe exits in single-digit milliseconds, so the racy "
            "poller reliably loses this race. This is the exact case the "
            "prior redteam/README.md already called 'LIKELY MISS'; this "
            "evaluation confirms it via source trace rather than intuition, "
            "and generalises it to every single-shot discovery command."
        ),
        "code_change": (
            "Covered by the architectural EID1 fix for the timing "
            "component. But note: LOW severity was likely chosen precisely "
            "because a lone `whoami /priv` is weak evidence on its own -- "
            "raising it to fire more aggressively as a standalone signal "
            "would reintroduce the FP risk the project's design principle "
            "argues against. The recon-burst ESP sequence fix (see "
            "disc-local-accounts) is the more consistent long-term answer: "
            "let whoami contribute a weak signal to a COMBINATION, rather "
            "than trying to make it fire reliably alone."
        ),
    },

    "lat-psexec-smb": {
        "root_cause": (
            "Named rule exists (T1021.002); racy poller only. CONDITIONAL "
            "rather than MISS because PsExec's remote service process tends "
            "to run longer than a bare native command. ALSO structurally "
            "limited to a single-VM evaluation the same way as the other "
            "Lateral Movement entries: a self-target run proves the tool/ "
            "service signature is recognised, not that cross-host movement "
            "is detected."
        ),
        "code_change": (
            "Covered by the architectural fix for the single-host "
            "signature. The cross-host gap is a test-infrastructure "
            "limitation, not a code fix -- see the Lateral Movement tactic "
            "note recommending a 2-VM topology for tier 4."
        ),
    },

    "evasion-encoded-powershell": {
        "root_cause": (
            "classify_cmdline's encoded-PowerShell signal is reachable via "
            "TWO different call sites with different reliability: the racy "
            "2s process poll (process_telemetry.ProcInfo.to_event) for a "
            "one-shot interactive launch, and the reliable 15s artifact-at-"
            "rest persistence scan (_persistence_severity) when the encoded "
            "command is stored IN a persistence location rather than run "
            "interactively. CONDITIONAL reflects that split: which path "
            "applies depends entirely on how the atomic delivers the "
            "encoded command."
        ),
        "code_change": (
            "Covered by the architectural EID1 fix for the interactive-"
            "launch case (classify_cmdline could be folded into the same "
            "EID1 wiring change, or called alongside classify_behavior "
            "since both take a cmdline string). No change needed for the "
            "persistence-artifact case -- it is already reliable."
        ),
    },

    "persist-local-account": {
        "root_cause": (
            "No artifact-at-rest scanner for local accounts, unlike "
            "registry Run keys / scheduled tasks / services / startup "
            "folder (all covered by persistence_telemetry.py's 15s poller). "
            "Detection depends entirely on catching `net.exe` alive during "
            "the 2s process poll; `net user ... /add` exits near-instantly."
        ),
        "code_change": (
            "Add a fifth ASEP-style check to persistence_telemetry.py: "
            "PersistenceCollector already snapshot-diffs 4 location types "
            "every 15s (see _ACTIVITY_LABEL). Add a local-accounts snapshot "
            "using `net user` output (or, better, the Win32_UserAccount WMI "
            "class via `wmi` if already a dependency, or parsing "
            "`net user` -- diff the account-name set between polls the same "
            "way _run_key_specs() diffs registry values. A NEW account "
            "appearing between two 15s polls is itself the signal, "
            "independent of catching the creating process -- the same "
            "principle that makes the existing 4 ASEP checks reliable. "
            "This ALSO fixes T1087.001 Discovery's false-negative in the "
            "sense that it stops relying on catching the discovery command "
            "at all -- discovery of an account Valkyrie already knows about "
            "genuinely has no artifact to detect, which is a fair, honest "
            "limit rather than a gap (see the Discovery tactic note below)."
        ),
        "related_finding": "net-user-add-overbroad",
    },

    "disc-local-accounts": {
        "root_cause": (
            "See OVERBROAD_RULE_FINDINGS['net-user-add-overbroad'] -- the "
            "existing rule fires on this input, but as a MISLABELED "
            "T1136.001 hit, not as recognition of T1087.001 discovery. "
            "Separately: Discovery techniques that only ever READ state "
            "(whoami, systeminfo, tasklist, net view, net user with no "
            "argument) are architecturally the hardest tactic for any EDR "
            "that scores on process behaviour, because the commands "
            "themselves are indistinguishable from routine administration -- "
            "the entire category of 'single discovery command, alone, at "
            "medium+ severity' is a false-positive generator by "
            "construction, and Valkyrie's own precision-over-aggression "
            "design principle (documented in behavior_score.py's module "
            "docstring) argues against ever firing on one in isolation."
        ),
        "code_change": (
            "Do not add a HIGH/MEDIUM severity rule for any single discovery "
            "command -- that would trade a real detection gap for a real FP "
            "generator, which is the wrong trade for this product. Instead: "
            "add a WEAK, INFO-severity label ('discovery_command') to "
            "classify_process() for a small, curated set of discovery "
            "LOLBins (systeminfo.exe, tasklist.exe, net.exe view/user with "
            "no mutating args, nltest.exe, whoami.exe), and add a new ESP "
            "sequence rule to behavioral_sequences.py: fire (MEDIUM, "
            "'reconnaissance burst') only when >= 3 DISTINCT discovery "
            "labels are observed from the SAME actor within a short window "
            "(e.g. 120s) -- mirroring the existing 'combination of weak "
            "signals' pattern already used for the anomaly scorer. A single "
            "`whoami` never fires anything; `whoami` + `systeminfo` + "
            "`net user` + `tasklist` inside two minutes does. This is "
            "consistent with the project's own stated design philosophy "
            "rather than a bolt-on."
        ),
    },

    "disc-systeminfo": {"root_cause": "No rule exists for systeminfo.exe at "
        "all -- a genuine coverage hole, not a wiring hole.",
        "code_change": "See disc-local-accounts's fix -- part of the same "
                       "recon-burst ESP sequence, not a standalone rule."},
    "disc-tasklist": {"root_cause": "No rule exists for tasklist.exe.",
        "code_change": "Same recon-burst ESP sequence fix."},
    "disc-net-view": {"root_cause": "No rule exists for `net view`.",
        "code_change": "Same recon-burst ESP sequence fix."},
    "disc-domain-trust": {
        "root_cause": "A named rule (T1482) exists but is reachable only "
                      "via the racy 2s poller (nltest.exe exits fast). "
                      "Requires a domain-joined host to test authentically.",
        "code_change": "Covered by the architectural Sysmon-EID1 fix above; "
                       "no additional change needed beyond that."},

    "cred-sam-dump": {
        "root_cause": "`reg save hklm\\sam` has a named rule "
            "(behavioral_rules.py T1003.002) but, unlike LSASS access "
            "(Sysmon EID 10, ProcessAccess), there is no Sysmon event for a "
            "registry SAVE API call specifically -- EID 10 only covers "
            "process-handle access, not registry operations. So this "
            "technique has no real-time backstop even after the "
            "architectural fix restores EID1-cmdline coverage (which still "
            "leaves it dependent on the racy poller, just no longer WORSE "
            "than that).",
        "code_change": "Two options, in order of value: (1) the "
            "architectural fix above at minimum gets this to the same "
            "racy-but-present level as the other LOLBin rules. (2) For a "
            "real fix, Sysmon can be configured (via provision.ps1's "
            "sysmonconfig) to log EID 12/13/14 (RegistryEvent) for the SAM "
            "hive path specifically -- add a RegistryEvent handler to "
            "etw/sysmon.py for EID 12 (key create/delete) or 13 (value set) "
            "scoped to `HKLM\\SAM` / `HKLM\\SYSTEM`, which fires on the API "
            "call itself rather than depending on process survival."},

    "evasion-clear-eventlogs": {
        "root_cause": "Named rule exists (`T1070.001`); no Sysmon EID "
            "backstop for `wevtutil cl` specifically -- there is no "
            "'log cleared' Sysmon event Valkyrie currently consumes.",
        "code_change": "Covered by the architectural fix for the racy-poller "
            "case. For a real-time backstop independent of that: consume "
            "Windows Security event 1102 ('The audit log was cleared') via "
            "the SAME wineventlog.py machinery already used elsewhere "
            "(valkyrie/etw/wineventlog.py:parse_event_xml) -- this event is "
            "generated by the OS itself at the moment of clearing, "
            "independent of catching wevtutil.exe alive."},

    "evasion-firewall-disable": {
        "root_cause": "Named rule exists; racy poller only.",
        "code_change": "Covered by the architectural fix. A stronger, "
            "state-based backstop: Valkyrie's own firewall.py could "
            "periodically verify (alongside the persistence 15s poll) that "
            "the Windows Firewall service state matches what Valkyrie last "
            "set, the same pattern as the persistence ASEP scanner -- state "
            "drift detected at rest, not dependent on catching the process."},

    "impact-shadow-delete": {
        "root_cause": "Named CRITICAL-severity rule exists; racy poller "
            "only, and if this atomic runs standalone (not chained after a "
            "ransomware encryption phase the canary already caught), a "
            "CRITICAL-severity technique may go completely unseen.",
        "code_change": "Covered by the architectural fix as the primary "
            "improvement. Additionally: vssadmin/wbadmin/wmic "
            "shadowcopy delete all leave a durable, checkable artifact -- "
            "the shadow copy set itself is now empty. A periodic check "
            "(`vssadmin list shadows` parsed, or the VSS WMI provider) that "
            "detects an unexpected drop in shadow-copy count is an "
            "artifact-at-rest signal exactly like the persistence scanner, "
            "and would catch this even if the deleting process is never "
            "observed at all."},

    "impact-service-stop": {
        "root_cause": "No rule exists for `sc stop` / `Stop-Service` / "
            "`Set-Service -StartupType Disabled` targeting security-"
            "relevant services at all.",
        "code_change": "Add a new rule to behavioral_rules.py's RULES tuple: "
            "images=('sc.exe','powershell.exe'), "
            "cmd_any=('stop', 'config start= disabled') combined with a "
            "curated set of security-service names (WinDefend, "
            "SecurityHealthService, Sysmon64, EventLog, wuauserv, and "
            "Valkyrie's own service name) checked as a substring of the "
            "full command line -- technique T1489, severity HIGH. Because "
            "this is a state-CHANGING action against a well-known, finite "
            "list of service names (not a generic pattern), it is also a "
            "good candidate for an artifact-at-rest check: a periodic (15s, "
            "alongside the persistence scan) query of each watched "
            "service's StartMode/State via Win32_Service, flagging any "
            "watched service that transitions from Running/Auto to "
            "Stopped/Disabled without a corresponding Valkyrie-initiated "
            "change. This is the one fix in this report that does not "
            "depend on the architectural Sysmon change at all, and is "
            "worth prioritizing precisely because it is independently "
            "reliable."},

    "cred-browser-stores": {
        "root_cause": "Named rule exists (T1555); racy poller only, and "
            "PowerShell Get-Content against a browser profile path has no "
            "independent real-time backstop the way LSASS access does.",
        "code_change": "Covered by the architectural fix for the "
            "process-launch case. A stronger fix specifically for browser "
            "credential stores: file-system watch (already partially "
            "present via the ransomware canary's file-monitoring "
            "machinery) on the small, well-known set of browser "
            "credential-store paths (Chrome/Edge 'Login Data', Firefox "
            "'logins.json', etc.) -- an unexpected READ of one of these "
            "paths by a process other than the browser itself is a strong, "
            "specific signal independent of the launching command line."},

    "lat-wmi-remote": {
        "root_cause": "Named rule exists; racy poller only. ALSO "
            "structurally limited to a single-VM evaluation: real lateral "
            "movement requires a second host, so even a perfect detection "
            "here only proves the tool signature is recognised, not that "
            "cross-host movement specifically is caught.",
        "code_change": "Covered by the architectural fix for the "
            "single-host signature. The cross-host gap is a TEST-"
            "INFRASTRUCTURE limitation, not a code fix -- see the Lateral "
            "Movement tactic note recommending a 2-VM topology for tier 4."},

    "lat-tool-transfer": {
        "root_cause": "No rule exists for file-copy-to-admin-share patterns "
            "at all (`copy X \\\\host\\C$\\...`).",
        "code_change": "Add a rule to behavioral_rules.py: images=('cmd.exe', "
            "'powershell.exe', 'robocopy.exe', 'xcopy.exe'), "
            "cmd_any=('\\\\\\\\','$\\\\') combined with a written-executable "
            "extension check on the destination -- technique T1570, "
            "severity MEDIUM (this pattern alone is common in legitimate IT "
            "admin work, so MEDIUM not HIGH, consistent with the project's "
            "precision-first stance). Same single-VM caveat as above for "
            "proving the cross-host case."},
}

# =============================================================================
# Findings discovered BY RUNNING the harness, not predicted from source
# =============================================================================

OVERBROAD_RULE_FINDINGS = {
    "net-user-add-overbroad": {
        "discovered_via": "Tier A replay of disc-local-accounts "
            "(T1087.001) -- the real classify_behavior() call returned a "
            "hit where the catalog's static-analysis prediction was 'no "
            "code path'.",
        "location": "valkyrie/behavioral_rules.py, Rule('net-user-add', ...) "
            "cmd_any=('net user', 'net.exe user', "
            "'net localgroup administrators')",
        "problem": "Matches on the bare substring 'net user' with NO "
            "requirement for a mutating argument. `net user` alone (lists "
            "all local accounts -- routine, benign, and common) fires the "
            "identical MEDIUM-severity 'T1136.001 Create Local Account' "
            "incident as `net user backdoor P@ssw0rd123! /add` (an actual "
            "backdoor account). Same problem for `net localgroup "
            "administrators` (listing membership) vs `net localgroup "
            "administrators evilcorp /add` (adding to it).",
        "impact": "A real, live false-positive generator on any machine "
            "where routine administration includes listing local accounts "
            "or admin-group membership -- exactly the FP class this "
            "project's own stated design principle (precision over "
            "aggression, false positive is worse than a miss) argues "
            "hardest against, and it is currently shipping.",
        "code_change": "Zero engine changes needed -- `Rule.cmd_all` (ALL "
            "substrings must be present) already exists in the dataclass "
            "(behavioral_rules.py line ~43) and is used by other rules in "
            "the same file; this rule simply used the wrong field. Replace "
            "the single net-user-add Rule (cmd_any=('net user', 'net.exe "
            "user', 'net localgroup administrators')) with two rules using "
            "cmd_all instead: Rule(..., cmd_all=('net user', '/add')) for "
            "account creation, and Rule(..., cmd_all=('net localgroup "
            "administrators', '/add')) for admin-group addition. A one-rule "
            "data change, no new code path, removes a live FP source "
            "without affecting recall on the real malicious case (every "
            "genuine T1136.001 atomic includes /add).",
    },
}
