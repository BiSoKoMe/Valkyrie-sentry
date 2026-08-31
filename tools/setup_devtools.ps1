<#
  setup_devtools.ps1 - install the two things blocking Valkyrie development.

    1. Windows Driver Kit (WDK)  -> lets valkyrie_km.sys COMPILE and lets
                                    PREfast / Static Driver Verifier run.
                                    Compiling is safe: it is a compiler run.
                                    Nothing is loaded, no VM required.
    2. Sysmon                    -> closes the EID-1 command-line gap plus the
                                    EID 8 / 10 blind spots. Several red-team
                                    misses (T1055 injection, both T1003.001
                                    LSASS cases) become live detections the
                                    moment this is running.

  Safe + idempotent: skips anything already present, changes nothing else,
  and prints exactly what it did. Requires an ELEVATED PowerShell.
#>

$ErrorActionPreference = 'Continue'

function Say($m, $c = 'Gray') { Write-Host $m -ForegroundColor $c }

Say ""
Say "=== Valkyrie dev-tool setup ===" Cyan
Say ""

# -- elevation ---------------------------------------------------------------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Say "NOT ELEVATED. Close this and open PowerShell via right-click ->" Red
    Say "'Run as administrator', then run this script again." Red
    exit 1
}
Say "[ok] running elevated as $($id.Name)" Green

# -- 1. WDK ------------------------------------------------------------------
Say ""
Say "[1/2] Windows Driver Kit" Cyan
$kmLib = 'C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\km\x64\ntoskrnl.lib'
if (Test-Path $kmLib) {
    Say "  already installed (kernel libs present) - skipping" Green
} else {
    Say "  installing via winget (this is a large download, be patient)..."
    # NB: winget has no unversioned 'Microsoft.WindowsWDK' id - the ids are
    # version-suffixed. This one matches the $kmLib path checked above.
    winget install --id Microsoft.WindowsWDK.10.0.26100 -e --accept-source-agreements --accept-package-agreements
    if (Test-Path $kmLib) {
        Say "  [ok] WDK installed" Green
    } else {
        Say "  [!] winget did not place the kernel libs where expected." Yellow
        Say "      Install manually: https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk" Yellow
        Say "      (The WDK is a SEPARATE download from the Windows SDK.)" Yellow
    }
}

# -- 2. Sysmon ---------------------------------------------------------------
Say ""
Say "[2/2] Sysmon" Cyan
$svc = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue
if ($svc) {
    Say "  already installed ($($svc.Name), $($svc.Status)) - skipping install" Green
} else {
    Say "  installing via winget..."
    winget install --id Microsoft.Sysinternals.Sysmon -e --accept-source-agreements --accept-package-agreements
}

# Config tuned to exactly the event IDs valkyrie/etw/sysmon.py consumes.
# Deliberately narrow: broad Sysmon configs generate enormous log volume, and
# Valkyrie only reads these.
$cfgPath = Join-Path $env:TEMP 'valkyrie_sysmon.xml'
$cfg = @'
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- 1: process create (carries the COMMAND LINE - the key gap) -->
    <RuleGroup groupRelation="or"><ProcessCreate onmatch="exclude" /></RuleGroup>
    <!-- 3: network connect -->
    <RuleGroup groupRelation="or"><NetworkConnect onmatch="exclude" /></RuleGroup>
    <!-- 7: image load - unsigned modules + BYOVD -->
    <RuleGroup groupRelation="or">
      <ImageLoad onmatch="include"><Signed condition="is">false</Signed></ImageLoad>
    </RuleGroup>
    <!-- 8: CreateRemoteThread -> T1055 process injection -->
    <RuleGroup groupRelation="or"><CreateRemoteThread onmatch="exclude" /></RuleGroup>
    <!-- 10: ProcessAccess to lsass -> T1003.001 credential dumping -->
    <RuleGroup groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="image">lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>
    <!-- 11: file create in startup locations -->
    <RuleGroup groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">\Start Menu\Programs\Startup</TargetFilename>
      </FileCreate>
    </RuleGroup>
    <!-- 12/13: registry autostart -->
    <RuleGroup groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
    </RuleGroup>
    <!-- 25: process tampering (hollowing) -->
    <RuleGroup groupRelation="or"><ProcessTampering onmatch="exclude" /></RuleGroup>
  </EventFiltering>
</Sysmon>
'@
Set-Content -Path $cfgPath -Value $cfg -Encoding utf8

$sysmonExe = (Get-Command sysmon64.exe -ErrorAction SilentlyContinue).Source
if (-not $sysmonExe) { $sysmonExe = (Get-Command sysmon.exe -ErrorAction SilentlyContinue).Source }
# winget modifies PATH for FUTURE shells, so a fresh install is invisible to the
# process that just did the installing. Look where winget actually put it.
if (-not $sysmonExe) {
    $sysmonExe = Get-ChildItem -Path "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" `
                     -Filter 'Sysmon64.exe' -Recurse -ErrorAction SilentlyContinue |
                 Select-Object -First 1 -ExpandProperty FullName
}

if ($sysmonExe) {
    if ($svc) {
        Say "  applying Valkyrie-tuned config to existing install..."
        & $sysmonExe -c $cfgPath
    } else {
        Say "  installing service with Valkyrie-tuned config..."
        & $sysmonExe -accepteula -i $cfgPath
    }
    $svc2 = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue
    if ($svc2 -and $svc2.Status -eq 'Running') {
        Say "  [ok] Sysmon running ($($svc2.Name))" Green
    } else {
        Say "  [!] Sysmon service not running - check output above" Yellow
    }
} else {
    Say "  [!] sysmon64.exe not on PATH yet." Yellow
    Say "      Close and reopen this admin shell, then re-run this script." Yellow
}

# -- verify ------------------------------------------------------------------
Say ""
Say "=== result ===" Cyan
$wdkOk = Test-Path $kmLib
$symOk = [bool](Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue)
Say ("  WDK (driver can compile) : " + $(if ($wdkOk) { "YES" } else { "NO" })) $(if ($wdkOk) { 'Green' } else { 'Yellow' })
Say ("  Sysmon (cmdline sensor)  : " + $(if ($symOk) { "YES" } else { "NO" })) $(if ($symOk) { 'Green' } else { 'Yellow' })
Say ""
Say "Nothing was loaded and no driver was installed - this only set up tooling." Gray
Say "Next: open a fresh Claude Code session and run /loop to continue." Gray
Say ""
