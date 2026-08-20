# ============================================================================
#  provision.ps1 - prepare a VM guest to give Valkyrie its honest best shot at
#  Atomic Red Team. Run ELEVATED inside the throwaway VM. No reboot required.
#
#  Installs / enables:
#    1. Sysmon (+ SwiftOnSecurity config) - unlocks injection (EID 8), LSASS
#       access (EID 10), image loads (EID 7), network+process (EID 3). Without
#       this Valkyrie is blind to memory-level tradecraft.
#    2. PowerShell Script Block Logging (4104) - unlocks the PowerShell atomics.
#    3. Red Canary's Invoke-AtomicRedTeam module + the atomics folder.
#
#  It does NOT install Valkyrie - install ValkyrieSetup.exe separately and
#  confirm its API answers on http://127.0.0.1:8090 before running the tests.
#
#  DESTRUCTIVE-TEST SAFETY: this only prepares the box. Take a VM snapshot AFTER
#  provisioning and BEFORE running run-redteam.ps1.
# ============================================================================
[CmdletBinding()]
param(
    [string]$WorkDir = "C:\redteam",
    [switch]$SkipSysmon,
    [switch]$SkipAtomics
)

$ErrorActionPreference = "Stop"
function Info($m) { Write-Host "[provision] $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "[provision] $m" -ForegroundColor Yellow }

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this elevated (Administrator) - it configures logging and installs Sysmon."
}
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

# ---------------------------------------------------------------------------
# 1. Sysmon
# ---------------------------------------------------------------------------
if (-not $SkipSysmon) {
    if (Get-Service -Name Sysmon*, 'Sysmon64' -ErrorAction SilentlyContinue) {
        Info "Sysmon already installed - leaving it."
    } else {
        Info "Downloading Sysmon + SwiftOnSecurity config..."
        $sysZip = Join-Path $WorkDir "Sysmon.zip"
        $sysDir = Join-Path $WorkDir "Sysmon"
        Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $sysZip -UseBasicParsing
        Expand-Archive $sysZip -DestinationPath $sysDir -Force
        $cfg = Join-Path $WorkDir "sysmonconfig.xml"
        Invoke-WebRequest "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
            -OutFile $cfg -UseBasicParsing
        # The SwiftOnSecurity config keeps ProcessAccess (EID 10) minimal because
        # it is noisy — but EID10->lsass.exe is EXACTLY the signal Valkyrie's
        # credential-theft (T1003.001) detection consumes. Without it the LSASS
        # atomics run and Sysmon logs NOTHING, so the technique scores MISS for a
        # blind-sensor reason, not a rule reason (confirmed by a live run: EID10
        # count = 0 during the destructive battery). Add an explicit, additive
        # ProcessAccess include RuleGroup for lsass.exe so the sensor emits what
        # the detector needs. Additive (Sysmon ORs RuleGroups), and fully
        # best-effort: any failure falls back to the stock config so provisioning
        # — and the whole run — can never be broken by this patch.
        try {
            [xml]$sx = Get-Content $cfg -Raw
            $filtering = $sx.Sysmon.EventFiltering
            if ($filtering) {
                $rg = $sx.CreateElement("RuleGroup")
                $rg.SetAttribute("name", "valkyrie-lsass-access")
                $rg.SetAttribute("groupRelation", "or")
                $pa = $sx.CreateElement("ProcessAccess")
                $pa.SetAttribute("onmatch", "include")
                $ti = $sx.CreateElement("TargetImage")
                $ti.SetAttribute("condition", "image")
                $ti.InnerText = "lsass.exe"
                $pa.AppendChild($ti) | Out-Null
                $rg.AppendChild($pa) | Out-Null
                $filtering.AppendChild($rg) | Out-Null
                $sx.Save($cfg)
                Info "Patched Sysmon config: ProcessAccess->lsass.exe (EID 10) explicitly ON."
            } else {
                Warn "Sysmon config had no EventFiltering node — using stock config."
            }
        } catch {
            Warn "Could not patch Sysmon config for lsass EID10 (using stock): $($_.Exception.Message)"
        }
        Info "Installing Sysmon..."
        & (Join-Path $sysDir "Sysmon64.exe") -accepteula -i $cfg
        Info "Sysmon installed."
    }
} else { Warn "Skipping Sysmon (per -SkipSysmon) - memory-level atomics will be invisible to Valkyrie." }

# ---------------------------------------------------------------------------
# 2. PowerShell Script Block Logging (Event 4104)
# ---------------------------------------------------------------------------
Info "Enabling PowerShell Script Block Logging (4104)..."
$psKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $psKey -Force | Out-Null
New-ItemProperty -Path $psKey -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force | Out-Null
Info "Script Block Logging enabled."

# ---------------------------------------------------------------------------
# 3. Invoke-AtomicRedTeam + atomics
# ---------------------------------------------------------------------------
if (-not $SkipAtomics) {
    Info "Installing Invoke-AtomicRedTeam (Red Canary) + atomics..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    # The classic NuGet package-provider bootstrap is flaky under PowerShell 7
    # (it threw and aborted provisioning on the GitHub runner) and is NOT required
    # there for Install-Module. Make it strictly best-effort; PSResourceGet /
    # PowerShellGet in pwsh handles the download without it.
    try {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null
    } catch { Warn "NuGet provider bootstrap skipped (not needed on pwsh): $($_.Exception.Message)" }
    try { Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop } catch {}
    Install-Module -Name Invoke-AtomicRedTeam -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck -ErrorAction Stop
    Import-Module Invoke-AtomicRedTeam -Force
    # Fetch the atomics content (the actual test definitions) next to the module.
    IEX (IWR "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1" -UseBasicParsing)
    Install-AtomicRedTeam -getAtomics -Force
    Info "Atomic Red Team ready."
} else { Warn "Skipping Atomic module (per -SkipAtomics)." }

Info "Provisioning complete."
Write-Host ""
Write-Host "  NEXT:" -ForegroundColor Green
Write-Host "   1. Install ValkyrieSetup.exe and confirm: Invoke-RestMethod http://127.0.0.1:8090/api/health"
Write-Host "   2. Take a VM SNAPSHOT now (the run includes destructive atomics)."
Write-Host "   3. .\redteam\run-redteam.ps1 -ApiBase http://127.0.0.1:8090"
Write-Host ""
