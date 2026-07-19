<#
.SYNOPSIS
    Register the no-prompt on-demand tasks the app uses to arm/disarm DNS
    protection without a UAC prompt (called by the installer, elevated).

.DESCRIPTION
    Setting the system DNS adapter requires admin. Triggering a pre-registered
    highest-privilege scheduled task never re-prompts for UAC, so the app can
    flip protection on/off silently. This registers:
      * ValkyrieArm    -> arm-protection.ps1    (point DNS at the engine)
      * ValkyrieDisarm -> disarm-protection.ps1 (reset DNS to automatic)
    Both run <Root>\*.ps1 with highest privileges in the user's session.
.PARAMETER Root
    Directory containing arm-protection.ps1 / disarm-protection.ps1.
#>
param([Parameter(Mandatory)][string]$Root)
$ErrorActionPreference = 'Stop'

$armPs    = Join-Path $Root 'arm-protection.ps1'
$disarmPs = Join-Path $Root 'disarm-protection.ps1'
foreach ($f in @($armPs, $disarmPs)) {
    if (-not (Test-Path $f)) { throw "Required script not found: $f" }
}

$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)

function Register-ValkyrieTask {
    param([string]$Name, [string]$Script, [string]$Description)
    # -WindowStyle Hidden so arming/disarming protection never flashes a console
    # window — the app must feel like a native product, not a script.
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Script`"" -WorkingDirectory $Root
    Register-ScheduledTask -TaskName $Name -Action $action -Principal $principal `
        -Settings $settings -Description $Description -Force | Out-Null
    Write-Host "[OK] Registered on-demand task: $Name"
}

Register-ValkyrieTask -Name 'ValkyrieArm'    -Script $armPs `
    -Description 'Arm Valkyrie DNS protection (elevated, on demand).'
Register-ValkyrieTask -Name 'ValkyrieDisarm' -Script $disarmPs `
    -Description 'Disarm Valkyrie DNS protection (elevated, on demand).'
