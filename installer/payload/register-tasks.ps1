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
$wrapper  = Join-Path $Root 'run-hidden.vbs'
foreach ($f in @($armPs, $disarmPs, $wrapper)) {
    if (-not (Test-Path $f)) { throw "Required script not found: $f" }
}

$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)

function Register-ValkyrieTask {
    param([string]$Name, [string]$Script, [string]$Description)
    # Launch via the run-hidden.vbs wrapper (WScript.Shell.Run, window style
    # 0), NOT `powershell.exe -WindowStyle Hidden` directly. -WindowStyle
    # Hidden hides the console *after* Windows has already created and shown
    # it - a well-documented race that can flash a console for a frame or
    # two on arm/disarm, i.e. on literally every Start/Stop Protection click.
    # WScript.Shell.Run sets the hidden-window flag in the process's
    # STARTUPINFO *before* CreateProcess runs, so the window is never shown
    # at all - the only fully deterministic fix on Windows short of a
    # compiled native helper. See run-hidden.vbs for the full explanation.
    $action = New-ScheduledTaskAction -Execute 'wscript.exe' `
        -Argument "//B //NoLogo `"$wrapper`" `"$Script`"" -WorkingDirectory $Root
    Register-ScheduledTask -TaskName $Name -Action $action -Principal $principal `
        -Settings $settings -Description $Description -Force | Out-Null
    Write-Host "[OK] Registered on-demand task: $Name"
}

Register-ValkyrieTask -Name 'ValkyrieArm'    -Script $armPs `
    -Description 'Arm Valkyrie DNS protection (elevated, on demand).'
Register-ValkyrieTask -Name 'ValkyrieDisarm' -Script $disarmPs `
    -Description 'Disarm Valkyrie DNS protection (elevated, on demand).'
