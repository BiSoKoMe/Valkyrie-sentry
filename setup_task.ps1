<#
.SYNOPSIS
    Registers two on-demand Windows Scheduled Tasks - "ValkyrieStart" and
    "ValkyrieStop" - that run start_all.ps1 / stop_all.ps1 with highest
    privileges in the current user's session.

.DESCRIPTION
    Run this ONCE as Administrator (it self-elevates if you don't). After that,
    double-clicking start_valkyrie.bat / stop_valkyrie.bat triggers the tasks
    via "schtasks /run", which the Task Scheduler service executes with the
    configured highest privileges - and with NO UAC prompt, because triggering
    an already-registered task never re-prompts for elevation.

    Each task:
      - Runs as the current user, in the interactive logon session, so the
        startup console window and the dashboard are visible.
      - Has "Run with highest privileges" set (RunLevel = Highest).
      - Has NO schedule trigger - it only runs on demand.
      - Has no execution time limit (Valkyrie runs until you stop it).

    NOTE: this convenience relies on the current account being a member of the
    local Administrators group. RunLevel Highest elevates only within the
    rights the account already has; it cannot grant admin to a standard user.
#>

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Self-elevate - registering a highest-privilege task requires Administrator.
# ---------------------------------------------------------------------------
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host "[*] Re-launching setup with Administrator privileges..."
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$PSCommandPath`""
    )
    exit
}

# ---------------------------------------------------------------------------
# Resolve paths + identity
# ---------------------------------------------------------------------------
$root    = $PSScriptRoot
$startPs = Join-Path $root 'start_all.ps1'
$stopPs  = Join-Path $root 'stop_all.ps1'

foreach ($f in @($startPs, $stopPs)) {
    if (-not (Test-Path $f)) { throw "Required script not found: $f" }
}

$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-Host "[*] Registering tasks for user : $user"
Write-Host "[*] Project root               : $root"

# ---------------------------------------------------------------------------
# Shared principal + settings
# ---------------------------------------------------------------------------
# Interactive logon so the startup console + dashboard are visible in the
# user's session. Highest run level is the "Run with highest privileges" box.
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest

# No execution time limit (PT0S) so the task host isn't killed after the
# default 72h; keep running on battery; ignore duplicate on-demand triggers.
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit ([TimeSpan]::Zero)

function Register-ValkyrieTask {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Script,
        [Parameter(Mandatory)] [string] $Description
    )
    $action = New-ScheduledTaskAction `
        -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$Script`"" `
        -WorkingDirectory $root

    # -Force overwrites any existing task of the same name, so re-running this
    # setup is safe and idempotent.
    Register-ScheduledTask -TaskName $Name -Action $action -Principal $principal `
        -Settings $settings -Description $Description -Force | Out-Null
    Write-Host "[OK] Registered on-demand task: $Name"
}

Register-ValkyrieTask -Name 'ValkyrieStart' -Script $startPs `
    -Description 'Start the Valkyrie privacy gateway (elevated, on demand).'
Register-ValkyrieTask -Name 'ValkyrieStop'  -Script $stopPs `
    -Description 'Stop the Valkyrie privacy gateway (elevated, on demand).'

Write-Host ""
Write-Host "Done. Two on-demand tasks are registered:" -ForegroundColor Green
Get-ScheduledTask -TaskName 'ValkyrieStart', 'ValkyrieStop' |
    Format-Table TaskName, State, @{ n = 'RunLevel'; e = { $_.Principal.RunLevel } } -AutoSize

Write-Host "From now on, no Administrator prompt is needed:"
Write-Host "  Start protection : double-click start_valkyrie.bat"
Write-Host "  Stop protection  : double-click stop_valkyrie.bat"
Write-Host ""
Write-Host "(This window can be closed.)"
