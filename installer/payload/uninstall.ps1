<#
.SYNOPSIS
    Uninstalls Valkyrie: stops protection, removes tasks, shortcuts, the
    Add/Remove Programs entry, and the install directory.

.DESCRIPTION
    Registered as the UninstallString in Add/Remove Programs by
    ValkyrieSetup.exe. Self-elevates, then reverses everything the installer did.
    Runs from the install directory (that's where the installer places it).
#>
$ErrorActionPreference = 'Continue'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)
}
if (-not (Test-Admin)) {
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`""
    )
    exit
}

$InstallDir = $PSScriptRoot
Write-Host "[*] Uninstalling Valkyrie from $InstallDir" -ForegroundColor Cyan

# 1. Stop protection (resets DNS, kills the engine, restores Unbound).
$stopPs = Join-Path $InstallDir 'stop_all.ps1'
if (Test-Path $stopPs) {
    Write-Host "[*] Stopping protection..."
    try { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $stopPs } catch {}
}
# Belt-and-suspenders: make sure the engine is dead before we delete its exe.
Get-Process -Name 'valkyrie' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# 2. Remove the scheduled tasks.
$unreg = Join-Path $InstallDir 'unregister-tasks.ps1'
if (Test-Path $unreg) { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $unreg }

# 3. Remove shortcuts (all-users Start Menu folder + public desktop).
$startMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Valkyrie'
if (Test-Path $startMenu) { Remove-Item $startMenu -Recurse -Force -ErrorAction SilentlyContinue }
$publicDesktop = Join-Path $env:PUBLIC 'Desktop\Valkyrie.lnk'
if (Test-Path $publicDesktop) { Remove-Item $publicDesktop -Force -ErrorAction SilentlyContinue }

# 4. Remove the Add/Remove Programs entry.
$arp = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Valkyrie'
if (Test-Path $arp) { Remove-Item $arp -Recurse -Force -ErrorAction SilentlyContinue }

# 5. Remove the install directory. We can't delete the folder we're running
#    from while this script is executing, so schedule a detached cleanup.
Write-Host "[*] Removing files..."
$cleanup = "Start-Sleep -Seconds 2; Remove-Item -LiteralPath '$InstallDir' -Recurse -Force -ErrorAction SilentlyContinue"
Start-Process -FilePath 'powershell.exe' -WindowStyle Hidden -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $cleanup
)

Write-Host ""
Write-Host "Valkyrie has been uninstalled." -ForegroundColor Green
Start-Sleep -Seconds 2
