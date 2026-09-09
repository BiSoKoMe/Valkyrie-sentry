<#
.SYNOPSIS
    Stop + remove the ValkyrieShield service and restore native Unbound.
    Called at uninstall time (elevated).
.PARAMETER Root
    Directory containing nssm.exe (...\resources\engine).
#>
param([string]$Root = $PSScriptRoot)
$ErrorActionPreference = 'Continue'

$nssm = Join-Path $Root 'nssm.exe'
$svc  = 'ValkyrieShield'

# Restore DNS BEFORE removing the service that answers it, not after. This
# script previously only stopped/removed the service and restored Unbound -
# it never touched the adapter at all. A client who uninstalls while
# protection is armed (DNS pointed at 127.0.0.1) would have that address
# removed from under them: nothing left listening there, no Valkyrie process
# left running to self-heal it (host_safety.py's watchdog dies with the
# service it runs inside), and no reason for them to connect "uninstalled a
# program" with "internet stopped working." disarm-protection.ps1 already
# has the exact safe, idempotent logic for this (it also degrades gracefully
# with zero tracked state, its own "no tracked change" branch), so this
# reuses it rather than re-deriving a second copy of the same safety logic.
$disarmScript = Join-Path $Root 'disarm-protection.ps1'
if (Test-Path $disarmScript) {
    Write-Host '[*] Restoring DNS to automatic before removing the service...'
    & powershell -NoProfile -ExecutionPolicy Bypass -File $disarmScript *> $null
} else {
    # Payload file missing somehow - still must not leave DNS at a loopback
    # with no resolver behind it. Universal safe fallback, same shape as
    # host_safety.py's own RESET_TO_AUTO branch.
    Write-Host '[*] disarm-protection.ps1 not found - resetting common adapters to automatic directly...'
    foreach ($name in @('Wi-Fi', 'Ethernet')) {
        if (Get-NetAdapter -Name $name -ErrorAction SilentlyContinue) {
            Set-DnsClientServerAddress -InterfaceAlias $name -ResetServerAddresses -ErrorAction SilentlyContinue
        }
    }
    Clear-DnsClientCache -ErrorAction SilentlyContinue
}

& sc.exe query $svc *> $null
if ($LASTEXITCODE -eq 0) {
    Write-Host "[*] Stopping + removing service '$svc'..."
    if (Test-Path $nssm) {
        & $nssm stop $svc *> $null
        & $nssm remove $svc confirm *> $null
    } else {
        & sc.exe stop $svc *> $null
        & sc.exe delete $svc *> $null
    }
}

# Restore native Unbound to automatic if it exists (we set it to manual on install).
if (Get-Service -Name 'Unbound' -ErrorAction SilentlyContinue) {
    Set-Service -Name 'Unbound' -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name 'Unbound' -ErrorAction SilentlyContinue
}
Write-Host '[OK] Service removed.'
