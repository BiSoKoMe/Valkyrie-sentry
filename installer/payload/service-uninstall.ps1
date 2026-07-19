<#
.SYNOPSIS
    Stop + remove the ValkyrieShield service and restore native Unbound.
    Called at uninstall time (elevated).
.PARAMETER Root
    Directory containing nssm.exe (…\resources\engine).
#>
param([string]$Root = $PSScriptRoot)
$ErrorActionPreference = 'Continue'

$nssm = Join-Path $Root 'nssm.exe'
$svc  = 'ValkyrieShield'

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
