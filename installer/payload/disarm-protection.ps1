<#
.SYNOPSIS
    Disarms Valkyrie DNS interception: resets the adapter DNS back to automatic.

.DESCRIPTION
    Reverses arm-protection.ps1. Reads the adapter it changed from
    data\valkyrie_dns_adapter.txt, resets it to DHCP/automatic, and removes the
    state file so the app knows protection is off. Leaves the ValkyrieShield
    engine service running (the engine is always available; only the OS pointer
    changes). Registered as the no-prompt task "ValkyrieDisarm".
#>
$ErrorActionPreference = 'Continue'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)
}
if (-not (Test-Admin)) {
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -WindowStyle Hidden -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', "`"$PSCommandPath`""
    )
    exit
}

$DataDir = Join-Path $env:ProgramData 'Valkyrie'
$AdapterStateFile = Join-Path $DataDir 'valkyrie_dns_adapter.txt'

if (Test-Path $AdapterStateFile) {
    $adapterAlias = Get-Content $AdapterStateFile -ErrorAction SilentlyContinue
    if ($adapterAlias) {
        Write-Host "[*] Resetting DNS to automatic on adapter: $adapterAlias"
        Set-DnsClientServerAddress -InterfaceAlias $adapterAlias -ResetServerAddresses -ErrorAction SilentlyContinue
    }
    Remove-Item $AdapterStateFile -ErrorAction SilentlyContinue
} else {
    # No tracked change — best-effort reset of common adapters so a stale arm
    # can never strand DNS at 127.0.0.1.
    foreach ($name in @('Wi-Fi', 'Ethernet')) {
        if (Get-NetAdapter -Name $name -ErrorAction SilentlyContinue) {
            Set-DnsClientServerAddress -InterfaceAlias $name -ResetServerAddresses -ErrorAction SilentlyContinue
        }
    }
}
Clear-DnsClientCache -ErrorAction SilentlyContinue
Write-Host '[OK] Protection disarmed - DNS back to automatic.'
