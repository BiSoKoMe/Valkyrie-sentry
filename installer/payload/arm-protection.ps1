<#
.SYNOPSIS
    Arms Valkyrie DNS interception: points the active network adapter at
    127.0.0.1 - but ONLY after confirming the engine is answering on port 53.

.DESCRIPTION
    In the packaged product the engine runs continuously as the ValkyrieShield
    Windows service (bound to :53 + :8090). "Protection" is simply whether the
    OS points its DNS at that engine. This script flips it ON.

    Abort-safe by design: if the engine is not answering on :53 it changes
    NOTHING, so you can never be left without working DNS. Records the adapter
    it changed in data\valkyrie_dns_adapter.txt (the app reads this file to know
    protection is armed); disarm-protection.ps1 reverses it.

    Registered as the highest-privilege on-demand task "ValkyrieArm", so the app
    can trigger it with no UAC prompt.
#>
$ErrorActionPreference = 'Stop'

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

# Writable state lives in %ProgramData%\Valkyrie (same place the engine service
# keeps its data), never in the read-only install directory.
$DataDir = Join-Path $env:ProgramData 'Valkyrie'
if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }
$AdapterStateFile = Join-Path $DataDir 'valkyrie_dns_adapter.txt'
$DnsPort = 53

function Test-DnsPort {
    param([int]$Port)
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.UdpClient
        $client.Client.ReceiveTimeout = 1500
        $client.Connect('127.0.0.1', $Port)
        $query = [byte[]](0xAB,0xCD,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x01)
        $client.Send($query, $query.Length) | Out-Null
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $resp = $client.Receive([ref]$remote)
        return ($resp.Length -ge 12)
    } catch { return $false } finally { if ($client) { $client.Close() } }
}

Write-Host '[*] Confirming Valkyrie engine is answering on port 53...'
if (-not (Test-DnsPort -Port $DnsPort)) {
    Write-Host '[ERROR] Engine is not answering on 127.0.0.1:53 - leaving system DNS unchanged.'
    Write-Host '        (Is the ValkyrieShield service running?) No internet risk taken.'
    exit 1
}

# Detect the adapter currently providing internet.
$adapterAlias = $null
$activeProfile = Get-NetConnectionProfile -ErrorAction SilentlyContinue |
    Where-Object { $_.IPv4Connectivity -eq 'Internet' } | Select-Object -First 1
if ($activeProfile) {
    $adapterAlias = $activeProfile.InterfaceAlias
} else {
    foreach ($name in @('Wi-Fi', 'Ethernet')) {
        $a = Get-NetAdapter -Name $name -ErrorAction SilentlyContinue
        if ($a -and $a.Status -eq 'Up') { $adapterAlias = $name; break }
    }
}
if (-not $adapterAlias) {
    Write-Host '[ERROR] Could not detect an active network adapter - DNS not changed.'
    exit 1
}

Write-Host "[*] Pointing DNS at 127.0.0.1 on adapter: $adapterAlias"
Set-DnsClientServerAddress -InterfaceAlias $adapterAlias -ServerAddresses '127.0.0.1'
Set-Content -Path $AdapterStateFile -Value $adapterAlias -Encoding utf8 -NoNewline
Clear-DnsClientCache -ErrorAction SilentlyContinue
Write-Host '[OK] Protection armed - traffic now flows through Valkyrie.'
