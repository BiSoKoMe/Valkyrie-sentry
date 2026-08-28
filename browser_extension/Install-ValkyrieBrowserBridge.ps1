[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-p]{32}$')]
    [string]$ExtensionId,
    [string]$Python = "python",
    [int]$WebPort = 8080,
    [ValidateSet('Chrome', 'Edge')]
    [string[]]$Browser = @('Chrome', 'Edge')
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$data = if ($env:VALKYRIE_DATA_DIR) { $env:VALKYRIE_DATA_DIR } else { Join-Path $root 'data' }
$destination = Join-Path $data 'browser-bridge'
New-Item -ItemType Directory -Path $destination -Force | Out-Null

$hostScript = Join-Path $PSScriptRoot 'native_host.py'
$tokenFile = Join-Path $data 'browser_context_token.txt'
$launcher = Join-Path $destination 'valkyrie-browser-host.cmd'
@"
@echo off
"$Python" "$hostScript" --endpoint "http://127.0.0.1:$WebPort/api/browser/events" --token-file "$tokenFile"
"@ | Set-Content -LiteralPath $launcher -Encoding ASCII

$manifest = Join-Path $destination 'com.valkyrie.browser_context.json'
@{
    name = 'com.valkyrie.browser_context'
    description = 'Valkyrie local browser-context relay'
    path = $launcher
    type = 'stdio'
    allowed_origins = @("chrome-extension://$ExtensionId/")
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifest -Encoding UTF8

$keys = @{
    Chrome = 'HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.valkyrie.browser_context'
    Edge = 'HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\com.valkyrie.browser_context'
}
foreach ($name in $Browser) {
    New-Item -Path $keys[$name] -Force | Out-Null
    Set-ItemProperty -Path $keys[$name] -Name '(default)' -Value $manifest
}

Write-Host "Registered Valkyrie browser bridge for $($Browser -join ', ')."
Write-Host "Load the unpacked extension from: $PSScriptRoot"
Write-Host "The engine must be running with --web before browser events will be accepted."
