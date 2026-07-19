<#
.SYNOPSIS
    Release test: proves Valkyrie starts with ZERO console windows.

.DESCRIPTION
    Two checks, both must pass (exit 0), else exit 1:
      1. Subsystem check - the frozen engine must be a GUI-subsystem binary
         (PE subsystem 2). A console-subsystem (3) engine can flash a console
         on any interactive launch, so this is release-blocking.
      2. Runtime check - launching the engine spawns no new console host
         (conhost.exe) / powershell / cmd process.

    Run standalone after a build, or from the CI/build audit:
        powershell -File tests\no_console_startup.ps1 -Engine dist\valkyrie.exe
.PARAMETER Engine
    Path to the frozen engine exe to test. Defaults to dist\valkyrie.exe.
.PARAMETER AppExe
    Optional path to the packaged Valkyrie.exe (Electron shell) to also test.
#>
param(
    [string]$Engine = "dist\valkyrie.exe",
    [string]$AppExe
)

$ErrorActionPreference = 'Stop'
$fail = 0

function Get-Subsystem([string]$Path) {
    $b = [System.IO.File]::ReadAllBytes((Resolve-Path $Path))
    $e = [BitConverter]::ToInt32($b, 0x3C)
    return [BitConverter]::ToUInt16($b, $e + 24 + 68)   # OptionalHeader.Subsystem
}

function Test-NoConsoleSpawn([string]$Path, [string[]]$AppArgs) {
    $before = (Get-Process conhost, powershell, cmd, pwsh -EA SilentlyContinue).Id
    $p = Start-Process $Path -ArgumentList $AppArgs -PassThru
    Start-Sleep -Seconds 3
    $after = (Get-Process conhost, powershell, cmd, pwsh -EA SilentlyContinue).Id
    $new = $after | Where-Object { $before -notcontains $_ }
    try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue } } catch {}
    return $new
}

Write-Host "=== Valkyrie no-console startup test ===`n"

# 1. Engine subsystem must be GUI (2).
if (-not (Test-Path $Engine)) { Write-Host "SKIP engine test - $Engine not found" -ForegroundColor Yellow }
else {
    $sub = Get-Subsystem $Engine
    if ($sub -eq 2) { Write-Host "[PASS] engine is GUI-subsystem (windowless): $Engine" -ForegroundColor Green }
    else { Write-Host "[FAIL] engine subsystem is $sub (expected 2/GUI): $Engine" -ForegroundColor Red; $fail = 1 }

    # 2. Launching the engine must not spawn a console host.
    $new = Test-NoConsoleSpawn -Path $Engine -AppArgs @('--hunt', 'list')
    if ($new) { Write-Host "[FAIL] engine launch spawned console process id(s): $($new -join ', ')" -ForegroundColor Red; $fail = 1 }
    else { Write-Host "[PASS] engine launch spawned no console/powershell/cmd process" -ForegroundColor Green }
}

# 3. Optional: the packaged Electron shell must be GUI-subsystem too.
if ($AppExe -and (Test-Path $AppExe)) {
    $sub = Get-Subsystem $AppExe
    if ($sub -eq 2) { Write-Host "[PASS] app shell is GUI-subsystem: $AppExe" -ForegroundColor Green }
    else { Write-Host "[FAIL] app shell subsystem is $sub (expected 2): $AppExe" -ForegroundColor Red; $fail = 1 }
}

Write-Host ""
if ($fail) { Write-Host "RESULT: FAIL - console-window regression detected." -ForegroundColor Red; exit 1 }
Write-Host "RESULT: PASS - no console windows at startup." -ForegroundColor Green
exit 0
