<#
.SYNOPSIS
    Developer smoke test — runs EVERYTHING locally, no admin, no build.

.DESCRIPTION
    1. Unit test suite            (tests/run_tests.py)
    2. Detection-efficacy scorecard (tests/efficacy/harness.py)
    3. Boots the engine headless with --web --endpoint, waits until it's up,
       then hits every new API surface added recently and prints the results,
       and shuts the engine down cleanly.

    This does NOT touch system DNS, does NOT need Administrator, and does NOT
    install anything. It runs the same source the Electron dev app runs.

.USAGE
    .\dev_smoke.ps1
#>

$ErrorActionPreference = "Continue"
$root = $PSScriptRoot
Set-Location $root
$env:PYTHONUTF8 = "1"
$port = 8090
$base = "http://127.0.0.1:$port"

function Section($t) { Write-Host "`n========== $t ==========" -ForegroundColor Cyan }

# ── 1. Unit tests ──────────────────────────────────────────────────────────
Section "1/3  Unit test suite"
python tests\run_tests.py

# ── 2. Efficacy scorecard ──────────────────────────────────────────────────
Section "2/3  Detection-efficacy scorecard"
python tests\efficacy\harness.py

# ── 3. Live engine + new endpoints ─────────────────────────────────────────
Section "3/3  Engine (dev) + new API surfaces"
Write-Host "Starting engine: python -m valkyrie --web --endpoint --web-port $port" -ForegroundColor DarkCyan
$engine = Start-Process -FilePath "python" `
    -ArgumentList "-m","valkyrie","--web","--endpoint","--web-port","$port" `
    -PassThru -WindowStyle Minimized

try {
    # Wait up to 30s for the API to answer.
    $up = $false
    for ($i = 0; $i -lt 30; $i++) {
        try {
            $h = Invoke-RestMethod "$base/api/health" -TimeoutSec 2
            $up = $true; break
        } catch { Start-Sleep -Seconds 1 }
    }
    if (-not $up) { throw "engine did not come up on $base within 30s" }
    Write-Host "Engine is up.`n" -ForegroundColor Green

    $endpoints = @(
        @{ n = "Component registry / plugin health"; u = "/api/components" },
        @{ n = "Threat-intel feed status";           u = "/api/intel/status" },
        @{ n = "SIEM export status";                 u = "/api/siem/status" },
        @{ n = "SOAR playbooks status";              u = "/api/edr/playbooks/status" },
        @{ n = "Ransomware shield status";           u = "/api/ransomware/status" },
        @{ n = "Endpoint telemetry status";          u = "/api/telemetry/endpoint" },
        @{ n = "EDR incidents";                      u = "/api/edr/incidents" },
        @{ n = "Compliance evidence (JSON)";         u = "/api/compliance/report?hours=24" }
    )
    foreach ($e in $endpoints) {
        Write-Host ("--- {0}   GET {1}" -f $e.n, $e.u) -ForegroundColor Yellow
        try {
            $r = Invoke-RestMethod "$base$($e.u)" -TimeoutSec 5
            ($r | ConvertTo-Json -Depth 4 -Compress) | Out-String | Write-Host
        } catch {
            Write-Host "  (error: $($_.Exception.Message))" -ForegroundColor Red
        }
    }

    Write-Host "`nCompliance report as Markdown:" -ForegroundColor Yellow
    try {
        (Invoke-WebRequest "$base/api/compliance/report?format=md&hours=24" `
            -TimeoutSec 5).Content | Write-Host
    } catch { Write-Host "  (error: $($_.Exception.Message))" -ForegroundColor Red }
}
finally {
    if ($engine -and -not $engine.HasExited) {
        Write-Host "`nStopping engine (pid $($engine.Id))..." -ForegroundColor DarkCyan
        Stop-Process -Id $engine.Id -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`nDone. Nothing was installed; system DNS was never touched." -ForegroundColor Green
