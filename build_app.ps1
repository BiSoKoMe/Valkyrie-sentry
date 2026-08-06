# ===================================================================
#  build_app.ps1 - ONE local command -> ValkyrieSetup.exe (full product)
#
#  Produces the complete premium desktop installer, entirely on this machine,
#  no GitHub:
#     1. Builds the Python engine        -> dist\valkyrie.exe   (PyInstaller)
#     2. Stages the engine payload       -> electron\engine_payload\
#        (frozen exe + scripts + nssm + optional VC++ runtime)
#     3. Builds the Electron app + NSIS  -> dist_installer\ValkyrieSetup.exe
#        (electron-builder; bundles the payload as resources\engine)
#     4. Copies ValkyrieSetup.exe into the repo root.
#
#  The result is ONE file: download it, double-click, and it installs the
#  Valkyrie service + premium app with shortcuts and auto-launch. No Python,
#  no browser, no localhost, no command line for the end user.
#
#  THREE BUILD MODES:
#     Development — run from source, hot reload, debug:  cd electron; npm run dev
#     Release (default)  — .\build_app.ps1            -> ValkyrieSetup.exe (NSIS,
#                          installs the service, shortcuts, auto-launch)
#     Portable           — .\build_app.ps1 -Portable  -> ValkyriePortable.exe
#                          (no install, no service, all state beside the .exe)
#
#  Run ON WINDOWS:  .\build_app.ps1
#  Flags:
#     -Portable     build the portable single-exe instead of the installer.
#     -SkipEngine   reuse the existing dist\valkyrie.exe (fast: only re-stage +
#                   rebuild the Electron output).
#     -WithAI       (deprecated no-op) AI investigation now needs no vendor SDK —
#                   its providers speak plain HTTP via httpx, which is bundled.
#     -NoVCRedist   skip the best-effort VC++ runtime download.
# ===================================================================
param(
    [switch]$Portable,
    [switch]$SkipEngine,
    [switch]$WithAI,
    [switch]$NoVCRedist
)

# NOTE: 'Continue', not 'Stop'. Native build tools (PyInstaller, npm,
# electron-builder) write progress to stderr; under 'Stop' in Windows
# PowerShell that stderr is wrapped as a terminating error and aborts the build
# spuriously. We instead gate on $LASTEXITCODE / Test-Path after each step.
$ErrorActionPreference = "Continue"
$root = $PSScriptRoot
Set-Location $root
$engineExe = Join-Path $root "dist\valkyrie.exe"

function Assert-LastExit($what) {
    if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE) - see log above." }
}

# ---------------------------------------------------------------------------
# 1. Engine
# ---------------------------------------------------------------------------
if ($SkipEngine) {
    if (-not (Test-Path $engineExe)) { throw "-SkipEngine given but dist\valkyrie.exe missing. Run once without it." }
    Write-Host "`n [1/4] Reusing existing engine: dist\valkyrie.exe" -ForegroundColor Cyan
} else {
    Write-Host "`n [1/4] Building engine (dist\valkyrie.exe)..." -ForegroundColor Cyan
    python -m pip install --upgrade pip | Out-Null
    python -m pip install -r requirements_modular.txt pyinstaller cryptography httpx
    # AI investigation is vendor-neutral over httpx (installed above); no AI SDK.

    # Capture the pre-build state so "the file exists" can never again be
    # mistaken for "this run produced it". On 2026-08-05, valkyrie.spec had a
    # stale datas entry (a file moved to experimental/ months earlier); every
    # PyInstaller run hard-errored on it, and the ONLY check below --
    # Test-Path -- passed anyway because a TWO-DAY-OLD dist\valkyrie.exe was
    # still sitting there from the last successful build. The pipeline
    # staged, audited, and shipped that stale engine as a "Done." build,
    # containing none of the day's actual changes. Caught by hand, after the
    # fact, by comparing the exe's timestamp to wall-clock time -- that
    # comparison is now load-bearing, not optional.
    $preBuildTime = if (Test-Path $engineExe) { (Get-Item $engineExe).LastWriteTimeUtc } else { $null }

    python -m PyInstaller --clean --noconfirm valkyrie.spec
    $pyinstallerExit = $LASTEXITCODE

    if ($pyinstallerExit -ne 0) {
        throw "Engine build failed - PyInstaller exited with code $pyinstallerExit (see log above)."
    }
    if (-not (Test-Path $engineExe)) {
        throw "Engine build failed - dist\valkyrie.exe not produced."
    }
    $postBuildTime = (Get-Item $engineExe).LastWriteTimeUtc
    if ($preBuildTime -ne $null -and $postBuildTime -le $preBuildTime) {
        throw ("Engine build did not actually run: dist\valkyrie.exe's timestamp " +
               "($postBuildTime) is no newer than before this build started " +
               "($preBuildTime). PyInstaller exited 0 but a stale binary was left " +
               "in place -- aborting rather than packaging it. Check the PyInstaller " +
               "log above for a swallowed error.")
    }
    Write-Host "     engine rebuilt: $engineExe ($postBuildTime UTC)" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# 2. Stage the engine payload that electron-builder bundles as resources\engine
# ---------------------------------------------------------------------------
Write-Host "`n [2/4] Staging engine payload..." -ForegroundColor Cyan
$stage = Join-Path $root "electron\engine_payload"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$payload = @(
    @{ src = "dist\valkyrie.exe";                          dst = "valkyrie.exe" },
    @{ src = "start_all.ps1";                              dst = "start_all.ps1" },
    @{ src = "stop_all.ps1";                               dst = "stop_all.ps1" },
    @{ src = "installer\payload\arm-protection.ps1";       dst = "arm-protection.ps1" },
    @{ src = "installer\payload\disarm-protection.ps1";    dst = "disarm-protection.ps1" },
    @{ src = "installer\payload\register-tasks.ps1";       dst = "register-tasks.ps1" },
    @{ src = "installer\payload\run-hidden.vbs";           dst = "run-hidden.vbs" },
    @{ src = "installer\payload\unregister-tasks.ps1";     dst = "unregister-tasks.ps1" },
    @{ src = "installer\payload\service-install.ps1";      dst = "service-install.ps1" },
    @{ src = "installer\payload\service-uninstall.ps1";    dst = "service-uninstall.ps1" },
    @{ src = "valkyrie\defaults\rules.default.yaml";       dst = "rules.default.yaml" },
    @{ src = "tools\nssm.exe";                             dst = "nssm.exe" }
)
foreach ($f in $payload) {
    $s = Join-Path $root $f.src
    if (-not (Test-Path $s)) { throw "Missing payload source: $($f.src)" }
    Copy-Item $s (Join-Path $stage $f.dst) -Force
    Write-Host "     + $($f.dst)"
}

# Best-effort VC++ runtime bundle (Win11 usually already has it).
if (-not $NoVCRedist) {
    $vc = Join-Path $stage "vc_redist.x64.exe"
    try {
        Write-Host "     downloading VC++ runtime (optional)..." -ForegroundColor DarkCyan
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile $vc -UseBasicParsing -TimeoutSec 40
        Write-Host "     + vc_redist.x64.exe" -ForegroundColor DarkCyan
    } catch {
        Write-Host "     (skipped VC++ runtime - $($_.Exception.Message))" -ForegroundColor DarkYellow
    }
}

# ---------------------------------------------------------------------------
# 2b. RELEASE-BLOCKING AUDIT of the staged payload (fail fast before building)
# ---------------------------------------------------------------------------
Write-Host "`n [audit] Verifying staged payload contains no developer/user data..." -ForegroundColor Cyan
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "installer\audit_build.ps1") -Stage $stage
if ($LASTEXITCODE -ne 0) { throw "Build audit failed on staged payload - aborting (see violations above)." }

# Release-blocking: the engine must be windowless (GUI subsystem) so it can
# never flash a console. See docs/adr/0001-windowless-startup.md.
Write-Host "`n [audit] Verifying windowless startup (no console)..." -ForegroundColor Cyan
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "tests\no_console_startup.ps1") -Engine (Join-Path $stage "valkyrie.exe")
if ($LASTEXITCODE -ne 0) { throw "No-console startup test failed - aborting (engine would show a console)." }

# ---------------------------------------------------------------------------
# 3. Electron app + installer/portable output (electron-builder)
# ---------------------------------------------------------------------------
$target  = if ($Portable) { "portable" } else { "nsis" }
$outName = if ($Portable) { "ValkyriePortable.exe" } else { "ValkyrieSetup.exe" }
Write-Host "`n [3/4] Building Electron app ($target) via electron-builder..." -ForegroundColor Cyan
Push-Location (Join-Path $root "electron")
try {
    if (-not (Test-Path "node_modules\electron-builder") -and -not (Test-Path "node_modules\.bin\electron-builder.cmd")) {
        Write-Host "     installing electron-builder..." -ForegroundColor DarkCyan
        npm install
    }
    npx --no-install electron-builder --win $target
} finally {
    Pop-Location
}

$setup = Join-Path $root "dist_installer\$outName"
if (-not (Test-Path $setup)) { throw "electron-builder did not produce $outName (see log above)." }

# Final release-blocking audit of the actual packaged output (app.asar + engine).
Write-Host "`n [audit] Verifying packaged app contains no developer/user data..." -ForegroundColor Cyan
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "installer\audit_build.ps1") `
    -Stage $stage -Unpacked (Join-Path $root "dist_installer\win-unpacked")
if ($LASTEXITCODE -ne 0) { throw "Build audit failed on packaged output - NOT publishing installer." }

# ---------------------------------------------------------------------------
# 4. Publish to repo root
# ---------------------------------------------------------------------------
Write-Host "`n [4/4] Publishing $outName to repo root..." -ForegroundColor Cyan
Copy-Item $setup (Join-Path $root $outName) -Force
$size = "{0:N1} MB" -f ((Get-Item $setup).Length / 1MB)

Write-Host "`n Done." -ForegroundColor Green
Write-Host "   Built : dist_installer\$outName" -ForegroundColor Green
Write-Host "   Copy  : $outName  ($size)  <- hand this to any Windows box" -ForegroundColor Green
Write-Host ""
Write-Host " Release installer:  .\build_app.ps1"
Write-Host " Portable single-exe:.\build_app.ps1 -Portable"
Write-Host " Installer-only change: .\build_app.ps1 -SkipEngine"
Write-Host ""
