# ===================================================================
#  build_setup.ps1 - ONE local command -> ValkyrieSetup.exe
#
#  Builds the whole distributable installer on this machine, no GitHub:
#     1. Builds the engine        -> dist\valkyrie.exe   (PyInstaller)
#     2. Builds the installer stub -> dist\ValkyrieSetup.exe (bundles #1)
#     3. Copies ValkyrieSetup.exe into the repo root so it's easy to grab.
#
#  Run ON WINDOWS (PyInstaller does not cross-compile):
#     Right-click -> Run with PowerShell,  or:  .\build_setup.ps1
#
#  Flags:
#     -SkipEngine   reuse the existing dist\valkyrie.exe (fast: only rebuild
#                   the installer, e.g. after editing installer.py / scripts).
#     -WithAI       (deprecated no-op) AI investigation now needs no vendor SDK;
#                   its providers speak plain HTTP via httpx, bundled by default.
#
#  Hand the resulting ValkyrieSetup.exe to any Windows box and double-click it:
#  it self-elevates and installs to Program Files with no-prompt Start/Stop.
# ===================================================================
param(
    [switch]$SkipEngine,
    [switch]$WithAI
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

$engineExe = Join-Path $PSScriptRoot "dist\valkyrie.exe"

# ---------------------------------------------------------------------------
# 1. Engine
# ---------------------------------------------------------------------------
if ($SkipEngine) {
    if (-not (Test-Path $engineExe)) {
        throw "-SkipEngine was given but dist\valkyrie.exe does not exist. Run without -SkipEngine once."
    }
    Write-Host "`n [1/3] Reusing existing engine: dist\valkyrie.exe" -ForegroundColor Cyan
} else {
    Write-Host "`n [1/3] Building engine (dist\valkyrie.exe)..." -ForegroundColor Cyan
    python -m pip install --upgrade pip | Out-Null
    python -m pip install -r requirements_modular.txt pyinstaller
    python -m pip install cryptography httpx
    # AI investigation is vendor-neutral over httpx (installed above) — no AI SDK.

    # See build_app.ps1's identical guard for why Test-Path alone is not
    # enough: a stale exe left over from a previous build passes it even
    # when THIS run's PyInstaller invocation hard-failed.
    $preBuildTime = if (Test-Path $engineExe) { (Get-Item $engineExe).LastWriteTimeUtc } else { $null }
    python -m PyInstaller --clean --noconfirm valkyrie.spec
    $pyinstallerExit = $LASTEXITCODE

    if ($pyinstallerExit -ne 0) {
        throw "Engine build failed - PyInstaller exited with code $pyinstallerExit (see log above)."
    }
    if (-not (Test-Path $engineExe)) {
        throw "Engine build failed - dist\valkyrie.exe was not produced. Check the log above."
    }
    $postBuildTime = (Get-Item $engineExe).LastWriteTimeUtc
    if ($preBuildTime -ne $null -and $postBuildTime -le $preBuildTime) {
        throw ("Engine build did not actually run: dist\valkyrie.exe's timestamp " +
               "($postBuildTime) is no newer than before this build started " +
               "($preBuildTime) - aborting rather than packaging a stale binary.")
    }
}

# ---------------------------------------------------------------------------
# 2. Installer stub -> ValkyrieSetup.exe (embeds the engine from step 1)
# ---------------------------------------------------------------------------
Write-Host "`n [2/3] Building installer (dist\ValkyrieSetup.exe)..." -ForegroundColor Cyan
python -m pip install pyinstaller | Out-Null
python -m PyInstaller --clean --noconfirm "installer\valkyrie_setup.spec"

$setupExe = Join-Path $PSScriptRoot "dist\ValkyrieSetup.exe"
if (-not (Test-Path $setupExe)) {
    throw "Installer build failed - dist\ValkyrieSetup.exe was not produced. Check the log above."
}

# ---------------------------------------------------------------------------
# 3. Copy into the repo root for easy grabbing / handing off
# ---------------------------------------------------------------------------
Write-Host "`n [3/3] Publishing to repo root..." -ForegroundColor Cyan
$rootCopy = Join-Path $PSScriptRoot "ValkyrieSetup.exe"
Copy-Item $setupExe $rootCopy -Force

$size = "{0:N1} MB" -f ((Get-Item $rootCopy).Length / 1MB)
Write-Host "`n Done." -ForegroundColor Green
Write-Host "   Built : dist\ValkyrieSetup.exe" -ForegroundColor Green
Write-Host "   Copy  : ValkyrieSetup.exe  ($size)  <- hand this to any Windows box" -ForegroundColor Green
Write-Host ""
Write-Host " To ship an update later:  .\build_setup.ps1        (rebuilds engine + installer)"
Write-Host " Installer-only change:    .\build_setup.ps1 -SkipEngine"
Write-Host ""
