# ===================================================================
#  Build valkyrie.exe - single self-contained Windows executable
#  bundling the whole app incl. the EDR / security-operations layer.
#
#  Run ON WINDOWS (PyInstaller does not cross-compile):
#      Right-click -> Run with PowerShell,  or:  .\build_exe.ps1
#  Requires Python 3.10+ on PATH. Result: dist\valkyrie.exe
#
#  Flags:
#      -WithAI   also bundle the optional Claude-assisted investigation
#                (installs the 'anthropic' package into the .exe)
# ===================================================================
param([switch]$WithAI)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

Write-Host "`n [1/3] Installing build + runtime dependencies..." -ForegroundColor Cyan
python -m pip install --upgrade pip | Out-Null
python -m pip install -r requirements_modular.txt pyinstaller
# cryptography enables signed remote-response; small, so bundle it by default.
python -m pip install cryptography
if ($WithAI) {
    Write-Host "     + bundling optional AI investigation (anthropic)..." -ForegroundColor DarkCyan
    python -m pip install anthropic
}

Write-Host "`n [2/3] Building valkyrie.exe with PyInstaller..." -ForegroundColor Cyan
python -m PyInstaller --clean --noconfirm valkyrie.spec

Write-Host "`n [3/3] Done." -ForegroundColor Cyan
if (Test-Path "dist\valkyrie.exe") {
    Write-Host "`n Built:  dist\valkyrie.exe" -ForegroundColor Green
    Write-Host "`n Quick check:"
    Write-Host "     dist\valkyrie.exe --hunt list"
    Write-Host "     dist\valkyrie.exe --web`n"
    Write-Host " The exe keeps its data\ folder, valkyrie_rules.yaml and logs next"
    Write-Host " to itself - copy the whole dist\ folder to deploy."
} else {
    Write-Host "`n WARNING: dist\valkyrie.exe was not produced - check the log above." -ForegroundColor Yellow
}
