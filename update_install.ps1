# ===================================================================
#  update_install.ps1 - update an EXISTING Valkyrie install in place.
#
#  For when you have already installed Valkyrie and just want the current
#  source on the machine WITHOUT uninstalling and re-running ValkyrieSetup.exe.
#
#  It updates exactly the two artifacts that carry application code:
#     1. resources\engine\valkyrie.exe   <- dist\valkyrie.exe   (PyInstaller)
#     2. resources\app.asar              <- electron\src\**     (Electron shell)
#
#  Everything else about the install is left alone on purpose: the service
#  registration, the scheduled tasks, the shortcuts, and above all your data in
#  %ProgramData%\Valkyrie (database, keys, config, quarantine). That is the
#  whole point of updating in place rather than reinstalling.
#
#  The app.asar is PATCHED, not rebuilt from scratch: the installed archive is
#  extracted, the JS/HTML/CSS is refreshed from electron\src, and it is repacked.
#  That preserves the trimmed package.json electron-builder generates at install
#  time, so this script never needs to reproduce electron-builder's packaging
#  rules -- it only replaces the files that actually changed.
#
#  SAFETY
#     * Both originals are backed up next to themselves as *.bak-<timestamp>.
#     * If the engine does not answer after the swap, the script ROLLS BACK
#       automatically and restarts the service on the old binary.
#     * Nothing under %ProgramData%\Valkyrie is touched, read or written.
#
#  USAGE (must be elevated -- it writes to Program Files and stops a service):
#
#     Right-click Windows Terminal / PowerShell -> "Run as administrator", then:
#         cd "C:\Users\badam\OneDrive\Desktop\Valkyrie"
#         .\update_install.ps1
#
#     Options:
#         -EngineOnly     only swap valkyrie.exe
#         -AppOnly        only swap app.asar
#         -SkipBuild      use dist\valkyrie.exe as-is (default is to use it
#                         as-is anyway; build with .\build_exe.ps1 first)
#         -NoLaunch       do not relaunch the desktop app afterwards
# ===================================================================

[CmdletBinding()]
param(
    [string] $InstallDir = 'C:\Program Files\Valkyrie',
    [switch] $EngineOnly,
    [switch] $AppOnly,
    [switch] $NoLaunch
)

$ErrorActionPreference = 'Stop'
$RepoRoot  = Split-Path -Parent $MyInvocation.MyCommand.Path
$Stamp     = Get-Date -Format 'yyyyMMdd-HHmmss'
$WebPort   = 8090
$Service   = 'ValkyrieShield'

function Say  ($m) { Write-Host "  $m" }
function Step ($m) { Write-Host "`n[*] $m" -ForegroundColor Cyan }
function Ok   ($m) { Write-Host "  OK  $m" -ForegroundColor Green }
function Warn ($m) { Write-Host "  !   $m" -ForegroundColor Yellow }
function Die  ($m) { Write-Host "`n[X] $m" -ForegroundColor Red; exit 1 }

# --- 0. Preflight ---
Step 'Preflight'

$isAdmin = ([Security.Principal.WindowsPrincipal] `
            [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Die ("Not elevated. This writes to Program Files and stops a Windows " +
         "service, so it needs an administrator PowerShell.`n" +
         "      Right-click PowerShell -> Run as administrator, then re-run.")
}
Ok 'running elevated'

if (-not (Test-Path $InstallDir)) { Die "No Valkyrie install found at $InstallDir" }
Ok "install found: $InstallDir"

$doEngine = -not $AppOnly
$doApp    = -not $EngineOnly

$engineSrc = Join-Path $RepoRoot 'dist\valkyrie.exe'
$engineDst = Join-Path $InstallDir 'resources\engine\valkyrie.exe'
$asarDst   = Join-Path $InstallDir 'resources\app.asar'
$asarCli   = Join-Path $RepoRoot 'electron\node_modules\.bin\asar.cmd'
$srcDir    = Join-Path $RepoRoot 'electron\src'

if ($doEngine) {
    if (-not (Test-Path $engineSrc)) {
        Die ("dist\valkyrie.exe not found. Build it first:`n" +
             "      python -m PyInstaller --clean --noconfirm valkyrie.spec")
    }
    if (-not (Test-Path $engineDst)) { Die "Installed engine not found: $engineDst" }
    $srcTime = (Get-Item $engineSrc).LastWriteTime
    $dstTime = (Get-Item $engineDst).LastWriteTime
    Ok ("engine build  {0:yyyy-MM-dd HH:mm}  ->  installed {1:yyyy-MM-dd HH:mm}" -f $srcTime, $dstTime)
    if ($srcTime -lt $dstTime) {
        Warn 'the built engine is OLDER than the installed one -- rebuild if that is unexpected'
    }
}
if ($doApp) {
    if (-not (Test-Path $asarCli)) { Die "asar CLI not found: $asarCli  (run: cd electron; npm install)" }
    if (-not (Test-Path $asarDst)) { Die "Installed app.asar not found: $asarDst" }
    if (-not (Test-Path $srcDir))  { Die "Electron source not found: $srcDir" }
    # Entries marked asarUnpack live OUTSIDE the archive, in this sidecar dir.
    # `asar extract` reads them from there, so a missing sidecar fails the
    # extract with a bare ENOENT on tray.ico rather than anything self
    # -explanatory. Caught by dry-running this script against a copy that had
    # the .asar but not the sidecar -- check it up front instead.
    if (-not (Test-Path "$asarDst.unpacked")) {
        Die ("app.asar.unpacked is missing next to app.asar. The archive " +
             "cannot be extracted without it -- reinstall is the only fix.")
    }
    Ok 'app.asar + unpacked sidecar + asar CLI + electron source present'
}

# --- 1. Stop the app and the service ---
Step 'Stopping Valkyrie'

$appExe = Join-Path $InstallDir 'Valkyrie.exe'
$running = @(Get-Process -Name 'Valkyrie' -ErrorAction SilentlyContinue |
             Where-Object { $_.Path -eq $appExe })
if ($running.Count) {
    $running | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Ok "closed the desktop app ($($running.Count) process(es))"
} else {
    Say 'desktop app was not running'
}

$svc = Get-Service -Name $Service -ErrorAction SilentlyContinue
$svcWasRunning = $false
if ($svc) {
    $svcWasRunning = ($svc.Status -eq 'Running')
    if ($svcWasRunning) {
        Stop-Service -Name $Service -Force
        try { (Get-Service $Service).WaitForStatus('Stopped', '00:00:45') }
        catch { Die "Service $Service did not stop within 45s" }
        Ok "stopped service $Service"
    } else {
        Say "service $Service was already stopped"
    }
} else {
    Warn "service $Service not registered -- swapping files anyway"
}

# The frozen exe can linger a moment after the service reports Stopped.
for ($i = 0; $i -lt 20; $i++) {
    if (-not (Get-Process -Name 'valkyrie' -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Milliseconds 500
}

# --- 2. Back up, then swap ---
Step 'Backing up and replacing'

$backups = @()

if ($doEngine) {
    $bak = "$engineDst.bak-$Stamp"
    Copy-Item $engineDst $bak -Force
    $backups += ,@($engineDst, $bak)
    Ok "backup: $(Split-Path -Leaf $bak)"
    try {
        Copy-Item $engineSrc $engineDst -Force
        Ok ("engine replaced ({0:N0} bytes)" -f (Get-Item $engineDst).Length)
    } catch {
        Die "Could not replace the engine (is something still holding it?): $_"
    }
}

if ($doApp) {
    $bak = "$asarDst.bak-$Stamp"
    Copy-Item $asarDst $bak -Force
    $backups += ,@($asarDst, $bak)
    Ok "backup: $(Split-Path -Leaf $bak)"

    $work = Join-Path $env:TEMP "valkyrie-asar-$Stamp"
    $tree = Join-Path $work 'app'
    New-Item -ItemType Directory -Path $tree -Force | Out-Null

    # Extract what is installed, refresh the code, repack. Extracting first is
    # what preserves electron-builder's trimmed package.json.
    & $asarCli extract $asarDst $tree
    if ($LASTEXITCODE -ne 0) { Die 'asar extract failed' }

    # Mirror electron-builder's "files" rule: src/**/* minus *.test.js.
    # /MIR would delete the tray icons, so copy over the top instead.
    robocopy $srcDir (Join-Path $tree 'src') /E /NFL /NDL /NJH /NJS /NP /XF '*.test.js' | Out-Null
    if ($LASTEXITCODE -ge 8) { Die "robocopy failed (exit $LASTEXITCODE)" }
    Ok 'refreshed src\ from the repo (test files excluded)'

    $newAsar = Join-Path $work 'app.asar'
    # One --unpack glob only: the CLI keeps the LAST one given, so a second
    # flag silently drops the first pattern. "**/tray.*" covers .ico and .png,
    # matching the asarUnpack rule in electron\package.json.
    & $asarCli pack $tree $newAsar --unpack '**/tray.*'
    if ($LASTEXITCODE -ne 0) { Die 'asar pack failed' }

    Copy-Item $newAsar $asarDst -Force
    $unpackSrc = "$newAsar.unpacked"
    $unpackDst = "$asarDst.unpacked"
    if (Test-Path $unpackSrc) {
        robocopy $unpackSrc $unpackDst /E /NFL /NDL /NJH /NJS /NP | Out-Null
        if ($LASTEXITCODE -ge 8) { Die "robocopy of app.asar.unpacked failed ($LASTEXITCODE)" }
    }
    Ok ("app.asar replaced ({0:N0} bytes)" -f (Get-Item $asarDst).Length)
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}

# --- 3. Restart and verify ---
Step 'Restarting and verifying'

function Test-EngineUp {
    param([int] $TimeoutSec = 90)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        foreach ($path in '/api/ping', '/api/health') {
            try {
                $r = Invoke-WebRequest "http://127.0.0.1:$WebPort$path" `
                        -UseBasicParsing -TimeoutSec 4
                if ($r.StatusCode -eq 200) { return $true }
            } catch { }
        }
        Start-Sleep -Milliseconds 800
    }
    return $false
}

$verified = $true
if ($svc -and ($svcWasRunning -or $svc.StartType -eq 'Automatic')) {
    Start-Service -Name $Service
    Ok "started service $Service"
    Say "waiting for the API on 127.0.0.1:$WebPort ..."
    if (Test-EngineUp) {
        Ok 'engine is answering -- this is what the app polls'
    } else {
        $verified = $false
        Warn 'engine did NOT answer within 90s'
    }
} else {
    Say 'service not started (was not running and is not Automatic)'
}

# --- 4. Roll back if the swap left a dead engine ---
if (-not $verified) {
    Step 'Rolling back'
    try { Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue } catch { }
    Start-Sleep -Seconds 2
    foreach ($pair in $backups) {
        Copy-Item $pair[1] $pair[0] -Force
        Say "restored $(Split-Path -Leaf $pair[0])"
    }
    try { Start-Service -Name $Service } catch { }
    Die ("Update rolled back -- the previous version is running again. " +
         "Nothing was lost, and your data was never touched.")
}

# --- 5. Relaunch the app ---
if (-not $NoLaunch) {
    Step 'Launching Valkyrie'
    if (Test-Path $appExe) {
        Start-Process $appExe
        Ok 'desktop app launched'
    } else {
        Warn "app not found at $appExe"
    }
}

Write-Host "`n===================================================================" -ForegroundColor Green
Write-Host " Valkyrie updated in place. No reinstall, data untouched." -ForegroundColor Green
Write-Host "===================================================================" -ForegroundColor Green
Write-Host " Backups (delete once you are happy):"
foreach ($pair in $backups) { Write-Host "   $($pair[1])" }
Write-Host ""
