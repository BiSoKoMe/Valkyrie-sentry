<#
.SYNOPSIS
    Release-blocking build audit. Fails (exit 1) if anything that must never
    ship is found in the staged engine payload or the final packaged app.

.DESCRIPTION
    Enforces "no developer/user data in the installer". Checks:
      * Forbidden files/dirs in the staged payload (databases, logs, env files,
        keys/certs, caches, VCS metadata, tokens, the working rules file).
      * The developer username or an absolute C:\Users\<name>\ path embedded in
        any shipped binary or text file (the frozen engine, app.asar, scripts).
    Third-party binaries (nssm, vc_redist) are scanned too — they should be
    clean, and a hit means something is wrong.

.PARAMETER Stage
    The staged engine payload directory (electron\engine_payload).
.PARAMETER Unpacked
    Optional: the electron-builder win-unpacked directory, to also scan
    resources\app.asar (the packaged renderer/main code).
#>
param(
    [Parameter(Mandatory)][string]$Stage,
    [string]$Unpacked
)

$ErrorActionPreference = 'Stop'
$script:violations = New-Object System.Collections.Generic.List[string]
$script:warnings   = New-Object System.Collections.Generic.List[string]

# --- What must never appear in the shipped bits ---------------------------
$devUser = $env:USERNAME
$hardNeedles = @()
if ($devUser) {
    $hardNeedles += $devUser
    $hardNeedles += "C:\Users\$devUser"
    $hardNeedles += "\Users\$devUser\"
}
$hardNeedles += "OneDrive\Desktop\Valkyrie"     # this repo's dev path
$softNeedles = @("C:\Users\")                    # any other user-absolute path

# Files/dirs that must never be staged into the installer payload.
$forbiddenFilePatterns = @(
    '\.db$', '\.log$', '\.env$', '\.pem$', '\.key$', '\.pfx$', '\.crt$', '\.conf$',
    '\.map$',        # source maps
    '\.pyc$', '\.pyo$', '\.pdb$'   # python/debug build artifacts
)
$forbiddenNames = @(
    'control_token.txt', 'fleet_agent.json', 'valkyrie.db', 'blocklist.txt',
    'valkyrie_rules.yaml'   # the working rules file — only rules.default.yaml (bundled) may ship
)
$forbiddenDirs = @('data', 'logs', '__pycache__', '.git', '.venv', 'venv', 'node_modules',
                   '.pytest_cache', '.mypy_cache', 'tests', '__tests__', '.vscode', '.idea')
# Test files must never ship (test_x.py, x_test.js, x.test.ts, x.spec.js).
$testFileRe = '^test_.*|.*[_.]test\.[a-z]+$|.*\.spec\.[a-z]+$'
# Assets larger than this (that aren't the known big payload members) are flagged.
$oversizeBytes = 60MB
$oversizeAllow = @('valkyrie.exe', 'vc_redist.x64.exe')

function Test-BinaryForNeedles {
    param([string]$Path, [string[]]$Needles)
    # Latin1 maps bytes 1:1 to chars, so ordinal substring search finds any
    # ASCII path/username regardless of surrounding binary data.
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    # ISO-8859-1 (Latin1) maps bytes 1:1 to chars. Use GetEncoding rather than
    # the ::Latin1 property, which only exists in PowerShell 7+/.NET Core.
    $text  = [System.Text.Encoding]::GetEncoding(28591).GetString($bytes)
    $hits  = @()
    foreach ($n in $Needles) {
        if ($text.IndexOf($n, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $hits += $n }
    }
    return $hits
}

function Invoke-ScanFile {
    param([string]$Path)
    $rel = Split-Path $Path -Leaf
    $hard = Test-BinaryForNeedles -Path $Path -Needles $hardNeedles
    foreach ($h in $hard) { $script:violations.Add("[$rel] contains forbidden string: '$h'") }
    $soft = Test-BinaryForNeedles -Path $Path -Needles $softNeedles
    foreach ($s in $soft) { $script:warnings.Add("[$rel] contains a user-absolute path fragment: '$s'") }
}

# Scan a directory tree for forbidden files/dirs/test-files/oversized/duplicates.
function Invoke-ScanForbidden {
    param([string]$Dir, [string]$Label)
    if (-not (Test-Path $Dir)) { return }
    Get-ChildItem $Dir -Recurse -Force | ForEach-Object {
        if ($_.PSIsContainer) {
            if ($forbiddenDirs -contains $_.Name) { $script:violations.Add("[$Label] forbidden directory: $($_.Name)") }
        } else {
            if ($forbiddenNames -contains $_.Name) { $script:violations.Add("[$Label] forbidden file: $($_.Name)") }
            if ($_.Name -match $testFileRe)        { $script:violations.Add("[$Label] test file shipped: $($_.Name)") }
            foreach ($pat in $forbiddenFilePatterns) {
                if ($_.Name -match $pat) { $script:violations.Add("[$Label] forbidden file type: $($_.Name)") }
            }
            if ($_.Length -gt $oversizeBytes -and ($oversizeAllow -notcontains $_.Name)) {
                $script:warnings.Add("[$Label] oversized asset ($([math]::Round($_.Length/1MB))MB): $($_.Name)")
            }
        }
    }
    # Duplicate files (same content shipped twice) — a warning, by SHA256.
    $byHash = @{}
    Get-ChildItem $Dir -Recurse -File -Force | Where-Object { $_.Length -gt 0 } | ForEach-Object {
        $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        if ($byHash.ContainsKey($h)) { $script:warnings.Add("[$Label] duplicate content: $($_.Name) == $($byHash[$h])") }
        else { $byHash[$h] = $_.Name }
    }
}

Write-Host "[audit] Scanning staged payload: $Stage"
if (-not (Test-Path $Stage)) { Write-Host "[audit] ERROR: stage not found"; exit 1 }

# 1) Forbidden files/dirs/test-files/oversized/duplicates in the stage.
Invoke-ScanForbidden -Dir $Stage -Label 'stage'

# 2) Every staged file scanned for dev username / absolute paths.
Get-ChildItem $Stage -Recurse -File -Force | ForEach-Object { Invoke-ScanFile -Path $_.FullName }

# 3) The packaged app code (app.asar) if a build output was provided.
if ($Unpacked) {
    $asar = Join-Path $Unpacked 'resources\app.asar'
    if (Test-Path $asar) { Write-Host "[audit] Scanning $asar"; Invoke-ScanFile -Path $asar }
    # The bundled engine must be as clean as the stage (forbidden files, test
    # files, source maps, .pyc, oversized, duplicates).
    Invoke-ScanForbidden -Dir (Join-Path $Unpacked 'resources\engine') -Label 'packaged-engine'
    # No stray source maps anywhere under resources (our own code ships none).
    Get-ChildItem (Join-Path $Unpacked 'resources') -Recurse -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '\.map$' } |
        ForEach-Object { $script:violations.Add("source map shipped: $($_.FullName)") }
}

# --- Report ---------------------------------------------------------------
Write-Host ""
foreach ($w in $warnings)   { Write-Host "  [warn] $w" -ForegroundColor DarkYellow }
if ($violations.Count -gt 0) {
    Write-Host ""
    Write-Host "  RELEASE-BLOCKING: build contains developer/user data:" -ForegroundColor Red
    foreach ($v in $violations) { Write-Host "    x $v" -ForegroundColor Red }
    Write-Host ""
    exit 1
}
Write-Host "[audit] PASS - no developer or user data found in the build." -ForegroundColor Green
exit 0
