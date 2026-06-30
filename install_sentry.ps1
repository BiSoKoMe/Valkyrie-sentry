#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Valkyrie Sentry — Windows installer (testing / desktop use)
    Mirrors the logic of install_sentry.sh using NSSM + netsh portproxy.

.DESCRIPTION
    1. System check
    2. Verify Python
    3. Install pip dependencies
    4. DNS redirect via netsh portproxy (port 53 → 5300)
    5. Create Windows service via NSSM
    6. Open firewall port 8080
    7. Verify installation
    8. Print summary
#>

param(
    [string]$ValkyrieDir = (Split-Path -Parent $MyInvocation.MyCommand.Path),
    [int]$DnsPort   = 5300,
    [int]$WebPort   = 8080,
    [string]$NssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
)

$ErrorActionPreference = 'Stop'
$ServiceName           = "ValkyrieShield"

function Write-Pass { param([string]$msg) Write-Host "[PASS] $msg" -ForegroundColor Green }
function Write-Fail { param([string]$msg) Write-Host "[FAIL] $msg" -ForegroundColor Red; exit 1 }
function Write-Info { param([string]$msg) Write-Host "[INFO] $msg" -ForegroundColor Yellow }

# ── Step 1: System check ─────────────────────────────────────────────────────
Write-Info "Step 1 - System check"

$os = [System.Environment]::OSVersion
if ($os.Platform -ne 'Win32NT') { Write-Fail "Windows required" }

$freeDisk = (Get-PSDrive -Name C).Free
if ($freeDisk -lt 200MB) { Write-Fail "Not enough disk space (need >200 MB on C:)" }

$freeRam = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1024
if ($freeRam -lt 32MB) { Write-Fail "Not enough RAM (need >32 MB free)" }

Write-Pass "System checks passed"

# ── Step 2: Python check ──────────────────────────────────────────────────────
Write-Info "Step 2 - Checking Python"

try {
    $pyVer = & python --version 2>&1
    Write-Pass "Python found: $pyVer"
} catch {
    Write-Fail "Python not found. Install from https://python.org"
}

# ── Step 3: Install pip dependencies ─────────────────────────────────────────
Write-Info "Step 3 - Installing Python dependencies"

$packages = "dnspython", "psutil", "pyyaml", "rich", "fastapi", "uvicorn", "aiofiles"
foreach ($pkg in $packages) {
    Write-Info "  pip install $pkg"
    & python -m pip install $pkg --quiet
}

Write-Pass "Python dependencies installed"

# ── Step 4: DNS redirect via netsh portproxy ─────────────────────────────────
Write-Info "Step 4 - Configuring DNS portproxy (port 53 -> $DnsPort)"

# Remove existing rule if present
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=53 2>$null
netsh interface portproxy add v4tov4 `
    listenaddress=0.0.0.0 `
    listenport=53 `
    connectaddress=127.0.0.1 `
    connectport=$DnsPort

Write-Pass "DNS portproxy: port 53 -> 127.0.0.1:$DnsPort"

# ── Step 5: Install NSSM and create service ───────────────────────────────────
Write-Info "Step 5 - Installing Windows service via NSSM"

$toolsDir = Join-Path $ValkyrieDir "tools"
$nssmExe  = Join-Path $toolsDir "nssm.exe"

if (-not (Test-Path $nssmExe)) {
    Write-Info "  Downloading NSSM from $NssmUrl"
    New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null
    $zipPath = Join-Path $env:TEMP "nssm.zip"
    Invoke-WebRequest -Uri $NssmUrl -OutFile $zipPath -UseBasicParsing
    $extractDir = Join-Path $env:TEMP "nssm_extract"
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
    $nssmBin = Get-ChildItem -Path $extractDir -Filter "nssm.exe" -Recurse | Where-Object { $_.DirectoryName -like "*win64*" } | Select-Object -First 1
    if (-not $nssmBin) {
        $nssmBin = Get-ChildItem -Path $extractDir -Filter "nssm.exe" -Recurse | Select-Object -First 1
    }
    Copy-Item -Path $nssmBin.FullName -Destination $nssmExe
    Remove-Item $zipPath -Force
    Remove-Item $extractDir -Recurse -Force
    Write-Pass "NSSM downloaded to $nssmExe"
}

$pyExe = (Get-Command python).Source

# Remove old service if it exists
$svcStatus = & sc.exe query $ServiceName 2>$null
if ($svcStatus -match "SERVICE_NAME") {
    & sc.exe stop $ServiceName 2>$null
    Start-Sleep -Seconds 2
    & $nssmExe remove $ServiceName confirm 2>$null
}

# Install new service
& $nssmExe install $ServiceName $pyExe "-m valkyrie --web --no-ui --port $DnsPort --web-port $WebPort"
& $nssmExe set $ServiceName AppDirectory $ValkyrieDir
& $nssmExe set $ServiceName Start SERVICE_AUTO_START
& $nssmExe set $ServiceName ObjectName LocalSystem
& sc.exe failure $ServiceName reset= 3600 actions= restart/5000/restart/5000/restart/5000

Write-Pass "Service '$ServiceName' created"

& sc.exe start $ServiceName | Out-Null
Start-Sleep -Seconds 3
Write-Pass "Service started"

# ── Step 6: Firewall rules ────────────────────────────────────────────────────
Write-Info "Step 6 - Opening firewall ports"

$ruleName = "Valkyrie Web Dashboard"
netsh advfirewall firewall delete rule name="$ruleName" 2>$null
netsh advfirewall firewall add rule `
    name="$ruleName" `
    dir=in action=allow protocol=TCP `
    localport=$WebPort profile=any | Out-Null

$dnsRuleName = "Valkyrie DNS UDP $DnsPort"
netsh advfirewall firewall delete rule name="$dnsRuleName" 2>$null
netsh advfirewall firewall add rule `
    name="$dnsRuleName" `
    dir=in action=allow protocol=UDP `
    localport=$DnsPort profile=any | Out-Null

Write-Pass "Firewall rules added for ports $WebPort (TCP) and $DnsPort (UDP)"

# ── Step 7: Verify ────────────────────────────────────────────────────────────
Write-Info "Step 7 - Verifying installation (waiting 10s)"
Start-Sleep -Seconds 10

# DNS block test
try {
    $resolver = [System.Net.Dns]::GetHostAddresses("doubleclick.net")
    $ip = $resolver[0].ToString()
    if ($ip -eq "0.0.0.0" -or $ip -eq "::") {
        Write-Pass "DNS block test: doubleclick.net -> $ip (BLOCKED)"
    } else {
        Write-Host "[WARN] DNS block test: got $ip (expected 0.0.0.0)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[WARN] DNS block test failed: $_" -ForegroundColor Yellow
}

# DNS allow test
try {
    $resolver = [System.Net.Dns]::GetHostAddresses("google.com")
    $ip = $resolver[0].ToString()
    if ($ip -ne "0.0.0.0" -and $ip -match '\d+\.\d+\.\d+\.\d+') {
        Write-Pass "DNS allow test: google.com -> $ip"
    } else {
        Write-Host "[WARN] DNS allow test: unexpected result $ip" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[WARN] DNS allow test failed: $_" -ForegroundColor Yellow
}

# Web UI test
try {
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:$WebPort" -TimeoutSec 5 -UseBasicParsing
    if ($response.Content -imatch "valkyrie") {
        Write-Pass "Web UI test: http://127.0.0.1:$WebPort responding"
    } else {
        Write-Host "[WARN] Web UI responded but content unexpected" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[WARN] Web UI not responding on port $WebPort — may still be starting" -ForegroundColor Yellow
}

# ── Step 8: Summary ───────────────────────────────────────────────────────────
Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Valkyrie Sentry installed and running." -ForegroundColor Green
Write-Host ""
Write-Host "Web dashboard: http://localhost:$WebPort" -ForegroundColor Cyan
Write-Host "DNS port: $DnsPort"
Write-Host "Service name: $ServiceName"
Write-Host ""
Write-Host "Every application on this machine is now protected."
Write-Host "Run 'sc query $ServiceName' to check service status."
Write-Host "================================================" -ForegroundColor Cyan
