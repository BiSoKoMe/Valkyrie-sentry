<#
.SYNOPSIS
    One-command Valkyrie startup: Unbound handoff, launch, DNS takeover,
    dashboard.

.DESCRIPTION
    1. Self-elevates (UAC) if not already Administrator.
    2. Stops the native "Unbound" Windows service if running, freeing
       127.0.0.1:53 for Valkyrie itself to bind. Windows' built-in DNS
       client (Set-DnsClientServerAddress) can only ever target port 53 on
       a server IP, so Valkyrie's filter/sinkhole must be the thing
       answering there for OS-level interception to work at all. Leaving
       the native service on 53 would make Valkyrie fail to bind, which
       would point Windows at a server with nothing listening - a full
       internet outage. Valkyrie's own resolver.py transparently spawns a
       *private* Unbound subprocess on port 5301 for the actual recursive
       resolution backend, so local non-leaking DNS resolution is
       preserved either way. stop_all.ps1 restarts the native service.
    3. Launches `python -m valkyrie --port 53 --web --no-ui --web-port 8090`
       in a new, visible console window.
    4. Actively verifies Valkyrie is really listening (web API + raw DNS
       probe on port 53) BEFORE touching system DNS. If it never comes up,
       aborts without changing anything and restores Unbound, so the user
       is never left without internet.
    5. Points the network adapter currently providing internet
       connectivity at 127.0.0.1.
    6. Opens the dashboard in the default browser.
    7. Prints a short summary.

    Safe to re-run: detects an already-running, tracked Valkyrie instance
    and skips re-launch; DNS/service changes are naturally idempotent.
#>

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# 1. Self-elevate
# ---------------------------------------------------------------------------

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host "[*] Relaunching with Administrator privileges..."
    Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-NoExit",
        "-File", "`"$PSCommandPath`""
    )
    exit
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

$ProjectRoot = $PSScriptRoot
$DataDir     = Join-Path $ProjectRoot "data"
if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }

$PidFile          = Join-Path $DataDir "valkyrie_pid.txt"
$AdapterStateFile = Join-Path $DataDir "valkyrie_dns_adapter.txt"
$UnboundStateFile = Join-Path $DataDir "valkyrie_unbound_stopped.txt"
$WebPort          = 8090
$DnsPort          = 53

function Test-DnsPort {
    <# Raw UDP DNS probe — True if something answers on 127.0.0.1:<Port>. #>
    param([int]$Port)
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.UdpClient
        $client.Client.ReceiveTimeout = 1500
        $client.Connect("127.0.0.1", $Port)
        # Minimal A-record query for "." (root) — always a valid query.
        $query = [byte[]](0xAB,0xCD,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x01)
        $client.Send($query, $query.Length) | Out-Null
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $resp = $client.Receive([ref]$remote)
        return ($resp.Length -ge 12)
    } catch {
        return $false
    } finally {
        if ($client) { $client.Close() }
    }
}

# ---------------------------------------------------------------------------
# Idempotency check — is a tracked Valkyrie instance already running?
# ---------------------------------------------------------------------------

$AlreadyRunning = $false
if (Test-Path $PidFile) {
    $existingPid = Get-Content $PidFile -ErrorAction SilentlyContinue
    if ($existingPid -and (Get-Process -Id $existingPid -ErrorAction SilentlyContinue)) {
        $AlreadyRunning = $true
    }
}

if ($AlreadyRunning) {
    Write-Host "[OK] Valkyrie is already running (PID $existingPid) - skipping relaunch."
} else {

    # -----------------------------------------------------------------
    # 2. Stop native Unbound service to free port 53 for Valkyrie
    # -----------------------------------------------------------------
    $unboundSvc = Get-Service -Name "Unbound" -ErrorAction SilentlyContinue
    if ($unboundSvc) {
        if ($unboundSvc.Status -eq 'Running') {
            Write-Host "[*] Stopping native Unbound service to free port 53 for Valkyrie..."
            Stop-Service -Name "Unbound" -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
            Set-Content -Path $UnboundStateFile -Value "1" -Encoding utf8 -NoNewline
            Write-Host "[OK] Unbound service stopped (stop_all.ps1 will restart it)."
        } else {
            Write-Host "[OK] Unbound service already stopped."
        }
    } else {
        Write-Host "[WARNING] Unbound service not installed - Valkyrie will fall back to public DNS upstream."
    }

    # -----------------------------------------------------------------
    # 3. Launch Valkyrie in a new visible console window
    # -----------------------------------------------------------------
    Write-Host "[*] Starting Valkyrie on port $DnsPort (dashboard on $WebPort)..."
    $valkyrieArgs = @("-m", "valkyrie", "--port", "$DnsPort", "--web", "--no-ui", "--web-port", "$WebPort")
    $proc = Start-Process -FilePath "python" -ArgumentList $valkyrieArgs `
        -WorkingDirectory $ProjectRoot -WindowStyle Normal -PassThru
    Set-Content -Path $PidFile -Value "$($proc.Id)" -Encoding utf8 -NoNewline

    # -----------------------------------------------------------------
    # 4. Poll until Valkyrie is ready, then verify DNS before touching
    #    system DNS. No fixed sleep — browser opens only after the API
    #    confirms 200 OK, so the WebSocket connects on first load.
    # -----------------------------------------------------------------
    Write-Host "[*] Waiting for Valkyrie to start..."
    $maxWait = 30
    $waited  = 0
    $valkyrieUp = $false
    while ($waited -lt $maxWait) {
        $webOk = $false
        try {
            $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$WebPort/api/stats" -UseBasicParsing -TimeoutSec 1 -ErrorAction Stop
            $webOk = ($resp.StatusCode -eq 200)
        } catch { $webOk = $false }

        if ($webOk -and (Test-DnsPort -Port $DnsPort)) {
            $valkyrieUp = $true
            break
        }
        Start-Sleep -Seconds 1
        $waited++
    }

    if (-not $valkyrieUp) {
        Write-Host ""
        Write-Host "[ERROR] Valkyrie did not come up on port $DnsPort / $WebPort after $maxWait seconds - aborting"
        Write-Host "        WITHOUT changing system DNS. Check the Valkyrie console"
        Write-Host "        window for the actual error."
        if (Test-Path $UnboundStateFile) {
            Write-Host "[*] Restoring native Unbound service..."
            Start-Service -Name "Unbound" -ErrorAction SilentlyContinue
            Remove-Item $UnboundStateFile -ErrorAction SilentlyContinue
        }
        exit 1
    }
    Write-Host "[OK] Valkyrie HTTP+DNS confirmed ready (after ${waited}s)."
    # WebSocket listener initialises slightly after the HTTP API.
    # A quick TCP connect confirms the port is accepting connections
    # before we open the browser, so the WS handshake succeeds first try.
    $tcp = New-Object System.Net.Sockets.TcpClient
    try { $tcp.Connect("127.0.0.1", $WebPort) } catch {} finally { $tcp.Close() }
    Start-Sleep -Seconds 2

    # -----------------------------------------------------------------
    # 5. Point the active network adapter's DNS at Valkyrie
    # -----------------------------------------------------------------
    Write-Host "[*] Detecting active network adapter..."
    $adapterAlias = $null
    $activeProfile = Get-NetConnectionProfile -ErrorAction SilentlyContinue |
        Where-Object { $_.IPv4Connectivity -eq 'Internet' } | Select-Object -First 1
    if ($activeProfile) {
        $adapterAlias = $activeProfile.InterfaceAlias
    } else {
        foreach ($name in @("Wi-Fi", "Ethernet")) {
            $a = Get-NetAdapter -Name $name -ErrorAction SilentlyContinue
            if ($a -and $a.Status -eq 'Up') { $adapterAlias = $name; break }
        }
    }

    if (-not $adapterAlias) {
        Write-Host "[ERROR] Could not detect an active network adapter - DNS was NOT changed."
        Write-Host "        Valkyrie is running; point your adapter's DNS at 127.0.0.1 manually"
        Write-Host "        to route traffic through it."
    } else {
        Write-Host "[*] Setting DNS to 127.0.0.1 on adapter: $adapterAlias"
        Set-DnsClientServerAddress -InterfaceAlias $adapterAlias -ServerAddresses "127.0.0.1"
        Set-Content -Path $AdapterStateFile -Value $adapterAlias -Encoding utf8 -NoNewline
        Write-Host "[OK] DNS updated."
    }

    # -----------------------------------------------------------------
    # 6. Open the dashboard
    # -----------------------------------------------------------------
    Write-Host "[*] Opening dashboard..."
    Start-Process "http://localhost:$WebPort"
}

# ---------------------------------------------------------------------------
# 7. Summary
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "Valkyrie is now protecting this device."
Write-Host "Dashboard: http://localhost:$WebPort"
Write-Host "To stop protection, run: stop_all.bat"
