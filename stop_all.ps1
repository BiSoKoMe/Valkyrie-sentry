<#
.SYNOPSIS
    Reverses everything start_all.ps1 did.

.DESCRIPTION
    1. Resets DNS back to automatic on whichever adapter start_all.ps1
       changed (tracked in data\valkyrie_dns_adapter.txt).
    2. Stops the tracked Valkyrie process (data\valkyrie_pid.txt). Falls
       back to a best-effort command-line search if the PID file is
       missing (e.g. the console window was closed manually).
    3. Restarts the native Unbound Windows service if start_all.ps1 had
       stopped it (tracked in data\valkyrie_unbound_stopped.txt).
    4. Prints a short confirmation.

    Safe to re-run: every step is a no-op if there's nothing tracked to
    undo, and never errors out partway through.
#>

$ErrorActionPreference = 'Continue'   # keep going so every cleanup step gets a chance to run

# ---------------------------------------------------------------------------
# Self-elevate
# ---------------------------------------------------------------------------

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host "[*] Relaunching with Administrator privileges..."
    Start-Process -FilePath "powershell.exe" -Verb RunAs -WindowStyle Hidden -ArgumentList @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden",
        "-File", "`"$PSCommandPath`""
    )
    exit
}

$ProjectRoot = $PSScriptRoot
$DataDir     = Join-Path $ProjectRoot "data"

$PidFile          = Join-Path $DataDir "valkyrie_pid.txt"
$AdapterStateFile = Join-Path $DataDir "valkyrie_dns_adapter.txt"
$UnboundStateFile = Join-Path $DataDir "valkyrie_unbound_stopped.txt"

# ---------------------------------------------------------------------------
# 1. Reset DNS on whichever adapter was changed
# ---------------------------------------------------------------------------

if (Test-Path $AdapterStateFile) {
    $adapterAlias = Get-Content $AdapterStateFile -ErrorAction SilentlyContinue
    if ($adapterAlias) {
        Write-Host "[*] Resetting DNS on adapter: $adapterAlias"
        Set-DnsClientServerAddress -InterfaceAlias $adapterAlias -ResetServerAddresses -ErrorAction SilentlyContinue
        Write-Host "[OK] DNS reset to automatic."
    }
    Remove-Item $AdapterStateFile -ErrorAction SilentlyContinue
} else {
    Write-Host "[*] No tracked DNS change found - nothing to reset."
}

# ---------------------------------------------------------------------------
# 2. Stop the Valkyrie process
# ---------------------------------------------------------------------------

$stopped = $false
if (Test-Path $PidFile) {
    $valkyriePid = Get-Content $PidFile -ErrorAction SilentlyContinue
    if ($valkyriePid) {
        $proc = Get-Process -Id $valkyriePid -ErrorAction SilentlyContinue
        if ($proc) {
            Write-Host "[*] Stopping Valkyrie (PID $valkyriePid)..."
            Stop-Process -Id $valkyriePid -Force -ErrorAction SilentlyContinue
            Write-Host "[OK] Valkyrie stopped."
            $stopped = $true
        } else {
            Write-Host "[*] Tracked Valkyrie process (PID $valkyriePid) was not running."
        }
    }
    Remove-Item $PidFile -ErrorAction SilentlyContinue
}

if (-not $stopped) {
    # Fallback: best-effort match by command line, in case the console
    # window was closed manually or the PID file is otherwise missing.
    # Match both the frozen engine (valkyrie.exe) and a source run
    # (python.exe -m valkyrie), so stop works whichever way it was started.
    $candidates = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            ($_.Name -eq 'valkyrie.exe') -or
            ($_.Name -eq 'python.exe' -and $_.CommandLine -like "*-m valkyrie*")
        }
    if ($candidates) {
        foreach ($c in $candidates) {
            Write-Host "[*] Stopping Valkyrie process (PID $($c.ProcessId)) found via command-line match..."
            Stop-Process -Id $c.ProcessId -Force -ErrorAction SilentlyContinue
        }
        Write-Host "[OK] Valkyrie stopped."
    } else {
        Write-Host "[*] No running Valkyrie process found."
    }
}

# ---------------------------------------------------------------------------
# 3. Restore native Unbound service if start_all.ps1 stopped it
# ---------------------------------------------------------------------------

if (Test-Path $UnboundStateFile) {
    Write-Host "[*] Restoring native Unbound service..."
    Start-Service -Name "Unbound" -ErrorAction SilentlyContinue
    Remove-Item $UnboundStateFile -ErrorAction SilentlyContinue
    Write-Host "[OK] Unbound service restored."
}

Write-Host ""
Write-Host "Protection stopped. Internet back to normal."
