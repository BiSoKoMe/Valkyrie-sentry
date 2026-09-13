<#
.SYNOPSIS
    Install the frozen Valkyrie engine as the auto-start Windows service
    "ValkyrieShield" (no Python required). Called by the installer, elevated.

.DESCRIPTION
    The engine runs continuously as a service so the app is instantly live the
    moment it opens and protection survives reboots. It binds :53 (DNS
    sinkhole/resolver) and :8090 (dashboard API). Native Unbound, if present on
    :53, is stopped and set to manual so the engine can bind :53 (the engine
    spawns its own private Unbound on 5301 for upstream recursion).

    Traffic only flows through the engine once the DNS adapter is armed
    (arm-protection.ps1 / the app's START button) - installing the service does
    NOT change system DNS, so there is no internet risk at install time.
.PARAMETER Root
    Directory containing valkyrie.exe and nssm.exe (...\resources\engine).
#>
param([Parameter(Mandatory)][string]$Root)
$ErrorActionPreference = 'Continue'

$nssm = Join-Path $Root 'nssm.exe'
$exe  = Join-Path $Root 'valkyrie.exe'
$svc  = 'ValkyrieShield'
# Service logs go with the rest of the writable state in %ProgramData%\Valkyrie,
# never in the read-only install directory.
$data = Join-Path $env:ProgramData 'Valkyrie'
if (-not (Test-Path $data)) { New-Item -ItemType Directory -Path $data -Force | Out-Null }

# %ProgramData%'s own default ACL grants BUILTIN\Users create/write on new
# subfolders (that is what the folder is for, historically). Left inherited,
# this SYSTEM-privileged service reads its own detection policy - playbooks,
# rules, the control token the desktop app authenticates with - from a
# directory ANY standard-user account or process on the machine can write
# into. No admin rights needed to disable enforcement (rewrite playbooks.yaml
# to dry_run), plant an exclusion for a specific attacker binary, or read the
# control token and drive the loopback API's mutation endpoints directly.
# That is a real, checked-in security gap: docs/ENGINEERING_ROADMAP lists the
# HTTP side of this exact problem as its #1 release blocker (SEC-01).
#
# The app still needs to READ this directory unelevated (the Electron main
# process reads control\token directly off disk to authenticate its own API
# calls), so this narrows Users to Read+Execute rather than removing access
# outright. Only SYSTEM (the service's own identity) and Administrators keep
# write. Re-run on every upgrade - icacls /inheritance:r is idempotent, and a
# failure here must never block install; the prior (inherited, permissive)
# ACL is what every install had before this line existed.
Write-Host '[*] Restricting write access to the data directory to SYSTEM/Administrators...'
& icacls $data /inheritance:r 2>&1 | Out-Null
& icacls $data /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' 'Users:(OI)(CI)(RX)' /T /C 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[WARNING] Could not restrict $data's ACL (exit $LASTEXITCODE) - a standard-user process on this machine can still rewrite Valkyrie's own policy files."
}

foreach ($f in @($nssm, $exe)) {
    if (-not (Test-Path $f)) { Write-Host "[ERROR] Missing $f"; exit 1 }
}

# Free port 53: stop native Unbound if it holds it, and stop it auto-starting.
$unbound = Get-Service -Name 'Unbound' -ErrorAction SilentlyContinue
if ($unbound) {
    Write-Host '[*] Stopping native Unbound service to free port 53...'
    Stop-Service -Name 'Unbound' -Force -ErrorAction SilentlyContinue
    Set-Service  -Name 'Unbound' -StartupType Manual -ErrorAction SilentlyContinue
}

# Reinstall cleanly if a previous service exists.
& sc.exe query $svc *> $null
if ($LASTEXITCODE -eq 0) {
    Write-Host '[*] Removing existing service before reinstall...'
    & $nssm stop $svc *> $null
    & $nssm remove $svc confirm *> $null
    Start-Sleep -Seconds 1
}

Write-Host "[*] Installing service '$svc' (frozen engine)..."
# --endpoint turns on the process / network / persistence telemetry collectors
# so the EDR pipeline sees endpoint activity, not just DNS.
# --privacy turns on the privacy pillar at every boot: randomise the MAC and
# spoof the TCP/IP fingerprint (both reversible, both need the SYSTEM rights the
# service already has).
& $nssm install $svc $exe
& $nssm set $svc AppParameters '--port 53 --web --no-ui --web-port 8090 --endpoint --privacy'
& $nssm set $svc AppDirectory $Root
& $nssm set $svc DisplayName 'Valkyrie Privacy Shield'
& $nssm set $svc Description 'Local privacy gateway - DNS sinkhole, firewall and EDR.'
& $nssm set $svc Start SERVICE_AUTO_START
& $nssm set $svc AppStdout (Join-Path $data 'service_stdout.log')
& $nssm set $svc AppStderr (Join-Path $data 'service_stderr.log')
& $nssm set $svc AppExit Default Restart
& $nssm set $svc AppRestartDelay 5000
& $nssm set $svc AppThrottle 5000

Write-Host '[*] Starting service...'
& $nssm start $svc
Start-Sleep -Seconds 2
& sc.exe query $svc | Select-String 'STATE'
Write-Host '[OK] ValkyrieShield installed and running.'
