<#
  vm_lab.ps1 - post-install automation for the "valkyrie-lab" VirtualBox VM.

  This is a FUNCTION LIBRARY, not a script that does things on load. Dot-source
  it, then call the functions you need:

      . .\tools\vm_lab.ps1
      New-VmLabSnapshot -Name clean
      Copy-VmLabPayload
      Enable-VmLabTestSigning -Reboot

  Everything here talks to the guest exclusively through `VBoxManage guestcontrol
  <valkyrie-lab>` or VM-scoped commands (snapshot/storageattach/startvm/controlvm).
  Nothing in this file ever touches host networking, host DNS, host AV, or a host
  driver, and nothing here reboots the HOST - nothing needs to, since every verb
  is scoped to a named VM. Guest reboots (test-signing, verifier) are the guest's
  own reboot, not the host's.

  Deliberately NOT automated: BRINGUP.md's stage gates (section 4 checklist, the section 6
  Mimikatz/LSASS validation, section 7 prevention rollout, the 72h Driver Verifier soak).
  Those require a human reading guest behaviour and deciding whether to proceed -
  scripting past them would defeat the point of having gates. This file gives you
  the plumbing (copy in, run a step, pull results out, snapshot/revert) so each
  gate is a fast manual call, not a slow manual retype of the same commands.

  First-time setup in the guest (do this once, manually, after Windows install +
  Guest Additions):
    - Create/confirm an administrator account - guest processes started via
      VBoxManage guestcontrol under an admin account run fully elevated (no UAC
      prompt, since CreateProcessWithLogonW via the host doesn't get the UAC
      filtered token that interactive console logons get).
    - Guest Additions must be installed for guestcontrol/copyto/copyfrom to work
      at all - that's the manual step you're doing before touching this file.
#>

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

$Script:VmName    = 'valkyrie-lab'
$Script:RepoRoot  = Split-Path -Parent $PSScriptRoot
$Script:GuestRoot = 'C:\ValkyrieLab'

$Script:VBoxManage = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
if (-not (Test-Path $Script:VBoxManage)) {
    $cmd = Get-Command VBoxManage.exe -ErrorAction SilentlyContinue
    if ($cmd) { $Script:VBoxManage = $cmd.Source }
    else { throw "VBoxManage.exe not found. Is VirtualBox installed?" }
}

# Matches BRINGUP.md section 1's actual msbuild output path (driver\valkyrie_km\x64\Release\),
# not the shorthand driver\x64\Release\ - override with -DriverSysPath if yours differs.
$Script:DefaultDriverSysPath = Join-Path $Script:RepoRoot 'driver\valkyrie_km\x64\Release\valkyrie_km.sys'

$Script:VmLabCred = $null

function Say($m, $c = 'Gray') { Write-Host $m -ForegroundColor $c }

# ---------------------------------------------------------------------------
# Credentials + low-level guestcontrol plumbing
# ---------------------------------------------------------------------------

function Get-VmLabCredential {
    <# Prompts once for the guest admin account, caches for the rest of the session. #>
    if (-not $Script:VmLabCred) {
        $Script:VmLabCred = Get-Credential -Message `
            "Administrator account inside valkyrie-lab (created during Windows setup)"
    }
    return $Script:VmLabCred
}

function Invoke-VmLabGuestControl {
    <# Internal: runs `VBoxManage guestcontrol <vm> <verb> <auth> <rest>` with the
       password passed via a throwaway --passwordfile (never on the command line). #>
    param(
        [Parameter(Mandatory)][string]$Verb,
        [string[]]$Rest = @(),
        [pscredential]$Credential
    )
    if (-not $Credential) { $Credential = Get-VmLabCredential }

    $pwFile = Join-Path $env:TEMP "vmlab_pw_$([guid]::NewGuid()).txt"
    try {
        $plain = $Credential.GetNetworkCredential().Password
        Set-Content -Path $pwFile -Value $plain -NoNewline -Encoding ascii
        $authArgs = @('--username', $Credential.UserName, '--passwordfile', $pwFile)
        $full = @('guestcontrol', $Script:VmName, $Verb) + $authArgs + $Rest
        & $Script:VBoxManage @full
        if ($LASTEXITCODE -ne 0) {
            throw "VBoxManage guestcontrol $Verb failed (exit $LASTEXITCODE)"
        }
    } finally {
        Remove-Item -Path $pwFile -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# VM lifecycle
# ---------------------------------------------------------------------------

function Start-VmLab {
    param([switch]$Headless)
    $type = if ($Headless) { 'headless' } else { 'gui' }
    & $Script:VBoxManage startvm $Script:VmName --type $type
}

function Stop-VmLab {
    <# ACPI shutdown by default (graceful); -Force does a hard poweroff (needed
       before restoring a snapshot). Either way this powers off the GUEST. #>
    param([switch]$Force)
    if ($Force) {
        & $Script:VBoxManage controlvm $Script:VmName poweroff
    } else {
        & $Script:VBoxManage controlvm $Script:VmName acpipowerbutton
    }
}

function Wait-VmLabReady {
    <# Blocks until the guest has a desktop session up (Guest Additions running,
       a user logged in) - i.e. guestcontrol calls will actually work. #>
    param([int]$TimeoutSec = 600)
    Say "Waiting for valkyrie-lab desktop run level (timeout ${TimeoutSec}s)..." Cyan
    & $Script:VBoxManage guestcontrol $Script:VmName waitrunlevel --timeout ($TimeoutSec * 1000) desktop
    if ($LASTEXITCODE -ne 0) { throw "Guest did not reach desktop run level in time" }
    Say "Guest ready." Green
}

# ---------------------------------------------------------------------------
# Snapshot / revert
# ---------------------------------------------------------------------------

function New-VmLabSnapshot {
    param([Parameter(Mandatory)][string]$Name, [string]$Description = '')
    & $Script:VBoxManage snapshot $Script:VmName take $Name --description $Description
    if ($LASTEXITCODE -ne 0) { throw "Snapshot '$Name' failed" }
    Say "Snapshot '$Name' taken." Green
}

function Restore-VmLabSnapshot {
    <# Powers the VM off (hard) if running, then restores. This is the "revert"
       button between failed BRINGUP.md attempts. #>
    param([Parameter(Mandatory)][string]$Name)
    $running = (& $Script:VBoxManage list runningvms) -match [regex]::Escape($Script:VmName)
    if ($running) {
        Say "Powering off valkyrie-lab before restore..." Yellow
        Stop-VmLab -Force
        Start-Sleep -Seconds 3
    }
    & $Script:VBoxManage snapshot $Script:VmName restore $Name
    if ($LASTEXITCODE -ne 0) { throw "Restore of snapshot '$Name' failed" }
    Say "Restored snapshot '$Name'." Green
}

function Get-VmLabSnapshots {
    & $Script:VBoxManage snapshot $Script:VmName list
}

function Get-VmLabStatus {
    Say "=== valkyrie-lab status ===" Cyan
    $state = (& $Script:VBoxManage showvminfo $Script:VmName --machinereadable) -match '^VMState='
    Say "  $state"
    Say "  --- snapshots ---"
    Get-VmLabSnapshots
    Say "  --- guest additions ---"
    & $Script:VBoxManage guestproperty get $Script:VmName "/VirtualBox/GuestAdd/Version"
}

# ---------------------------------------------------------------------------
# Copy-in
# ---------------------------------------------------------------------------

function Copy-VmLabPayload {
    <# Copies the built driver + the valkyrie/ python package + tests/ into the
       guest under C:\ValkyrieLab. Run this after every fresh build you want to
       test, and again after any snapshot restore (the guest state resets, the
       host build tree obviously doesn't). #>
    param(
        [string]$DriverSysPath = $Script:DefaultDriverSysPath,
        [switch]$SkipValkyriePackage,
        [switch]$SkipTests
    )

    if (-not (Test-Path $DriverSysPath)) {
        throw "Driver .sys not found at '$DriverSysPath'. Build it first (BRINGUP.md section 1), " +
              "or pass -DriverSysPath to point at your actual build output."
    }

    # Cheap pre-flight check for BRINGUP.md's #1 first-driver failure mode.
    $dumpbin = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if ($dumpbin) {
        $hdr = & $dumpbin.Source /headers $DriverSysPath 2>$null | Select-String -Pattern 'Integrity'
        if ($hdr) { Say "  [ok] $hdr" Green }
        else { Say "  [!] /INTEGRITYCHECK not found in headers - sc start will likely fail with STATUS_ACCESS_DENIED (BRINGUP.md section 1)" Yellow }
    }

    Say "Creating guest directories under $Script:GuestRoot..." Cyan
    Invoke-VmLabGuestControl -Verb mkdir -Rest @('--parents', "$Script:GuestRoot\driver")

    Say "Copying driver .sys..." Cyan
    Invoke-VmLabGuestControl -Verb copyto -Rest @($DriverSysPath, '--target-directory', "$Script:GuestRoot\driver")

    $bringup = Join-Path $Script:RepoRoot 'driver\BRINGUP.md'
    if (Test-Path $bringup) {
        Invoke-VmLabGuestControl -Verb copyto -Rest @($bringup, '--target-directory', "$Script:GuestRoot\driver")
    }

    if (-not $SkipValkyriePackage) {
        Say "Copying valkyrie/ package..." Cyan
        Invoke-VmLabGuestControl -Verb copyto -Rest @(
            '--recursive', (Join-Path $Script:RepoRoot 'valkyrie'), '--target-directory', $Script:GuestRoot
        )
    }

    if (-not $SkipTests) {
        Say "Copying tests/..." Cyan
        Invoke-VmLabGuestControl -Verb copyto -Rest @(
            '--recursive', (Join-Path $Script:RepoRoot 'tests'), '--target-directory', $Script:GuestRoot
        )
    }

    Say "Payload copied to $Script:GuestRoot in the guest." Green
}

function Copy-VmLabResults {
    <# Pulls files/folders back from the guest to a host directory, e.g. logs or
       a results JSON your test scripts wrote. #>
    param(
        [Parameter(Mandatory)][string]$GuestPath,
        [Parameter(Mandatory)][string]$HostDestDir
    )
    New-Item -ItemType Directory -Path $HostDestDir -Force | Out-Null
    Invoke-VmLabGuestControl -Verb copyfrom -Rest @('--recursive', $GuestPath, $HostDestDir)
    Say "Pulled '$GuestPath' -> '$HostDestDir'" Green
}

# ---------------------------------------------------------------------------
# Generic command runner
# ---------------------------------------------------------------------------

function Invoke-VmLabCommand {
    <# Runs one command in the guest, streaming its stdout/stderr to the host
       console (and optionally teeing to a host log file for later review). #>
    param(
        [Parameter(Mandatory)][string]$Exe,
        [string[]]$Arguments = @(),
        [string]$Cwd,
        [string]$LogPath,
        [int]$TimeoutMs
    )
    $rest = @('--exe', $Exe, '--wait-stdout', '--wait-stderr')
    if ($Cwd) { $rest += @('--cwd', $Cwd) }
    if ($TimeoutMs) { $rest += @('--timeout', $TimeoutMs) }
    $rest += '--'
    $rest += $Arguments

    if ($LogPath) {
        Invoke-VmLabGuestControl -Verb run -Rest $rest *>&1 | Tee-Object -FilePath $LogPath
    } else {
        Invoke-VmLabGuestControl -Verb run -Rest $rest
    }
}

# ---------------------------------------------------------------------------
# BRINGUP.md step wrappers - mechanical steps only, no stage-gate judgment calls
# ---------------------------------------------------------------------------

function Enable-VmLabTestSigning {
    <# BRINGUP.md section 0. Requires a guest reboot to take effect. #>
    param([switch]$Reboot)
    Say "Enabling test signing in the guest..." Cyan
    Invoke-VmLabCommand -Exe 'cmd.exe' -Arguments @('/c', 'bcdedit /set testsigning on')
    Invoke-VmLabCommand -Exe 'cmd.exe' -Arguments @('/c', 'bcdedit /set nointegritychecks off')
    if ($Reboot) {
        Say "Rebooting guest..." Yellow
        try { Invoke-VmLabCommand -Exe 'shutdown.exe' -Arguments @('/r', '/t', '0') } catch {}
        Start-Sleep -Seconds 5
        Wait-VmLabReady
        Say "Reminder: take the 'testsigning' snapshot now (New-VmLabSnapshot -Name testsigning)." Yellow
    } else {
        Say "Test signing set. Reboot the guest (or re-run with -Reboot) before it takes effect." Yellow
    }
}

function Install-VmLabDriver {
    <# BRINGUP.md section 4. Assumes Copy-VmLabPayload already placed the .sys under
       C:\ValkyrieLab\driver\. Loads telemetry-only - the driver itself defaults
       to prevention off. #>
    Say "Installing ValkyrieKm service in the guest..." Cyan
    Invoke-VmLabCommand -Exe 'cmd.exe' -Arguments @(
        '/c', "copy /Y $Script:GuestRoot\driver\valkyrie_km.sys C:\Windows\System32\drivers\valkyrie_km.sys"
    )
    Invoke-VmLabCommand -Exe 'sc.exe' -Arguments @('create', 'ValkyrieKm', 'type=', 'kernel', 'binPath=', 'C:\Windows\System32\drivers\valkyrie_km.sys')
    Invoke-VmLabCommand -Exe 'sc.exe' -Arguments @('start', 'ValkyrieKm')
    Get-VmLabDriverStatus
}

function Get-VmLabDriverStatus {
    Invoke-VmLabCommand -Exe 'sc.exe' -Arguments @('query', 'ValkyrieKm')
}

function Uninstall-VmLabDriver {
    <# BRINGUP.md section 8 recovery row: "machine boots but is unusable". #>
    try { Invoke-VmLabCommand -Exe 'sc.exe' -Arguments @('stop', 'ValkyrieKm') } catch {}
    Invoke-VmLabCommand -Exe 'sc.exe' -Arguments @('delete', 'ValkyrieKm')
}

function Enable-VmLabDriverVerifier {
    <# BRINGUP.md section 5. Requires a guest reboot to take effect; this is the start
       of the 72h soak, not something to loop through unattended. #>
    param([switch]$Reboot)
    Invoke-VmLabCommand -Exe 'verifier.exe' -Arguments @('/standard', '/driver', 'valkyrie_km.sys')
    if ($Reboot) {
        try { Invoke-VmLabCommand -Exe 'shutdown.exe' -Arguments @('/r', '/t', '0') } catch {}
        Start-Sleep -Seconds 5
        Wait-VmLabReady
    } else {
        Say "Driver Verifier flag set. Reboot the guest (or re-run with -Reboot) before it takes effect." Yellow
    }
}

function Get-VmLabVerifierStatus {
    Invoke-VmLabCommand -Exe 'verifier.exe' -Arguments @('/querysettings')
}

function Disable-VmLabDriverVerifier {
    Invoke-VmLabCommand -Exe 'verifier.exe' -Arguments @('/reset')
}

# ---------------------------------------------------------------------------

Say ""
Say "=== vm_lab.ps1 loaded (VM: $Script:VmName) ===" Cyan
Say "  Lifecycle : Start-VmLab, Stop-VmLab, Wait-VmLabReady, Get-VmLabStatus"
Say "  Snapshots : New-VmLabSnapshot, Restore-VmLabSnapshot, Get-VmLabSnapshots"
Say "  Files     : Copy-VmLabPayload, Copy-VmLabResults"
Say "  Run       : Invoke-VmLabCommand -Exe ... -Arguments ..."
Say "  BRINGUP   : Enable-VmLabTestSigning, Install-VmLabDriver, Get-VmLabDriverStatus,"
Say "              Uninstall-VmLabDriver, Enable-VmLabDriverVerifier, Get-VmLabVerifierStatus,"
Say "              Disable-VmLabDriverVerifier"
Say "Stage gates (section 4, section 6, section 7, the 72h soak) are on you - this only handles the mechanics." Gray
Say ""
