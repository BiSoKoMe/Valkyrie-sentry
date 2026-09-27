<#
  Read-only gate before a Valkyrie live-validation run.

  This script never creates, starts, changes, or deletes a VM.  It only proves
  that the existing VirtualBox lab is usable, isolated, snapshotted, and has
  the checked installer and Tier-B runner available.  Run the destructive
  workloads only after every required check reports true.
#>
[CmdletBinding()]
param(
    [string]$VmName = 'valkyrie-lab',
    [string]$VBoxManage = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe',
    [switch]$AsJson
)

$repoRoot = Split-Path -Parent $PSScriptRoot
$checks = [System.Collections.Generic.List[object]]::new()

function Add-Check([string]$Name, [bool]$Ok, [string]$Detail) {
    $checks.Add([pscustomobject]@{ name = $Name; ok = $Ok; detail = $Detail })
}

if (-not (Test-Path -LiteralPath $VBoxManage)) {
    $command = Get-Command VBoxManage.exe -ErrorAction SilentlyContinue
    if ($command) { $VBoxManage = $command.Source }
}

$vboxPresent = Test-Path -LiteralPath $VBoxManage
Add-Check 'virtualbox_binary' $vboxPresent $(if ($vboxPresent) { $VBoxManage } else { 'VBoxManage.exe not found.' })

$vboxReady = $false
if ($vboxPresent) {
    $vmList = & $VBoxManage list vms 2>&1 | Out-String
    $vboxReady = $LASTEXITCODE -eq 0
    Add-Check 'virtualbox_service' $vboxReady $(if ($vboxReady) { 'VBoxManage can enumerate VMs.' } else { $vmList.Trim() })
} else {
    Add-Check 'virtualbox_service' $false 'VirtualBox cannot run without VBoxManage.exe.'
}

$vmFound = $false
$snapshotFound = $false
$safeNetwork = $false
if ($vboxReady) {
    $vmList = & $VBoxManage list vms 2>$null
    $vmFound = $vmList -match ('"' + [regex]::Escape($VmName) + '"')
    Add-Check 'lab_vm' $vmFound $(if ($vmFound) { "Found $VmName." } else { "No VM named $VmName." })
    if ($vmFound) {
        $info = & $VBoxManage showvminfo $VmName --machinereadable 2>$null
        $network = ($info | Where-Object { $_ -match '^nic1=' }) -replace '^nic1="|"$'
        $safeNetwork = $network -in @('nat', 'hostonly', 'intnet')
        Add-Check 'isolated_network' $safeNetwork $(if ($safeNetwork) { "Adapter 1 is $network." } else { "Adapter 1 is $network; use NAT, host-only, or internal networking, never bridged." })
        $snapshots = & $VBoxManage snapshot $VmName list 2>$null | Out-String
        $snapshotFound = $snapshots -match 'Name:'
        Add-Check 'recovery_snapshot' $snapshotFound $(if ($snapshotFound) { 'At least one recovery snapshot exists.' } else { 'Take a clean snapshot after provisioning and before Atomic Red Team.' })
    }
} else {
    Add-Check 'lab_vm' $false 'VM check skipped because VirtualBox is unavailable.'
    Add-Check 'isolated_network' $false 'Network check skipped because VirtualBox is unavailable.'
    Add-Check 'recovery_snapshot' $false 'Snapshot check skipped because VirtualBox is unavailable.'
}

$installer = Join-Path $repoRoot 'ValkyrieSetup.exe'
$tierB = Join-Path $repoRoot 'redteam\evaluation\run_live_evaluation.ps1'
Add-Check 'installer_artifact' (Test-Path -LiteralPath $installer) $(if (Test-Path -LiteralPath $installer) { $installer } else { 'Build ValkyrieSetup.exe before guest installation.' })
Add-Check 'tier_b_runner' (Test-Path -LiteralPath $tierB) $(if (Test-Path -LiteralPath $tierB) { $tierB } else { 'Tier-B runner missing.' })

$ready = $vboxReady -and $vmFound -and $snapshotFound -and $safeNetwork `
    -and (Test-Path -LiteralPath $installer) -and (Test-Path -LiteralPath $tierB)
$result = [pscustomobject]@{
    vm_name = $VmName
    ready_for_live_validation = $ready
    checks = $checks
    next = if ($ready) {
        'Inside the guest: redteam/provision.ps1, install ValkyrieSetup.exe, take a fresh snapshot, then run redteam/vm_selftest.ps1 before redteam/evaluation/run_live_evaluation.ps1.'
    } else {
        'Fix every failed check. Do not run Atomic Red Team until this gate passes.'
    }
}

if ($AsJson) { $result | ConvertTo-Json -Depth 4 } else { $result }
