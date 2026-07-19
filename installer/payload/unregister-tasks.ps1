<#
.SYNOPSIS
    Remove the Valkyrie on-demand tasks. Called at uninstall time.
#>
$ErrorActionPreference = 'Continue'
foreach ($name in @('ValkyrieArm', 'ValkyrieDisarm', 'ValkyrieStart', 'ValkyrieStop')) {
    try {
        if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $name -Confirm:$false
            Write-Host "[OK] Removed task: $name"
        }
    } catch {
        Write-Host "[WARN] Could not remove task ${name}: $($_.Exception.Message)"
    }
}
