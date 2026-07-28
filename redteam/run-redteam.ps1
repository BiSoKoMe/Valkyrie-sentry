# ============================================================================
#  run-redteam.ps1 - run real Atomic Red Team atomics against a running
#  Valkyrie and score DETECTED / BLOCKED / MISSED honestly.
#
#  RUN ONLY IN A THROWAWAY VM WITH A FRESH SNAPSHOT. The plan includes
#  destructive atomics (shadow-copy deletion, Defender disable). Revert after.
#
#  Prereqs (see provision.ps1): Sysmon + config, PS Script Block Logging, the
#  Invoke-AtomicRedTeam module, and Valkyrie installed with its API answering.
#
#  Scoring is not massaged: for each atomic it snapshots Valkyrie's incident
#  list, runs the atomic, waits for the pipeline to settle, then checks whether
#  a NEW incident carries the expected ATT&CK technique. BLOCKED (action really
#  prevented) is counted separately from DETECTED (alerted only).
# ============================================================================
[CmdletBinding()]
param(
    [string]$ApiBase = "http://127.0.0.1:8090",
    [int]$SettleSeconds = 10,
    [switch]$SkipDestructive   # skip T1490 / T1562.001 / the ransomware sequence
)

$ErrorActionPreference = "Continue"
function Info($m) { Write-Host "[redteam] $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "[redteam] $m" -ForegroundColor Yellow }

# ---------------------------------------------------------------------------
# The plan. `Expect` is the ATT&CK id a matching Valkyrie detection must carry.
# `Custom` (a scriptblock) runs instead of Invoke-AtomicTest for non-ART actions.
# `Destructive` rows are skippable with -SkipDestructive.
# ---------------------------------------------------------------------------
$Plan = @(
  @{ Id="dns-c2";        Attack="T1071.004"; Expect="T1071"; Predict="DETECT (strong)";
     Custom={ Resolve-DnsName -Name "doubleclick.net" -Type A -ErrorAction SilentlyContinue | Out-Null };
     Note="Requires the VM's DNS to route through Valkyrie's sinkhole." }
  @{ Id="runkey";        Attack="T1547.001"; Tests="1";  Expect="T1547.001"; Predict="DETECT" }
  @{ Id="schtask";       Attack="T1053.005"; Tests="1";  Expect="T1053.005"; Predict="DETECT" }
  @{ Id="squiblydoo";    Attack="T1218.010"; Tests="1";  Expect="T1218.010"; Predict="CONDITIONAL" }
  @{ Id="lsass-comsvcs"; Attack="T1003.001"; Tests="3";  Expect="T1003.001"; Predict="CONDITIONAL" }
  @{ Id="defender-off";  Attack="T1562.001"; Tests="1";  Expect="T1562.001"; Predict="CONDITIONAL"; Destructive=$true }
  @{ Id="vss-delete";    Attack="T1490";     Tests="1";  Expect="T1490";     Predict="CONDITIONAL"; Destructive=$true }
  @{ Id="injection";     Attack="T1055";     Tests="1";  Expect="T1055";     Predict="CONDITIONAL/MISS" }
  @{ Id="whoami-disc";   Attack="T1033";     Tests="1";  Expect="T1033";     Predict="LIKELY MISS" }
  @{ Id="ransomware-seq";Attack="T1486";     Tests="1";  Expect="T1486";     Predict="CONDITIONAL"; Destructive=$true }
)

# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------
function Get-Incidents {
    try { return @(Invoke-RestMethod -Uri "$ApiBase/api/edr/incidents" -TimeoutSec 10) }
    catch { return @() }
}
function Get-IncidentTechniques([string]$id) {
    # Pull the detail (which includes detections) and collect their techniques.
    try {
        $inc = Invoke-RestMethod -Uri "$ApiBase/api/edr/incidents/$id" -TimeoutSec 10
    } catch { return @{ techniques=@(); blocked=$false } }
    $techs = @(); $blocked = $false
    foreach ($d in @($inc.detections)) {
        if ($d.technique) { $techs += [string]$d.technique }
        if ($d.action -eq "blocked") { $blocked = $true }
    }
    if ($inc.technique) { $techs += [string]$inc.technique }
    return @{ techniques = $techs; blocked = $blocked }
}

# ---------------------------------------------------------------------------
# Liveness
# ---------------------------------------------------------------------------
try { Invoke-RestMethod -Uri "$ApiBase/api/health" -TimeoutSec 8 | Out-Null }
catch { throw "Valkyrie API not reachable at $ApiBase - install/start Valkyrie in the VM first." }
if (-not (Get-Module -ListAvailable -Name Invoke-AtomicRedTeam)) {
    throw "Invoke-AtomicRedTeam not installed - run provision.ps1 first."
}
Import-Module Invoke-AtomicRedTeam -Force

$results = @()
foreach ($t in $Plan) {
    if ($t.Destructive -and $SkipDestructive) {
        Warn "SKIP (destructive): $($t.Id) [$($t.Attack)]"
        $results += [pscustomobject]@{ Id=$t.Id; Attack=$t.Attack; Predict=$t.Predict; Result="SKIPPED" }
        continue
    }

    Info "-- $($t.Id)  [$($t.Attack)]  predict=$($t.Predict)"
    $before = @(Get-Incidents | ForEach-Object { $_.id })

    try {
        if ($t.Custom) { & $t.Custom }
        else {
            Invoke-AtomicTest $t.Attack -TestNumbers $t.Tests -GetPrereqs -TimeoutSeconds 60 -ErrorAction SilentlyContinue | Out-Null
            Invoke-AtomicTest $t.Attack -TestNumbers $t.Tests -TimeoutSeconds 120 -ErrorAction SilentlyContinue
        }
    } catch { Warn "atomic raised: $($_.Exception.Message)" }

    Start-Sleep -Seconds $SettleSeconds

    $after = @(Get-Incidents | ForEach-Object { $_.id })
    $newIds = $after | Where-Object { $_ -notin $before }

    $detected = $false; $blocked = $false; $matchTech = ""
    foreach ($id in $newIds) {
        $info = Get-IncidentTechniques $id
        foreach ($tech in $info.techniques) {
            if ($tech -like "*$($t.Expect)*" -or $tech -like "*$($t.Attack)*") {
                $detected = $true; $matchTech = $tech
                if ($info.blocked) { $blocked = $true }
            }
        }
    }
    $result = if ($blocked) { "BLOCKED" } elseif ($detected) { "DETECTED" } else { "MISSED" }
    $glyph = switch ($result) { "BLOCKED" {"[BLOCK]"} "DETECTED" {"[DETECT]"} default {"[MISS]"} }
    Write-Host "   $glyph $result  ($matchTech)" -ForegroundColor ($(if ($result -eq "MISSED") {"Red"} else {"Green"}))

    # Clean up the atomic (ART leaves persistence/artifacts otherwise).
    if (-not $t.Custom) {
        try { Invoke-AtomicTest $t.Attack -TestNumbers $t.Tests -Cleanup -TimeoutSeconds 60 -ErrorAction SilentlyContinue | Out-Null } catch {}
    }
    $results += [pscustomobject]@{ Id=$t.Id; Attack=$t.Attack; Predict=$t.Predict; Result=$result; Tech=$matchTech }
}

# ---------------------------------------------------------------------------
# Scorecard (honest - whatever actually happened)
# ---------------------------------------------------------------------------
Write-Host "`n======================================================================"
Write-Host "  VALKYRIE vs ATOMIC RED TEAM - REAL SCORECARD"
Write-Host "======================================================================"
$results | Format-Table Id, Attack, Predict, Result, Tech -AutoSize | Out-String | Write-Host

$scored    = @($results | Where-Object { $_.Result -ne "SKIPPED" })
$detOrBlk  = @($scored  | Where-Object { $_.Result -in @("DETECTED","BLOCKED") }).Count
$blocked   = @($scored  | Where-Object { $_.Result -eq "BLOCKED" }).Count
$total     = $scored.Count
Write-Host ("  Detected/blocked: {0}/{1}   Prevented(blocked): {2}   Missed: {3}" -f `
    $detOrBlk, $total, $blocked, ($total - $detOrBlk))
Write-Host "  NOTE: 'detected' = alerted. 'blocked' = actually prevented (rare without the"
Write-Host "        kernel driver). This is measurement, not a target - read it honestly."
Write-Host "======================================================================`n"
