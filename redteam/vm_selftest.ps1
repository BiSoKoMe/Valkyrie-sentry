<#
  vm_selftest.ps1 -- one-shot honest EDR check, built for a locked-down VM.

  You run this ONCE inside the throwaway VM and paste the output back. It:
    * confirms Valkyrie's API is up and reports its own health honestly,
    * checks Sysmon (the linchpin -- without it, command-line detection is dead),
    * runs a curated set of atomics that ACTUALLY execute in a locked-down
      Win11 Home VM (no Smart-App-Control-blocked binaries, no registry-editing
      tests that a policy refuses),
    * for each one, distinguishes three outcomes that a raw run conflates:
        RAN + DETECTED    the attack executed AND Valkyrie raised an incident
        RAN + MISSED      the attack executed and Valkyrie did NOT -- a real miss
        DID-NOT-RUN       Windows itself blocked it / no Windows test exists,
                          which tells us nothing about Valkyrie either way
    * writes a JSON report to your Desktop and prints a table.

  It is deliberately NON-destructive: every technique here runs without
  disabling Defender, dumping LSASS, deleting shadow copies or clearing logs.
  You already snapshotted, so the destructive set can come later if you want it.

  Requires: Valkyrie installed and its API answering on 127.0.0.1:8090, and the
  Invoke-AtomicRedTeam module imported (the same one you already installed).
#>

[CmdletBinding()]
param(
    [string]$Api = "http://127.0.0.1:8090",
    [int]$SettleSeconds = 8
)

$ErrorActionPreference = "Continue"
function Line($m, $c = "Gray") { Write-Host $m -ForegroundColor $c }

# --- API helpers -----------------------------------------------------------
function Api-Json($path) {
    try { return (Invoke-WebRequest "$Api$path" -UseBasicParsing -TimeoutSec 6).Content | ConvertFrom-Json }
    catch { return $null }
}
function Incident-Ids {
    $inc = Api-Json "/api/edr/incidents"
    if ($null -eq $inc) { return @() }
    return @($inc | ForEach-Object { $_.id })
}
function Incidents-After($knownIds) {
    $inc = Api-Json "/api/edr/incidents"
    if ($null -eq $inc) { return @() }
    return @($inc | Where-Object { $knownIds -notcontains $_.id })
}

# --- Preflight -------------------------------------------------------------
Line "`n===================  Valkyrie VM self-test  ===================" "Cyan"

$health = Api-Json "/api/health"
if ($null -eq $health) {
    Line "STOP: Valkyrie API is not answering on $Api" "Red"
    Line "      Is the Valkyrie app installed and running? Try opening it first." "Yellow"
    exit 1
}
Line "Valkyrie API: UP" "Green"

$stats = Api-Json "/api/stats"
if ($stats) {
    $healthy = $stats.protection_healthy
    Line ("Engine self-reported health: " + ($(if ($healthy) {"healthy"} else {"DEGRADED -- see the app's event feed"}))) `
         $(if ($healthy) {"Green"} else {"Yellow"})
}

$sysmon = Get-Service Sysmon64 -ErrorAction SilentlyContinue
if (-not $sysmon) { $sysmon = Get-Service Sysmon -ErrorAction SilentlyContinue }
if ($sysmon -and $sysmon.Status -eq "Running") {
    Line "Sysmon: RUNNING (command-line detection is live)" "Green"
    $sysmonOk = $true
} else {
    Line "Sysmon: NOT RUNNING -- Execution/Discovery detections will mostly MISS." "Yellow"
    Line "        That is a setup gap, not a Valkyrie result. Install Sysmon first" "Yellow"
    Line "        for a fair number." "Yellow"
    $sysmonOk = $false
}

if (-not (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue)) {
    Line "`nSTOP: Invoke-AtomicTest not found. Import the module first:" "Red"
    Line '  Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force' "Yellow"
    exit 1
}

# --- The curated, VM-safe technique set ------------------------------------
# Chosen because they EXECUTE in a locked-down Win11 Home VM. If a test number
# is wrong for your ART version the run reports "no windows test" rather than
# failing -- so a bad number never poisons the result.
$Tests = @(
    @{ id="T1053.005"; n=1; tactic="Persistence";     what="Scheduled task"           },
    @{ id="T1059.003"; n=1; tactic="Execution";       what="cmd batch script"         },
    @{ id="T1547.001"; n=8; tactic="Persistence";     what="Startup-folder shortcut"  },
    @{ id="T1082";     n=1; tactic="Discovery";       what="systeminfo"               },
    @{ id="T1033";     n=1; tactic="Discovery";       what="whoami"                   },
    @{ id="T1016";     n=1; tactic="Discovery";       what="ipconfig / net config"    },
    @{ id="T1049";     n=1; tactic="Discovery";       what="netstat connections"      },
    @{ id="T1087.001"; n=1; tactic="Discovery";       what="net user (local accounts)"},
    @{ id="T1518.001"; n=1; tactic="Discovery";       what="security software recon"  },
    @{ id="T1105";     n=2; tactic="C2";              what="ingress tool transfer"    }
)

$results = @()
foreach ($t in $Tests) {
    Line ("`n--- {0}  {1}  ({2})" -f $t.id, $t.what, $t.tactic) "White"
    $before = Incident-Ids

    $raw = (Invoke-AtomicTest $t.id -TestNumbers $t.n -GetPrereqs 2>&1 | Out-String)
    $raw += (Invoke-AtomicTest $t.id -TestNumbers $t.n 2>&1 | Out-String)

    # Did the attack actually execute? Detect the three ways it can NOT.
    $didNotRun = $false; $why = ""
    if ($raw -match "Found 0 atomic tests applicable") { $didNotRun=$true; $why="no Windows test #$($t.n)" }
    elseif ($raw -match "Access is denied")            { $didNotRun=$true; $why="blocked by Windows (Smart App Control)" }
    elseif ($raw -match "disabled by your administrator"){ $didNotRun=$true; $why="blocked by Windows policy" }

    Start-Sleep -Seconds $SettleSeconds
    $new = Incidents-After $before
    $detected = @($new).Count -gt 0

    if ($didNotRun) {
        Line ("   DID NOT RUN -- {0}. Tells us nothing about Valkyrie." -f $why) "DarkGray"
        $verdict = "did-not-run"
    } elseif ($detected) {
        Line ("   RAN + DETECTED  ->  " + (($new | ForEach-Object { $_.title }) -join " | ")) "Green"
        $verdict = "detected"
    } else {
        Line "   RAN + MISSED -- executed, no Valkyrie incident." "Red"
        $verdict = "missed"
    }

    $results += [pscustomobject]@{
        technique = $t.id; test = $t.n; tactic = $t.tactic; what = $t.what
        verdict = $verdict; note = $why
        incidents = @($new | ForEach-Object { $_.title })
    }
    # Best-effort cleanup so back-to-back tests don't cross-contaminate.
    Invoke-AtomicTest $t.id -TestNumbers $t.n -Cleanup 2>&1 | Out-Null
}

# --- Report ----------------------------------------------------------------
$ran      = @($results | Where-Object { $_.verdict -ne "did-not-run" })
$detected = @($results | Where-Object { $_.verdict -eq "detected" })
$missed   = @($results | Where-Object { $_.verdict -eq "missed" })
$noRun    = @($results | Where-Object { $_.verdict -eq "did-not-run" })

Line "`n==============================  RESULT  ==============================" "Cyan"
Line ("Techniques that actually executed : {0} of {1}" -f $ran.Count, $results.Count)
if ($ran.Count -gt 0) {
    Line ("Detected by Valkyrie              : {0} / {1}  ({2}%)" -f `
        $detected.Count, $ran.Count, [math]::Round(100*$detected.Count/$ran.Count)) `
        $(if ($detected.Count -eq $ran.Count) {"Green"} else {"Yellow"})
}
Line ("Blocked by the VM (not a result)  : {0}" -f $noRun.Count) "DarkGray"
if (-not $sysmonOk) { Line "NOTE: Sysmon was not running -- treat any Execution/Discovery miss as a setup gap." "Yellow" }

Line "`nPer technique:"
$results | ForEach-Object {
    $c = switch ($_.verdict) { "detected" {"Green"} "missed" {"Red"} default {"DarkGray"} }
    Line ("  {0,-11} {1,-12} {2,-26} {3}" -f $_.technique, $_.tactic, $_.what, $_.verdict.ToUpper()) $c
}

$out = "$env:USERPROFILE\Desktop\valkyrie_vm_result.json"
$results | ConvertTo-Json -Depth 5 | Out-File $out -Encoding utf8
Line "`nFull JSON written to: $out" "Cyan"
Line "Paste the RESULT block (or the JSON) back to continue.`n" "Cyan"
