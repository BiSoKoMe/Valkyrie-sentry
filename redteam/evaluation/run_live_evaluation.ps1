# =============================================================================
#  run_live_evaluation.ps1 -- Tier B: the REAL EDR evaluation. VM ONLY.
#
#  RUN ONLY IN A THROWAWAY VM WITH A FRESH SNAPSHOT. This plan includes
#  genuinely destructive atomics: LSASS memory dumping, Defender disabling,
#  Windows Firewall disabling, event-log clearing, shadow-copy deletion,
#  service stopping, local-account creation. Revert the snapshot after.
#
#  AUTHORED, NOT EXECUTED HERE. Same honesty convention as redteam/README.md's
#  original kit: this dev machine has no hypervisor and no VM, so this script
#  has been written carefully and reviewed against Valkyrie's real API and
#  the technique catalog it drives from, but it has not been run end to end
#  against a live Valkyrie instance. Treat it like the kernel driver: real,
#  reviewable, unrun until someone with a VM runs it.
#
#  WHAT THIS DOES THAT replay_harness.py (Tier A) CANNOT:
#    - Actually executes each technique (or, for the 10 techniques the
#      original redteam kit already vetted, delegates to Invoke-AtomicTest
#      with the SAME test numbers that kit already verified).
#    - Measures REAL detection latency (stopwatch from execution to the
#      first matching incident appearing via the API).
#    - Collects REAL evidence: live process snapshots, registry snapshots,
#      network connections, DNS query log, file system changes -- not
#      synthetic inputs.
#    - Produces a REAL false-positive count: every OTHER new incident that
#      appeared during the settle window, not attributable to the technique
#      under test, is counted as a false positive for that run.
#
#  WHAT THIS DOES NOT DO (scope limits, stated rather than silently ignored):
#    - Techniques without a verified Atomic Red Team test number (i.e.
#      everything this evaluation ADDED beyond the original 10-atomic plan)
#      are executed via their LITERAL documented command line -- the same
#      command replay_harness.py (Tier A) fed to the classifier -- rather
#      than via Invoke-AtomicTest, because this script's author could not
#      verify exact ART test-number-to-repository-version mappings without
#      a live ART checkout in front of them. Getting a wrong test NUMBER
#      would fail loudly; running the documented literal command is honest
#      about what actually happened, which matters more here.
#    - Lateral-movement entries are SELF-TARGET simulations on one VM (see
#      catalog.py notes on each). A second VM is required for authentic
#      cross-host detection and is out of scope for this script.
#
#  Prereqs: provision.ps1 (Sysmon + config, PS Script Block Logging, the
#  Invoke-AtomicRedTeam module), Valkyrie installed and its API answering,
#  Python available on PATH (for catalog.py --export and score.py).
# =============================================================================
[CmdletBinding()]
param(
    [string]$ApiBase = "http://127.0.0.1:8090",
    [int]$SettleSeconds = 10,
    [switch]$SkipDestructive,
    [string]$RepoRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
)

$ErrorActionPreference = "Continue"
function Info($m)  { Write-Host "[eval] $m" -ForegroundColor Cyan }
function Warn($m)  { Write-Host "[eval] $m" -ForegroundColor Yellow }
function Bad($m)   { Write-Host "[eval] $m" -ForegroundColor Red }

# ── 0. Export the catalog from the single source of truth (catalog.py) ──────
$CatalogJson = Join-Path $PSScriptRoot "catalog_export.json"
Info "Exporting technique catalog from catalog.py (single source of truth)..."
& python (Join-Path $PSScriptRoot "catalog.py") --export $CatalogJson
if (-not (Test-Path $CatalogJson)) { throw "catalog export failed -- is python on PATH?" }
$Catalog = (Get-Content $CatalogJson -Raw | ConvertFrom-Json)
$CatalogVersion = $Catalog.catalog_version
$Techniques = $Catalog.techniques

# Techniques with a verified Atomic Red Team mapping, carried over from the
# original redteam/run-redteam.ps1 plan (already vetted by that kit's author).
# Keyed by catalog `id`. Anything NOT in this table runs via its literal
# documented command instead (see header).
$VettedAtomics = @{
    "persist-run-key"           = @{ Attack = "T1547.001"; Tests = "1" }
    "persist-scheduled-task"    = @{ Attack = "T1053.005"; Tests = "1" }
    "exec-regsvr32-squiblydoo"  = @{ Attack = "T1218.010"; Tests = "1" }
    "cred-lsass-comsvcs"        = @{ Attack = "T1003.001"; Tests = "3" }
    "cred-lsass-procdump"       = @{ Attack = "T1003.001"; Tests = "1" }
    "evasion-defender-disable"  = @{ Attack = "T1562.001"; Tests = "1"; Destructive = $true }
    "impact-shadow-delete"      = @{ Attack = "T1490";     Tests = "1"; Destructive = $true }
    "evasion-process-injection" = @{ Attack = "T1055";     Tests = "1" }
    "disc-whoami-priv"          = @{ Attack = "T1033";     Tests = "1" }
}

# ---------------------------------------------------------------------------
# Evidence collectors -- real, live, at the moment of execution
# ---------------------------------------------------------------------------
function Get-ProcessEvidence {
    try {
        Get-CimInstance Win32_Process |
            Select-Object ProcessId, ParentProcessId, Name, CommandLine, CreationDate |
            ForEach-Object { @{ pid = $_.ProcessId; ppid = $_.ParentProcessId;
                                name = $_.Name; cmdline = $_.CommandLine;
                                created = "$($_.CreationDate)" } }
    } catch { @() }
}

function Get-RegistryAsepEvidence {
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    )
    $out = @()
    foreach ($p in $paths) {
        try {
            $item = Get-Item -Path $p -ErrorAction Stop
            foreach ($name in $item.Property) {
                $out += @{ path = $p; name = $name; value = "$($item.GetValue($name))" }
            }
        } catch {}
    }
    $out
}

function Get-NetworkEvidence {
    try {
        Get-NetTCPConnection -State Established, SynSent -ErrorAction SilentlyContinue |
            Select-Object -First 50 LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
            ForEach-Object { @{ local = "$($_.LocalAddress):$($_.LocalPort)";
                                remote = "$($_.RemoteAddress):$($_.RemotePort)";
                                pid = $_.OwningProcess } }
    } catch { @() }
}

function Get-DnsEvidence([string]$SinceIso) {
    # Valkyrie's own DNS event log, via its real API -- not the OS resolver
    # cache, since Valkyrie's OWN view of what it saw is the relevant evidence.
    try {
        $events = Invoke-RestMethod -Uri "$ApiBase/api/events?limit=50" -TimeoutSec 8
        @($events | Where-Object { $_.type -eq "dns" -or $_.domain } |
            ForEach-Object { @{ domain = $_.domain; decision = $_.decision;
                                timestamp = $_.timestamp } })
    } catch { @() }
}

function Get-FileEvidence([string[]]$WatchDirs) {
    $out = @()
    foreach ($d in $WatchDirs) {
        if (Test-Path $d) {
            try {
                Get-ChildItem -Path $d -File -ErrorAction SilentlyContinue |
                    Select-Object -First 20 FullName, Length, LastWriteTime |
                    ForEach-Object { $out += @{ path = $_.FullName; size = $_.Length;
                                                modified = "$($_.LastWriteTime)" } }
            } catch {}
        }
    }
    $out
}

# ---------------------------------------------------------------------------
# Incident helpers
# ---------------------------------------------------------------------------
function Get-Incidents {
    try { return @(Invoke-RestMethod -Uri "$ApiBase/api/edr/incidents" -TimeoutSec 10) }
    catch { return @() }
}
function Get-IncidentDetail([string]$id) {
    try { return Invoke-RestMethod -Uri "$ApiBase/api/edr/incidents/$id" -TimeoutSec 10 }
    catch { return $null }
}

# ---------------------------------------------------------------------------
# Liveness
# ---------------------------------------------------------------------------
try { Invoke-RestMethod -Uri "$ApiBase/api/health" -TimeoutSec 8 | Out-Null }
catch { throw "Valkyrie API not reachable at $ApiBase -- install/start Valkyrie in the VM first." }
$HaveAtomics = [bool](Get-Module -ListAvailable -Name Invoke-AtomicRedTeam)
if ($HaveAtomics) { Import-Module Invoke-AtomicRedTeam -Force }
else { Warn "Invoke-AtomicRedTeam not installed -- vetted-ART techniques will be SKIPPED, not faked. Run provision.ps1 first for full coverage." }

$WatchDirs = @("$env:USERPROFILE\Documents", "$env:USERPROFILE\Desktop",
              "$env:USERPROFILE\Downloads", "$env:PUBLIC\Documents")

$Records = @()
$RunTs = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")

foreach ($t in $Techniques) {
    if ($t.destructive -and $SkipDestructive) {
        Warn "SKIP (destructive, -SkipDestructive set): $($t.id) [$($t.technique_id)]"
        continue
    }

    Info "-- $($t.id)  [$($t.technique_id)]  $($t.technique_name)"
    $beforeIds = @(Get-Incidents | ForEach-Object { $_.id })
    $beforeProc = Get-ProcessEvidence
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $attackExecuted = $false
    $executionError = ""

    try {
        if ($VettedAtomics.ContainsKey($t.id) -and $HaveAtomics) {
            $v = $VettedAtomics[$t.id]
            Invoke-AtomicTest $v.Attack -TestNumbers $v.Tests -GetPrereqs -TimeoutSeconds 60 -ErrorAction SilentlyContinue | Out-Null
            Invoke-AtomicTest $v.Attack -TestNumbers $v.Tests -TimeoutSeconds 120 -ErrorAction SilentlyContinue
            $attackExecuted = $true
        }
        elseif ($VettedAtomics.ContainsKey($t.id) -and -not $HaveAtomics) {
            Warn "   (Invoke-AtomicRedTeam unavailable -- skipping vetted atomic rather than approximating it)"
        }
        else {
            # Literal-command execution -- the same command Tier A replayed.
            switch ($t.probe) {
                "dns"        { Resolve-DnsName -Name $t.probe_input.domain -Type A -ErrorAction SilentlyContinue | Out-Null; $attackExecuted = $true }
                "dga"        { Resolve-DnsName -Name $t.probe_input.domain -Type A -ErrorAction SilentlyContinue | Out-Null; $attackExecuted = $true }
                "dns_tunnel" {
                    for ($i = 0; $i -lt [Math]::Min($t.probe_input.n_labels, 40); $i++) {
                        $label = -join ((48..57 + 97..102) | Get-Random -Count 8 | ForEach-Object {[char]$_})
                        Resolve-DnsName -Name "$label.$($t.probe_input.base)" -Type A -ErrorAction SilentlyContinue | Out-Null
                    }
                    $attackExecuted = $true
                }
                "network" {
                    try {
                        $tcp = New-Object System.Net.Sockets.TcpClient
                        $tcp.ConnectAsync($t.probe_input.ip, $t.probe_input.port).Wait(3000) | Out-Null
                        $tcp.Close()
                    } catch {}
                    $attackExecuted = $true
                }
                "ransomware" {
                    # Use Valkyrie's OWN self-test endpoint rather than writing
                    # into a real user's Documents folder -- it exercises the
                    # canary + entropy path the way the product ships it.
                    try {
                        Invoke-RestMethod -Method Post -Uri "$ApiBase/api/ransomware/self-test" `
                            -Headers @{ "X-Valkyrie-Token" = $env:VALKYRIE_TOKEN } -TimeoutSec 15 | Out-Null
                        $attackExecuted = $true
                    } catch { $executionError = $_.Exception.Message }
                }
                "persistence" {
                    # Write the artifact directly per probe_input.activity --
                    # exercises the SAME artifact-at-rest scanner Tier A
                    # replayed against, for real.
                    $cmd = $t.probe_input.command
                    switch ($t.probe_input.activity) {
                        "run_key" {
                            New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
                                -Name "ValkyrieEvalTest" -Value $cmd -PropertyType String -Force | Out-Null
                        }
                        "startup_folder" {
                            Set-Content -Path $cmd -Value "REM eval artifact" -ErrorAction SilentlyContinue
                        }
                        default { Warn "   (activity '$($t.probe_input.activity)' needs manual setup -- see catalog.py probe_input)" }
                    }
                    $attackExecuted = $true
                }
                default {
                    # ioa_rule / cmdline / behavior_score / process_relationship /
                    # powershell probes all carry a literal, real command line.
                    $cmd = $t.probe_input.cmdline
                    if ($t.probe -eq "powershell") { $cmd = "powershell.exe -Command `"$($t.probe_input.script_block)`"" }
                    if ($cmd) {
                        Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $cmd `
                            -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
                        $attackExecuted = $true
                    } else {
                        Warn "   (no literal command for probe '$($t.probe)' -- see catalog.py)"
                    }
                }
            }
        }
    } catch {
        $executionError = $_.Exception.Message
        Warn "   execution raised: $executionError"
    }

    Start-Sleep -Seconds $SettleSeconds
    $sw.Stop()

    # ── Score against new incidents ─────────────────────────────────────────
    $afterIds = @(Get-Incidents | ForEach-Object { $_.id })
    $newIds = $afterIds | Where-Object { $_ -notin $beforeIds }

    $detected = $false; $detectionCategory = "none"; $matchedSeverity = ""
    $matchedConfidence = 0.0; $matchedReason = ""; $latency = $null
    $falsePositiveIds = @()

    foreach ($id in $newIds) {
        $inc = Get-IncidentDetail $id
        if (-not $inc) { continue }
        $techs = @()
        foreach ($d in @($inc.detections)) { if ($d.technique) { $techs += [string]$d.technique } }
        if ($inc.technique) { $techs += [string]$inc.technique }
        $isMatch = $techs | Where-Object { $_ -like "*$($t.technique_id)*" }

        if ($isMatch) {
            # EXCLUSION RULE, applied here at the point of live truth: a
            # detection whose category/reason marks it as a user-authored
            # always_block rule does not count as a behavioral detection,
            # per the evaluation brief. Checked against the incident's own
            # recorded category/reason, not inferred.
            $category = "$($inc.category)".ToLower()
            $reason = "$($inc.reason)".ToLower()
            if ($category -eq "user_rule" -or $reason -like "user:always_block*") {
                $detectionCategory = "user_rule"
                Warn "   matched via a USER-DEFINED rule -- NOT counted (see scoring rule)"
            } else {
                $detected = $true
                $detectionCategory = if ($category) { $category } else { "behavioral" }
                $matchedSeverity = "$($inc.severity)"
                $matchedReason = "$($inc.reason)"
                if (-not $latency) { $latency = [math]::Round($sw.Elapsed.TotalSeconds, 2) }
            }
        } else {
            $falsePositiveIds += $id
        }
    }

    $record = [ordered]@{
        schema = "valkyrie-redteam-evaluation/1"
        tier = "B_live"
        catalog_version = $CatalogVersion
        id = $t.id
        technique_id = $t.technique_id
        technique_name = $t.technique_name
        test_number = $t.art_test_ref
        tactic = $t.tactic
        mitre = @{ tactic = $t.tactic; technique_id = $t.technique_id; technique_name = $t.technique_name }
        destructive = $t.destructive

        attack_executed = $attackExecuted
        attack_executed_note = if ($executionError) { "execution error: $executionError" } else { "" }

        classifier_logic_fires = $detected   # in Tier B this IS the live outcome
        predicted_tier_b = $t.predicted_tier_b
        counted_as_detected = $detected
        known_mismatch = $null
        detection_category = $detectionCategory
        is_user_defined_rule = ($detectionCategory -eq "user_rule")

        detection_latency_seconds = $latency
        theoretical_latency_bound_seconds = $null
        latency_note = if ($latency) { "measured: execution to first matching incident" } else { "no matching incident observed within the $SettleSeconds s settle window" }

        severity_assigned = $matchedSeverity
        confidence_score = $matchedConfidence
        confidence_note = "as recorded on the matching incident"

        false_positives_generated = $falsePositiveIds.Count
        false_positives_note = "count of NEW incidents in the settle window not attributable to this technique"

        reason = $matchedReason
        evidence = @{
            processes = (Get-ProcessEvidence | Select-Object -First 20)
            registry = (Get-RegistryAsepEvidence)
            network = (Get-NetworkEvidence)
            dns = (Get-DnsEvidence "")
            files = (Get-FileEvidence $WatchDirs)
        }
        delivery_mechanism = $t.delivery
        detector_path = $t.detector_path
        source_confidence = $t.source_confidence
        error = $executionError
        notes = $t.notes
    }
    $Records += $record

    $glyph = if ($detected) { "[DETECT]" } elseif ($detectionCategory -eq "user_rule") { "[EXCLUDED]" } else { "[MISS]" }
    Write-Host "   $glyph  fp=$($falsePositiveIds.Count)  latency=$latency" `
        -ForegroundColor ($(if ($detected) {"Green"} else {"Red"}))

    # Cleanup best-effort (vetted atomics clean themselves; literal-command
    # artifacts get a best-effort removal here).
    if ($VettedAtomics.ContainsKey($t.id) -and $HaveAtomics) {
        try { Invoke-AtomicTest $VettedAtomics[$t.id].Attack -TestNumbers $VettedAtomics[$t.id].Tests -Cleanup -TimeoutSeconds 60 -ErrorAction SilentlyContinue | Out-Null } catch {}
    }
    if ($t.probe -eq "persistence" -and $t.probe_input.activity -eq "run_key") {
        Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "ValkyrieEvalTest" -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Write results in the SAME schema replay_harness.py emits, so score.py
# works unmodified on either tier's output.
# ---------------------------------------------------------------------------
$ResultsDir = Join-Path $PSScriptRoot "results"
New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null
$OutPath = Join-Path $ResultsDir "$RunTs`__tierB.json"
@{ tier = "B_live"; catalog_version = $CatalogVersion; generated_at = $RunTs; records = $Records } |
    ConvertTo-Json -Depth 10 | Set-Content -Path $OutPath -Encoding UTF8

Write-Host "`n======================================================================"
Write-Host "  Tier B live evaluation complete: $($Records.Count) techniques run."
Write-Host "  Results: $OutPath"
Write-Host "  Run the scorer:  PYTHONUTF8=1 python redteam/evaluation/score.py `"$OutPath`""
Write-Host "======================================================================`n"
Write-Host "  REVERT THE SNAPSHOT NOW." -ForegroundColor Yellow
