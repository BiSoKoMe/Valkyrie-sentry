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
    # Maximum time to wait for a matching incident before scoring a MISS. The
    # detection is polled, not slept-on: a fast real-time detection breaks out in
    # under a second (and records true latency), while this ceiling must clear
    # the SLOWEST sensor's period plus ingest. The persistence collector polls
    # every 15s (valkyrie/persistence_telemetry.py PersistenceCollector.interval)
    # and the process poller every ~2s, so a 10s fixed sleep -- the previous
    # behaviour -- structurally could NOT observe an artifact-at-rest detection.
    # 30s clears 15s + poll jitter + ingest with margin.
    [int]$DetectWindowSeconds = 30,
    [int]$PollIntervalSeconds = 2,
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
    # evasion-defender-disable: intentionally NOT mapped to an ART atomic. The
    # T1562.001 atomic yaml is missing on the GitHub runner image (errored every
    # run), so fall through to the literal Set-MpPreference command line from the
    # catalog probe instead — which fires the defender_tamper rule (verified via
    # match_process). Real detection, no dependency on a missing atomic file.
    "impact-shadow-delete"      = @{ Attack = "T1490";     Tests = "1"; Destructive = $true }
    "disc-whoami-priv"          = @{ Attack = "T1033";     Tests = "1" }
    # evasion-process-injection intentionally NOT delegated to ART -- Test #1
    # drifted onto an Office-dependent variant (see the "sysmon_eid8" probe
    # case below). catalog.py's own probe="sysmon_eid8" now drives it.
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

# Invoke-RestMethod (WinINet/HttpWebRequest) hangs to its own timeout against
# this API in some guest environments even though the server answers instantly
# -- reproduced directly, isolated from proxy/Expect100Continue settings, cause
# not fully root-caused. curl.exe (a completely separate HTTP stack) is 100%
# reliable against the same endpoint, so these thin wrappers replace every
# Invoke-RestMethod call site rather than leave a flaky harness.
function Invoke-CurlGet([string]$Uri, [int]$TimeoutSec = 10) {
    $raw = & cmd.exe /c "curl.exe -s -m $TimeoutSec `"$Uri`"" 2>$null
    $raw = ($raw -join "`n")
    if ([string]::IsNullOrWhiteSpace($raw)) { throw "curl-via-cmd (exit $LASTEXITCODE) returned nothing from $Uri" }
    if ($raw -notmatch '^\s*[\{\[]') { throw "curl-via-cmd (exit $LASTEXITCODE) non-JSON output from ${Uri}: $raw" }
    return $raw | ConvertFrom-Json
}
function Invoke-CurlPost([string]$Uri, [hashtable]$Headers = @{}, [int]$TimeoutSec = 10) {
    $headerArgs = @()
    foreach ($k in $Headers.Keys) { $headerArgs += @("-H", "${k}: $($Headers[$k])") }
    $raw = & curl.exe -s -m $TimeoutSec -X POST @headerArgs $Uri 2>$null
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    try { return $raw | ConvertFrom-Json } catch { return $raw }
}

function Get-DnsEvidence([string]$SinceIso) {
    # Valkyrie's own DNS event log, via its real API -- not the OS resolver
    # cache, since Valkyrie's OWN view of what it saw is the relevant evidence.
    try {
        $events = Invoke-CurlGet -Uri "$ApiBase/api/events?limit=50" -TimeoutSec 8
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
    # brief=true -> the FAST incident list (raw rows, no per-incident impact
    # assessment / explanation). The full view is O(incidents) and times out
    # under polling — that is what scored every real detection as MISS. The
    # brief view returns in well under the detect window.
    try { return @(Invoke-CurlGet -Uri "$ApiBase/api/edr/incidents?brief=true" -TimeoutSec 30) }
    catch { return @() }
}
function Get-IncidentDetail([string]$id) {
    try { return Invoke-CurlGet -Uri "$ApiBase/api/edr/incidents/$id" -TimeoutSec 20 }
    catch { return $null }
}

# ---------------------------------------------------------------------------
# Liveness
# ---------------------------------------------------------------------------
$HealthOk = $false
$LastErr = $null
for ($i = 1; $i -le 5; $i++) {
    try { Invoke-CurlGet -Uri "$ApiBase/api/health" -TimeoutSec 8 | Out-Null; $HealthOk = $true; break }
    catch { $LastErr = $_; Start-Sleep -Seconds 3 }
}
if (-not $HealthOk) { throw "Valkyrie API not reachable at $ApiBase after 5 attempts -- $($LastErr.Exception.Message)" }
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
    # Time-anchor the scoring. Valkyrie CORRELATES related detections into one
    # incident per actor-lineage, so a detection for this technique may fold
    # into a PRE-EXISTING incident instead of creating a new id -- diffing
    # incident ids alone then scores a real detection as a miss. Match instead
    # on any detection whose technique fits AND whose own timestamp is at/after
    # this moment, which is robust to correlation and to a dirty incident store.
    # 5s of skew tolerance for collector event.ts vs this process's clock.
    $execStartUtc = (Get-Date).ToUniversalTime().AddSeconds(-5)
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
                        Invoke-CurlPost -Uri "$ApiBase/api/ransomware/self-test" `
                            -Headers @{ "X-Valkyrie-Token" = $env:VALKYRIE_TOKEN } -TimeoutSec 15 | Out-Null
                        $attackExecuted = $true
                    } catch { $executionError = $_.Exception.Message }
                }
                "sysmon_eid8" {
                    # Real CreateRemoteThread injection -- deliberately NOT
                    # delegated to Atomic Red Team's numbered content. T1055
                    # Test #1 drifted onto a VBA/Office-automation variant
                    # (Red Canary content changes over time; ART content isn't
                    # pinned) and failed outright on a runner with no Office
                    # installed. This is self-contained and dependency-free:
                    # spawn a target, inject a remote thread that calls
                    # LoadLibraryA("kernel32.dll") -- kernel32 is already
                    # loaded in every process, so this is inert (no payload,
                    # no real DLL load) while still performing the genuine
                    # OpenProcess -> VirtualAllocEx -> WriteProcessMemory ->
                    # CreateRemoteThread sequence Sysmon EID8 watches for.
                    $target = $null
                    try {
                        $target = Start-Process notepad.exe -PassThru
                        Start-Sleep -Milliseconds 800
                        if (-not ("ValkyrieEval.Inject" -as [type])) {
                            Add-Type -Namespace ValkyrieEval -Name Inject -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
[DllImport("kernel32.dll")] public static extern IntPtr VirtualAllocEx(IntPtr hProc, IntPtr addr, uint size, uint allocType, uint protect);
[DllImport("kernel32.dll")] public static extern bool WriteProcessMemory(IntPtr hProc, IntPtr addr, byte[] buf, uint size, out int written);
[DllImport("kernel32.dll", CharSet = CharSet.Ansi)] public static extern IntPtr GetProcAddress(IntPtr hModule, string name);
[DllImport("kernel32.dll", CharSet = CharSet.Ansi)] public static extern IntPtr GetModuleHandle(string name);
[DllImport("kernel32.dll")] public static extern IntPtr CreateRemoteThread(IntPtr hProc, IntPtr sa, uint stackSize, IntPtr startAddr, IntPtr param, uint flags, out IntPtr threadId);
'@
                        }
                        $hProc = [ValkyrieEval.Inject]::OpenProcess(0x1FFFFF, $false, $target.Id)
                        if ($hProc -ne [IntPtr]::Zero) {
                            $dllBytes = [System.Text.Encoding]::ASCII.GetBytes("kernel32.dll`0")
                            $addr = [ValkyrieEval.Inject]::VirtualAllocEx($hProc, [IntPtr]::Zero, [uint32]$dllBytes.Length, 0x3000, 0x40)
                            $written = 0
                            [ValkyrieEval.Inject]::WriteProcessMemory($hProc, $addr, $dllBytes, [uint32]$dllBytes.Length, [ref]$written) | Out-Null
                            $loadLibAddr = [ValkyrieEval.Inject]::GetProcAddress([ValkyrieEval.Inject]::GetModuleHandle("kernel32.dll"), "LoadLibraryA")
                            $threadId = [IntPtr]::Zero
                            [ValkyrieEval.Inject]::CreateRemoteThread($hProc, [IntPtr]::Zero, 0, $loadLibAddr, $addr, 0, [ref]$threadId) | Out-Null
                        }
                        Start-Sleep -Milliseconds 500
                        $attackExecuted = $true
                    } catch {
                        $executionError = $_.Exception.Message
                    } finally {
                        if ($target) { Stop-Process -Id $target.Id -Force -ErrorAction SilentlyContinue }
                    }
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
                "recon_burst" {
                    # The reconnaissance-burst sequence IOA fires on >=3 DISTINCT
                    # discovery commands from ONE process lineage within 120s.
                    # Running only this technique's single command (which the old
                    # STALE export mislabelled ioa_rule, and the per-technique loop
                    # spaces ~70s apart) can NEVER complete the burst -- so every
                    # burst-covered Discovery technique scored MISS for a harness
                    # reason, not a detection reason. Run the command AND its
                    # catalogued co-occurring discovery commands back-to-back from
                    # ONE cmd.exe, exactly how a real recon script behaves and what
                    # the detector is built to catch.
                    $cmds = @([string]$t.probe_input.cmdline)
                    foreach ($co in @($t.probe_input.co_occurring)) { $cmds += [string]$co[1] }
                    $joined = ($cmds -join " & ")
                    Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $joined `
                        -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
                    $attackExecuted = $true
                }
                "cred_store_watch" {
                    # browser_cred_watch.py raises HIGH when a NON-browser process
                    # holds a known browser credential-store file open. It watches
                    # the CURRENT USER's real Chrome path (credential_store_paths()),
                    # snapshotted at start() -- NOT the catalog's fictional 'alice'
                    # path, which is why this used to miss. provision.ps1 seeds the
                    # real file before Valkyrie starts; here we just open that exact
                    # path from this (non-browser) process and hold past the 5s poll.
                    $p = Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data\Default\Login Data"
                    try {
                        $dir = Split-Path $p -Parent
                        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
                        if (-not (Test-Path $p)) { Set-Content -Path $p -Value "eval-credstore" -ErrorAction SilentlyContinue }
                        $fs = [System.IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
                        Start-Sleep -Seconds 8
                        $fs.Close()
                    } catch { $executionError = $_.Exception.Message }
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

    # ── Condition-based, correlation-robust detection wait ───────────────────
    # Poll until a matching DETECTION (not just a new incident) appears or the
    # window expires. A detection matches when its technique fits this technique
    # AND its own timestamp is at/after $execStartUtc -- so a detection that
    # folds into a pre-existing correlated incident still counts, and stale
    # detections from earlier techniques never do. A real-time hit breaks out in
    # ~1s; artifact-at-rest hits get the full window to clear the 15s poll.
    $detected = $false; $detectionCategory = "none"; $matchedSeverity = ""
    $matchedConfidence = 0.0; $matchedReason = ""; $latency = $null
    $matchedSource = ""; $matchedLabels = @()
    $newIncidentIds = @{}
    $tid = $t.technique_id
    $deadline = (Get-Date).AddSeconds($DetectWindowSeconds)

    function _ParseUtc([string]$s) {
        try { return [datetime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture,
                 [Globalization.DateTimeStyles]::AdjustToUniversal) } catch { return [datetime]::MinValue }
    }

    while ((Get-Date) -lt $deadline -and -not $detected) {
        Start-Sleep -Seconds $PollIntervalSeconds
        $incs = @(Get-Incidents)
        foreach ($head in $incs) {
            if ($head.id -and ($head.id -notin $beforeIds)) { $newIncidentIds[$head.id] = $true }
            # Only pull detail for incidents actually touched since we started.
            $upd = _ParseUtc ([string]$head.updated_at)
            if ($upd -lt $execStartUtc) { continue }
            $inc = Get-IncidentDetail $head.id
            if (-not $inc) { continue }
            foreach ($d in @($inc.detections)) {
                $dts = _ParseUtc ([string]$d.timestamp)
                if ($dts -lt $execStartUtc) { continue }        # stale detection
                $techs = @()
                if ($d.technique) { $techs += [string]$d.technique }
                if ($d.details -and $d.details.all_techniques) {
                    foreach ($at in @($d.details.all_techniques)) { $techs += [string]$at } }
                if (-not ($techs | Where-Object { $_ -like "*$tid*" })) { continue }
                $category = "$($inc.category)".ToLower()
                $dreason = "$($d.title)$($inc.reason)".ToLower()
                if ($category -eq "user_rule" -or $dreason -like "*user:always_block*") {
                    $detectionCategory = "user_rule"
                    Warn "   matched via a USER-DEFINED rule -- NOT counted (see scoring rule)"
                    continue
                }
                $detected = $true
                $detectionCategory = if ($d.source) { [string]$d.source } elseif ($category) { $category } else { "behavioral" }
                $matchedSeverity = "$($d.severity)"
                $matchedReason = "$($d.title)"
                $matchedSource = "$($d.source)"
                if ($d.details -and $d.details.labels) { $matchedLabels = @($d.details.labels | Select-Object -Unique) }
                $latency = [math]::Round($sw.Elapsed.TotalSeconds, 2)
                break
            }
            if ($detected) { break }
        }
    }
    $sw.Stop()

    # False positives: NEW incidents raised during the window whose techniques
    # never matched this one. (A folded detection on a pre-existing incident is
    # not a new incident, so it is never miscounted as an FP.)
    $falsePositiveIds = @()
    foreach ($id in $newIncidentIds.Keys) {
        $inc = Get-IncidentDetail $id
        if (-not $inc) { continue }
        $techs = @()
        foreach ($d in @($inc.detections)) {
            if ($d.technique) { $techs += [string]$d.technique }
            if ($d.details -and $d.details.all_techniques) {
                foreach ($at in @($d.details.all_techniques)) { $techs += [string]$at } }
        }
        if ($inc.technique) { $techs += [string]$inc.technique }
        if (-not ($techs | Where-Object { $_ -like "*$tid*" })) { $falsePositiveIds += $id }
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

        # Explicit, mutually-exclusive Tier B outcome state so the report never
        # has to re-derive "why" from a bare detected/missed boolean. A miss on a
        # technique that never executed is NOT a detection failure and must not be
        # scored as one.
        outcome = if ($detected) { "detected" }
                  elseif ($detectionCategory -eq "user_rule") { "detected_user_rule_excluded" }
                  elseif (-not $attackExecuted -and $executionError) { "blocked_before_execution" }
                  elseif (-not $attackExecuted) { "not_executed_no_command" }
                  else { "executed_missed" }

        detection_latency_seconds = $latency
        theoretical_latency_bound_seconds = $null
        latency_note = if ($latency) { "measured: execution to first matching incident" } else { "no matching incident observed within the ${DetectWindowSeconds}s detection window" }

        matched_source = $matchedSource     # which sensor produced the detection
        matched_labels = $matchedLabels     # the detection's own labels

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
