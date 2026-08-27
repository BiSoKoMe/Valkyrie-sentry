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
    # Drain gap between techniques. DEFAULT 0 -- ON PURPOSE.
    #
    # This was briefly defaulted to 3s to stop the battery saturating
    # SensorManager's bounded queue. That silently changed WHAT IS BEING
    # MEASURED, and the effect was not small: run 32440735442 (settle=0)
    # recorded 27 distinct techniques in the incident store, while run
    # 32441713709 (settle=3, plus two per-technique API reads) recorded 4 --
    # on a BYTE-IDENTICAL engine, with only this harness changed.
    #
    # The mechanism is visible in run 32440735442's own detections: 4
    # edr.sequence and 4 edr.killchain hits, with "burst"/"reconnaissance"
    # all over the reasons. db_coverage.py credits EVERY technique named in a
    # correlation detection's all_techniques list, so a single reconnaissance
    # burst credits the whole discovery cluster at once. Those bursts only
    # form because the harness fires atomics back-to-back. Spread them out and
    # the correlation windows never fill.
    #
    # So pacing is a MEASUREMENT PARAMETER, not a tuning knob, and it is
    # recorded in the results. 0 keeps the historical, comparable number.
    # A non-zero value measures something different -- and arguably more
    # honest, since no real adversary runs 39 techniques back-to-back -- but
    # it is NOT comparable to any previously quoted figure.
    [int]$SettleSeconds = 0,
    # How long to wait for the engine to become STABLE before measuring it, and
    # how many consecutive health checks count as stable.
    [int]$ReadyTimeoutSeconds = 420,
    [int]$ReadyStreak = 3,
    # Minimum seconds the engine must stay alive (answering health, gaps allowed)
    # after its first OK before the battery starts - proves startup has settled
    # while tolerating the transient GIL stalls the single-loop API suffers.
    [int]$ReadyMinWarmupSeconds = 30,
    [switch]$SkipDestructive,
    [string]$RepoRoot = (Resolve-Path "$PSScriptRoot\..\..").Path,
    # Run only these catalog ids (e.g. -OnlyIds evasion-process-injection).
    # For isolating ONE technique during the Detection Coverage milestone's
    # per-technique attack loop, without needing a bespoke one-off script per
    # fix - reuses this file's own already-vetted execution, scoring, and
    # evidence-capture logic instead of duplicating it. Empty (default) runs
    # the full battery exactly as before; this parameter changes nothing when
    # omitted.
    [string[]]$OnlyIds = @(),
    # Run only techniques whose catalog `tactic` field exactly matches one of
    # these (e.g. -OnlyTactic "Discovery","Persistence"). Added for the
    # matrix-job split once the catalog grew past what one ~90min job could
    # comfortably run (52 -> 90+ techniques): each matrix leg filters by
    # tactic instead of needing a hand-maintained id list per leg, so it
    # never drifts out of sync as catalog.py grows. Composable with -OnlyIds
    # (both filters apply; a technique must pass whichever ones are non-empty).
    [string[]]$OnlyTactic = @()
)

$ErrorActionPreference = "Continue"
function Info($m)  { Write-Host "[eval] $m" -ForegroundColor Cyan }
function Warn($m)  { Write-Host "[eval] $m" -ForegroundColor Yellow }
function Bad($m)   { Write-Host "[eval] $m" -ForegroundColor Red }

# --- 0. Export the catalog from the single source of truth (catalog.py) ---
$CatalogJson = Join-Path $PSScriptRoot "catalog_export.json"
Info "Exporting technique catalog from catalog.py (single source of truth)..."
& python (Join-Path $PSScriptRoot "catalog.py") --export $CatalogJson
if (-not (Test-Path $CatalogJson)) { throw "catalog export failed -- is python on PATH?" }
$Catalog = (Get-Content $CatalogJson -Raw | ConvertFrom-Json)
$CatalogVersion = $Catalog.catalog_version
$Techniques = $Catalog.techniques
if ($OnlyIds.Count -gt 0) {
    $Techniques = @($Techniques | Where-Object { $OnlyIds -contains $_.id })
    Info "OnlyIds filter active: running $($Techniques.Count) of $($Catalog.techniques.Count) catalog techniques ($($OnlyIds -join ', '))"
    if ($Techniques.Count -eq 0) { throw "No catalog technique matched -OnlyIds $($OnlyIds -join ', ')" }
}
if ($OnlyTactic.Count -gt 0) {
    $Techniques = @($Techniques | Where-Object { $OnlyTactic -contains $_.tactic })
    Info "OnlyTactic filter active: running $($Techniques.Count) of $($Catalog.techniques.Count) catalog techniques (tactic in: $($OnlyTactic -join ', '))"
    if ($Techniques.Count -eq 0) { throw "No catalog technique matched -OnlyTactic $($OnlyTactic -join ', ')" }
}

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
    # catalog probe instead - which fires the defender_tamper rule (verified via
    # match_process). Real detection, no dependency on a missing atomic file.
    "impact-shadow-delete"      = @{ Attack = "T1490";     Tests = "1"; Destructive = $true }
    "disc-whoami-priv"          = @{ Attack = "T1033";     Tests = "1" }
    # evasion-process-injection intentionally NOT delegated to ART -- Test #1
    # drifted onto an Office-dependent variant (see the "sysmon_eid8" probe
    # case below). catalog.py's own probe="sysmon_eid8" now drives it.
}

# Best-effort revert for the Round 2/2B literal-command ("ioa_rule") entries
# that write real, persistent registry keys or drop real files. Every
# scriptblock here undoes exactly what that ONE catalog entry's probe_input
# cmdline did - nothing more (e.g. removing a single value, never an entire
# pre-existing key that might hold unrelated data). -ErrorAction
# SilentlyContinue throughout: a technique that never actually executed
# (tool missing, blocked) must not fail cleanup trying to undo something
# that was never done.
$IoaRuleCleanup = @{
    "cred-lsa-secrets" = {
        Remove-Item "C:\Users\Public\secrets" -Force -ErrorAction SilentlyContinue
    }
    "evasion-masquerade-lsass" = {
        Get-Process | Where-Object { $_.Path -eq "C:\Windows\Temp\lsass.exe" } |
            Stop-Process -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\Windows\Temp\lsass.exe" -Force -ErrorAction SilentlyContinue
    }
    "evasion-modify-registry" = {
        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
            -Name "HideFileExt" -ErrorAction SilentlyContinue
    }
    "persist-winlogon-shell" = {
        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" `
            -Name "Shell" -ErrorAction SilentlyContinue
    }
    "persist-logon-script" = {
        Remove-ItemProperty -Path "HKCU:\Environment" -Name "UserInitMprLogonScript" -ErrorAction SilentlyContinue
        Remove-Item "C:\Users\Public\art.bat" -Force -ErrorAction SilentlyContinue
    }
    "privesc-uac-eventvwr" = {
        Remove-Item -Path "HKCU:\Software\Classes\mscfile" -Recurse -Force -ErrorAction SilentlyContinue
    }
    "privesc-uac-sdclt" = {
        # Matches ART's own T1548.002 Test #7 cleanup command exactly.
        Remove-Item -Path "HKCU:\Software\Classes\Folder" -Recurse -Force -ErrorAction SilentlyContinue
    }
    "privesc-uac-wsreset" = {
        Remove-Item -Path "HKCU:\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2" `
            -Recurse -Force -ErrorAction SilentlyContinue
    }
    "privesc-uac-progids" = {
        Remove-Item -Path "HKCU:\Software\Classes\.pwn" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "HKCU:\Software\Classes\ms-settings\CurVer" -Recurse -Force -ErrorAction SilentlyContinue
    }
    "privesc-dll-searchorder-amsi" = {
        Remove-Item "$env:APPDATA\updater.exe", "$env:APPDATA\amsi.dll" -Force -ErrorAction SilentlyContinue
    }
    "collect-stage-download" = {
        Remove-Item "$env:TEMP\discovery.bat" -Force -ErrorAction SilentlyContinue
    }
    "disc-file-directory" = {
        Remove-Item "C:\Users\Public\t1083.txt" -Force -ErrorAction SilentlyContinue
    }
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
function Get-SensorDrops {
    # Backpressure/dedup counters, so a MISS can be told apart from a
    # NEVER-DELIVERED. Returns $null when the endpoint is unavailable rather
    # than zeroes -- "unknown" must never be reported as "nothing dropped".
    try {
        # Short timeout ON PURPOSE. This runs twice per technique, so a
        # generous timeout would itself pace the battery -- and pacing
        # measurably changes coverage (see -SettleSeconds). Diagnostics must
        # never become part of what is being measured; if the endpoint is
        # slow we give up and record "unknown" rather than distort the run.
        $r = Invoke-CurlGet "$ApiBase/api/sensors/status" 3
        if (-not $r -or -not $r.enabled) { return $null }
        return @{ backpressure = [int]$r.dropped_backpressure
                  dedup        = [int]$r.dropped_dedup
                  submitted    = [int]$r.submitted
                  emitted      = [int]$r.emitted }
    } catch { return $null }
}

function Get-Incidents {
    # brief=true -> the FAST incident list (raw rows, no per-incident impact
    # assessment / explanation). The full view is O(incidents) and times out
    # under polling - that is what scored every real detection as MISS. The
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
# The old gate allowed 5 attempts x (8s timeout + 3s sleep) ~= 55 seconds and
# accepted a SINGLE success. Both were wrong, and it cost a whole run:
# the workflow's own probe saw the API answer, then 56s later this gate failed
# five times with curl exit 28 (timeout) and the battery never started.
#
# The engine legitimately goes deaf for a while during startup -- it parses a
# ~360k-domain blocklist, loads threat intel and warms the intelligence layer,
# and that work blocks the event loop. "Answered once" therefore does not mean
# "ready to be measured": it means the engine happened to reply between two
# pieces of heavy lifting.
#
# So: wait far longer, and require CONSECUTIVE successes so a battery is never
# started during a lull in a stall. Also say WHICH failure it is -- a refused
# connection (not listening yet) and a timeout (listening but too busy) call
# for completely different fixes, and a bare "not reachable" hid that.
# READINESS GATE - tolerant of GIL stalls, by design (rewritten 2026-08-24).
#
# The old gate required $ReadyStreak CONSECUTIVE health OKs. That is the wrong
# test for THIS engine: its web API is one asyncio loop that GIL-heavy startup
# threads transiently stall for several seconds (persistence snapshot, etc.),
# so /api/health flaps - and 3-in-a-row 3s-apart probes almost never all land in
# a clean window. Every deaf-engine Tier B failure died here, at the GATE, before
# a single technique fired.
#
# The key fact that makes a tolerant gate CORRECT, not a cheat: detections are
# written to the SQLite incident store by the engine's sensor/rule THREADS,
# independent of the uvicorn API loop, and authoritative coverage is read from
# that DB AT REST after the engine stops (the 'Authoritative coverage' step /
# db_coverage.py). So transient API deafness cannot lose a detection - it only
# affects whether we're allowed to START. The gate therefore only needs to
# confirm the engine is genuinely ALIVE and past its heavy startup, not that its
# API is flawlessly stable.
#
# New definition of ready: the engine answered health at least $ReadyStreak
# times (gaps allowed) AND stayed alive across at least $ReadyMinWarmupSeconds
# since its first OK - proof it is up and startup has settled, while tolerating
# the stalls. A single OK followed by death still fails (it never clears warmup).
$HealthOk = $false
$LastErr = $null
$oks = 0
$firstOk = $null
$deadline = (Get-Date).AddSeconds($ReadyTimeoutSeconds)
$attempt = 0
Info "Waiting for a LIVE engine at $ApiBase (>= $ReadyStreak health OKs across >= ${ReadyMinWarmupSeconds}s, stalls tolerated, up to ${ReadyTimeoutSeconds}s)..."
while ((Get-Date) -lt $deadline) {
    $attempt++
    try {
        Invoke-CurlGet -Uri "$ApiBase/api/health" -TimeoutSec 15 | Out-Null
        $oks++
        if (-not $firstOk) { $firstOk = Get-Date }
        $warm = ((Get-Date) - $firstOk).TotalSeconds
        Info ("  health OK ({0} total, {1:N0}s since first OK)" -f $oks, $warm)
        if ($oks -ge $ReadyStreak -and $warm -ge $ReadyMinWarmupSeconds) {
            $HealthOk = $true; break
        }
    } catch {
        $LastErr = $_
        Warn "  health probe failed (transient - engine likely busy under startup GIL load); tolerating and continuing"
    }
    Start-Sleep -Seconds 3
}
if (-not $HealthOk) {
    $why = if ($LastErr) { $LastErr.Exception.Message } else { "no attempt succeeded" }
    throw ("Valkyrie API never became LIVE at $ApiBase within ${ReadyTimeoutSeconds}s " +
           "($attempt attempts, $oks health OKs total) -- $why")
}
Info "Engine is live ($oks health OKs across the warm-up). Starting the battery."
$HaveAtomics = [bool](Get-Module -ListAvailable -Name Invoke-AtomicRedTeam)
if ($HaveAtomics) { Import-Module Invoke-AtomicRedTeam -Force }
else { Warn "Invoke-AtomicRedTeam not installed -- vetted-ART techniques will be SKIPPED, not faked. Run provision.ps1 first for full coverage." }

$WatchDirs = @("$env:USERPROFILE\Documents", "$env:USERPROFILE\Desktop",
              "$env:USERPROFILE\Downloads", "$env:PUBLIC\Documents")

$Records = @()
$RunTs = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")

# CRASH-PROOF RESULTS. The battery used to write its JSON exactly once, after
# the final technique -- so any run that died mid-battery (the destructive
# atomics genuinely crash the GitHub runner; the job can also hit its timeout)
# threw away every technique it had already PROVEN. That is the single biggest
# reason the live number was untrustworthy: a run reporting 4/39 was usually a
# run that died at technique 5, not a detector that failed 35 times.
# Each record is now appended to a JSONL the instant it is known, so a crashed
# run still yields everything it got to. The final aggregate JSON is still
# written on a clean finish, for score.py.
$ResultsDir = Join-Path $PSScriptRoot "results"
New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null
$PartialPath = Join-Path $ResultsDir "$RunTs`__tierB.partial.jsonl"
Set-Content -Path $PartialPath -Value "" -Encoding UTF8
Info "Streaming per-technique results to $(Split-Path -Leaf $PartialPath) (survives a crash)."

foreach ($t in $Techniques) {
    if ($t.destructive -and $SkipDestructive) {
        Warn "SKIP (destructive, -SkipDestructive set): $($t.id) [$($t.technique_id)]"
        continue
    }

    Info "-- $($t.id)  [$($t.technique_id)]  $($t.technique_name)"
    $beforeIds = @(Get-Incidents | ForEach-Object { $_.id })
    $dropsBefore = Get-SensorDrops
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
    # Separate from $executionError on purpose: that variable also drives the
    # outcome bucketing (line ~686, "-not $attackExecuted -and $executionError"
    # -> blocked_before_execution). A missing binary was never attempted, let
    # alone actively blocked by a security control - conflating the two would
    # misreport an environment limitation as "Defender/AV stopped this attack".
    $toolMissingNote = ""

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
                    $persistenceHandled = $true
                    switch ($t.probe_input.activity) {
                        "run_key" {
                            New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
                                -Name "ValkyrieEvalTest" -Value $cmd -PropertyType String -Force | Out-Null
                        }
                        "startup_folder" {
                            Set-Content -Path $cmd -Value "REM eval artifact" -ErrorAction SilentlyContinue
                        }
                        "service" {
                            # Found via the Detection Coverage milestone: this
                            # case did not exist at all before - it fell through
                            # to the warn-and-do-nothing default below, yet
                            # $attackExecuted was still set $true unconditionally,
                            # so persist-new-service scored "executed_missed"
                            # every run with NO real service ever created for
                            # Valkyrie to observe. A real Windows service (sc.exe
                            # writes the standard
                            # HKLM\SYSTEM\CurrentControlSet\Services\<name> key
                            # persistence_telemetry.py's ASEP scanner reads) with
                            # the catalog's own suspicious-path binary, deleted
                            # again once the poller has had its 15s+ window.
                            $svcName = "ValkyrieEvalTestSvc"
                            & sc.exe create $svcName binPath= "$cmd" start= demand | Out-Null
                        }
                        default {
                            $persistenceHandled = $false
                            Warn "   (activity '$($t.probe_input.activity)' needs manual setup -- see catalog.py probe_input)"
                        }
                    }
                    $attackExecuted = $persistenceHandled
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
                        # Found via the Detection Coverage milestone: this always
                        # ran the command through "cmd.exe /c <cmd>" and set
                        # attackExecuted = $true unconditionally right after -
                        # Start-Process only errors if cmd.exe itself can't be
                        # found, which it always can. If the REAL target binary
                        # (wmic.exe, msbuild.exe, ntdsutil.exe, rar.exe - all
                        # absent by default on a modern Windows/CI host) doesn't
                        # exist, cmd.exe starts, prints its own "not recognized"
                        # error to a window nobody reads, and exits - and the
                        # harness recorded a false attack_executed=true for four
                        # real catalog techniques, confirmed by cross-checking
                        # both live runs' own JSON records. Check the actual
                        # target binary FIRST; only skip when we are sure it is
                        # actually missing, never for the merely-unusual.
                        $img = $t.probe_input.image
                        $imgMissing = $false
                        if ($img) {
                            $imgMissing = -not [bool](Get-Command $img -ErrorAction SilentlyContinue)
                        }
                        if ($imgMissing) {
                            $toolMissingNote = "target binary not found on this host: $img"
                            $attackExecuted = $false
                            Warn "   SKIPPED: $toolMissingNote"
                        } else {
                            Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $cmd `
                                -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
                            $attackExecuted = $true
                        }
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

    # --- Condition-based, correlation-robust detection wait ---
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

    $dropsAfter = Get-SensorDrops
    $dropDeltaBp = $null; $dropDeltaDd = $null
    $dropNote = "sensor metrics unavailable"
    if ($dropsBefore -and $dropsAfter) {
        $dropDeltaBp = [Math]::Max(0, $dropsAfter.backpressure - $dropsBefore.backpressure)
        $dropDeltaDd = [Math]::Max(0, $dropsAfter.dedup        - $dropsBefore.dedup)
        $dropNote = if ($dropDeltaBp -gt 0) {
            "WARNING: $dropDeltaBp event(s) dropped by backpressure during this technique - a miss here may be a blind sensor, not a rule gap"
        } else { "no backpressure drops during this technique" }
    }

    $record = [ordered]@{
        schema = "valkyrie-redteam-evaluation/1"
        tier = "B_live"
        catalog_version = $CatalogVersion
        # Pacing materially changes coverage (see -SettleSeconds), so every
        # record carries it -- a result file must describe the conditions that
        # produced it, or two runs get compared that never measured the same thing.
        settle_seconds = $SettleSeconds
        id = $t.id
        technique_id = $t.technique_id
        technique_name = $t.technique_name
        test_number = $t.art_test_ref
        tactic = $t.tactic
        mitre = @{ tactic = $t.tactic; technique_id = $t.technique_id; technique_name = $t.technique_name }
        destructive = $t.destructive

        attack_executed = $attackExecuted
        attack_executed_note = if ($executionError) { "execution error: $executionError" }
                               elseif ($toolMissingNote) { $toolMissingNote }
                               else { "" }

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

        # Sensor delivery during THIS technique. A miss with a non-zero
        # backpressure delta is a BLIND SENSOR, not a failed rule -- the two
        # must never be conflated when reading coverage.
        sensor_dropped_backpressure = $dropDeltaBp
        sensor_dropped_dedup        = $dropDeltaDd
        sensor_delivery_note        = $dropNote

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
        error = if ($executionError) { $executionError } else { $toolMissingNote }
        notes = $t.notes
    }
    $Records += $record
    # Persist immediately (one JSON object per line). Best-effort: a failure to
    # write the progress file must never abort the battery itself.
    try {
        ($record | ConvertTo-Json -Depth 10 -Compress) | Add-Content -Path $PartialPath -Encoding UTF8
    } catch { Warn "could not append partial result for $($t.id): $($_.Exception.Message)" }

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
    if ($t.probe -eq "persistence" -and $t.probe_input.activity -eq "service") {
        & sc.exe delete "ValkyrieEvalTestSvc" | Out-Null
    }
    # Round 2/2B additions (catalog.py, 2026-08-26): these write real registry
    # keys or drop real files via the generic literal-command ("ioa_rule")
    # path, which has no cleanup mechanism of its own - unlike the "service"/
    # "run_key" cases above, nothing reverted them before this. Left dirty,
    # a persistence-shaped key (Winlogon Shell, UserInitMprLogonScript) could
    # both leave the runner in a genuinely broken logon state for the rest of
    # the job AND get re-observed by the 15s artifact-at-rest poller on a
    # LATER technique's detection window, misattributing a stale leftover as
    # a fresh detection. Keyed by catalog id, mirroring $VettedAtomics' own
    # id-keyed shape, since these are not their own probe type.
    if ($IoaRuleCleanup.ContainsKey($t.id)) {
        try { & $IoaRuleCleanup[$t.id] } catch {
            Warn "   cleanup for $($t.id) raised: $($_.Exception.Message)"
        }
    }

    # Let the sensor pipeline drain before the next technique fires (see
    # -SettleSeconds). Without this the battery is one long burst and the
    # bounded queue evicts real events.
    if ($SettleSeconds -gt 0) { Start-Sleep -Seconds $SettleSeconds }
}

# ---------------------------------------------------------------------------
# Write results in the SAME schema replay_harness.py emits, so score.py
# works unmodified on either tier's output.
# ---------------------------------------------------------------------------
$OutPath = Join-Path $ResultsDir "$RunTs`__tierB.json"
@{ tier = "B_live"; catalog_version = $CatalogVersion; generated_at = $RunTs;
   settle_seconds = $SettleSeconds; detect_window_seconds = $DetectWindowSeconds;
   records = $Records } |
    ConvertTo-Json -Depth 10 | Set-Content -Path $OutPath -Encoding UTF8

Write-Host "`n======================================================================"
Write-Host "  Tier B live evaluation complete: $($Records.Count) techniques run."
Write-Host "  Results: $OutPath"
Write-Host "  Run the scorer:  PYTHONUTF8=1 python redteam/evaluation/score.py `"$OutPath`""
Write-Host "======================================================================`n"

# INTERPRETIVE NOTE, not a fix - this number IS working as designed, but three
# CI runs in a row (5-8 of 50 techniques, one or two techniques absorbing
# 20-77 "false positives" apiece, and WHICH technique varies run to run) made
# it clear this reads as alarming to anyone who has not also read lines 80-82
# and 707-710 above.
#
# With -SettleSeconds 0 (the CI default, chosen for speed - "no real adversary
# runs 39 techniques back-to-back"), there is ZERO drain time between
# techniques. A detection legitimately caused by technique N can land during
# technique N+1's window and, because that incident's technique label does not
# match N+1's id, gets counted as a false positive AGAINST N+1. The instability
# of WHICH technique absorbs the count run to run is the signature of this:
# it depends only on which techniques happen to be adjacent that run, not on
# anything either technique's rule got wrong.
#
# This is entirely separate from, and does not affect, the false-positive
# figures measured against real software on a live host (see
# valkyrie/edr/elastic_import.py's harvested corpus and the ad-hoc live-process
# sweeps) - those measure real benign commands with no adjacent attack traffic
# at all. Do not quote this run's total false_positives_generated as a
# real-world FP rate; it is an attribution-window artifact of running at
# SettleSeconds=0, not evidence Valkyrie fires on legitimate activity.
$totalFp = ($Records | ForEach-Object { $_.false_positives_generated } | Measure-Object -Sum).Sum
$fpTechs = ($Records | Where-Object { $_.false_positives_generated -gt 0 }).Count
if ($totalFp -gt 0) {
    Write-Host ("  NOTE: false_positives_generated totals $totalFp across " +
               "$fpTechs/$($Records.Count) techniques, at -SettleSeconds " +
               "$SettleSeconds. This is very likely cross-technique attribution " +
               "bleed (see script header, ~line 80), NOT a real-software false- " +
               "positive rate - re-run with -SettleSeconds 5+ before treating " +
               "this number as meaningful on its own.") -ForegroundColor DarkYellow
}
Write-Host "  REVERT THE SNAPSHOT NOW." -ForegroundColor Yellow
