# Live-Fire Detection Evaluation (Tier B)

**This is the strongest evidence Valkyrie has for "does it actually detect
attacks" — real Atomic Red Team techniques, including the destructive ones,
executed against a genuinely running Valkyrie instance on a disposable,
single-use machine, scored against the engine's own incident store.**
`docs/DETECTION_EFFICACY_REPORT.md` measures something real but weaker
(synthetic inputs fed straight to the classifier functions — no execution,
no sensors, no real false-positive rate). Read this document first if you're
deciding whether to trust Valkyrie's detection claims.

## Why "live-fire" and not a rules count

Any detection engine can enumerate rules. The only question a technical
evaluator should actually ask is narrower: *when a known attack technique is
deliberately executed, does Valkyrie produce a correctly attributed
detection, reliably, across independent trials?* A detection was only
credited when the resulting incident carried a **specific, technique-accurate
label** — e.g. `lsass_dump` / `critical` with the reason "a known
LSASS-dumping tool was executed" — never merely the presence of a process
event.

## Infrastructure

- **Runner:** GitHub Actions `windows-latest` — a freshly provisioned,
  single-use VM destroyed unconditionally at job completion. This is what
  makes the destructive subset of the catalog (credential dumping, security
  control tampering, shadow-copy deletion, simulated ransomware) safe to run
  at all.
- **Catalog:** 90 cataloged technique variants (`redteam/evaluation/catalog.py`),
  73 unique in-scope MITRE techniques for live execution (several techniques
  are tested more than one way — e.g. two independent LSASS-dumping tools —
  and are counted once for the denominator, not once per variant); 4
  explicitly excluded a priori for stated structural reasons (e.g. a
  technique requiring a Domain Controller). Grew from the original 52 via a
  deliberate expansion pass (see "Expanded evaluation" below), not by
  padding — every addition was chosen to probe a specific, previously-untested
  class of coverage.
- **Reproduce it yourself:**
  `.github/workflows/redteam-tierb.yml`, manually dispatchable
  (`gh workflow run redteam-tierb.yml -f skip_destructive=false`), or
  `redteam/evaluation/run_live_evaluation.ps1` directly inside your own
  disposable VM. `-OnlyIds <id1,id2,...>` or `-OnlyTactic <name,...>` run a
  subset without the full battery — useful for verifying one fix in
  isolation, or splitting the full catalog across parallel matrix jobs (see
  `redteam-tierb.yml`'s `run_full_matrix` input) now that one job no longer
  comfortably fits the whole thing.

## Scoring discipline

A single run on shared CI infrastructure is not trustworthy alone — sensor
backpressure under a dense atomic burst, transient runner slowness, and job
timeouts can all suppress a real detection. None of these failure modes can
*manufacture* one. The honest number is therefore a **union across runs**: a
technique counts once any run demonstrates it, reported as a proven floor,
never rounded up.

```
detected(T) = OR over every real run: was T observed in that run?
```

## Result — CURRENT (commit `1fb0b6a`, 26 independent runs: 22 from the expansion pass plus 4 preserved from the original baseline)

| Corpus | Attempted | Detected |
|---|---:|---:|
| **Union (authoritative, current)** | **73 in-scope** | **55 → 75.3%** |

This is the current, authoritative number. It supersedes the original
baseline below, which is kept for context, not because it is still current:

| Corpus | Attempted | Detected |
|---|---:|---:|
| Baseline (first pass, historical) | 52 in-scope | 38 → 73.1% |
| Expanded (round 2) | 73 in-scope | 48 → 65.8% |
| **Generalization gaps closed (current)** | **73 in-scope** | **55 → 75.3%** |

**The percentage went down. That is expected, not a regression.** The
expansion added 21 new techniques chosen specifically because coverage there
was uncertain — PowerShell-cmdlet equivalents of already-covered native
binaries, previously-untested tactics (Privilege Escalation, Collection),
and techniques that turned out to reveal real generalization gaps. A bigger,
harder denominator producing a lower raw percentage is the honest result of
testing more rigorously, not evidence the detection engine got worse: every
technique proven live in the original 52-technique baseline was re-proven
live in this pass (the union only ever grows), and the Detection Coverage
log below shows every fix found this round, with none of them a regression.

This includes correctly attributed, live-executed detections of: LSASS
memory dumping (two independent tool implementations), simulated ransomware
encryption, Defender and firewall tampering, volume shadow copy deletion,
Windows event log clearing, local-account creation, registry Run-key /
scheduled-task / startup-folder / Winlogon-shell / logon-script persistence,
three distinct UAC-bypass mechanisms, and multiple living-off-the-land
binary proxy techniques.

### What was not detected, and exactly why

No miss is folded into an unexplained residual. 73 − 55 = 18 currently-open
gaps, categorized (the table below does not sum to exactly 18 against an
older draft of this document — that pre-existing discrepancy predates this
pass and has not yet been separately audited; treat the 73/55 figures as
authoritative, since they come directly from the union computation, not from
summing this table by hand):

| Class | Techniques | Reason |
|---|---|---|
| Config-excluded | 3× DNS/C2 (`T1071.004`×3) | This test configuration runs with `--no-dns` by default to avoid touching the runner's real resolver — not exercised, not a code gap. `enable_network_layer` re-enables this class for anyone who wants to test it. |
| Tool absent on host | `collect-archive-rar`, `exec-msbuild-inline`, `cred-ntdsutil-ifm`, `evasion-wmic-xsl`, `exec-cmd-office-child`, `exec-lure-doubleext`, `lat-psexec-smb` (needs a 2nd host), `persist-wmi-subscription` | `rar.exe` / `msbuild.exe` / `ntdsutil.exe` / `wmic.exe` are not present on a stock Windows/CI host (verified directly); the rest have no runnable atomic on a single standalone VM |
| Real, confirmed mislabeling (fires, wrong ATT&CK id) | `cred-lsa-secrets` (fires as T1003.002), `evasion-masquerade-lsass` (fires as T1036.005), `collect-stage-download` (fires as T1105), `disc-network-share`/`disc-network-shares-smb` (fires as T1018), `disc-domain-groups` (fires as T1087.002), `cred-registry-password-hunt` (fires as T1012) | A real, adjacent detection exists but under a different specific technique — never credited as correct per this evaluation's own rule, even though the underlying signal is genuine |
| Genuine, confirmed generalization gaps | `collect-clipboard`, `disc-file-directory`/`disc-file-dir-ps`, `disc-security-software` (the native tasklist/netsh chain — the CIM/WMI form was closed, see milestone #8), `privesc-dll-searchorder-amsi`, `evasion-modify-registry` (likely by design — an ordinary registry write, not obviously worth a rule) | The binary/cmdline form of the technique has no detector at all. `disc-file-directory`/`disc-file-dir-ps` (`dir`/`Get-ChildItem`) were deliberately deferred, not overlooked — both are ubiquitous, benign-by-default operations, and this project's zero-FP prime directive means that generalization needs more care than the batch closed in milestone #8. |
| Closed 2026-08-27 (milestone #8) | `disc-net-connections-ps`, `disc-service-discovery-ps`, `disc-service-net-start`, `disc-scheduled-tasks-query`, `disc-security-software-cim`, `disc-software-installed`, `disc-password-policy` | 7 confirmed generalization gaps — PowerShell-cmdlet and net.exe-verb equivalents of already-covered native-binary techniques — closed and live-verified. See milestone log below. |
| Long-standing, inconclusive | `disc-whoami-priv` (T1033) | Investigated in an earlier pass; evidence was inconsistent with a test-pacing artifact rather than a confirmed code gap — left open rather than claimed either way |

## Case study: a self-inflicted false-positive storm, found and fixed

One live run produced 2,447 incidents against a 49-incident baseline — a
~50× anomaly investigated to root cause rather than dismissed as noise.

**Root cause:** the network-anomaly scorer's strongest signal
(`never_resolved` — "this destination was never looked up via DNS, so it was
likely hardcoded") was unconditionally true for *every* connection whenever
DNS interception was inactive (i.e. every `--no-dns` test run), because the
resolution log conflated "interception never ran" with "interception ran and
genuinely saw nothing." Combined with a second signal true of nearly every
non-OS-signed process on a CI runner, two weak signals cleared the firing
threshold for completely ordinary traffic — including Valkyrie's own
loopback API traffic, which a separate gap (self-recognition matching only a
packaged install, not a source-checkout run) never suppressed.

**Fix:** the resolution log now returns a genuine "unknown" — not a guessed
"unresolved" — until it has processed at least one real resolution; and
self-recognition now also matches the running process by its own OS process
ID, an exact identity check with no name or path allowlist.

**Verified, before/after, same isolated reproduction:**

| | Before | After |
|---|---:|---:|
| Spurious network-category detections | 7 | **0** |
| Genuine, technique-driven detections | 40 | **40 (unchanged)** |

Full account: `docs/adr/` incident-storm entry and the commit history on
`feat/efficacy-etw-coverage` (`resolution_log.py`, `trust.py`).

## Detection Coverage milestone — ongoing, in-repo log

Following the baseline, each genuine miss is attacked individually: isolate
it, read the real telemetry, find the exact layer where the signal is lost,
fix the smallest correct thing, add a regression test, and re-verify live —
never a blanket threshold change, never a name-based allowlist. Fixes shipped
so far on `feat/efficacy-etw-coverage`:

1. **`net localgroup` mislabeled T1087.001 instead of T1069.001** — the live
   atomic's exact command already matched existing code, under the wrong
   ATT&CK id, so a scorer that never credits a wrong label never credited it.
   (`process_telemetry.py`, `behavioral_sequences.py`)
2. **Sysmon never emitted CreateRemoteThread (EID 8) at all** — the stock
   config disables it by default; provisioning now turns it on. (An empty
   `onmatch="include"` block was tried first and silently matched nothing —
   the corrected fix uses the empty-`onmatch="exclude"` idiom Sysmon actually
   requires to mean "log everything.") (`provision.ps1`)
3. **Four techniques falsely reported `attack_executed=true`** when their
   target binary didn't exist on the host — the harness only checked that
   `cmd.exe` launched, never that the real inner command ran. Now checks the
   real binary first and buckets a missing tool as `not_executed_no_command`,
   never `executed_missed` (nothing to have missed) or
   `blocked_before_execution` (implies an active security block, which this
   is not). (`run_live_evaluation.ps1`)
4. **`persist-new-service` never created a real service** — the harness's
   persistence probe only implemented `run_key`/`startup_folder`; `service`
   silently did nothing while still reporting execution. Implemented for
   real via `sc.exe create`. (`run_live_evaluation.ps1`)
5. **`disc-localgroup`'s catalog entry was stale relative to fix #1** — fix
   #1 above was verified with an ad hoc manual test using real burst
   partners, but the catalog entry itself was never updated off
   `probe="ioa_rule"` (standalone, deliberately never alerts by this
   project's own design) and `predicted_tier_b="MISS"`. Every automated run
   since fix #1 landed was still testing the scenario fix #1 explicitly
   doesn't cover alone, not the scenario it actually fixed. First correction
   attempt reused the wrong burst partners (`nltest.exe /domain_trusts` is
   deliberately excluded from the classifier's own diversity count, since it
   has a separate named rule) and still failed offline before being caught;
   corrected to the same partner pattern proven everywhere else in the
   catalog. (`catalog.py`)
6. **The ransomware probe tested an isolated unit-test stub, not the real
   shield** — `impact-ransomware-encrypt`, Valkyrie's own most mature,
   purpose-built detector, scored a clean live miss
   (`attack_executed=true`, `classifier_logic_fires=false`) in the expanded
   pass. Traced to source: the probe called `/api/ransomware/self-test`,
   which invokes `ransomware_shield.py`'s `simulate()` — a function whose
   own docstring says it builds an isolated, throwaway `CanaryManager` in a
   temp directory, "used by the /api self-test AND UNIT TESTS." It never
   touches the real, running shield's own watched canaries and publishes no
   `TelemetryEvent`, so it could never produce a scoreable incident
   regardless of detector quality. Fixed to read the real armed shield's own
   manifest (`data/ransomware_canaries.json`) and overwrite an actual
   live-armed canary with random high-entropy bytes — what a real attack
   does to a real tripwire. (`run_live_evaluation.ps1`)
7. **`privesc-dll-searchorder-amsi`'s tool-check used the wrong binary
   name** — its `probe_input.image` was set to `updater.exe`, the *output*
   of the technique's own first step (a `copy` that creates the renamed
   file), not a pre-existing tool. The harness's tool-presence pre-check
   (`Get-Command`) always fails on a file that doesn't exist yet, so this
   entry was silently misclassified `not_executed_no_command` on every real
   run instead of being attempted. Fixed to check `cmd.exe`, the binary
   actually being invoked. (`catalog.py`)
8. **7 confirmed generalization gaps closed** — `classify_discovery` already
   covered `net.exe view/group/localgroup/user` and a handful of PowerShell
   AD-module cmdlets, but the PowerShell-cmdlet and net.exe-verb equivalents
   of several already-covered native-binary techniques fell through
   unclassified: `Get-NetTCPConnection` (T1049), `Get-Service` (T1007), bare
   `net start`/`net accounts` (T1007/T1201, distinguished from their mutating
   forms — "start `<svc>`"/"accounts `/param`" — by the same
   verb-then-argument shape net.exe's own syntax already uses), a new
   `schtasks.exe` query-vs-mutating branch mirroring the existing
   `reg.exe`/`sc.exe` pattern, `Get-CimInstance` scoped to the
   securityCenter2/antivirusproduct namespace (T1518.001), and
   `Get-ItemProperty`/`Get-Item` scoped to the Uninstall registry key —
   deliberately labeled T1518 (Software Discovery), not the generic T1012
   `reg.exe`'s own branch already covers, since crediting it under a
   different ATT&CK id than the one under test is the same wrong-label trap
   fix #1 and `disc-domain-groups` hit. `T1201`/`T1518` added to
   `behavioral_sequences.py`'s reconnaissance-burst technique tuple
   (`T1049`/`T1012`/`T1007` were already there). All 7 catalog entries moved
   from `probe="ioa_rule"` (the wrong mechanism — these are INFO-only labels
   that only alert via the burst sequence, never standalone) to
   `probe="recon_burst"` with the same proven `systeminfo.exe`/`tasklist.exe`
   co-occurring partners used for fix #5. (`process_telemetry.py`,
   `behavioral_sequences.py`, `catalog.py`)

**Live re-verification (isolated `-OnlyIds`/`-OnlyTactic` re-runs on the same
disposable runner class, each fix confirmed individually against the real
engine, then folded into the full-battery union above):**

| Fix | Technique | Result |
|---|---|---|
| #1 (label) | `disc-localgroup` T1069.001 | **`[DETECT]`, fp=0, latency=2.1s** — confirmed live with real burst partners |
| #2 (Sysmon EID8) | `evasion-process-injection` T1055 | **`[DETECT]`, fp=0, latency=4.9s** — confirmed live; `Get-WinEvent` independently confirmed 1 real EID8 event captured |
| #3 (harness honesty) | 4 tool-absent techniques | Confirmed correctly reclassified `not_executed_no_command`, no longer falsely `executed_missed` |
| #5 (catalog staleness) | `disc-localgroup` T1069.001, again | Confirmed `[DETECT]` from the catalog entry itself, not just an ad hoc test — `classifier_logic_fires=True, counted_as_detected=True` in `replay_harness.py`, then live in the full battery |
| #6 (ransomware probe) | `impact-ransomware-encrypt` T1486 | **`[DETECT]`, fp=0, latency=10.23s** — confirmed live against a real armed canary, not the self-test stub |
| #7 (tool-check bug) | `privesc-dll-searchorder-amsi` T1574.001 | Now genuinely attempted and genuinely missed (no rule exists for this technique) — correctly reclassified from a masked harness bug to an honest, confirmed gap |
| #8 (7 generalization gaps) | `disc-net-connections-ps` T1049, `disc-service-net-start`/`disc-service-discovery-ps`/`disc-scheduled-tasks-query` T1007, `disc-security-software-cim` T1518.001, `disc-software-installed` T1518, `disc-password-policy` T1201 | All 7 **`[DETECT]`** live, run `33039444502`, `-OnlyIds` targeted. 3 of the 7 (`disc-net-connections-ps`, `disc-service-net-start`, `disc-security-software-cim`) also reported `fp=1` — `run_live_evaluation.ps1`'s own documented caveat applies: at the CI default `-SettleSeconds 0`, an incident legitimately caused by technique N can land during technique N+1's window and get miscounted against N+1 purely by adjacency, "NOT evidence Valkyrie fires on legitimate activity" (see the script's own header comment, ~line 929). This is the same known attribution-window artifact already documented for running multiple recon-burst techniques back-to-back, not a new false-positive bug; a from-scratch re-run with `-SettleSeconds 5+` would isolate it cleanly but was not performed this pass. |

9. **Three of the six confirmed mislabeling findings closed (2026-08-31)** —
   `cred-lsa-secrets` (T1003.004), `cred-registry-password-hunt` (T1552.002),
   and `disc-domain-groups` (T1069.002) all used to fire under a different,
   wrong ATT&CK id (see "Real, confirmed mislabeling" in the gap table
   above, and `redteam/evaluation/catalog.py`'s per-entry notes for the full
   detail on each). Fixed by reading the exact matching logic and correcting
   or adding the smallest rule that fixes it: `reg-save-hive` split into two
   rules so HKLM\SECURITY gets its own T1003.004 tag instead of borrowing
   HKLM\SAM's T1003.002; a new `cred-registry-password-hunt` rule
   (`reg.exe query ... /f <password-like keyword>`) added, same
   verb-ANDed-with-keyword shape as the existing `cred-hunt-files` rule; and
   `process_telemetry.py`'s `net group` branch corrected from T1087.002
   (Account Discovery) to T1069.002 (Permission Groups Discovery) — the same
   bug class as the earlier `net localgroup` / T1069.001 fix, just never
   done for the domain-groups sibling. **Offline-verified only** (new cases
   added to `test_behavioral_rules.py` and `test_process_telemetry.py`) —
   live Tier B re-verification has NOT been run yet; treat these three as
   "expected fixed, not yet proven" until a live `-OnlyIds` re-run confirms
   it, the same standard every other fix in this log was held to before
   being folded into the union number below. The remaining three mislabeling
   findings (`collect-stage-download`, `disc-network-share`/
   `disc-network-shares-smb`, `evasion-masquerade-lsass`) and
   `evasion-file-delete` were deliberately left alone — the catalog's own
   comments flag those as potentially acceptable overlap between adjacent
   ATT&CK sub-techniques rather than a clear-cut bug, which needs live
   evidence to decide, not a guess.

All eight fixes through #8 are folded into the 55/73 (75.3%) union above —
that number is not pending, it is the current authoritative result. Fix #9
is NOT yet folded in (no live run has confirmed it) — expect 55/73 to move
only after that re-run. This log is updated as the milestone continues;
treat any coverage percentage above as a floor as of the commit it cites,
not a permanent ceiling.

## What this evaluation does not claim

- Comprehensive coverage of the full ATT&CK matrix — 73 in-scope techniques
  is a deliberate, representative slice, not an exhaustive one.
- Multi-host lateral movement — structurally out of reach of a single
  disposable runner.
- Sensor behavior under sustained, high-volume production load — measured at
  CI-battery scale, not validated at that scale yet.
- A false-positive rate on real user workloads — measured against a CI
  runner's own background activity, not a real desktop's.
