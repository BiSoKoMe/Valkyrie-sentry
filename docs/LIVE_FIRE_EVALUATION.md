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
  control tampering, shadow-copy deletion) safe to run at all.
- **Catalog:** 62 cataloged techniques (`redteam/evaluation/catalog.py`), 52
  in-scope for live execution; 10 excluded a priori for stated structural
  reasons (e.g. a technique requiring a Domain Controller).
- **Reproduce it yourself:**
  `.github/workflows/redteam-tierb.yml`, manually dispatchable
  (`gh workflow run redteam-tierb.yml -f skip_destructive=false`), or
  `redteam/evaluation/run_live_evaluation.ps1` directly inside your own
  disposable VM. `-OnlyIds <id1,id2,...>` runs a subset without the full
  battery — useful for verifying one fix in isolation.

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

## Result (baseline, commit `0497740`, two independent runs)

| Run | Attempted | Detected |
|---|---:|---:|
| Run 1 | 58 | 42 |
| Run 2 | 58 | 36 |
| **Union (authoritative)** | **52 in-scope** | **38 → 73.1%** |

This includes correctly attributed, live-executed detections of: LSASS
memory dumping (two independent tool implementations), Defender and firewall
tampering, volume shadow copy deletion, Windows event log clearing, registry
Run-key / scheduled-task / startup-folder / WMI-subscription persistence,
and multiple living-off-the-land binary proxy techniques.

### What was not detected, and exactly why

No miss is folded into an unexplained residual.

| Class | Techniques | Reason |
|---|---|---|
| Config-excluded | 4× DNS/C2 (`T1071`, `T1071.004`×3) | This test configuration runs with `--no-dns` to avoid touching the runner's real resolver — not exercised, not a code gap |
| Tool absent on host | `collect-archive-rar`, `exec-msbuild-inline`, `cred-ntdsutil-ifm` | `rar.exe` / `msbuild.exe` / `ntdsutil.exe` are not present on a stock Windows/CI host (verified directly) |
| Needs a 2nd host | `lat-psexec-smb` | Single-runner limitation, not a Valkyrie question |
| Requires a Domain Controller | (folded into tool-absent above) | `ntdsutil.exe` ships with the AD DS role |
| Genuine, open gaps | `T1204.002`, `T1220`, `T1543.003` at baseline, `T1033`, `T1069.001` at baseline | Executed for real, no matching incident — see the Detection Coverage log below for which of these have since been root-caused and fixed |
| No runnable test | `exec-cmd-office-child` | No atomic command available for this probe |
| Predicted miss | `collect-archive-rar` (2nd reason) | No rule claims to catch this shape; not a surprise |

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

**Live re-verification (same day, isolated `-OnlyIds` re-runs on the same
disposable runner class — not a full battery re-run, but each fix confirmed
individually against the real engine):**

| Fix | Technique | Result |
|---|---|---|
| #1 (label) | `disc-localgroup` T1069.001 | **`[DETECT]`, fp=0, latency=2.1s** — confirmed live with real burst partners |
| #2 (Sysmon EID8) | `evasion-process-injection` T1055 | **`[DETECT]`, fp=0, latency=4.9s** — confirmed live; `Get-WinEvent` independently confirmed 1 real EID8 event captured |
| #3 (harness honesty) | 4 tool-absent techniques | Confirmed correctly reclassified `not_executed_no_command`, no longer falsely `executed_missed` |

Two genuine, previously-missing techniques (T1055, T1069.001) are now
independently confirmed live, moving the proven floor from 38/52 (73.1%)
toward 40/52 (76.9%) pending a full-battery re-run to fold this into the
authoritative union number. This log is updated as the milestone continues;
treat any coverage percentage above as a floor as of the commit it cites,
not a permanent number.

## What this evaluation does not claim

- Comprehensive coverage of the full ATT&CK matrix — 52 in-scope techniques
  is a deliberate, representative slice, not an exhaustive one.
- Multi-host lateral movement — structurally out of reach of a single
  disposable runner.
- Sensor behavior under sustained, high-volume production load — measured at
  CI-battery scale, not validated at that scale yet.
- A false-positive rate on real user workloads — measured against a CI
  runner's own background activity, not a real desktop's.
