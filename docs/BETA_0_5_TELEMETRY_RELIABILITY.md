# Platform Beta 0.5 — Telemetry Reliability Qualification

## Qualification status

**OPEN. Do not freeze this baseline.**

Corrected CI qualification on 2026-08-30:

- Dry-run `33330512824`: PASS. All three collectors were available for all
  127 samples and completed repeated polls; the scoped Tier B workload ran
  exactly 3 catalog techniques; API failures were zero.
- Fault test `33330847426`: PASS. A frozen test collector produced
  `DEGRADED`, and `HEALTHY` returned only after a real completed poll resumed.
- Three-run 25-minute soak `33330959664`: FAIL (1/3 runners passed).
  - Run 1: 25 API health timeouts; the second Phase E scoped workload timed out.
  - Run 2: 26 API health timeouts, one `process_collector:stale_poll`, and the
    second Phase E scoped workload timed out.
  - Run 3: workload and API checks completed, but 30 consecutive watchdog
    samples reported `persistence_collector:stale_poll` before recovery.
  - Platform Alpha's frozen baseline passed on all three runners.

The failed soak is evidence of progress stalls without collector exceptions,
which is the exact failure class Beta 0.5 exists to eliminate. Eventual recovery
does not convert a stale interval into a pass. NYX work does not begin from this
result.

Predeclared 2026-08-30, before any CI run. This document is written first;
`redteam/evaluation/beta05_reliability.py` implements exactly what is written
here, not the reverse. If the harness and this document ever disagree, the
harness has a bug.

## What this qualifies, and what it does not

[docs/LIVE_FIRE_EVALUATION.md](LIVE_FIRE_EVALUATION.md) proved **coverage**:
55/73 (75.3%) MITRE techniques detected live, union of 26 CI runs. That
document explicitly disclaims two things it never measured: sensor behavior
under sustained load, and telemetry continuity over time. This document
covers exactly those two gaps, and nothing else.

**Coverage** asks: when technique T runs, can we recognize it?
**Reliability** asks: can the system keep producing a trustworthy event
stream long enough for recognition to even be possible?

This qualification does not add detection rules, does not run the 73-
technique battery, and treats detection score as a sanity signal only, never
a pass/fail gate. A missed technique here is not a failure of this
qualification — a collector going silently quiet is.

## Why CI, not the local machine

Beta 0.5 is specifically about real Windows task scheduling, real collector
threads, real event-loop progress under the OS's own scheduling jitter, and
telemetry continuity over real wall-clock minutes. A local smoke test proves
the harness's own API/syntax is correct; it cannot substitute for the target
environment (a disposable GitHub Actions `windows-latest` runner — the same
class `docs/LIVE_FIRE_EVALUATION.md`'s 55/73 was measured on), so a local run
is never counted as evidence toward this qualification.

## Workload (A–E), reusing existing, already-vetted-safe paths

No new workload is invented. Every command/technique below already exists
and was already proven safe in this project before today.

| Phase | Duration | Content |
|---|---|---|
| A. Idle baseline | 2–3 min | Runner background activity only — no stimulus from the harness |
| B. Benign host activity | ~5 min | The bare, read-only Windows admin commands `redteam/evaluation/live_safe.py`'s HARD SAFETY RULE allowlist already vets: `whoami`, `systeminfo`, `tasklist`, `hostname`, `ipconfig /all`, `netstat -ano`, `reg query HKLM\SOFTWARE\...` — ordinary process launches, filesystem-adjacent reads, harmless registry reads, and (via `netstat`) a real look at the runner's own normal outbound connections |
| C. Known telemetry-producing activity | ~5 min | A 3-technique, **non-destructive**, already-Tier-B-proven subset, run via the existing `run_live_evaluation.ps1 -OnlyIds` against the already-running engine — chosen because each one exercises a *different* collector this qualification instruments, not for technique coverage: `exec-powershell-encoded` (T1059.001, process_collector), `persist-run-key` (T1547.001, persistence_collector), `exec-wmic-process-call` (T1047, process_collector / WMI) |
| D. Recovery / continued operation | ~5 min | Same as phase B — verify collectors keep advancing after phase C's burst |
| E. Sustained mixed activity | Remainder of soak | Repeat bounded phase B commands + a single light rerun of phase C's subset, at a controlled rate (own-process spacing, never a dense burst) |

Engine boot flags are the exact baseline set `tierb-run-reusable.yml` already
uses and has already proven stable on this runner class (network layer off):
`--no-dns --no-unbound --no-intelligence --no-firewall --no-tls
--no-sysmon-setup --no-download-lists`. `--no-intelligence` specifically is
kept off because it is an already-documented, unrelated GIL-contention
source (`valkyrie_startup_deafness`) — introducing it here would contaminate
the telemetry-reliability signal this qualification exists to isolate. AMSI
and the ransomware shield are left at their real production default (on),
since the process/network/persistence collectors and the event loop — not
those two — are what this qualification instruments.

## What is sampled, continuously, for the whole run

Every 2 seconds, independent of any phase boundary:

- Event-loop heartbeat age (`/api/telemetry/watchdog` → `loop`)
- Process collector poll age
- Network collector poll age
- Persistence collector poll age
- Per-collector exception counts
- API responsiveness (health check latency and success/failure)
- Event-count progression (`/api/edr/causality/stats` → `nodes`/`artifacts` —
  fed by *every* `ingest_telemetry` call regardless of detection severity,
  so this is a detection-agnostic "is the pipe alive" signal, not a scoring
  signal)
- ETW sensor manager metrics (`/api/sensors/status` → submitted / emitted /
  dropped_backpressure / dropped_dedup / restarts)
- Engine readiness (`/api/health`, `/api/telemetry/watchdog` overall)
- Every DEGRADED transition (timestamp + reason)
- Every recovery-to-HEALTHY transition (timestamp)

All samples are streamed to a JSONL file as they are taken (crash-proof —
matching this project's existing Tier B convention of partial, resumable
results), never held only in memory.

## Fault-detection step (before the long soak)

A soak that completes green with everything healthy is not evidence the
alarm works — it might just mean nothing ever went wrong. Before the 20–30
minute qualification, a dedicated short CI run boots the engine with
`VALKYRIE_DEBUG_FAULT_COLLECTOR=1`, which wires one extra, fake, test-only
collector (`FaultInjectableTestCollector`) into the exact same
`TelemetryWatchdog` a real deployment uses — never touching any real
collector. The harness:

1. Confirms the watchdog reads HEALTHY with the fault collector ticking normally.
2. Calls the debug-only `POST /api/debug/telemetry/fault?freeze=true` (a route
   that does not exist in the app's route table at all unless that env var
   was set at boot).
3. Waits past the collector's own stale bound and confirms the watchdog
   transitions to DEGRADED, reason `stale_poll`.
4. Calls `freeze=false` and confirms the watchdog returns to HEALTHY only
   after `last_poll_completed_at` genuinely advances again — not merely
   because the flag flipped.

## Predeclared PASS criteria

**PASS only if every one of the following holds:**

1. Zero silent collector deaths — no wired collector's `is_running()` goes
   `False` unexplained (a deliberate stop for shutdown does not count).
2. Zero periods where a collector's poll age exceeds its own stale bound
   while the watchdog's `overall` field simultaneously reads `HEALTHY` —
   computed independently by the harness from the raw ages, not by trusting
   the watchdog's own self-report alone.
3. Zero unexplained event-loop stalls beyond 5.0 seconds (the existing
   `_loop_stall_monitor` print threshold is 1.5s; 5.0s is the harness's
   pass/fail bound, generous over normal jitter and drastically smaller than
   the historical 200s+ catastrophic freezes this system exists to catch).
   Any stall observed must correlate to an explainable phase transition
   (e.g. process-launch burst) or is an unexplained failure.
4. Every wired collector completes repeated polls throughout the *entire*
   soak — sampled poll ages stay within their stale bound at every sample,
   not just at the end.
5. The API remains responsive: every `/api/health` sample during the run
   succeeds within its timeout.
6. Phase C causes `/api/edr/causality/stats`'s `nodes` (or `artifacts`)
   count to be strictly higher after phase C than before it — proof the
   pipe stayed alive and ingesting, independent of whether any technique
   was scored as a detected incident.
7. Fault-detection step only: the watchdog reaches DEGRADED after freeze and
   returns to HEALTHY only after real recovery (criterion above).
8. No reasoning-layer regression: Platform Alpha's frozen baseline
   (`tests/test_platform_alpha_baseline.py`) still passes unchanged.

A single run failing criterion 3 alone (an isolated CI-runner hiccup) does
not fail the whole qualification on its own — see "Independent runs" below —
but every criterion must pass in the *majority* of the three independent
runs, and criteria 1, 2, 6, 7, and 8 must pass in **all three**.

## Independent runs

Three independent 20–30 minute runs on three fresh `windows-latest` runners,
not one. `docs/LIVE_FIRE_EVALUATION.md` already established the operating
principle this project uses for exactly this reason: shared CI can have
transient slowness, so a single clean run is weak evidence on its own.

## Sequence

1. Commit watchdog infrastructure separately. (done — see git history)
2. 2–3 min local/API smoke — **not qualification evidence**, syntax/API
   sanity only.
3. CI 5-minute dry-run — validates the harness itself and its artifact
   pipeline, not reliability.
4. CI fault-detection run — proves the alarm fires and recovers correctly.
5. CI 20–30 minute qualification soak.
6. Repeat step 5 on two more independent fresh runners (3 total).
7. If all pass per the criteria above, freeze this as the Beta 0.5 baseline
   and move to Platform Beta 1 (NYX). If not, the gap is named and fixed
   before re-running — never averaged away or quietly dropped.

## Beta 0.5.1: contention attribution

The corrected qualification run remains a failure: only one of three fresh
runners completed, Runs 1 and 2 lost API responsiveness, and Runs 2 and 3
reported stale collectors. Platform Alpha stayed green on all three, which
isolates the open problem to live telemetry reliability rather than reasoning.

Before another 3 x 25-minute qualification, the `contention` workflow mode
runs the exact same A-E workload and strict bounds on one fresh runner. It
stops at the first API failure or watchdog DEGRADED transition and records:

- start, end, duration, and outcome for every sampled API request;
- event-loop heartbeat state and drift;
- collector poll start time, running duration, current internal stage, stage
  running duration, last stage durations, and longest completed poll;
- active Python thread inventory and AnyIO worker-pool token/waiter state;
- engine CPU, memory, thread, and handle counts;
- the continuously drained engine log.

Persistence stages are split into run keys, services, scheduled tasks, startup
folders, and diff/normalization/emission. Process stages are split into process
enumeration, per-process metadata, and diff/enrichment/emission. Network stages
separate connection enumeration from diff/scoring/emission.

The harness previously left engine stdout connected to an undrained pipe until
shutdown. A full Windows pipe can block its writer, so that setup could itself
create progress loss. Engine output now streams directly to the evidence log.
This is a harness correction, not a relaxed reliability bound. API timeouts,
collector stale bounds, workload density, and scoring remain unchanged.

After attribution, fix only the smallest demonstrated cause, preserve a
regression test, run the corrected 5-minute dry-run, repeat the fault test only
if watchdog behavior changed, then repeat the full 3 x 25-minute qualification.
