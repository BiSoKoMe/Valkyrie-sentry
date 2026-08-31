# Platform Beta 0.5 — Telemetry Reliability Qualification

## Qualification status

**OPEN. No next milestone starts until this is fixed and proven.** An
engine-process-disappearing finding (see "Beta 0.5.5" below) is not yet
root-caused; continuous resource instrumentation was added specifically to
stop guessing at it (see "Reversed, 2026-08-30" near the end of this
document) and the investigation is active, not deferred.

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

**Update, same day, after the undrained-pipe fix (see "Beta 0.5.1" below):**
the corrected dry-run and fault test passed again; the 3x25-minute soak
(`33334684087`) was still 1/3 (run 1 PASS). The pipe fix clearly worked - no
run showed the old 25+-API-timeout / 200s+-stall shape - but run 2 had one
API failure plus two small `process_collector:stale_poll` samples during
phase C (real, unexplained, much smaller magnitude), and run 3 crashed with
an uncaught harness exception (a `subprocess` timeout shorter than the
Tier B runner's own documented worst case, discarding its evidence). See
"Beta 0.5.2" for the fix and what is still open.

**Third attempt**, after the Phase C timeout fix (`33336540336`): 1/3 passed
(run 3), and critically **no run crashed** - the crash-proofing held. Run 1
surfaced a precise, evidenced finding via the new stage-level diagnostics: a
persistence-collector poll cycle stuck for 72.6s inside `diff_normalize_emit`
specifically (not the already-protected registry/service/task-enumeration
stages), while the causality graph, sensors, event loop, and API all kept
advancing normally - ruling out a global freeze and pointing at write-path
lock contention instead. See "Beta 0.5.3". **Still OPEN** - holding for
direction on which of two possible fixes (bound this stage's own wall-clock
time vs. address `EdrStore`'s shared lock) to pursue, since the second
touches shared production code every detection source depends on.

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

### Attribution result, 2026-08-30

The single fresh-runner contention experiment completed the full 25 minutes
without reaching its stop-on-first-failure condition. Run 33332925488 produced
690 successful API samples with zero failures, no stale or dead collectors,
zero DEGRADED transitions, and event-node progression from 239 to 450. Platform
Alpha remained green. The worst loop drift was 4.765 seconds, below the strict
5-second bound.

The corrected output handling supplies a direct mechanism for both symptoms in
the failed qualification. Uvicorn request logging and the persistence poll
diagnostic both wrote to the same undrained subprocess pipe. Once its finite
Windows buffer filled, an API worker writing an access log could block, and the
persistence thread writing its poll diagnostic could block before beginning its
next poll. Redirecting stdout/stderr to the continuously written evidence file
removes that shared blocking resource. A regression test now forbids restoring
`subprocess.PIPE` without a concurrent drain.

This run is attribution evidence, not qualification evidence. Beta 0.5 remains
open until the corrected dry-run and three independent qualification runs pass.

## Beta 0.5.2: the pipe fix held, a harness timeout bug did not

Corrected CI qualification, second attempt, 2026-08-30 (`33334684087`, after
the undrained-pipe fix): the corrected dry-run (`33334364642`, 6m40s) and the
fault test (unchanged, already green) both passed cleanly first. The 3x25-minute
soak itself: **1/3 passed (run 1)**, run 2 FAILED, run 3 CRASHED.

The pipe fix demonstrably worked: no run this time showed the old shape (25+
API timeouts, 30-consecutive-sample stale stretches, 200s+ loop stalls). Run
2's worst loop drift was 2.58s, comfortably under the 5s bound, and its API
responsiveness was 690/691 samples successful.

**Run 2 (FAIL, real, small-magnitude):** exactly one API health failure and
two `process_collector:stale_poll` samples, both during phase C while the
Tier B subset's process-launch techniques were executing. `no_stale_while_healthy`
(the independent cross-check) still passed - the watchdog itself never lied -
but `no_unexpected_degraded_intervals` and `collectors_advance_throughout`
correctly caught it, exactly the criteria added after the first corrected
attempt to stop eventual recovery from erasing a real stall. This is a much
smaller-magnitude version of the same failure class (thread alive, briefly
not progressing) and remains unexplained: plausibly GIL contention between
`process_collector`'s own `psutil.process_iter()` poll and the ART battery's
process launches, but that is a hypothesis, not yet demonstrated.

**Run 3 (CRASHED, a harness bug, not a reliability finding):** the harness's
own `RuntimeError("Phase E safe Tier B subset did not execute successfully")`
escaped uncaught when `run_phase_c`'s second (Phase E) invocation hit the
harness's `subprocess.run(..., timeout=300)` bound and was killed. That bound
was never checked against what it was timing: `run_live_evaluation.ps1`'s own
`-ReadyTimeoutSeconds` defaults to 420s and its readiness gate legitimately
tolerates gaps up to that whole budget before a single technique executes,
plus up to 30s x 3 techniques after that - a documented worst case of ~510s,
already past the harness's 300s bound. The crash discarded all 20+ minutes of
sampler evidence run 3 had already collected, which is precisely the failure
mode this project's own Tier B tooling (`.partial.jsonl` streaming,
`union_coverage.py`'s crash-tolerant union) was already built to avoid
elsewhere - this harness had not yet applied that lesson to itself.

Fixed (not yet re-verified in CI):
- `PHASE_C_TIMEOUT_S` raised to 600s, with the 510s worst-case budget stated
  in the code as the reason, not a round number picked by feel.
- On a timeout, `run_phase_c` now prints whatever stdout/stderr the script
  had already produced before the kill, so a future occurrence is
  diagnosable (was a technique executing, or still waiting on the readiness
  gate?) instead of just "it timed out."
- A Tier B subset failure or timeout in phase C or phase E is now a scored
  criterion (`phase_c_technique_execution_completed`) rather than a raised
  exception - the harness always finishes, writes its summary, and reports
  what it actually observed, matching the crash-proof discipline the rest of
  this project already applies to Tier B. Covered by
  `tests/test_beta05_reliability.py` checks [11]-[12].

Beta 0.5 remains **OPEN**. Next: rerun the 3x25-minute qualification with
these fixes; if run 3's crash was purely the timeout bug, it should now
produce a real, scored result instead of losing its evidence. Run 2's
small-magnitude `process_collector:stale_poll` during phase C is still real
and still needs its own root cause before this qualification can pass -
being smaller than the pre-pipe-fix failures does not make it acceptable on
its own terms, per this document's own criterion 2.

## Beta 0.5.3: the timeout fix held (no more crashes); a new, more precise finding

CI qualification, third attempt, 2026-08-30 (`33336540336`, after the
Phase C timeout fix): corrected dry-run (`33336229646`) passed again. The
3x25-minute soak: **1/3 passed (run 3 this time)**, run 1 and run 2 FAILED -
but critically, **neither crashed**. Both ran the full 25 minutes and
produced a real, scored result, confirming the crash-proofing fix worked.

**Run 2:** one API failure, one `process_collector:stale_poll` sample.
Small, matches the pre-existing unexplained pattern from Beta 0.5.2.

**Run 1:** `no_unexplained_loop_stalls` PASS (worst drift 4.625s), `api_responsive`
PASS (0/692 failures) - the event loop and API were fine the entire run. But
`persistence_collector` went DEGRADED for 14 consecutive 2-second samples
(~26s of sampling, corresponding to a much longer real stall) during phase E.

`PollDiagnostics` (Beta 0.5.1's stage instrumentation) pinpointed this
precisely, which is exactly what it was built for: the stall was NOT in
`run_keys`, `services`, `scheduled_tasks`, or `startup_folders` (the stages
the original 253s-freeze fix already protects with a cooperative yield and a
wall-clock budget) - it was entirely inside `diff_normalize_emit`, which has
no such protection, and it ran for **72.594 seconds** in one poll cycle.

Cross-checking the same window's `/api/edr/causality/stats` (`nodes`) and
`/api/sensors/status` (`submitted`/`emitted`) shows both climbing normally
throughout the entire 72s stall. That rules out a global GIL/event-loop
freeze (the original failure class) - everything else in the process kept
making progress. Only this one thread's own poll cycle was stuck, which
points at something that blocks that thread specifically rather than
starving the whole interpreter.

The leading hypothesis, from reading the code (not yet proven by a targeted
repro): `valkyrie/edr/store.py`'s `EdrStore` guards every write
(`add_detection`, incident upsert, response log) behind one shared
`threading.RLock()`, and every telemetry source's `ingest_telemetry()` call
writes through it. `diff_normalize_emit` calls `_emit_new()` once per new
persistence entry found in that cycle's diff, each of which blocks on that
same lock. Under Phase E's dense concurrent write load (process launches
from the benign command loop, PLUS the ART battery's own detections, all
landing on the same lock), a cycle that discovers several new entries at
once would wait its turn for each one sequentially - unbounded Python-level
lock queueing, not a 5-second SQLite `busy_timeout` (`valkyrie/store.py`
already sets `PRAGMA busy_timeout=5000` and WAL mode, which caps genuine
SQLite-level contention, but does not bound how long this collector's thread
queues on the shared Python `RLock` before ever reaching SQLite).

This is left as a named, evidenced finding rather than an in-flight fix: it
touches `EdrStore`, the shared write path every detection source in the
product depends on, not test-only harness code. Two different-sized fixes
are possible - give `diff_normalize_emit` the same wall-clock-budget-and-defer
treatment `snapshot()`'s other stages already have (bounds this symptom
without touching the shared lock), or address the lock contention in
`EdrStore` itself (a bigger, more invasive change to code every collector and
the EDR engine depend on). Which one to pursue is a real design decision, not
a mechanical fix, and is being held for direction rather than decided alone.

**Decision: do both, landed separately.** The small fix (bound
`diff_normalize_emit`'s own wall-clock time) is landed now, so Beta 0.5 has a
concrete mitigation to re-test. The `EdrStore` lock-contention question is
**not** being fixed under this qualification's time pressure - it is tracked
as its own follow-up investigation (see "Follow-up" below), separate from
whether Beta 0.5 itself passes.

### The `diff_normalize_emit` budget (landed)

`PersistenceCollector` gained an `emit_budget` parameter (default 4.0s,
floored at 1.0s, mirroring `snapshot_budget`'s own floor). `poll_once()` now
tracks wall-clock time across the diff/emit loop; once the budget is spent,
any remaining newly-discovered entries this cycle are deliberately left OUT
of the new baseline (`self._last`) rather than emitted or dropped - so the
next poll's diff rediscovers and retries them. `last_poll_completed_at` is
therefore bounded by `emit_budget` the same way `snapshot()` is already
bounded by `snapshot_budget`, regardless of how long the underlying
`EdrStore` write actually takes. `.status()`'s existing `truncated` field
(previously set by `snapshot()` but never actually surfaced anywhere) now
also reports when this stage had to defer, and now that it is read anywhere,
it is exposed. Covered by
`tests/test_endpoint_telemetry.py::test_diff_normalize_emit_defers_rather_than_blocks_when_budget_exhausted`.

Trade-off, stated plainly: a persistence detection whose emit is deferred
surfaces one poll cycle later (up to `poll_interval_s`, 15s by default) than
it otherwise would have. That is the accepted cost of never letting
`last_poll_completed_at` go stale for longer than `emit_budget` regardless of
write-path contention.

### Follow-up (tracked, not fixed here): `EdrStore`'s shared write lock

`valkyrie/edr/store.py`'s `EdrStore` serializes every write
(`add_detection`, incident upsert, response log) behind one
`threading.RLock()` shared across every telemetry source and the EDR engine
itself. The evidence above is consistent with this becoming a real
contention point under concurrent write load (dense process-launch activity
plus simultaneous ART-technique detections), but it has not yet been
directly proven with a targeted repro (e.g. instrumenting the lock's own
acquisition wait time). Whether and how to relax this - per-writer batching,
a queue instead of synchronous inline writes, sharding the lock, or leaving
it as-is if a targeted repro shows the contention is rarer than this one
sample suggests - is an open design question against code every collector
and the EDR engine depend on, and deserves its own investigation rather than
a change rushed under this qualification's time pressure.

Beta 0.5 remains **OPEN**. Next: rerun the 3x25-minute qualification with the
`diff_normalize_emit` bound in place.

## Beta 0.5.4: the persistence stall is gone; the same fix applied to ProcessCollector

CI qualification, fourth attempt, 2026-08-30 (`33338623568`, after the
`emit_budget` fix): corrected dry-run passed again. The 3x25-minute soak:
**2/3 passed** (runs 2 and 3), up from 1/3. Run 1's own
`persistence_collector` was **696/696 healthy samples, `pass: true`** - the
72s-class stall is gone. Its only remaining failure was a single
`process_collector:stale_poll` sample (695/696 healthy) - the same small,
recurring, one-or-two-sample pattern already seen (unexplained) across
multiple earlier runs.

`ProcessCollector.poll_once()` had the exact same shape as
`PersistenceCollector`'s pre-fix `diff_normalize_emit`: `self._last = new`
committed immediately, then an unbounded loop calling `self._emit(...)` once
per newly-discovered process - subject to the identical `EdrStore`
lock-contention mechanism, just far less often triggered (process_collector
polls every 2s vs. persistence's 15s, so far fewer new items typically
accumulate per cycle before its own, much shorter, 8s stale bound is
reached). Applied the identical fix: `ProcessCollector` gained the same
`emit_budget` parameter and `diff_enrich_emit` wall-clock bound, deferring
any not-yet-emitted new process to the next poll rather than blocking
`last_poll_completed_at` on a slow/contended emit. Covered by
`tests/test_process_telemetry.py`'s new `[5b]` checks, mirroring
`test_endpoint_telemetry.py`'s persistence-side test exactly.

Beta 0.5 remains **OPEN**. Next: rerun the 3x25-minute qualification with
both collectors bounded; if this was the last of the recurring
single-sample staleness, all three runs should pass clean.

## Beta 0.5.5: a new, more fundamental failure - the engine process itself, not a collector

CI qualification, fifth attempt, 2026-08-30 (`33340339842`, after the
`ProcessCollector` fix): dry-run passed again. The 3x25-minute soak: **1/3
passed** (run 2). Run 1 **crashed** the harness with an uncaught
`ConnectionRefusedError`; run 3 produced a real scored FAIL (19 API
failures, one Phase E Tier B subset failure).

This is NOT the collector-staleness class the `emit_budget` fixes address.
In both failing runs, `/api/health` went from succeeding to
`ConnectionResetError` ("forcibly closed by the remote host") to
`ConnectionRefusedError` ("actively refused") - the shape of a listening
socket that stopped existing, not a slow response. Run 1's own engine log
(now fully captured thanks to the Beta 0.5.2 pipe fix) confirms this: it
printed startup banners and healthy `[persist-poll]` timings up to
`23:02:55`, then stopped entirely - no exception, no shutdown message,
nothing - while the harness kept trying and failing to reach it for the
next ~7 minutes until an unprotected `_safe_get`-less call crashed the
script. Run 3 hit the same "engine unreachable" shape for about 19 samples
(~38s) but recovered on its own and finished the full run. This happened
during Phase C / early Phase E - the highest concurrent-load window (the
harness's own benign-command loop, `run_live_evaluation.ps1`'s ART battery,
and the engine's own collectors/ETW sensors/EDR reasoning all running at
once on a 2-vCPU runner). The leading hypothesis is resource exhaustion
(memory or handle pressure) under that combined load, not yet confirmed -
stated as a hypothesis, not a proven cause.

Two things fixed, both harness robustness (not reliability-bound changes):
- Every direct API call in `run_soak`/`run_dry_run` outside the Sampler now
  goes through `_safe_get`, which never raises - a before/after causality
  snapshot that fails is recorded as unavailable, not a crash.
- The entire phase-execution body in both functions is now wrapped in a
  top-level `try/except`: any unhandled exception is recorded
  (`unhandled_exception` in the result, forcing `overall: FAIL`) and
  scoring still runs against whatever samples were already collected,
  instead of losing them. This is the same principle behind Beta 0.5.2's
  crash-proofing, generalized - a new call site crashing (this one) proved
  the earlier fix was scoped to one symptom, not the actual invariant
  ("this harness must never lose evidence to an uncaught exception,
  anywhere").
- A new, explicit criterion, `engine_process_alive_throughout`, checks the
  engine subprocess's own exit code directly (`proc.poll()`) rather than
  inferring "the engine is fine" from the absence of HTTP errors - the
  engine disappearing entirely is a more fundamental failure than any
  single collector or API call going stale, and deserves its own name in
  the report rather than showing up only as a pile of `api_responsive`
  failures.

This finding is NOT yet root-caused, unlike the collector-level stalls.
Whether it is resource exhaustion, something specific to running the
benign-command loop and the ART battery concurrently, or a runner-specific
flake needs its own targeted investigation (e.g. capturing engine memory/
handle counts throughout a run, or running phase C and the benign loop
sequentially instead of concurrently as a controlled experiment) rather than
another guess-and-patch cycle.

Beta 0.5 remains **OPEN**. The qualification cannot pass while the engine
process itself can disappear mid-run, regardless of how clean the
collector-level metrics are otherwise.

### Contention-mode attempt, 2026-08-30 (inconclusive)

A single dedicated `--mode contention` run (`33341952582`, one fresh
runner, stop-on-first-failure, rich psutil/thread/worker-pool diagnostics
armed) ran the full 25 minutes and did **not** reproduce the engine-death
shape: `overall: PASS`, `first_failure: null`,
`experiment_completed_without_failure: true`. This does not clear the
finding - the failure was already intermittent (2 of 3 runners hit it in
the batch that found it, 1 did not), so one clean attempt is exactly the
kind of single-run result this project's own methodology (union-across-runs,
`docs/LIVE_FIRE_EVALUATION.md`) already treats as weak evidence on its own.
It is recorded as inconclusive, not as a clean bill of health.

## Reversed, 2026-08-30: no next step until this is actually fixed and proven

The "track it, move to NYX" call above was rejected: this qualification's
whole discipline is "we only move on if we fix and prove it," and an
unattributed engine-death finding does not meet that bar just because CI
cycles are expensive. Continuing the investigation, not deferring it.

### Continuous engine-resource instrumentation (measure before guessing again)

One dedicated `--mode contention` attempt not reproducing the failure is
weak evidence either way - and guessing at the cause (resource exhaustion)
without measuring it would repeat the exact mistake this project's own
methodology exists to prevent ("measure before mitigate, falsify don't
rationalize"). Rather than keep re-running the same blind experiment, the
harness now captures the engine process's own resource usage - RSS, virtual
memory, thread count, handle count, CPU - on **every sample**, not only at
the moment a failure is detected. A clean run now produces a full resource
timeline (does anything trend toward a wall even when nothing fails?); a
run that does hit the engine-death shape now has the complete lead-up, not
one snapshot taken after the fact.

Implementation: `_engine_process_stats(pid)` (one cached `psutil.Process`
handle per pid across the whole run, since `cpu_percent()` only means
anything measured against its own last call on the same handle) is now
called from `Sampler._sample_once()` every `SAMPLE_INTERVAL_S`, and
`_capture_failure()` reuses that same per-cycle reading instead of taking
its own separate one. `score()`'s output always includes
`engine_resource_trend` (first/last/min/max for rss/handles/threads across
the run, plus any process-read errors like `NoSuchProcess` verbatim - itself
evidence the process had already exited, not merely gone quiet). This is
deliberately **not yet a pass/fail gate** - there is no measured threshold
for what "trending toward a wall" looks like for this engine on this runner
class yet, and inventing one before seeing real numbers would be exactly
the guessing this instrumentation exists to replace. Bounds get set from
what real runs actually show, the same way `snapshot_budget`/`emit_budget`
were sized from measured numbers rather than picked ahead of any data.
Covered by `tests/test_beta05_reliability.py` checks `[14]`-`[17]`.

Next: rerun contention mode (and/or the full soak) with this instrumentation
active, and read the actual resource trend - whether or not the engine-death
shape reproduces this time - before deciding what, if anything, needs fixing.

## Beta 0.5.6: a real, precise cause found - not resource exhaustion

A contention-mode run with the new instrumentation active (`33343938831`)
stopped early at 11m33s, having caught a real failure: `process_collector`
went `stale_poll` (8.32s vs. its own 8.0s bound) during phase C. Critically,
the engine's own resource snapshot at that exact moment was completely
unremarkable - 84.7MB RSS, 696 handles, 29 threads, 14.8% CPU, no different
from the clean dry-run's baseline range. **This rules out resource
exhaustion as the cause of this failure.** The API was still answering
(`health_ok: true`) throughout - this was never the "engine disappears
entirely" shape, a smaller and more mundane failure than the one this
instrumentation was built to catch, but a real one, and precisely
diagnosable from the data this run captured.

`process_collector`'s own `PollDiagnostics` pinned it exactly:
`poll_started_at` to `current_stage_started_at` (entering
`diff_enrich_emit`) was **3.8 seconds**, before `emit_budget` even had a
chance to bound anything. That time was spent in the `process_iter` /
`process_metadata` stages - i.e., inside `ProcessCollector.snapshot()`
itself, not the emit path the earlier fixes addressed.

Reading `snapshot()`'s code confirmed why: it called `pr.exe()` (a real
syscall) for **every currently-running process on the host, every single
poll** - not only newly-appeared ones - to populate a `path` field that,
for a process already seen in a prior poll, cannot have changed. Under
Phase C/E's process-launch load this is O(all running processes) work every
2 seconds, for a value that is almost always unchanged from last time.
`PersistenceCollector`'s `snapshot()` already had cost-bounding from the
original 253s-freeze fix; `ProcessCollector`'s never did.

**Fixed:** `snapshot()` now looks up each process by `(pid, create_time)`
against `self._last` (the prior poll's baseline) before calling `pr.exe()`;
an already-known process instance reuses its previously-observed path
instead of re-querying it, turning the cost from O(every running process)
into O(genuinely new processes) per cycle. Verified live: a real
`snapshot()`/`snapshot()` back-to-back pair on this machine's own process
table shows the second call makes zero `pr.exe()` calls for any process
seen in the first (`tests/test_process_telemetry.py` `[5c]`, which
monkeypatches `psutil.Process.exe` to count real calls rather than
asserting on a guess).

This is real, causally-verified progress on the reliability question, but it
answers "why did ProcessCollector go briefly stale under load" - it is not
yet proven to be the same or a different mechanism from the earlier,
more severe "engine becomes completely unreachable" shape (Beta 0.5.5),
which this run did not reproduce. Both are real; only one is now fixed with
proof.

Beta 0.5 remains **OPEN**. Next: rerun contention mode and the soak with
this fix in place, and keep reading the engine_resource_trend data on every
attempt - if the engine-death shape does reproduce again, this same
methodical stage-level attribution is exactly what should be pointed at it
next, not a repeat of the same guess-and-patch loop.
