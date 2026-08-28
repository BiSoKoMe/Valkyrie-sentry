# Live-Fire Validation - Run Plan (resume after host reboot)

Written 2026-08-12, before the first real live validation of the Sysmon EID1 -> IOA wiring.
Branch `feat/efficacy-etw-coverage`. This plan exists because the host had to be rebooted
for RAM headroom mid-setup.

## Ground truth going in

- Live detection is **UNPROVEN**. Only real live run on record: **1/40 (2%)**.
- All 90-98% figures were offline Tier A replay, not live. Do not cite them.
- The claim "2.9% was a measurement bug / 6/6 live" is **unsupported**. Do not repeat it.

## Pre-boot gate (hard stop)

Measure with the perf counter, not `FreePhysicalMemory`:

```powershell
(Get-Counter '\Memory\Available MBytes').CounterSamples[0].CookedValue
```

Require **>= 11000 MB** for the 8 GB VM. Below that, stop and report - do not boot.
Booting short causes guest timeouts and dropped events that masquerade as detection
misses and corrupt the run.

## Steps

1. **Boot** `valkyrie-lab` headless from snapshot `pre-redteam-valkyrie-live`
   (not the current snapshot `post-fixes-clean`).
2. **Deploy the DIRTY WORKING TREE.** Do not clone or checkout the branch.
   - Working tree: **146** rules. `HEAD`: **40**. The EID1 wiring is uncommitted too.
   - Verify inside the guest after copying:
     `grep -cE '^\s*Rule\(' valkyrie/behavioral_rules.py` must print **146**.
   - Restart the Valkyrie service.
3. **Verify the sensor is live BEFORE firing anything.** A sensor-down run is not a
   detection failure and must never be scored as one.
   - Sysmon service running.
   - Sysmon is emitting **EID1 with a populated `CommandLine`** (fire one benign
     `powershell.exe -Command Get-Date` and confirm it appears in the operational log).
   - Valkyrie healthy on `:8090`; `/api/edr/incidents` returns 200.
   - Confirm an incident can actually be written (baseline count before firing).
4. **Fire** real Invoke-AtomicRedTeam across the technique set.
5. **Score against the live incident store.** Report separately:
   attempted / executed / detected / blocked-before-execution / missed /
   detection latency / false positives / sensor failures / infra failures.
   Never fold infra or sensor failures into misses.

## Known issue to fix first: eval polling degrades the API

`run_live_evaluation.ps1` currently polls per technique - `while ((Get-Date) -lt $deadline)`
around line 331 - issuing a full `GET /api/edr/incidents` every `$PollIntervalSeconds`
for up to `$DetectWindowSeconds` (30s) **per technique**, plus a detail GET per touched
incident. Cost grows with the incident store, which is the known degradation symptom.

**Do not fix this by raising timeouts or swallowing errors.** Refactor to
fire-all-then-query-once. It is feasible with no loss of fidelity because:

- each detection carries its own `timestamp` (`server.py:139`), and
- incident heads carry `updated_at`.

Design:

1. Per technique, record `execStartUtc` / `execEndUtc`. Fire all techniques back to back
   with **no polling in between**.
2. After the last technique, sleep once past the slowest collector (persistence polls
   ~15s; use ~45s) so artifact-at-rest detections land.
3. Do **one** sweep: list incidents once, pull detail once per incident.
4. Attribute each detection to a technique by **technique ID match first**, using the
   `[execStartUtc, execEndUtc]` window only as a staleness filter and tiebreaker -
   techniques run sequentially so their windows are disjoint. This preserves correct
   attribution for late-arriving detections that the current time-window-only approach
   would misassign to the following technique.
5. Latency = `detection.timestamp - execStartUtc`, computed offline. This is *more*
   accurate than the current poll-interval-quantized measurement.

## Per-miss protocol

For each genuine live miss, find root cause and classify it as one of:
**rule gap** / **wiring** / **sensor precondition**. Fix as a general behavior class,
not a single command string. Redeploy, then re-run that technique **plus unseen
variations** to confirm the fix generalizes rather than fitting the test.

Loop until real misses are fixed or honestly documented as unresolved.
Report the real numbers plainly, even if low.
