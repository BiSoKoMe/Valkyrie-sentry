# Tier B Live-Fire Validation — Cloud Run Plan

Written 2026-08-23. Companion to `RUN_PLAN_LIVE.md`, which remains the
authority on *what* is measured and *how it is scored*. **This document changes
only the host.** Every gate, every honesty rule and every reporting requirement
in `RUN_PLAN_LIVE.md` still applies verbatim.

## Why this exists

The Tier B blocker on record is a **local** hardware limit, not an absolute
one: a 16 GB laptop with Hyper-V/VBS enabled forces VirtualBox into NEM, which
produced 25-minute non-boots, and only ~4.8 GB is free with a browser open.
Every one of those facts is a property of one particular machine. A cloud VM
has its own dedicated RAM on someone else's hardware; the laptop's only job
becomes running an RDP window. The block dissolves.

This is the single highest-leverage unblock in the project, because the largest
unknown in Valkyrie is not a missing feature — it is that the end-to-end
detection rate has never been measured. The only real Tier B number on record
is **1/40 (2%)**. The 90%+ figures are Tier A synthetic replay and must not be
cited as detection rate.

---

## 0. BLOCKER — fix the harness before spending any money

`run_live_evaluation.ps1` still polls **per technique**: line ~521 opens a
`while` loop issuing a full `GET /api/edr/incidents` every `$PollIntervalSeconds`
(default 2) for up to `$DetectWindowSeconds` (default 30), plus a detail GET per
touched incident. Cost grows with the incident store.

This is not a performance nit. This harness's own history records a **measured**
confound: run 32441713709 (settle=3 plus two per-technique API reads) recorded
**4** distinct techniques in the incident store, while run 32440735442
(settle=0) recorded **27** — on a *byte-identical engine*, with only the harness
changed. Harness-induced API load changes the result being measured.

`RUN_PLAN_LIVE.md` already specifies the fix and explicitly forbids the lazy
version ("Do not fix this by raising timeouts or swallowing errors"):

1. Per technique record `execStartUtc` / `execEndUtc`; fire all techniques back
   to back with **no polling in between**.
2. After the last technique, sleep **once** past the slowest collector
   (persistence polls ~15 s; use ~45 s).
3. Do **one** sweep: list incidents once, pull detail once per incident.
4. Attribute by **technique ID match first**, using the exec window only as a
   staleness filter and tiebreaker (techniques run sequentially, so windows are
   disjoint). This keeps attribution correct for late-arriving detections.

### Status

**Step 4 is DONE.** `attribute.py` implements the attribution offline as a pure
function over (fired techniques, one incident snapshot), with 27 checks in
`test_attribute.py`. Moving it out of PowerShell is what makes it verifiable at
all: logic embedded in a script that has never run end to end cannot be tested,
and this logic decides what counts as a detection. It preserves the previous
semantics exactly — technique-ID-first matching, substring comparison, folded
detections still count, user rules recorded but not counted, FPs attributed by
disjoint window — and improves one thing: **latency now comes from the
detection's own timestamp** rather than from poll cadence, which could not
resolve below 2 s and charged its own sleep to the product.

**Steps 1–3 remain**, and they are now a small, well-bounded PowerShell change:

- record `execStartUtc` / `execEndUtc` per technique (already computed);
- delete the `while ((Get-Date) -lt $deadline ...)` loop at ~line 521 and the
  per-technique FP re-read that follows it;
- keep the two `Get-SensorDrops` reads per technique — they are O(1), do not
  grow with the incident store, and carry the "a miss here may be a blind
  sensor, not a rule gap" diagnostic that the honesty reporting depends on;
- after the battery: one settle sleep, one `Get-Incidents`, one detail read per
  incident, dump to JSON;
- hand that JSON plus the fired-technique windows to `attribute.py`, then
  `merge_into_records()` into the existing result schema and score as before.

**Do this before provisioning anything. It is offline and free, and it is the
difference between buying a number and buying an artifact of the harness.**

---

## 1. Budget design — the $10 guard

The run is cheap. *Forgetting the VM* is what is expensive.

| Item | Approx | Note |
|---|---|---|
| B2s-class Windows VM | ~$0.08–0.12/hr | verify at purchase; regional |
| Managed OS disk (~30 GB) | ~$0.01/hr prorated | billed while the disk exists, running or not |
| Public IP | ~$0.005/hr | |
| **All-in** | **~$0.15/hr** | |
| **A full run (6–8 h)** | **~$1.00–1.20** | |
| **A VM left running for a month** | **~$108** | ← the only real risk |

Note that a *deallocated* VM still bills for its disk. Stopping is not deleting.

**Mandatory controls, set up BEFORE creating the VM:**

1. **Budget alert at $5** (Azure Cost Management → Budgets), with an email
   action. This is the backstop for every other control failing.
2. **Auto-shutdown at a fixed daily time** (Azure VMs have this built in, one
   toggle). Set it even if you plan to finish in one sitting.
3. **Delete the whole resource group when done** — not the VM, the *resource
   group*. Deleting the VM alone leaves the disk, the NIC and the public IP
   billing quietly. Put everything in one throwaway group named for the run.
4. If this is a new Azure account, the **$200 / 30-day credit** likely makes the
   whole exercise free. Confirm the credit is applied before assuming it.

Verify current prices at the vendor pricing page at purchase time. Third-party
pricing summaries are unreliable — one consulted for this plan stated a monthly
figure of ~$60.74 and then concluded "$2–3 per hour," which is internally
inconsistent by a factor of ~30.

---

## 2. Image choice — and an honest caveat

**Recommended for run #1: Windows Server 2022 Datacenter**, because it is
freely available on pay-as-you-go.

**The caveat, stated rather than buried:** Valkyrie's target is consumer
Windows 11, and Server 2022 is not that. Windows client images (10/11) on Azure
require a qualifying licence/subscription and are not simply available on
pay-as-you-go, so a faithful consumer image means bringing your own or paying
more.

What this costs us in fidelity: **little for what this run measures.** The
layer under test is command-line / process / ETW detection — Sysmon EID1,
Security 4688, ETW driver-load — and those behave equivalently on Server 2022.
What differs is Defender's default configuration, consumer-specific paths, and
some UI-driven behaviours. So:

- Report the result as **"Tier B, Windows Server 2022"**, never as an
  unqualified detection rate.
- Treat a consumer-Windows-11 run as a **separate, later** measurement, not as
  something this run stands in for.

---

## 3. Isolation and authorisation

This is authorised security testing on infrastructure you own and control. Keep
it unambiguously that way:

- **Dedicated resource group and virtual network.** Nothing else of yours in it.
- **Inbound: RDP from your IP only.** Never `0.0.0.0/0` — an open RDP port on a
  box that is about to have Defender disabled is an actual liability.
- **Outbound: allowed.** Several atomics legitimately need internet (download
  cradles, DNS). This is fine on a throwaway isolated host.
- **No credentials of yours on the box.** No sign-in to email, no repo
  credentials, no password manager. Deploy the working tree by file copy.
- **Never joins your home network.** It is not a lab extension of your LAN.
- **Snapshot before detonation** so the run is repeatable, and the destructive
  atomics (LSASS dumping, Defender disable, firewall disable, log clearing,
  shadow-copy deletion, account creation) are survivable.

---

## 4. Pre-flight gates — hard stops

`RUN_PLAN_LIVE.md` step 3 is the most important paragraph in this whole
programme, and today's finding proves it: on the dev host right now, `sysmon64`
is **installed but stopped** and `efficacy.sensor_health()` reports the
command-line eye **closed**. In that state all 166 command-line behavioural
rules are structurally incapable of firing. A run started in that condition
would score ~0 and the number would mean *nothing about the rules*.

**Do not fire a single technique until all of these pass:**

1. `python redteam/evaluation/environment.py` — Sysmon present, service
   running, log enabled, **collection live** (fresh events), expected EIDs
   configured.
2. `python -c "from valkyrie.efficacy import sensor_health; print(sensor_health())"`
   — must report `ready=True` with a named source.
3. Fire one benign `powershell.exe -Command Get-Date` and **confirm an EID1 with
   a populated `CommandLine`** appears in the Sysmon operational log. Presence
   of the service is not proof of ingestion.
4. Valkyrie service running; `GET /api/edr/incidents` returns 200.
5. **Prove an incident can be written** — record the baseline incident count,
   trigger one known-good detection, confirm the count moves. A pipeline that
   cannot write is indistinguishable from perfect evasion.
6. **Deploy the working tree, not `HEAD`.** Verify inside the guest:
   `grep -cE '^\s*Rule\(' valkyrie/behavioral_rules.py` must print **166**.

A failure at any gate is an **infrastructure failure**, is fixed, and the run
restarts. It is never scored as a detection miss.

---

## 5. Run sequence

1. Provision VM → snapshot `clean`.
2. Run `redteam/provision.ps1` (Sysmon + config, PS script-block logging,
   Invoke-AtomicRedTeam module).
3. Deploy working tree; install/start Valkyrie; verify on `:8090`.
4. Clear all six pre-flight gates. **Stop here if any fail.**
5. Snapshot `pre-redteam-valkyrie-live`.
6. Run the fixed `run_live_evaluation.ps1` with `-SettleSeconds 0` (pacing is a
   measurement parameter — keep it at 0 and record it).
7. Pull results off the VM (`results/`, the incident DB, the Sysmon log).
8. **Delete the resource group.**
9. Score offline with `score.py` / `union_coverage.py` on the dev machine.

Deliberately not automated: the gate checks in step 4. Scripting past a gate
defeats the point of having one.

---

## 6. What to report

Per `RUN_PLAN_LIVE.md`, report these **separately** and never fold them
together:

attempted / executed / detected / blocked-before-execution / missed /
detection latency / false positives / **sensor failures** / **infra failures**.

Sensor and infrastructure failures are not misses. Conflating them is how a
2% becomes a 90% in a slide deck.

## 7. Honesty

Whatever comes back is the number. If it is far below the Tier A 36/40, that is
a real finding about the gap between replaying inputs at a classifier and
detecting an attack that has to travel sensor → service → incident — which is
exactly the gap this run exists to measure. A result that can only confirm what
we hoped is not a measurement.
