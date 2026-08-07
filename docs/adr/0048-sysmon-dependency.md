# ADR 0048 — Sysmon as a first-class dependency, degraded mode as a main path

Date: 2026-08-05 · Status: accepted

## Context

Three techniques this product claims to detect — T1055 (process injection)
and both T1003.001 paths (LSASS credential dumping) — are only observable
through Sysmon's EID 8 (CreateRemoteThread) and EID 10 (ProcessAccess to
lsass.exe). Nothing else in the sensor stack sees them (`docs/adr/0026-
kernel-driver.md`'s honest boundary). Without Sysmon EID 1, command-line
detection (the 40-rule IOA engine, `cmdline_normalize.py`, the
reconnaissance-burst sequence) falls back to a 2-second `psutil` poll that
most native Windows tools — which exit in well under a second — simply
outrun. Sysmon was treated, before this ADR, as a nice-to-have the red-team
evaluation happened to need. That was wrong: it is a real dependency this
product's advertised detection rate depends on, the way a database or a TLS
library would be.

## The finding that forced this ADR

While diagnosing why this development machine's Sysmon had stopped working,
the actual sequence turned out to be:

1. `SysmonDrv` (boot-start kernel driver) and `Sysmon64` (auto-start service)
   were both installed successfully.
2. At the next reboot, `Sysmon64` crashed 25 seconds later (Service Control
   Manager event 7034, "terminated unexpectedly").
3. `SysmonDrv.sys` was **completely gone** from `System32\drivers` — not
   disabled, not present-but-stopped, gone — and its service registry key
   did not exist at all. No SCM removal event, no uninstall command in any
   shell history. Nothing recorded doing this.
4. Attempting to clean up and reinstall, `Sysmon64.exe -u` (and `-u force`)
   both failed identically: `DeleteService failed: Access is denied` — from
   an elevated Administrator token, against a service whose own security
   descriptor explicitly grants Administrators the delete right.

Readable and queryable, but not modifiable, by an admin, against a
driver-backed service, despite a DACL that says it should work — that
combination is the signature of a security product's self-defense driver
intercepting the Service Control Manager call, not a permissions bug. Avast
(a mainstream consumer AV, active on this machine) is the leading candidate
by elimination — it is the only active third-party security product on the
box — but this was **not** confirmed by a log entry naming it; its
readable text logs and quarantine chest showed nothing Sysmon-related.
Root-cause certainty was not reached, and this ADR does not claim it.

**The generalization matters more than the specific cause.** Whether it was
Avast specifically or a wider class of consumer AV self-defense behavior, a
kernel-driver-backed monitoring tool colliding with a resident AV's
behavioral engine is not a one-off — it will happen on a meaningful fraction
of real client machines running mainstream consumer antivirus. That
reframes the entire feature:

**Degraded mode is not an edge case to handle eventually. It is a main path
this product must be designed for from the start.**

## Decision

### 1. Sysmon is downloaded, not bundled (licensing)

The Sysinternals EULA does not permit redistribution. Valkyrie never ships
`Sysmon64.exe` in the installer or commits it to source control.
`valkyrie/sysmon_manager.py` downloads the official signed build from
Microsoft's own Sysinternals live endpoint (`config.SYSMON_DOWNLOAD_URL`) at
install/first-run time, verifies the Authenticode signature names Microsoft
(`verify_microsoft_signed` — rejects a validly-signed-but-non-Microsoft
binary, not just an invalid one) **before executing anything extracted from
the archive**, then installs it with Valkyrie's own minimal event config
(`VALKYRIE_SYSMON_CONFIG`) — narrowly scoped to exactly what this product's
detectors read (EID 1/3/7/8/10/11/13/25), not the much larger
SwiftOnSecurity community config `redteam/provision.ps1` uses for red-team
research. A researcher's box and a shipped agent's telemetry footprint are
different things.

### 2. Every install outcome is a named, first-class result — never a caught exception

`install_or_verify()` returns a `SysmonInstallResult(mode, degraded, reason,
env)`. Every branch is real and expected, not a generic catch-all:

| Mode | Meaning |
|---|---|
| `already_ours` | Healthy, Valkyrie installed it |
| `installed` | Fresh install succeeded and verified live |
| `foreign_config_left_alone` | Someone else's Sysmon is running; not touched — degraded only if its config is missing an EID Valkyrie needs, never because it isn't "ours" |
| `broken_needs_manual_repair` | Registered but not delivering events (the exact shape found above) — **not auto-repaired**, see below |
| `blocked_by_security_software` | Install ran, exit 0 or not, but the driver never came up live — the named outcome this ADR exists to give a name to |
| `download_failed` / `signature_rejected` | Network/signature failure |
| `not_windows` | Sysmon is Windows-only |

Critically: **the function never raises and never blocks startup.** Every
mode carries `degraded: bool`, consumed by the status box and the web API,
never by the decision of whether Valkyrie runs.

### 3. Never clobber, never auto-force-repair

- A **pre-existing foreign Sysmon** is never overwritten. Someone else's
  config may be load-bearing for their own tooling. Degraded status is
  judged on EID *coverage*, not on authorship — a foreign config that
  happens to cover everything Valkyrie needs is reported healthy.
- A **broken registration** (present, not delivering, the finding above) is
  **not automatically uninstalled and reinstalled**. This is deliberate,
  informed directly by the failure above: an automated repair cycle risks
  reproducing the exact self-defense collision that made this exact state
  undeletable even from an elevated admin token. Reporting it clearly and
  leaving it for manual remediation is safer than a service silently
  retrying a destructive operation against a security product's defenses,
  unattended, possibly in a worse way each time.
- **Uninstall removes only what Valkyrie added.** A `sysmon_managed_by_
  valkyrie.json` marker (written only on a Valkyrie-driven fresh install)
  gates `uninstall_valkyrie_sysmon()` — no marker means no action, by
  design, regardless of whether Sysmon happens to be present.

### 4. Status is surfaced, not buried

- The startup status box (`build_status_rows`) gets a `Sysmon` row like
  every other subsystem — red (✗) when degraded, with the specific reason,
  which flips overall `protection_state()` to `DEGRADED` the same way a
  failed firewall or DNS bind already does. No special-casing that would let
  a Sysmon failure hide behind an otherwise-green status box.
- `GET /api/sysmon/status` exposes `sysmon_healthy` / `degraded` / `detail`
  from the sensor-tamper monitor's cached state (see below) — deliberately
  a cache read, not a fresh probe, because `probe_sysmon()` shells out to
  PowerShell several times and a dashboard may poll this endpoint often.

### 5. Sensor tamper detection (new capability, not previously existing)

Nothing in this codebase, before this ADR, noticed when one of Valkyrie's
own sensors disappeared. That is exactly what happened above, silently, with
zero audit trail, while the engine kept reporting healthy. A detection
sensor going dark is itself an attack technique — **T1562.001, Impair
Defenses: Disable or Modify Tools** — regardless of whether the cause is
malware disabling Valkyrie on purpose or, as measured here, a resident
security product's self-defense colliding with it by accident. Either way
the right response is the same: raise it, don't degrade silently.

`valkyrie/sensor_tamper.py`'s `SensorTamperMonitor` polls Sysmon health
(present, running, collection actually live, the exact EIDs Valkyrie's
detectors read still in the active config) every 5 minutes and raises a
**CRITICAL** incident labeled `sensor_tamper` the moment a **previously
healthy** sensor goes unhealthy. Fires on the transition only — a host that
never had Sysmon, or has it deliberately disabled, is an already-reported
degraded mode (see above), not a tamper event; alerting on that forever
would be noise standing in for the one signal that actually matters: a
sensor that *was* working and stopped.

Scoped to Sysmon today because that is what this session found dying. Built
so another sensor's health check is a one-function addition to `_CHECKS`,
not a new watchdog class, when the next one needs it.

### 6. Sysmon's environment probe moved into product code

`probe_sysmon()`, `SysmonEnvironment`, and `check_requirements()` moved from
`redteam/evaluation/environment.py` into `valkyrie/sysmon_manager.py`. They
stopped being purely evaluation-time concerns the moment the shipped product
needed the same fact to decide its own status and to detect tampering.
`redteam/evaluation/environment.py` now re-exports from the product module,
so Tier A scores against the exact probe the product uses to make real
decisions — not a second implementation that could silently drift from it,
which is the same measurement-vs-product divergence ADR 0045 and ADR 0046
both found the hard way.

## Consequences

- New: `valkyrie/sysmon_manager.py`, `valkyrie/sensor_tamper.py`,
  `config.SYSMON_DOWNLOAD_URL`, `--no-sysmon-setup` CLI flag, a `Sysmon` row
  in the startup status box, `GET /api/sysmon/status`.
- `tests/test_sysmon_manager.py` (34 checks) and `tests/test_sensor_tamper.py`
  (17 checks) — every branch mocked; neither test touches a real Sysmon
  installation, downloads anything, or executes `Sysmon64.exe`, on purpose.
  Simulating "blocked by another security product" is the only safe way to
  test it; reproducing it live is not a test, it's the incident again.
- `tests/test_startup_smoke.py` gained `--no-sysmon-setup` — without it,
  every smoke-test boot on every developer machine and CI runner would
  attempt a real Sysmon install, which is exactly the live system change
  this ADR's own finding says can go wrong.
- `redteam/evaluation/test_environment_gate.py` and `replay_harness.py`
  needed no changes beyond the import path — 29/29 and Tier A's scoring both
  reproduce unchanged through the re-export shim.

## What this ADR deliberately does NOT do

- It does not attempt to fix Avast, add an AV exclusion, or otherwise touch
  any other security product. Rule: never disable, uninstall, or reconfigure
  another vendor's security software. The product design compensates for
  that constraint by degrading visibly instead of requiring cooperation it
  cannot assume it will get.
- It does not implement Part 2 of the task this ADR was written under (a
  live-execution red-team tier gated on healthy Sysmon) — that tier would
  measure the 2-second poller alone on this host right now, which is not
  what it exists to measure. It stays blocked on this host having a healthy
  Sysmon, which this ADR explicitly does not force.
- It does not merge a foreign Sysmon config with Valkyrie's. Correctly
  merging two independent Sysmon rule-config documents (rule-group
  precedence, `onmatch` interactions) is a real engineering problem on its
  own; "detect coverage gaps and report them" is the honest, bounded version
  of that problem, and doing the harder version half-way would be worse than
  not attempting it.

## Addendum (2026-08-06) — a real compensating control, not just a passive fallback

Control-taxonomy classification (`valkyrie/control_taxonomy.py`, IIBA §4.2.3)
found that the "falls back to a 2-second psutil poll" language above was
accurate but incomplete: the poller was *already running independently* of
Sysmon, but nothing *activated* it as a substitute — it polled at the same
cadence whether Sysmon was healthy or not, and there was no compensating
category anywhere in the codebase. `SensorTamperMonitor` now accepts a
`compensations` map; on the sysmon healthy→unhealthy transition it calls
`ProcessCollector.tighten()` (4x the poll rate, floored at 0.25s) and calls
`restore_interval()` back on recovery. Both transitions are recorded as
telemetry (`sensor_tamper` / `sensor_recovered`), so the compensation
turning on and off is itself auditable, not a silent internal state change.

This remains honest about its limits, unchanged from the original finding
above: it only helps process-CREATION visibility. It does nothing for the
EID 8/10/7/13-only signals (injection, LSASS access, unsigned modules,
autorun registry writes) that have no userland equivalent. See
`control_taxonomy.py`'s `sysmon_compensation` entry for the exact list.

## The long-term answer

The kernel driver (`driver/valkyrie_km`, ADR 0026/0031/0043) removes this
dependency entirely once it ships: it needs no third-party AV's cooperation
to see process/thread/image-load events, because it *is* a kernel component
with its own callback registrations, not a second driver a resident AV's
behavioral engine has to be talked into tolerating. Until it is signed and
loadable in production — it is currently unsigned and **must not be
loaded**, see `driver/BRINGUP.md` — Sysmon remains the best available
substitute for that visibility and is treated with the seriousness of a real
dependency, not a nice-to-have.
