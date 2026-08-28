# ADR 0052 - Sensor determinability: "cannot look" is not "nothing there"

Date: 2026-08-23 . Status: accepted . Follows: ADR 0048 (Sysmon dependency), ADR 0022/0023 (coverage gates authority)
Found by: live diagnosis on the dev host, 2026-08-23

## Context

The Sysmon operational log is readable only by Administrators.
`sysmon_manager.probe_sysmon()` read it through PowerShell with
`-ErrorAction SilentlyContinue`, so an unprivileged probe produced:

    log_enabled=False  record_count=0  newest_event_age=None  collection_live=False

which is **byte-identical to a genuinely dead sensor**. The permission error was
swallowed; the only trace it ever left was an accident — the error text landing
in a `float()` parse and being recorded as `unparsable newest-event age`.

`efficacy.sensor_health()` had the same shape: both the Sysmon channel check and
`native_audit.is_process_auditing_enabled()` (which shells to `auditpol`, an
Administrator-only command) were wrapped in bare `except`/falsy checks, so an
unprivileged caller fell through to `command_line_source="none"` with the text
*"a miss here is BLINDNESS, not a rule gap."*

**Both fired on 2026-08-23 and both were wrong.** The host was reported blind
while Sysmon was collecting 49,000 events, and separately while Windows 4688
command-line auditing was enabled (`ProcessCreationIncludeCmdLine_Enabled=1`)
and actively feeding `NativeProcessSensor` — as RUN A of the live-safe
evaluation had already demonstrated on 2026-08-07 with `etw.native` captures.

Downstream, `coverage._check_sysmon()` turned that into `ABSENT` — asserting a
negative it had never observed.

## Why this is a correctness bug, not a reporting nit

Coverage gates authority arithmetically (`authority.authorize`, gate 2). That
gate is the substance of Valkyrie's central claim: commercial EDR underwrites
autonomous action **contractually** — a 24/7 SOC and a support agreement absorb
the blast radius — while Valkyrie underwrites it **structurally**, by refusing
authority it cannot justify from live sensor evidence.

A structural claim is only as good as the honesty of its inputs. A probe that
asserts unobserved negatives is a defect sitting directly in the authority
chain, and it fails in both directions:

- reported as ABSENT when merely unverified → authority is withheld that the
  evidence would have supported, and a human is told the product is blind when
  it is not (what happened);
- the mirror failure — treating unverified as fine — would grant authority on
  a sensor nobody checked.

`sensor_deps.STATE_UNKNOWN` already existed for exactly this, documented as
*"Treated exactly as `degraded`: 'I do not know' is never allowed to read as
'fine'."* The policy layer was already correct. **The probes simply could never
produce that value.**

## Decision

**`SysmonEnvironment` gains `access_denied` and a `determinable` property.**
`probe_sysmon()` now inspects each log read for privilege-failure markers
(`UnauthorizedAccessException`, `Access is denied`, `attempted to perform an
unauthorized operation`, `requested registry access is not allowed`) and sets
the flag. `why_not()` returns an explicit *"cannot determine … this is NOT
evidence that Sysmon is dark; re-run elevated"*, and `detail` leads with the
same, labelling the raw field values as **not observations**.

`provides()` deliberately still returns False when undeterminable: authority is
never granted on an unverified sensor. The change is that callers can now
distinguish *why*, instead of a refusal and an absence rendering identically.

**`coverage.py` gains `UNKNOWN`**, defined to equal `sensor_deps.STATE_UNKNOWN`
(pinned by test), and `_check_sysmon()` returns it when the probe was refused.

**`efficacy.sensor_health()` gains `determinable`** and a fourth source value,
`"undetermined"`. The 4688 check is split into its two halves on purpose: the
registry flag is world-readable and the `auditpol` subcategory is not, so an
unprivileged caller reports "configured, liveness undetermined" rather than
"off". Its message now says explicitly: *do NOT read this as blindness.*

## Consequences

Positive:

- The product can no longer tell a human it is blind on the strength of a
  permission error. That error class cost two false diagnoses in one day, one
  of which drove a decision to uninstall two antivirus products.
- `UNKNOWN` degrades authority exactly as `degraded` does, so nothing unsafe is
  granted by the added honesty — pinned by test [5].
- 30 checks in `tests/test_sensor_determinability.py`, including negative
  controls that a genuinely dark or genuinely absent sensor still reports as
  such rather than hiding behind "cannot determine".

Negative / accepted:

- Access-denied detection is **text matching**, because
  `-ErrorAction SilentlyContinue` leaves no structured error to inspect. A
  localised Windows may not match the English markers and would fall back to
  the old behaviour. Preferred over rewriting every probe to structured error
  handling in this change; recorded rather than hidden.
- A false positive on those markers costs a "cannot determine" where a definite
  answer was available — the safe direction to be wrong in.
- Only the Sysmon and 4688 probes are converted. Other coverage controls may
  have the same latent shape and were not audited here.

## Honesty note

This fixes what Valkyrie *knows about itself*. It detects nothing new and does
not move any detection rate. Its value is that the coverage gate — and any
human reading the product's own health — now receives a fact rather than an
artefact of the privilege the probe happened to run with.
