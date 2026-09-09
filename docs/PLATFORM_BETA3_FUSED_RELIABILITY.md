# Platform Beta 3 -- Fused Pipeline Reliability

## Qualification status

**QUALIFIED — 2026-08-31.** The real 10-minute soak passed clean on the
first attempt: 285 of 285 real visits resolved a real subject, produced a
chain, derived a real DESTINATION observation, never fabricated an
unavailable category, and showed zero cross-visit contamination across
285 real subjects sharing one `DetectionArchitectureV2` instance. See
"Beta 3: QUALIFIED" near the end of this document.

## What this qualifies, and what it does not

Beta 2 (`docs/PLATFORM_BETA2_AEGIS_LIVE.md`) proved the `CanonicalEvent ->
ExposureObservation` bridge over ONE real causal chain, one subject. A
single-subject run cannot exercise the property that actually matters for
a real deployment: the live engine builds exactly ONE
`DetectionArchitectureV2` instance for its entire process lifetime, not
one per request, and reasons about MANY different real subjects over
time, sequentially and sometimes with overlapping in-flight activity. Does
that one shared instance keep each subject's evidence correctly isolated,
or can one subject's evidence leak into another's under sustained real
load?

This qualifies: real, sustained, multi-visit, multi-subject reliability of
the SAME already-proven pipeline (`ProcessCollector`/`NetworkCollector` →
real Nyx observation → `DetectionArchitectureV2` → `aegis_bridge` →
`aegis_exposure`), one shared engine instance across many real chains.

Does not qualify: any new detection rule, NYX capability, or Aegis
mechanism; a live production engine deployment (this harness still
constructs its own components in-process, same shape as Beta 1/Beta 2);
anything about `CanonicalEvent`'s schema (unchanged).

## Workload

One real Playwright Chromium browser, one shared context, launched once.
Loops opening a fresh page per "visit" for the run's duration (dry-run ~2
minutes, soak configurable, default 10 minutes), each visit generating its
own real chain (a real process/network footprint plus a real, unauthorized
Nyx privacy observation to a real tracker host) exactly like Beta 2's
single chain, but now dozens to hundreds of times across ONE shared
`DetectionArchitectureV2` instance and ONE shared pair of
`ProcessCollector`/`NetworkCollector` instances, matching the real
engine's actual lifetime shape.

## Predeclared PASS criteria

- **`most_visits_resolved_a_real_subject`** -- at least 80% of visits
  resolved a real subject pid (some visits legitimately losing the race
  against `ProcessCollector`'s poll interval is expected, not a failure,
  the same honest limitation Beta 2 already found and accepted).
- **`resolved_visits_produced_a_chain`** -- every visit that resolved a
  subject produced at least one real event for it.
- **`destination_derived_across_most_visits`** -- at least half of all
  visits derived a real DESTINATION observation.
- **`unavailable_categories_never_fabricated_any_visit`** -- VOLUME,
  DIRECTION, IDENTITY, SESSION never appear, on ANY visit, for the whole
  run.
- **`no_cross_visit_contamination`** -- the property this stage exists to
  prove: every visit's own Aegis observations trace ONLY to that same
  visit's own real event ids, never another visit's.
- **`no_observe_errors_any_visit`** -- `DetectionArchitectureV2.observe()`
  never raised, across the whole run, for any visit.
- **`no_process_crash`** -- the harness completes the full run (a crash
  still scores whatever was collected, same crash-proof discipline as
  every prior stage).

Non-gating / exploratory: this-process RSS trend across the run (no
threshold exists yet, same honesty Beta 0.5 used for its own first
CPU-trend measurement).

## Sequence

Platform Alpha → Beta 0 → Beta 0.5 (QUALIFIED+audited) → Beta 1/NYX
(QUALIFIED) → Beta 2/Aegis (QUALIFIED) → **Beta 3 (here) ← CLOSED**.

## Beta 3: QUALIFIED — 2026-08-31

**Dry-run (2 min, 57 visits): PASS, first attempt, every check green.**
**Real soak (10 min, 285 visits): PASS, first attempt, every check green:**

- `most_visits_resolved_a_real_subject`: 285/285.
- `resolved_visits_produced_a_chain`: 285/285.
- `destination_derived_across_most_visits`: 285/285 (not just "most" - all).
- `unavailable_categories_never_fabricated_any_visit`: 285/285.
- `no_cross_visit_contamination`: **285/285** - the property this stage
  exists to prove. 285 real, sequential subjects shared ONE
  `DetectionArchitectureV2` instance over a real 10-minute run, and not
  one observation from any visit ever traced to a different visit's event
  ids.
- `no_observe_errors_any_visit`: 0 across the whole run.
- `no_process_crash`: held.

Platform Alpha's frozen baseline (15 tests) unaffected.

**Beta 3 is genuinely done, not declared done.** No harness bugs this
time - Beta 2's hard-won lessons (privacy-event-pid-as-ground-truth,
NetworkCollector's honest "can miss a fast connection" limitation, the
`evaluate_pair()` return shape) transferred directly, and the one NEW
property this stage was built to test - one shared engine instance never
confusing one real subject's evidence for another's, at real volume, over
real sustained time - held cleanly on the first attempt at both scales.
This is the strongest evidence yet that the reasoning architecture (EDR +
NYX + Aegis, fused) is structurally sound under real, sustained,
multi-subject load, not just a single hand-picked one-shot scenario.
