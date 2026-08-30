# Aegis 1A -- Size-Exposure Reduction via Deterministic Bucketing

**Evidence class:** synthetic mechanism evaluation.
**Independent:** no.
**Stage:** Aegis 1A -- first mitigation attempt. Still no relaying, fake traffic, or timing perturbation.

## Research question

Aegis 0.5 found size alone (94.4%) is the strongest single driver of activity
classification in the frozen corpus. Before touching destination or timing at
all, this isolates one variable: **does replacing each connection's exact
byte count with a deterministic bucket ceiling actually remove useful
information from an informed observer, at an acceptable bandwidth/latency
cost?**

## The policies (defined before evaluation)

| Policy | Shape | Boundaries |
|---|---|---|
| CONTROL | no transform | exact sizes |
| BUCKET-A | coarse, 3 tiers | 1,000 / 100,000 / 5,000,000 |
| BUCKET-B | finer, 8 exponential (x4) tiers | 256 ... 1,048,576 / 5,000,000 |
| BUCKET-C | adaptive, geometric ratio 1.25 (~25% max overhead/bucket) | 46 tiers, 256 to 5,000,000 |
| BUCKET-D | aggressive, 2 tiers | 5,000 / 5,000,000 |

None were adjusted after seeing an accuracy number.

## The result: pure size bucketing does not survive the killer test

Two observer profiles are measured for every policy: `size_only_observer`
(isolates the causal effect of the transform) and `full_feature_observer`
(destination + size + timing -- what a real network observer would actually
use, since Aegis 1A touches only size).

| Policy | size-only naive | size-only retrained | full-feature naive | full-feature retrained | sequence-only | Bandwidth overhead |
|---|---:|---:|---:|---:|---:|---:|
| CONTROL | 93.1% | 93.1% | 83.3% | 83.3% | -- | 0% |
| BUCKET-A | 33.3% | **80.6%** | 70.8% | **90.3%** | 80.6% | 739% |
| BUCKET-B | 63.9% | **88.9%** | 87.5% | 87.5% | **97.2%** | 116% |
| BUCKET-C | 94.4% | 94.4% | 83.3% | 83.3% | **98.6%** | 13% |
| BUCKET-D | 33.3% | 33.3% | 55.6% | **86.1%** | 33.3% | 2395% |

**This is a negative result for pure size bucketing, and it is reported as
one.** Every policy's naive-observer drop is substantially or entirely an
illusion:

- **BUCKET-A/B**: the size-only naive accuracy looks like a win (93.1% ->
  33.3%/63.9%), but a retrained observer recovers most of it (80.6%/88.9%) --
  almost back to CONTROL. That is the exact failure mode named in advance:
  "Aegis didn't solve much, it merely confused an outdated observer."
- **BUCKET-C**: essentially free (13% overhead) and essentially useless --
  both naive and retrained accuracy are unchanged from CONTROL, because ~25%
  geometric buckets preserve almost all size precision by construction.
- **BUCKET-D**: the only policy where the size-only observer never recovers
  (33.3%, informed or not) -- but the full-feature retrained observer still
  reaches 86.1%, *higher* than CONTROL's 83.3%, because destination and
  timing (never touched) fully compensate. And the cost is catastrophic:
  2,395% mean bandwidth overhead, 2,389 of 4,481 connections (53%) flagged
  as a severe-expansion compatibility concern.

**None of the four policies reduce the realistic full-feature observer's
retrained accuracy below CONTROL.** Three of four (A, B, D) leave it *higher*
than CONTROL. Per the pre-declared falsification rule ("if it gets 94.4% ->
91% after retraining, kill the idea and move on"): **kill pure size
bucketing as a standalone mechanism.**

## The sequence-fingerprint finding

BUCKET-B and BUCKET-C's `sequence_only_accuracy` (97.2%, 98.6%) --
a classifier that never sees a single byte count, only each session's
histogram of which bucket tier its connections fell into -- exceeds even the
original size-only accuracy (93.1%). Finer bucketing didn't just fail to
remove information; the discretized shape became its own, cleaner
fingerprint (a real, literature-consistent effect: discretization can act as
noise reduction for a classifier). Hiding exact sizes accomplishes very
little when the sequence of buckets remains this distinctive.

## Why this happened, and what it rules in

The full-feature retrained observer's resilience is not a flaw in the
experiment -- it is the direct, correct consequence of Aegis 1A's own
isolation requirement (touch only size, nothing else). It confirms the
"exposure planner" architecture from the research plan: activity
classification's dominant leak is size, but a realistic observer doesn't
need to rely on size alone, and destination/timing were never touched here.
**A single universal mechanism was never going to be enough; this experiment
makes that concrete instead of assumed.**

## What Aegis 1B (destination/identity separation) inherits from this

- Any future size mechanism must be evaluated with the SAME two-observer
  discipline (retrained, not naive) or it will look like it works when it
  doesn't.
- Fine-grained bucketing schemes (B, C) must also be checked for
  sequence-level fingerprinting, not just per-message accuracy.
- Bandwidth overhead above roughly 100% (B) is already a real cost for zero
  or near-zero retrained-observer benefit; D's 2,395% is the cautionary
  extreme the research plan explicitly warned against ("don't let Aegis
  cheat by making everything max size").
- Aegis 0.5 already showed destination, not size, dominates cross-session
  linkability (78.4% vs. ~54%) -- Aegis 1B's split-trust/relay architecture
  remains the higher-leverage next experiment, unaffected by this result.

## Limitations

- Same frozen synthetic corpus as Aegis 0/0.5 (manifest pinned in code,
  checked at run time, raises rather than silently drifting).
- `modeled_added_latency_ms` is a stated model (extra bytes / an assumed
  10 Mbps link), not a measurement -- there is no real network here.
- `compatibility_concern` is a heuristic proxy (a large expansion-ratio
  threshold), not a report of real application breakage.
- Bucketing was evaluated as an isolated variable per the stage's own
  scope -- no relaying, fake traffic, or timing perturbation. That isolation
  is exactly what makes the full-feature-observer result so clear.
