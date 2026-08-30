# Aegis 4 -- Mechanism Characterization

**Evidence class:** mechanism characterization derived from an already-measured
synthetic experiment (Aegis 1A); not independent, not live.
**Independent:** no.
**Stage:** Aegis 4 -- one real mechanism, measured, not assumed. No second
mechanism, no synthetic mechanism dressed up as real.

## The question this stage exists to answer

Not "what privacy trick should we add." It's narrower and harder:

> Can one real mechanism be measured honestly enough that the planner can
> reason about it without lying to itself?

Aegis 1A already proved why this matters. "Bucketing reduces volume
exposure" is a true sentence. It would also have made a terrible catalog
entry for the Aegis 3 planner, because it says nothing about the sequence
fingerprint the same mechanism created -- the exact finding that got
bucketing killed as a mitigation. If Aegis 4 let a planner consume
`intended_effect` instead of measurement, it would reintroduce that mistake
one layer up, inside the reasoning system meant to prevent it.

## The mechanism, and why it needed no new experiment

`valkyrie/aegis_mechanism.py`'s `MechanismProfile` is characterized from
Aegis 1A's `BUCKET-A` (coarse 3-tier size bucketing) -- reusing numbers
already measured in that stage, pulled *live* from
`redteam.evaluation.aegis_1a_bucketing.run()` rather than retyped as
constants. If Aegis 1A's own numbers ever change, this characterization
changes with them instead of silently drifting stale.

| Category | Baseline precision | Measured precision | New signal |
|---|---:|---:|---|
| VOLUME | 0.917 | 0.767 | no |
| TIMING | 1.0 | 1.0 (unchanged) | no |
| DESTINATION | 1.0 | 1.0 (unchanged) | no |
| SEQUENCE | 0.0 | 0.767 | **yes** |

Precision is derived from accuracy via one stated, auditable formula --
`(accuracy - random_chance) / (1 - random_chance)` -- the only mapping used
anywhere in this file. `VOLUME`'s baseline comes from Aegis 0.5's
size-only observer accuracy (0.9306); its measured value from BUCKET-A's
retrained size-only accuracy (0.8056); `SEQUENCE`'s measured value from
BUCKET-A's own `sequence_only_accuracy` (0.8056, coincidentally identical --
both figures live in a 72-item test set, so repeated values are expected,
not a bug).

## Intended vs measured, kept structurally separate

`MechanismProfile.intended_effect` is free text -- "Weaken the VOLUME
exposure category..." -- and nothing in `valkyrie.aegis_mechanism` or
`valkyrie.aegis_planner` ever reads it. The only two things reasoning code
is allowed to consume are `weakened_categories()` (a naive, intent-shaped
view, built only to be checked against reality) and `apply_to()` (the
scenario as it actually looks after the mechanism runs, built only from
`measured_effects`).

## The verification: did the naive view get fooled?

A minimal scenario -- `VOLUME` and `DESTINATION` only, no `TIMING` -- was
built deliberately so a naive, intent-only mechanism entry has a genuine
chance to look correct before being checked (Aegis 1A/2's own replay
scenario already includes `TIMING`, which alone would keep
`ACTIVITY_CLASSIFICATION` established regardless of this mechanism, so it
would not isolate the question this stage asks).

```
naive_planner_believes_solved:  True   (VOLUME was the only activity-bearing
                                        fact; the naive entry declares it
                                        removed, so a one-mechanism plan
                                        looks like a full fix)
measured_still_established:     True   (VOLUME's real weight drops to 0.46,
                                        but the new SEQUENCE fact appears at
                                        the same 0.46, and combined via
                                        noisy-OR -- 0.71 -- still clears the
                                        0.5 alert threshold)
mismatch:                       True
```

**Conclusion:** a naive catalog entry built only from BUCKET-A's stated
intent would have led the Aegis 3 planner to report
`ACTIVITY_CLASSIFICATION` solved. Re-evaluating the exposure graph on
BUCKET-A's actual measured post-state shows it is not. The planner must not
count an inference as solved just because a mechanism's intent said it
should be -- and now there is a concrete, reproducible case proving that
distinction matters, not just an abstract warning about it.

## What was, and was not, measured

Recorded honestly, per the mechanism-profile fields the research plan
asked for:

- **Affected categories:** measured (VOLUME weakened, SEQUENCE newly
  appeared, TIMING/DESTINATION confirmed unchanged) -- not declared from
  intuition.
- **Strength:** the actual precision drop/appearance, not a qualitative
  "strong"/"weak" label.
- **Side effects:** the new SEQUENCE fingerprint is a first-class
  `ExposureEffect`, not a footnote inside the mechanism's own description.
- **Cost:** bandwidth overhead (739%) and a modeled latency figure, both
  carried over from Aegis 1A's own measurement.
- **Compatibility:** 945 of 4,481 connections flagged as a severe
  size-expansion concern (Aegis 1A's own heuristic proxy, not real
  application breakage -- restated, not re-measured).
- **Repeatability:** *not* measured in this stage, and said so directly --
  `aegis_1a_bucketing`'s frozen-corpus guard ties its train/test split to
  the same seed as the pinned corpus, so varying the split without also
  varying (and breaking comparability of) the corpus isn't available today.
  An open gap, not a silently assumed non-issue.

## Limitations

- Exactly one mechanism characterized, per this stage's own scope --
  `test_only_one_mechanism_is_characterized` pins that no other bucketing
  policy's name appears anywhere in the profile.
- This is a characterization of an already-synthetic experiment (Aegis 1A),
  not a live-network measurement -- the evidence class says so explicitly,
  and it is one derivative step further from reality than Aegis 1A itself.
- The verification scenario was built to isolate the intended-vs-measured
  question cleanly; it is not a claim about how BUCKET-A behaves in every
  possible exposure context, only in the one constructed here.

## What comes after this

Only after a real mechanism survives characterization this way --
measured, not assumed, with intended and measured effects kept apart, and
checked against the planner rather than trusted by it -- does expanding to
a second real mechanism, or building an actual mechanism catalog for live
use, become a reasonable next step. UNSAT remains the load-bearing
invariant underneath all of it: a system that can say "I cannot verify this
protects you" is worth more than one that always renders a green checkmark.
