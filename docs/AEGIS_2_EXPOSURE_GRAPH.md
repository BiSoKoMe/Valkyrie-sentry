# Aegis 2 -- The Exposure Graph

**Evidence class:** reasoning/measurement replay -- not a new observer-accuracy
measurement. See Aegis 1A/1B for those.
**Independent:** no.
**Stage:** Aegis 2 -- reasoning layer only. No mitigation attached.

## Why this stage exists

Aegis 1A (size bucketing) and Aegis 1B (identity/destination separation)
were killed for what looked like two different reasons, until they were put
side by side:

```
Aegis 1A: hide size precision -> other features compensate,
          and the transformed sequence becomes a NEW fingerprint.
Aegis 1B: separate identity/destination -> destination alone still
          links sessions, and timing/size re-link the separated views.
```

Neither failure was about a field. Both were about which *combinations* of
visible information let an observer join evidence into a conclusion. Tor's
own design material makes the same point in the general case: an observer
able to see both ends of a connection can use timing (and message-size)
correlation to confirm a relationship, independent of what specific
anonymization exists in between. The Aegis 1A/1B failures are instances of a
known hard problem in anonymity systems, not an Aegis-specific bug.

## The architecture

```
VALKYRIE                         AEGIS

raw telemetry                    raw network observations
      |                                  |
canonical behaviors               canonical exposures
      |                                  |
causal graph                      exposure graph
      |                                  |
hypotheses                        inference hypotheses
      |                                  |
evidence                          joinable observations
      |                                  |
decision                          privacy risk
```

`valkyrie/aegis_exposure.py` is the implementation. It deliberately reuses
`valkyrie.edr.hypothesis` (`EvidenceFact`, `HypothesisSpec`,
`evaluate_hypotheses`) directly rather than writing a second scoring system
-- the noisy-OR fusion, the supports/contradicts structure, and the
minimum-support/margin gate are not EDR-specific properties, so "apply the
principle, not copy the implementation" means literally sharing the module,
not re-deriving its logic under a new name.

## The vocabulary

**Exposure categories** (what is observable -- never itself "dangerous"):
`IDENTITY, DESTINATION, VOLUME, TIMING, SEQUENCE, FREQUENCY, SESSION, DIRECTION`

**Inference hypotheses** (what an observer might conclude by joining exposure):
`ACTIVITY_CLASSIFICATION, FLOW_LINKAGE, CROSS_SESSION_LINKABILITY, USER_LINKABILITY, DESTINATION_DISCLOSURE`

Nothing is scored independently ("timing=7, size=4, destination=9"). Every
exposure observation names which hypotheses it *supports* or *contradicts*;
`evaluate_hypotheses` fuses independent evidence and requires a minimum
support count plus a margin over the runner-up before it will alert --
exactly the property that keeps a lone weak signal from convicting.

`USER_LINKABILITY` is compositional: supported directly when `IDENTITY` and
`DESTINATION` are observable at the *same* point, or indirectly when
`IDENTITY` sits at one point, `DESTINATION` at another, and `FLOW_LINKAGE`
independently joins those two points. That second path is Aegis 1B's
"separated but re-linked" failure, produced as a *consequence* of the
representation, not encoded as a special case.

## The one rule the module must satisfy

Nothing inside `_derive_facts` or `evaluate_pair` may branch on which
experiment produced a scenario. It only ever sees a tuple of
`ExposureObservation` values in the vocabulary above.
`redteam/evaluation/aegis_2_exposure_graph.py` is where Aegis 1A and 1B get
*translated* into that vocabulary -- that translation is necessarily
experiment-specific (someone has to describe what each experiment exposed)
-- but the reasoning code itself never is.

## Replaying Aegis 1A

| | control | bucketed |
|---|---:|---:|
| ACTIVITY_CLASSIFICATION | alert, 0.84 | alert, 0.864 |

Bucketing degraded `VOLUME`'s precision (1.0 -> 0.25) but left `TIMING`
untouched and added a *new*, full-precision `SEQUENCE` observation (the
bucket-tier signature). The generic rule -- any activity-bearing category
(`VOLUME`/`SEQUENCE`/`TIMING`/`FREQUENCY`) supports `ACTIVITY_CLASSIFICATION`
-- reproduces the real measurement's qualitative shape (the hypothesis
barely moves, if anything strengthens) without a single line of code that
mentions bucketing.

## Replaying Aegis 1B

| | control | EXIT alone | ENTRY <-> EXIT |
|---|---:|---:|---:|
| CROSS_SESSION_LINKABILITY | alert, 0.90 | alert, 0.90 (identical) | -- |
| FLOW_LINKAGE | -- | -- | alert, 0.923 |
| USER_LINKABILITY | -- | -- | alert, 0.923 (composed) |

`EXIT` alone reaches the *identical* confidence as `CONTROL` for
`CROSS_SESSION_LINKABILITY`, because the generic destination-comparison rule
never required an identity signal in the first place -- reproducing the
real "hiding identity from EXIT did nothing" finding exactly. `FLOW_LINKAGE`
fires between `ENTRY` and `EXIT` because `TIMING`/`VOLUME` remain
correlatable at precision 0.85 (representing the real incidental relay
noise) -- and `USER_LINKABILITY` fires too, composed from that decision,
even though neither point ever held both `IDENTITY` and `DESTINATION`. Same
rulebook as Aegis 1A; zero 1B-specific code.

## The held-out generalization test

A three-point relay (`ENTRY` / `MIDDLE` / `EXIT`) never used to design the
rulebook: `ENTRY` exposes only `TIMING`, `EXIT` exposes only
`VOLUME`/`FREQUENCY`, `MIDDLE` exposes `FREQUENCY`/`SESSION` but neither
`IDENTITY` nor `DESTINATION`. The prediction -- written *before* running the
code -- was that `FLOW_LINKAGE` would stay unestablished, because `ENTRY`
and `EXIT` share no common correlatable category (unlike Aegis 1B, where
both had `TIMING` and `VOLUME`). The graph confirmed it: `FLOW_LINKAGE`
returns `observe` with "0 supporting facts; 1 required," and the composed
`USER_LINKABILITY` path correctly never opens. `DESTINATION_DISCLOSURE`
still fires at `EXIT`, correctly independent of linkage. One representation,
no new code path, a topology it had never seen.

This also surfaced an honest gap rather than hiding it: `MIDDLE`'s `SESSION`
observation contributes to **no** hypothesis in the current rulebook --
`SESSION` and `DIRECTION` are declared in the canonical vocabulary but not
yet wired to any inference rule.

## Exposure cut

`exposure_cut()` brute-forces the smallest subset of a scenario's
observations whose removal flips a target hypothesis from `alert` to
not-established -- reasoning about where a *future* mitigation would need
to act, without proposing one.

- Aegis 1B's `FLOW_LINKAGE`: cut size 2 -- both `ENTRY`'s `TIMING` *and*
  `VOLUME` observations must be removed. Either alone still supports
  `FLOW_LINKAGE` on its own (noisy-OR), meaning a real mitigation that only
  protects timing *or* only protects size leaves the other channel fully
  sufficient -- a concrete, measured argument for why a single-channel fix
  (Aegis 1A's own mistake) would fail here too.
- Aegis 1A's `ACTIVITY_CLASSIFICATION`: cut size 2 (`TIMING` + `SEQUENCE`) --
  `VOLUME` alone, at its degraded 0.25 precision, is not sufficient by
  itself (0.15 confidence, below the 0.5 threshold), so removing either
  `TIMING` or `SEQUENCE` alone still leaves the surviving one sufficient on
  its own.

## What this stage does and does not claim

It does not reproduce Aegis 1A/1B's numeric accuracy figures -- the
precision values used here are illustrative (e.g. 0.85 for the relay
noise), chosen to reflect the measured findings' direction, not fit to
match them exactly. It does not propose a mitigation; `exposure_cut`
identifies *where* one would need to act, nothing more. And the held-out
topology's prediction demonstrates internal consistency (the same code
reasons sensibly about a case it never saw), not validation against a real
network measurement, which does not exist for that topology.

## What comes after this, and what doesn't yet

The exposure-cut results already suggest a future privacy planner's shape:
choose the cheapest set of exposure edges to weaken that breaks a target
inference path, checking whether a candidate mitigation reconstructs the
broken path through another edge before crediting it. That planner, and any
actual mitigation, is explicitly future work -- consistent with systems like
Loopix, which target traffic analysis through combinations of mixing,
delay, and cover traffic rather than assuming any single relay eliminates
correlation. The research problem Aegis 2 answers first is which
information relationships need to be broken at all, before choosing how.
