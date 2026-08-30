# Aegis 3 -- The Privacy Planner

**Evidence class:** planner correctness demonstration -- synthetic mechanisms, no real privacy transformation.
**Independent:** no.
**Stage:** Aegis 3 -- mechanism-independent optimization on top of the Aegis 2 exposure graph. Nothing here is implemented as, or intended to become, a real mitigation without a further, separate decision.

## What this stage adds

Aegis 2 could already say "here is the smallest set of observations that
would need to disappear to break this inference." Aegis 3 answers the next
question without knowing anything about *how* an observation might be
weakened: given a synthetic catalog of candidate mechanisms -- each
declaring only which exposure categories it can affect and an abstract cost
-- find the cheapest mechanism combination that breaks every currently-open
inference path a policy cares about, across possibly several hypotheses at
once, or say plainly that none exists.

```
INFERENCE HYPOTHESIS -> SUPPORTING EXPOSURE PATHS -> MINIMAL EXPOSURE CUTS
    -> CANDIDATE CUT SETS -> ESTIMATED COST -> RANKED PLAN
```

`valkyrie/aegis_planner.py` is the implementation:
`enumerate_minimal_cuts` (added to `valkyrie/aegis_exposure.py`) returns
*every* minimal cut for a hypothesis, not just the first found -- Aegis 1B's
`FLOW_LINKAGE` has four equivalent minimal cuts (either endpoint of the
timing correlation, either endpoint of the volume correlation), and a
planner that only saw one would miss cheaper realizations at the other
endpoint. `Mechanism.covers()` checks whether a mechanism's declared
`affected_categories` (and optional `scope_observation_points`) neutralizes
one observation; `plan()` brute-forces every subset of the catalog and keeps
the cheapest one that realizes at least one minimal cut for *every* active
target simultaneously.

## Mechanisms never learn "timing leak -> jitter"

```
PRIVACY REASONING                     MECHANISM CATALOG
"break these inference-        -->    M affects TIMING, cost 2
 enabling relationships"              N affects VOLUME, cost 3
                                       O affects TIMING+VOLUME, cost 8
```

The planner only ever asks whether a declared category set covers a cut. No
mechanism in any test case is named after, or described as, a real technique
(`tests/test_aegis_3_planner.py` asserts this directly -- no mechanism name
contains "padding," "jitter," "relay," "vpn," or similar).

## Case 1: the worked example, reproduced exactly

Aegis 1B's topology, four mechanisms (M1 timing/cost 2, M2 volume/cost 3, M3
both/cost 8, M4 destination/cost 4). Result: `{M1, M2}`, cost 5 -- beating
M3 alone (cost 8), because timing and volume each independently support
`FLOW_LINKAGE` and both must be disrupted, exactly as hand-derived before
any code ran.

## Case 2: two hypotheses that do not share a solution

`FLOW_LINKAGE` needs the ENTRY<->EXIT timing/volume correlation broken.
`ACTIVITY_CLASSIFICATION`, evaluated independently for the EXIT-side flow,
has THREE of its own supporting facts (EXIT's timing, volume, and
sequence), each individually clearing the alert threshold alone -- so
breaking `FLOW_LINKAGE` cheaply at ENTRY (cost 2) leaves
`ACTIVITY_CLASSIFICATION` fully untouched. The optimal joint plan instead
spends more on the EXIT side (`{M_exit_timing, M_exit_volume,
M_exit_sequence}`, cost 12): cutting `FLOW_LINKAGE` via EXIT's timing+volume
happens to cover 2 of `ACTIVITY_CLASSIFICATION`'s 3 required removals,
undercutting the cost of solving both hypotheses independently (which would
total 14). The exhaustive search finds this overlap without being told it
exists.

## Case 3: redundant paths, cheapest realization

The same four-cut redundancy from Aegis 1B, but with mechanisms costing 9 at
ENTRY and 1 at EXIT for the same categories. Result: `{M_exit_timing,
M_exit_volume}`, cost 2 -- the planner picks the cheap side of a redundant
path rather than the first one enumerated.

## Case 4: held-out topology and catalog

A scenario and mechanism catalog written after the planner logic above was
frozen: a single observer with identity, destination, and frequency for one
flow, testing `USER_LINKABILITY` (direct co-location) and
`DESTINATION_DISCLOSURE` together. Both solved by cutting `DESTINATION`
alone (cost 6) -- the identity+destination co-location fact and the
disclosure fact share the same underlying observation, so one mechanism
clears both.

## Case 5: UNSAT is not a failure to hide

A scenario exposing only `DESTINATION`, a catalog that can only affect
`TIMING`/`VOLUME`. `DESTINATION_DISCLOSURE`'s only cut requires removing the
`DESTINATION` observation, which nothing in the catalog can touch. The
planner returns `satisfiable=False`, `chosen_mechanisms=()`,
`total_cost=0.0`, and names exactly what remains exposed and why --
`test_unsat_never_reports_a_cost_or_chosen_mechanism` pins this as an
invariant: UNSAT must never look like a cheap success.

## The explanation contract, preserved

Every case's report carries: the hypothesis and its `supporting_paths`
(Aegis 2's own decision, facts and provenance included), the enumerated
minimal cuts (`minimal_cuts_considered`, with the realized cut's full
observation detail), the `candidate_mechanisms` considered, the
`chosen_mechanisms` and `total_cost`, and `remaining_exposure` when
unsatisfiable. `test_every_case_preserves_the_full_explanation_contract`
checks all of it is present in every case, not only the ones that happen to
succeed.

## The SESSION gap: named, not wired in under time pressure

Aegis 2's held-out topology test surfaced that `SESSION` is declared in
`EXPOSURE_CATEGORIES` but contributes to zero inference rules. That finding
stands as *good* architecture feedback specifically because nothing was
mapped to make the gap disappear. Here is the honest state of it going into
Aegis 3, not papered over:

**A plausible operational meaning exists.** `SESSION` would represent
whether an observation point can even tell that a set of individual
connections belong to one continuous usage episode -- i.e., whether session
*boundaries* are visible at all, as distinct from `FREQUENCY` (how often
something recurs) or `SEQUENCE` (the shape within one already-known flow).
Under that meaning, `SESSION` is a *prerequisite*, not ordinary supporting
evidence: `FLOW_LINKAGE` and `CROSS_SESSION_LINKABILITY` currently assume
session boundaries are already given (every scenario in Aegis 1A/1B/2/3
pre-partitions its data into `flow_id`s), and a raw observer without
session-continuity awareness arguably cannot even frame the "are these the
same session" question, regardless of what else it sees.

**Why it is not wired in this stage.** Making `SESSION` a hard prerequisite
(via `EvidenceFact.blocks_decision`, the exact primitive
`valkyrie.edr.hypothesis` already has for "a required fact is missing") would
retroactively block `FLOW_LINKAGE`/`CROSS_SESSION_LINKABILITY` in *every*
existing scenario in this document and in Aegis 1A/1B/2, none of which
declare a `SESSION` observation today. That is a real, cross-cutting change
to the meaning of every prior result, not a local addition -- exactly the
kind of change that deserves its own dedicated pass (retrofitting every
scenario's `SESSION` observations deliberately) rather than a rushed
insertion at the end of building the planner. Declaring a producer and a
rule for `SESSION` now, without doing that retrofit carefully, would risk
becoming the "map it just because the vocabulary says it exists" mistake
this gap was explicitly raised to prevent.

**What closing it properly would require:** (1) a decision on which real
Valkyrie/Aegis telemetry source would actually emit "session boundaries are
observable here" as a fact (candidates: a stable connection/circuit
identifier at a relay hop, or a burst-gap heuristic at a raw packet
capture); (2) retrofitting Aegis 1A/1B/2's replayed scenarios to declare
`SESSION` (or its absence) explicitly, since their current results implicitly
assumed it; (3) re-running every existing test in this file and in
`test_aegis_2_exposure_graph.py` to confirm they still hold under the new
prerequisite, or updating them deliberately where they don't. None of that
is done here; it is the next honest step, not an omission to gloss over.

## Limitations

- Mechanism costs and `affected_categories` are synthetic and hand-chosen
  per case, not derived from any real privacy technique.
- This does not measure observer accuracy (Aegis 1A/1B's own job); it
  verifies the planner finds a correct, cheapest, feasible mechanism set
  given a declared catalog and the exposure graph's cut structure.
- `max_cut_size` (default 3, inherited from `valkyrie.aegis_exposure`)
  bounds the cut search; a hypothesis whose only cuts exceed this bound is
  reported as `unreachable_within_search_bound`, a distinct outcome from
  `unsatisfiable` (cuts exist, but no mechanism combination realizes one).
- The `SESSION` gap above remains open by design, not by oversight.

## What comes after this

Only once a mechanism-independent planner like this survives its own
held-out and UNSAT cases does attaching a *real* mechanism catalog become a
reasonable next step -- and even then, each real mechanism's
`affected_categories`, cost, and compatibility risk would need to be
independently measured (in the spirit of Aegis 1A/1B), not asserted, before
the planner's chosen plan could be trusted as more than a synthetic
demonstration.
