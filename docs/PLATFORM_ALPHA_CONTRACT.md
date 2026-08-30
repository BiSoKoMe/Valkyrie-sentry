# Platform Alpha Contract

**Status:** locked. This is a milestone contract, not a living design doc --
amend it only by deliberately re-opening Platform Alpha, never by quietly
drifting the code out from under it.

Platform Alpha's actual claim is narrower than "all three subsystems work."
It is: **one real event chain can feed three different reasoning systems
without collapsing their meanings together.** Everything below is a
guarantee that claim continues to hold, each one backed by a real,
currently-passing test -- not a promise resting on prose.

## The seven guarantees

**1. One canonical event stream can feed Valkyrie, NYX, and Aegis.**
`valkyrie/aegis_bridge.py` translates real `CanonicalEvent`s (the same ones
`valkyrie.edr.detection_v2.BehaviorEngine` and NYX's privacy facts already
consume) into Aegis's exposure vocabulary.
Proven by `redteam/evaluation/platform_alpha_evidence_story.py` and
`tests/test_platform_alpha_evidence_story.py`.

**2. Each subsystem preserves independent semantics. No universal
"safe/malicious" verdict exists.** Valkyrie, NYX, and Aegis report their own
hypothesis state; nothing merges them into one boolean.
Enforced by `test_no_global_verdict_field_exists_anywhere_in_the_report`.

**3. Cross-subsystem corroboration may affect a fused operational decision,
but subsystem hypotheses remain separately inspectable.** The report
carries `valkyrie.hypothesis_isolated`, `nyx.hypothesis_isolated`, and
`fused_decision.hypothesis` as three distinct fields -- the fused one is
what a real deployment acts on; the isolated ones stay inspectable
alongside it, never discarded.
Proven by `test_valkyrie_and_nyx_reach_different_isolated_conclusions_but_a_shared_fused_one`.

**4. Aegis derives only network-observer-relevant facts actually supported
by the event stream.** `translate_event`/`translate_session` restrict
themselves to event types that actually leave the host (`DNS`, `NETWORK`,
`PRIVACY`); a process-only or persistence-only event produces zero
observations, no matter how suspicious Valkyrie finds it.
Enforced by `tests/test_aegis_bridge.py`'s local-event tests and
`test_negative_no_network_evidence_does_not_inflate_valkyrie_or_produce_aegis_evidence`.

**5. Missing observability remains unavailable rather than inferred.**
`VOLUME`, `DIRECTION`, `IDENTITY`, and `SESSION` are named explicitly in
`valkyrie.aegis_bridge.UNAVAILABLE_CATEGORIES`, each with the specific
reason it cannot be honestly derived from the current schema -- a missing
field (`VOLUME`, `DIRECTION`) or a field that describes the wrong vantage
point (`IDENTITY`, `SESSION` -- `subject.instance_id` is Valkyrie's local
host-side attribution, not what a network observer can see).
Enforced by `test_negative_missing_fields_are_not_synthesized` and
`test_unavailable_categories_are_never_produced`.

**6. Every derived fact/hypothesis remains traceable to source events.**
Every `ExposureObservation` and every Valkyrie/NYX `EvidenceFact` carries
`provenance` back to a real `event_id`.
Enforced by `test_negative_every_aegis_observation_traces_back_to_a_real_event_id`,
`test_negative_every_valkyrie_and_nyx_fact_traces_to_a_real_event_id`, and
`test_negative_provenance_is_not_lost_when_two_observations_share_a_category_and_point`
(the last one pins the fix for a real bug this stage's own tests found: a
provenance summary keyed by `"category@point"` silently dropped one of two
same-point `DESTINATION` observations).

**7. Platform Alpha proves architecture and in-process integration only. It
does not prove complete live enforcement or production reliability.**
Nothing in `platform_alpha_evidence_story.py` touches a live host, a live
browser, or a live network. That boundary is deliberate, not an oversight --
see Platform Beta below.

## The frozen baseline

`redteam/evaluation/baselines/platform_alpha_baseline.json` is a committed
snapshot of `platform_alpha_evidence_story.run()`'s actual output.
`tests/test_platform_alpha_baseline.py` asserts every fresh run matches it
exactly. Because everything in this path is in-process and deterministic --
no live host, no live network, no randomness -- a failure in that test can
only mean the reasoning layer changed. Once Platform Beta starts touching
real hosts, real browsers, and real network capture, and those start
producing failures of their own, this baseline is what separates a
reasoning regression from an environment/telemetry failure. Update it
deliberately, with the reason stated in the commit, never silently.

## What comes next: Platform Beta -- the reality boundary

Not more architecture. Platform Alpha proved the reasoning layer is
coherent; the open question changed from "what architecture should these
systems have" to "do these architectures survive contact with the real
environment." Three subsystems, one at a time, each crossing its own
synthetic/in-process -> real-environment wall:

1. **Valkyrie** -- real telemetry reliability. Chosen first because every
   shared causal story in this contract depends on trustworthy events; if
   host telemetry is unreliable, Platform Alpha's guarantees rest on sand
   regardless of how sound the reasoning above them is.
2. **NYX** -- actual browser disclosure enforcement. The authority reasoning
   already exists (`NYX_ACT`, the enforcement scorecard); the real gap is
   complete request mediation in a live browser, not more reasoning.
3. **Aegis** -- real network observation/interception. Placed last because
   its reasoning core (Stages 0-4) is already well ahead of any real
   actuation layer; there is no reason to rush a live network component
   before the event foundation under it (Valkyrie, then NYX) is proven
   solid.

Platform Beta is not started by this document. It is named here so the next
session begins with the wall already identified, instead of rediscovering
it.
