# Platform Alpha: the CanonicalEvent -> ExposureObservation Bridge

**Evidence class:** real in-process integration -- actual `DetectionArchitectureV2`,
actual NYX facts, actual Aegis reasoning, over a fabricated but structurally
real event chain. Not a live-host or live-browser measurement.
**Independent:** no.
**Stage:** Platform Alpha integration. No new detection rules, NYX
features, Aegis mitigations, planner mechanisms, thresholds, or
live-host/browser infrastructure were added.

## The narrow target, and why it stayed narrow

Valkyrie and NYX already share one real pipeline: every `CanonicalEvent`
(from `valkyrie.edr.detection_v2.EventNormalizer`) is evaluated by the same
`BehaviorEngine` and fused by the same `evaluate_hypotheses` engine,
regardless of whether the evidence came from a process collector or from
NYX's own privacy observations. Aegis, up through Stage 4, only ever
reasoned over hand-built synthetic `ExposureObservation` scenarios. The one
integration task this stage adds is a translation boundary --
`valkyrie/aegis_bridge.py` -- that lets Aegis's exposure graph consume the
SAME real canonical events Valkyrie and NYX already do, in the same
one-directional relationship `behavior_ontology.py` already established for
Valkyrie's own detectors: raw input translates into a canonical vocabulary,
never the other way around.

Two constraints were treated as load-bearing, not optional:

- **`CanonicalEvent` was not changed.** Every gap below was checked against
  the real schema first; none of them justified widening a shared event
  model just to make one consumer's job easier.
- **Valkyrie and NYX do not import Aegis.** Checked directly, not just
  claimed --  `test_negative_valkyrie_and_nyx_modules_do_not_import_aegis`
  parses `detection_v2.py`, `hypothesis.py`, and `nyx.py`'s own ASTs and
  asserts none of them import anything with "aegis" in the module name.

## What is honestly derivable from a real CanonicalEvent today

| Aegis category | Derivable? | From | Restriction |
|---|---|---|---|
| DESTINATION | yes | `object.kind`/`object.identity` | only DNS/NETWORK/PRIVACY event types (see below) |
| TIMING, FREQUENCY, SEQUENCE | yes, from >=2 events | real timestamps for the same subject | needs a session, not a single event |
| VOLUME, DIRECTION | **no** | -- | no byte-count or inbound/outbound field exists anywhere in the real telemetry schema (checked: `network_telemetry.py`, `dns_interceptor.py`, `nyx.py`, `telemetry.TelemetryEvent`) |
| IDENTITY, SESSION | **no** | -- | `subject.instance_id` is real, but it is Valkyrie's LOCAL host-side process attribution, not something a network-vantage-point observer can see, and it is bounded to one process lifetime rather than a stable cross-session identity -- using it directly would conflate two different vantage points under one name |

`valkyrie.aegis_bridge.UNAVAILABLE_CATEGORIES` names all four gaps
programmatically, with the reason for each, so "what this bridge does not
claim" is answered by running code, not by re-reading prose.

### Cross-platform state vs. Aegis-specific state

Per the instruction to determine this before touching the schema: VOLUME
(a byte count) is plausibly **cross-platform** state -- Valkyrie's own
`network_score.py`-style reasoning could conceivably use transfer size too,
so if it is ever added to `CanonicalEvent`, that should be decided on
Valkyrie's own merits, not smuggled in to serve Aegis. IDENTITY and SESSION,
by contrast, are **not** missing schema fields at all -- the schema already
has the closest available fact (`subject.instance_id`); the honest finding
is that this fact describes a different vantage point than Aegis's
IDENTITY/SESSION categories mean, which no amount of schema editing fixes.
Neither conclusion justified a change in this stage.

## The bridge itself

`translate_event(event)` -- one event in, zero or more `ExposureObservation`s
out. Returns `()` for anything outside `{DNS, NETWORK, PRIVACY}` -- a
process launch or a registry write never reaches the wire, so it can never
honestly become Aegis evidence no matter how suspicious Valkyrie finds it.

`translate_session(events)` -- groups events by `subject.instance_id`
(used only as an internal grouping key, never itself exposed as an
observation), translates each network-visible event, and additionally
derives TIMING/FREQUENCY/SEQUENCE from real inter-event timestamps once two
or more network-visible events share a subject. Every observation carries
`provenance`: the source event id(s), their `source` module, their
category, and the process instance they were attributed to.

## The shared evidence story

`redteam/evaluation/platform_alpha_evidence_story.py` runs one realistic
causal chain -- a browser process with a suspicious-ancestry label, a
network connection, an unauthorized NYX privacy observation, all on one
process instance -- through the real `DetectionArchitectureV2`, then through
the bridge and Aegis's exposure graph, and assembles one report:

```
what happened                 -- the raw TelemetryEvents
causal/process identity        -- subject.instance_id, image, confidence
valkyrie.evidence + hypothesis_isolated
nyx.evidence + hypothesis_isolated
fused_decision.hypothesis      -- what the REAL engine actually concluded
aegis.exposure_observations + inference_hypotheses
provenance                     -- every fact/observation traced to its source event id
```

`hypothesis_isolated` for Valkyrie and NYX are reporting-only
recomputations (evaluating each subsystem's own evidence alone, through the
identical generic `evaluate_hypotheses` machinery) -- the real system never
computes them separately; it fuses both into `fused_decision`, exactly as
`detection_v2.BehaviorEngine` was built to do. Showing both is more
informative than showing the fused result twice under two names.

## Shared evidence story != shared verdict

In this run: Valkyrie's own evidence alone concludes `suspicious_execution_chain`
(confidence 0.87); NYX's own evidence alone concludes `possible_data_theft`
(confidence 0.96); the fused decision -- what a real deployment would act
on -- reaches `possible_data_theft` at a higher confidence still (0.98),
because genuine corroborating evidence from both sides combines rather than
competes. Aegis, over the identical event chain, answers a different set of
questions entirely: `DESTINATION_DISCLOSURE` and `ACTIVITY_CLASSIFICATION`
alert, while `CROSS_SESSION_LINKABILITY`, `FLOW_LINKAGE`, and
`USER_LINKABILITY` correctly stay unestablished, because this scenario has
only one flow -- there is nothing to link across observers or sessions yet.

None of that is disagreement. It is three different questions over one
shared causal chain, which is the entire point of the architecture --
`test_no_global_verdict_field_exists_anywhere_in_the_report` pins that no
merged malicious/safe field ever appears.

## Negative tests (all required, all passing)

1. **Non-network events do not become Aegis observations** -- a process-only
   chain produces zero exposure observations while Valkyrie still reasons
   about it normally.
2. **Missing exposure fields stay missing** -- VOLUME, DIRECTION, IDENTITY,
   SESSION never appear in any real translation output.
3. **Aegis cannot alter Valkyrie or NYX verdicts** -- the fused decision
   computed with the Aegis bridge invoked afterward is byte-for-byte
   identical to the decision computed without ever calling Aegis at all,
   and a direct AST check confirms `detection_v2.py`/`hypothesis.py`/`nyx.py`
   import nothing Aegis-related.
4. **One subsystem's failure to derive evidence does not fabricate evidence
   for another** -- a highly Valkyrie-suspicious, network-invisible event
   produces zero Aegis observations and zero Aegis alerts; Aegis's silence
   is not backfilled from Valkyrie's own suspicion score.
5. **Provenance survives the full path** -- every Aegis observation and
   every Valkyrie/NYX fact traces back to a real event id, including the
   case where two observations share the same category and observation
   point (fixed during this stage: the provenance summary used to be a dict
   keyed by `"category@point"`, which silently dropped the second
   DESTINATION observation in exactly this scenario -- now a list, so
   nothing is lost).

## What this does and does not prove

It proves the wiring: a real event stream can feed all three reasoning
layers without merging verdicts, without either side depending on the
other beyond the one-directional bridge, and without inventing exposure
facts the schema cannot honestly support. It does not prove browser-complete
mediation, production network enforcement, or live-host reliability --
those remain the next environmental wall, named rather than simulated.
