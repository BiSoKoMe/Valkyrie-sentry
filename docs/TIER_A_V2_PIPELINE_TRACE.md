# Tier A Catalog Through Detection Architecture v2

**Evidence class:** safe replay against the real catalog (Tier A) -- not a
live attack, and not the committed synthetic corpus in
`docs/DETECTION_V2_EXPERIMENT.md`.
**Independent:** no.

## Research question

`generalization.py` proves the v2 mechanism against 30 scenarios written to
exercise it -- proof the machine works, not proof it generalizes to
Valkyrie's actual detection surface. This asks the harder question the
"next plan" essay's section 13 demands ("make Atomic test your architecture"):
when the real per-technique inputs `replay_harness.py` already builds from
`catalog.py`'s 90-technique redteam catalog are turned into the canonical
events Detection Architecture v2 actually consumes, how far does the real
pipeline get -- stage by stage, using `pipeline_trace.py`'s vocabulary so one
aggregate number can't hide which stage broke.

## Coverage

63 of 90 catalog techniques map cleanly onto one canonical event (`ioa_rule`,
`process_relationship`, `cmdline`, `persistence`, `behavior_score`,
`network`, `dns` probes). The other 27 are named in the report's
`probe_unsupported` list, not dropped from the denominator: `recon_burst`
(19 -- a multi-event sequence IOA, not a single canonical event),
`sysmon_eid8`/`sysmon_eid10` (3), `powershell`, `dga`, `dns_tunnel`,
`cred_store_watch`, `ransomware` (1 each).

## Result

| Stage | Rate | Reading |
|---|---:|---|
| Telemetry | 100% (63/63) | the real classifier's real input, always present |
| Normalization | 100% (63/63) | `EventNormalizer` always produces a canonical event |
| Behavior | 17.5% (11/63) | v2's `BehaviorEngine` recognized a fact from the real classifier's real labels |
| Hypothesis | 17.5% (11/63) | tracks behavior here -- any fact gives non-zero confidence |
| Decision (alert) | 1.6% (1/63) | v2 accumulated enough evidence to alert |

Of the 50 techniques where the legacy classifier fired, **39 produced zero
evidence facts in v2** (the `vocabulary_gap` list, e.g.
`exec-mshta-remote`, `exec-regsvr32-squiblydoo`, `persist-wmi-subscription`,
`evasion-defender-disable`).

## The finding: two label vocabularies inside Valkyrie don't talk to each other

`detection_v2.BehaviorEngine._EXECUTION_LABELS` (`lolbin`,
`office_child_shell`, `encoded_powershell`, `download_cradle`,
`dynamic_exec`, `obfuscation`, `remote_thread_injection`,
`process_tampering`) matches the label vocabulary `process_telemetry.py`
emits. But the *dominant* classifier in the catalog --
`behavioral_rules.classify_behavior()`, covering 54/90 techniques via the
`ioa_rule` probe -- returns its own, larger, per-rule label vocabulary that
does not overlap with `_EXECUTION_LABELS` at all. So for most of Valkyrie's
166+-rule IOA engine, v2 today extracts no evidence whatsoever, not because
telemetry is missing or normalization is wrong, but because nothing bridges
the two vocabularies. That is a real, specific, actionable integration gap
-- not "v2 doesn't work" and not "the IOA rules don't work," but "these two
correct subsystems don't yet share a vocabulary."

## Why "hypothesis formed" is expected to be rare, and that is not a bug

Every technique here is replayed as one isolated canonical event with no
causal chain -- `replay_harness.py`'s own documented limitation ("one
isolated synthetic input, not a running system"). `detection_v2._HYPOTHESES`
requires >=2 supporting facts before an attack hypothesis even qualifies for
`alert` (`suspicious_execution_chain` and `persistence_attempt` both set
`minimum_support=2`). A single technique run alone will almost never clear
that bar -- that is v2 correctly refusing to convict on one weak signal, the
exact property CrowdStrike's own material (quoted in the essay) says matters:
"some individual atomic behaviors aren't malicious enough to alert on by
themselves." Only 1/63 reached `decision=YES` here, and that is the expected
shape of testing single events in isolation, not a regression to chase.

## Limitations

- Not a live attack: no process runs, no registry key changes, no clock
  between "attack" and "detection."
- Not the committed synthetic corpus in `generalization.py` -- it is the
  real catalog's real probe inputs through the real v2 pipeline, called
  fresh (a second call to each real classifier, alongside whatever
  `replay_harness.py` itself does with the first).
- 27/90 techniques are not yet covered (see Coverage); they need multi-event
  sequencing or a different canonical shape this module does not build.
- Every technique here is malicious by construction (the catalog has no
  benign twins), so `benign_control` is not applicable in this report.

## Next falsifiable hypothesis

Building a label-translation layer from `behavioral_rules.classify_behavior()`'s
per-rule vocabulary into `detection_v2.BehaviorEngine`'s recognized facts
should raise the behavior-stage rate well above 17.5% without changing the
decision-stage rate much, since decision is gated by causal chains and
corroborating evidence this single-event replay does not supply. That
isolates the translation-layer question from the "does v2 need real causal
context to alert" question, instead of conflating them in one number.
