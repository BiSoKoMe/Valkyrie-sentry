# Valkyrie Detection Architecture v2

## Status

This is an implemented experimental vertical slice, not a claim that Valkyrie
now matches a commercial EDR. It introduces a deterministic evidence ledger,
competing hypotheses, explicit contradictory evidence, held-out variants,
benign twins, and layer-by-layer evaluation records. Existing detections remain
active and automatic response remains separately policy and authority gated.

## Research question

Can Valkyrie recognize classes of dangerous causal behavior without adding one
final-verdict rule per manifestation, while refusing to originate a new alert
when normal host behavior or trusted maintenance better explains the evidence?

## What changed

`valkyrie/edr/hypothesis.py` adds a small deterministic fusion engine. Behavior
extractors emit bounded `EvidenceFact` objects. Every fact declares which
hypotheses it supports and contradicts, its strength, its explanation, and its
provenance. Duplicate evidence ids are ignored. Supporting and contradictory
evidence are fused with diminishing returns, then competing explanations are
compared by confidence and decision margin.

The first production adapter is in `valkyrie/edr/causal_detect.py`. Existing
causal motifs are treated as behavior evidence. Rare host structure supports a
`malicious_execution` hypothesis. Routine host structure supports
`routine_activity` and contradicts the attack explanation. A trusted installer,
updater, development, or OS lineage supports `trusted_maintenance` and also
contradicts the attack explanation. Missing causal state, an immature baseline,
or incomplete provenance blocks a graph-originated alert rather than pretending
the missing information is benign.

`valkyrie/edr/engine.py` now requires both the existing conservative causal
finding and the new competing-hypothesis decision before a causal structure can
originate an incident. The full evidence ledger is retained in detection
details for review. Rule-based detections are not routed through this new gate
yet, so this is a narrow vertical slice and not an architecture-wide migration.

`redteam/evaluation/pipeline_trace.py` separates execution, telemetry,
normalization, causal linkage, behavior recognition, hypothesis formation,
decision, prevention, and benign control. Unknown stages never enter a success
rate. This prevents a later detection from being used as fake proof that every
earlier layer worked.

## Why this is different from another score

The engine still has explicit thresholds and evidence strengths. Claiming that
it has eliminated rules would be dishonest. The architectural change is that a
single observation is no longer the entire verdict and suspicious evidence can
be weakened by a concrete competing explanation. The ledger also records the
facts and provenance needed to debug a wrong decision.

## Current tests

`tests/test_hypothesis_engine.py` checks duplicate resistance, an auditable rare
attack chain, a routine benign twin, a trusted-maintenance twin, incomplete
provenance refusal, and a held-out script-host variant that reuses existing
behavior primitives. `tests/test_pipeline_trace.py` verifies root-cause
localization and prevents unknown stages from inflating evaluation rates.

These are deterministic mechanism tests. They are not independent efficacy
evidence. The independent baseline remains the disposable Windows GitHub
Actions run from commit `876321a`, where 65 of 73 catalog entries executed and
Valkyrie detected 26. That is 40.0 percent of executed techniques. The 39
executed misses are the honest starting point, not a number to hide.

## Next experiment

The next meaningful step is to instrument the disposable Windows evaluation so
each external Atomic result carries a `PipelineTrace`. Then freeze the behavior
and hypothesis implementation, split the external scenarios into development
and held-out cohorts, add benign lookalikes, and compare four ablations:

1. Existing rule baseline.
2. Behavior evidence without causal linkage.
3. Behavior evidence plus causal linkage.
4. Full competing-hypothesis gate.

The comparison must report executed scenarios, first failed pipeline layer,
held-out recall, benign false-positive rate, median and p99 decision latency,
and whether a response was actually verified. If the full system does not
improve held-out detection without unacceptable benign regressions, this
architecture has not earned expansion.

## Limitations

- Only graph-originated causal detections use the hypothesis gate today.
- Evidence strengths are engineered constants and require ablation testing.
- The current benign twins are deterministic fixtures, not long-duration user
  workloads.
- The current held-out case proves code-path reuse, not real-world novelty.
- User-mode telemetry can miss short-lived processes.
- Nyx has real-browser enforcement evidence, but it is not yet fused through
  this generic hypothesis engine.
- No current result proves superiority to CrowdStrike, Cortex, Defender, or
  SentinelOne.
