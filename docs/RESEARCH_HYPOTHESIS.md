# Valkyrie Research Hypothesis

## Question

Can a Windows endpoint locally combine privacy and security metadata into a
provenance graph, reason about a causal consequence, and apply a safer policy
decision than either subsystem could make alone?

## Falsifiable experiment

The current experiment requires a complete, mature browser/document lineage,
an attributable Nyx privacy observation, and a rare descendant DNS/network
artifact. It compares this joint condition with either privacy or egress alone.

## Success evidence

- A controlled live workload demonstrates an added true positive or a reduced
  false-positive rate against a separated baseline.
- Attribution, policy, and enforcement latency are measured at p50/p95/p99.
- No raw request content is retained in graph, incident, or response records.

## Current status: EXPERIMENTAL / UNVALIDATED

The mechanism is implemented and structurally tested. No disposable-VM live
workload or Atomic Red Team result exists for this specific experiment, so the
hypothesis is neither proven nor disproven.
