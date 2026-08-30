# Detection Architecture v2 Experiment

**Evidence class:** synthetic mechanism evaluation.  
**Independent:** no.  
**Frozen manifest SHA-256:** `29e7237bb42d475b40f108c45ffee6c7c368dcbf93cfbf546462ab3c06964513`

## Research question

Can canonical events, shared behavioral evidence, contradictory evidence, and competing hypotheses recognize committed behavioral variants while allowing superficially similar benign activity?

## Cohorts

- Development: 6
- Frozen held-out variants: 12
- Benign twins: 12

## Ablation results

| Mode | Recall | Specificity | False-positive rate | p99 fast-path latency |
|---|---:|---:|---:|---:|
| rule_baseline | 0.0% | 100.0% | 0.0% | 0.0000 ms |
| behavior_only | 0.0% | 100.0% | 0.0% | 0.2019 ms |
| behavior_context | 100.0% | 100.0% | 0.0% | 0.1989 ms |
| full | 100.0% | 100.0% | 0.0% | 0.2170 ms |

## Result

The frozen synthetic corpus verifies the v2 mechanism and its privacy boundary. It does not establish real-world efficacy. In the current corpus, graph context does not improve recall over cross-event behavioral context. That means the causal contribution remains unproven rather than being credited because the architecture sounds sophisticated.

## Limitations

- Scenarios are synthetic and committed with the detector.
- Held-out means a frozen evaluation cohort, not independent real-world novelty.
- Prevention is not measured because Detection Architecture v2 is shadow-only.
- The corpus was authored in the same repository as the detector.
- The v2 path is shadow-only and cannot execute prevention.
- Independent Atomic and real-browser results must be reported separately.

## Next falsifiable hypothesis

On an independently executed Atomic cohort with stage-level telemetry, causal context should improve held-out behavioral recognition without increasing benign false positives or pushing fast-path p99 above 10 ms.
