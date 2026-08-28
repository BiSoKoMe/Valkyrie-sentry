# ADR 0022 - Detection-efficacy harness

Date: 2026-07-19 . Status: accepted

## Context

Valkyrie had 42 unit tests proving code does what it was told, and **zero
evidence it discriminates real attacker behavior from normal activity**.
That gap - not any missing feature - was the project's biggest weakness: a
detection product whose detection rate is unmeasured is built on faith. The
cheapest high-value thing a solo project can do is measure it.

## Decision

`tests/efficacy/` - a corpus + harness that drives the **real** classifiers
(no mocks) with MITRE-ATT&CK-tagged malicious inputs and a benign control
set, and scores recall + false-positive rate + precision, with a per-tactic
breakdown. It is a **regression gate**: non-zero exit if recall < 85% or
FPR > 5%.

- `corpus.py` - `Case` records (detector, malicious/benign, technique,
  input). Carries a loud honest-boundary docstring.
- `harness.py` - routes each case to the actual detection function, tallies
  TP/FN/FP/TN, prints a scorecard.

Kept out of the unit `run_tests.py` (it is a scorecard/gate, run on demand),
so a slow or network-shaped future case never destabilizes the unit suite.

## What it produced immediately

First run: 87.5% recall, surfacing a real gap (WScript `//b` silent-batch
execution, T1564.003, uncovered by the hidden-flag heuristic) and a corpus
artifact (an RFC 5737 doc-range C2 IP the validator correctly dropped).
Fixed the real gap in `process_telemetry._HIDDEN_FLAGS` (FP-safe:
trailing-space match avoids URLs), fixed the corpus IP -> re-measured 100% /
0%. It also surfaced a pre-existing tuning finding (`curl https` flags high
via a `"curl http"` substring match), documented for an operator decision
rather than reactively retuned.

## Honesty design

The report (docs/DETECTION_EFFICACY_REPORT.md) states plainly that 100% on
this corpus is **not** 100% malware detection - it measures classifier
discrimination on author-known inputs, not sensor capture or novel
adversary behavior, and does **not** replace live-sample VM testing (the
gold standard it complements). Thresholds encode current capability, not
aspiration.

## Rollback

Pure additive test tooling; delete `tests/efficacy/` to remove. The one
product change (WScript flags) stands on its own with the existing telemetry
tests green.

## Next

Grow the corpus toward broader ATT&CK coverage as detectors ship; wire the
gate into CI; and - the real gold standard - stand up a VM lab running
Atomic Red Team and a lab C2 beacon against the live agent to measure what
this harness structurally cannot (sensor capture + novel behavior).
