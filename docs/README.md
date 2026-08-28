# Valkyrie Documentation

This directory records both Valkyrie's implementation evidence and the limits
of that evidence. A feature described as implemented has source and focused
tests. A feature described as live validated has controlled, repeatable
measurement in an isolated Windows VM. Do not treat the two labels as
interchangeable.

## Start here

- [Valkyrie research paper](VALKYRIE_RESEARCH_PAPER.md) — formal description of
  the local privacy/security provenance experiment.
- [Provenance architecture assessment](PROVENANCE_ARCHITECTURE_ASSESSMENT.md) —
  implementation inventory, Windows data-source reality, gaps, and risks.
- [Provenance phase status](PROVENANCE_PHASE_STATUS.md) — current evidence
  ledger and the requirements for live validation.
- [Provenance experiment report](PROVENANCE_EXPERIMENT_REPORT.md) — measured
  synthetic ingest results and adversarial mechanism scope.

## Core models

- [Provenance model](PROVENANCE_MODEL.md)
- [Privacy model](PRIVACY_MODEL.md)
- [Consequence model](CONSEQUENCE_MODEL.md)
- [Enforcement model](ENFORCEMENT_MODEL.md)
- [Threat model](THREAT_MODEL.md)
- [Limitations](LIMITATIONS.md)

## Browser and application context

- [Browser context bridge](BROWSER_CONTEXT_BRIDGE.md) — experimental Chromium
  extension/native-host design and privacy boundary.

## Evaluation and future work

- [Experiments](EXPERIMENTS.md)
- [Research hypothesis](RESEARCH_HYPOTHESIS.md)
- [Vendor architecture notes](VENDOR_ARCHITECTURE_2026.md)
- [Threat landscape notes](THREAT_LANDSCAPE_2026.md)

## Safety boundary

Live validation must run on a disposable, snapshot-capable isolated Windows VM.
Do not use primary hardware for Atomic Red Team, driver loading, broad firewall
changes, or automatic-response experiments.
