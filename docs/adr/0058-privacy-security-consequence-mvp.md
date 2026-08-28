# ADR 0058 — Privacy/security consequence MVP

Status: experimental. Follows: ADR 0049 and ADR 0057.

## Hypothesis

On a mature local baseline, a **complete** browser/document-rooted causal
lineage with both (a) a Nyx privacy observation and (b) a rare descendant
DNS/network consequence is more useful than either observation alone. The
resulting signal is evaluated by the existing decision policy and authority
gates before a playbook may simulate a **later** DNS block.

## Boundaries

- The request that supplied the Nyx observation has already occurred. This is
  not retroactive prevention, packet interception, or a claim of WFP control.
- The detector requires 300 baseline observations and three sessions, complete
  provenance, an interactive owner, one unambiguous destination, and a rare
  descendant egress. Any uncertainty suppresses the finding.
- `tls_addon.py` emits a normalized `TelemetryEvent(category="privacy")` to
  `EdrEngine.ingest_telemetry`; it does not call the causality graph directly.
  The event carries only category, destination, first-party origin, attribution
  confidence, and a retry-safe event id. It never carries a body, query, raw
  content, value, or Nyx's masked diagnostic sample.
- The graph accepts privacy fields through a fixed allowlist and deduplicates a
  retry with the same event id. Findings retain only category, destination, and
  distinct network destination.
- The shipped `privacy-consequence-future-dns` playbook is **dry-run**. It can
  match only when both the policy and authority records say `block`; it cannot
  mutate DNS intelligence directly. Moving it to `enforce` remains contingent
  on live disposable-VM validation.

## Falsification criteria

Reject or revise this experiment if installer/updater workloads generate an
unacceptable false-positive rate, process/port attribution races make the
finding unreliable, privacy-boundary tests leak payload material, or measured
end-to-end latency makes future DNS enforcement ineffective for the scenario.

## Validation

`tests/test_privacy_consequence.py` covers maturity, incomplete provenance,
interactive-owner, routine egress, payload-boundary refusal, TLS event
normalization, retry idempotence, and policy/authority playbook gating. It is a
structural/integration test, not evidence of detection efficacy, DNS latency,
or live enforcement.

`tests/test_provenance_adversarial.py` additionally challenges event ordering,
PID reuse, missing parent provenance, and a bounded event storm. The local
synthetic ingest measurement is recorded in
`docs/PROVENANCE_EXPERIMENT_REPORT.md`; it is not a DNS hot-path measurement.

## Live validation gate

As of 2026-08-28, the available host is physical Windows hardware, Sysmon64 is
stopped, and Invoke-AtomicRedTeam is absent. Tier-B is therefore **LIVE
VALIDATION BLOCKED**. The dry-run playbook must not be promoted to `enforce`
until a disposable snapshot-capable Windows VM supplies the required evidence.
