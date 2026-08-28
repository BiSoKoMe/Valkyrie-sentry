# Valkyrie

**A local-first Windows security and privacy research prototype.**

Valkyrie investigates whether an endpoint can connect process lineage, network
activity, and privacy observations into a single, explainable decision about
what software behavior caused. It is not presented as a replacement for a
commercial EDR, a production antivirus product, or a completed privacy-control
system.

## Project status

Valkyrie has working local telemetry, causality, policy, DNS-control, and
privacy components. Its newest experiment—combining metadata-only privacy
observations with a process-provenance graph—is structurally and integration
tested, but not live-validated.

| Evidence level | Meaning |
|---|---|
| Implemented | Source code and focused tests exist in this repository. |
| Synthetic measurement | A controlled local benchmark or synthetic test passed. |
| Live validated | Measured in an isolated Windows VM against a controlled workload. |

The unified privacy/security consequence rule is **implemented and
synthetically measured, not live validated**. It remains dry-run and
policy/authority gated.

## The research question

Most endpoint products evaluate individual alerts: a process launched, a
domain was queried, or a privacy-sensitive value crossed a boundary. Valkyrie
asks whether the endpoint can instead reason about their relationship:

```text
interactive application -> descendant process -> network consequence
                         + metadata-only privacy observation
                         -> local policy decision
```

The goal is not more signatures. It is a falsifiable question: does local
provenance help make safer, more useful security-and-privacy decisions than
isolated signals alone?

## What is implemented

- Normalized process, DNS, network, persistence, ETW, malware, asset, and
  privacy telemetry.
- A bounded causality graph with process ancestry, PID-reuse safeguards,
  artifact attribution, inferred-node marking, and graph-completeness signals.
- DNS sinkhole control with inline allow, block, and deceive paths.
- Local EDR correlation, incident timelines, response actions, policy profiles,
  authority checks, and dry-run playbooks.
- Nyx metadata-only privacy telemetry: category, destination, and first-party
  context can enter the EDR; raw request bodies and masked samples do not.
- An experimental Chromium native-messaging bridge for sanitized navigation,
  trusted-gesture, form-submit, and coarse-consent metadata. It is
  observation-only and does not fabricate a Windows PID relationship.
- A narrow consequence experiment that joins browser/document lineage, a Nyx
  observation, and rare descendant egress into a policy-gated future-DNS
  incident.

## What Valkyrie does not claim

- Production efficacy or a measured end-to-end response time.
- Prevention of the privacy request that was already observed.
- A signed or deployed kernel driver; Valkyrie therefore cannot claim
  authoritative kernel provenance, pre-execution process blocking, or
  pre-write file/registry blocking.
- Reliable browser-semantic-to-Windows-PID attribution.
- TLS inspection for certificate-pinned applications.
- Suitability as the sole security control on a real device.

## Safe demonstration

This command creates an **in-memory synthetic session**. It does not read live
browser traffic, change DNS or firewall settings, open a listener, or load a
driver.

```powershell
python tools/provenance_demo.py
```

The demonstration shows one causal chain, retained metadata, the policy
decision, and a deliberate refusal to score content-bearing privacy metadata.

## Local development

### Requirements

- Windows 10 or 11 for Windows-specific collection and enforcement paths.
- Python 3.10 or newer.
- Administrator privileges only for optional host-level actions such as DNS
  redirection, firewall changes, selected ETW channels, and process response.

### Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements_modular.txt
```

Run the focused provenance tests:

```powershell
python -m pytest -q tests/test_provenance_demo.py tests/test_privacy_consequence.py tests/test_provenance_adversarial.py tests/test_browser_context.py
```

Run the synthetic local-ingest benchmark:

```powershell
python tools/provenance_benchmark.py --events 1000
```

The benchmark measures synchronous local `EdrEngine.ingest_telemetry()` cost
only. It is not a DNS hot-path, live-efficacy, or response-latency benchmark.

## Validation policy

Live validation belongs in a disposable, snapshot-capable, isolated Windows VM.
Do not run Atomic Red Team exercises, driver loading, or automatic-response
experiments on a primary workstation. Before promoting the experiment, the
project needs replicated VM results covering attribution error, end-to-end
latency, benign installer/updater false positives, and rollback.

## Documentation

Start with the [documentation index](docs/README.md).

- [Research paper](docs/VALKYRIE_RESEARCH_PAPER.md)
- [Provenance architecture assessment](docs/PROVENANCE_ARCHITECTURE_ASSESSMENT.md)
- [Provenance experiment report](docs/PROVENANCE_EXPERIMENT_REPORT.md)
- [Phase status](docs/PROVENANCE_PHASE_STATUS.md)
- [Browser context bridge](docs/BROWSER_CONTEXT_BRIDGE.md)
- [Security policy](SECURITY.md)

## Repository map

```text
valkyrie/              Core application, telemetry, DNS, EDR, and web API
valkyrie/edr/          Causality graph, correlation, policy, and response
tests/                 Unit, integration, adversarial, and regression tests
tools/                 Safe demo and synthetic benchmark tools
browser_extension/     Experimental Chromium native-messaging bridge
driver/                 Kernel driver source; not signed or deployed
docs/                   Evidence, architecture, experiment, and safety documents
redteam/                Controlled evaluation harnesses; VM-only live validation
```

## Contributing and license

Please open an issue before proposing a large security-control, telemetry, or
response change so its threat model and safety boundary can be reviewed first.

No open-source license has been selected yet. Public availability of this
repository is not a license grant; contact the repository owner before reuse or
redistribution.
