# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Valkyrie is primarily for a Windows computer owner or security-conscious operator who wants continuous protection without sending personal telemetry to a vendor. The operator needs to understand current protection state, inspect suspicious causal chains, and approve or review consequential responses without becoming a full-time SOC analyst.

## Product Purpose

Valkyrie is a local, continuous security and privacy enforcement layer. It observes endpoint, network, browser-context, and privacy metadata; joins those observations into provenance; makes deterministic policy decisions locally; and responds at the earliest technically available enforcement point. Success means useful protection with explainable decisions, bounded latency, and no developer access to customer activity.

## Positioning

Valkyrie's differentiating mechanism is a unified local provenance graph that reasons across security and privacy consequences. It is designed to answer not only whether an event looks suspicious, but what action caused it, what it affected, why a response was authorized, and which claim the available evidence cannot support.

## Operating Context

The desktop application is an always-on Windows console backed by a local engine. Routine use begins with protection state and recent decisions, then moves into detections, causal investigation, endpoint and network evidence, privacy activity, and response controls. It must remain useful offline. Risky live validation belongs on a disposable snapshot-capable Windows VM, not the user's daily machine.

## Capabilities and Constraints

- The runtime decision path is deterministic and does not depend on an AI model.
- Customer telemetry and private content remain local; the developer has no privileged view into customer activity.
- Browser observations retain coarse metadata, not page content, full URLs, form values, cookies, keystrokes, or DOM snapshots.
- User-mode attribution can be incomplete or racy, so automatic consequence enforcement remains authority- and evidence-gated.
- DNS is the current inline network enforcement point. Process and host responses exist, but potentially destructive actions require explicit safety controls.
- The unsigned kernel driver is not a deployable product capability and must not be presented as one.
- Synthetic tests and local benchmarks are mechanism evidence, not live efficacy evidence.

## Brand Commitments

- Product name: Valkyrie.
- Strict black, white, and neutral-gray visual identity.
- Serious, direct, technically honest voice.
- The interface must not resemble a generic AI product and must not imply AI-powered decisions.
- Product claims must clearly distinguish observed, inferred, simulated, dry-run, and enforced outcomes.

## Evidence on Hand

- The repository contains the Electron desktop console and local Python engine.
- Provenance, privacy-consequence, browser-context, authority, adversarial, and response tests are present under `tests/`.
- Architecture, experiment, phase-status, and browser-bridge documentation is present under `docs/`.
- A rebuilt Windows installer is produced at `dist_installer/ValkyrieSetup.exe`.
- Live provenance validation remains blocked until a snapshot-capable isolated Windows VM is available.

## Product Principles

1. Local by architecture, not merely by policy.
2. Explain decisions through provenance and evidence.
3. Refuse unsupported conclusions explicitly.
4. Prefer deterministic invariants and bounded authority over accumulating signatures.
5. Make safety, reversibility, and uncertainty visible at the decision point.

## Accessibility & Inclusion

The desktop console should support keyboard operation, visible focus, reduced motion, readable contrast, zoom, and plain-language explanations alongside security terminology.
