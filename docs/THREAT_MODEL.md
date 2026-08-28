# Provenance Threat Model

## In scope

- PID reuse, process termination, missing process starts, and spoofed process
  names/paths.
- Replayed or duplicate telemetry, event reordering, and event storms.
- Ambiguous local-port-to-process attribution.
- Privacy-content retention across graph, incident, policy, and response seams.
- Legitimate browser helpers, installers, and updaters that resemble a causal
  attack shape.

## Out of scope / OS-limited

- Kernel rootkits, authoritative pre-execution prevention, and complete file
  I/O provenance without a deployed signed driver.
- Browser UI intent, consent state, DOM behavior, and certificate-pinned flows
  without an extension or application integration.

## Required response

Ambiguity or incomplete provenance must suppress autonomous consequence action;
it must not be repaired with guessed lineage or a broader block.
