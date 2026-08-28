# Privacy Model

## Status: IMPLEMENTED (local minimization); UNVALIDATED (production privacy review)

Nyx may inspect request content locally to make an immediate local privacy
decision. Its provenance emission is a stricter boundary: body, query, raw
content, value, and masked diagnostic sample do not enter telemetry, graph,
incident, playbook, or response records.

The retained provenance fields are process identity, destination, first-party
origin, category, timing, attribution confidence, and event id. This permits
causal analysis while intentionally giving up content-level forensic detail.

Browser extension semantics are not implemented. Referer/Origin-derived
first-party context is absent on some traffic and must cause suppression rather
than guessed semantic attribution.
