# Three-component implementation status

Date: 2026-09-07. Target: one locally managed Windows PC.

This file tracks work completed from the engineering roadmap. It does not
declare production readiness. Host-changing validation remains restricted to a
disposable, snapshot-capable Windows VM.

## Implemented and locally tested

- A versioned component contract assigns endpoint sensing and response to
  Valkyrie, privacy defense to NYX, and durable investigation to Aegis. The
  contract is available at `GET /api/v1/capabilities`.
- Aegis provides versioned status and case APIs over the existing durable EDR
  store. Existing privacy exposure routes remain compatible and are also
  exposed under the NYX namespace.
- NYX records URL, body, and header rewrite outcomes separately. Partial or
  failed rewrites cannot report full success.
- The event bus counts subscriber delivery failures and isolates one failing
  subscriber from the others.
- Process termination requires PID plus observed creation time and rechecks the
  process identity immediately before termination.
- Temporary domain response blocks use a separate bounded SQLite store with a
  maximum 24-hour expiry. Releasing a response block does not alter independent
  threat intelligence.
- Real responses persist a pending audit row before calling the responder. An
  unavailable audit store blocks execution. Final write failure leaves the
  pending row and is visible through `audit_state`.
- Enforcement lease writes fail explicitly and roll back their in-memory
  mutation. If a post-enforcement lease grant fails, Valkyrie immediately calls
  the registered reverse action and records the outcome.
- Loopback control mutations require a locally published credential, reject
  remote origins, and no longer expose an HTTP token bootstrap endpoint.
  Electron IPC validates the sender, limits payload size, and exposes an
  allowlisted mutation surface.
- The Windows build depends on the required test workflow, checks packaged
  command exit codes, and publishes a SHA-256 digest. Unsigned tag builds create
  draft releases only.
- The desktop identifies Valkyrie, NYX, and Aegis directly. Aegis shows open
  cases and delivery uncertainty; NYX shows exposure-ledger failures, and the
  interface no longer presents a fabricated privacy score.

## Open release gates

- Replace the credential-file containment layer with an ACL-restricted Windows
  broker that authenticates the caller's identity and integrity level.
- Remove the host-isolation crash window between the firewall change and the
  durable lease grant. Prove recovery after termination and reboot.
- Add durable Windows event-log checkpoints, gap accounting, log-clear
  detection, and bounded ingest queues.
- Exercise install, upgrade, rollback, suspend, VPN, disk pressure, response,
  and uninstall against the exact packaged digest in disposable Windows VMs.
- Add Authenticode signing, a protected release key flow, SBOM generation, and
  verified update rollback before publishing a non-draft release.
- Build, sign, load, stress, and independently review any kernel driver before
  claiming driver-backed prevention. The current release contract excludes it.

## Current evidence boundary

The local tests exercise application logic, temporary databases, fake response
adapters, API contracts, and Electron security boundaries. They do not prove
that Windows firewall, DNS, service, installer, or driver recovery works on a
real installed endpoint. Those claims stay open until the VM gates above pass.
