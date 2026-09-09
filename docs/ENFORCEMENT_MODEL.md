# Enforcement Model

## Status: IMPLEMENTED (DNS response); EXPERIMENTAL (unified consequence)

The actual user-mode real-time boundary is DNS. DNS decisions can block or
deceive a query inline. `block_domain` is reversible and audited through the
response manager. Response blocks live in a dedicated, bounded store with a
matching lease expiry. Removing one never turns a separately learned threat
into a trusted domain.

Every real response with an EDR store writes a `pending` authorization record
before invoking its responder, then replaces that row with the final result.
If the preflight write fails, the responder is not called. The returned and
persisted action exposes `audit_state` as `preflight_persisted`,
`final_persisted`, `final_update_failed`, or `unavailable`.

Lease writes are atomic and errors are no longer ignored. A failed grant,
renewal, or release restores the registry's prior in-memory state and raises a
`LeaseError`. If enforcement succeeded but its lease could not be saved, the
response manager immediately calls the registered reverse action. A failed
reverse action is reported as critical and the original preflight row remains.

There is still a process-crash window between an OS change and the durable
lease grant for host isolation. The DNS response override has its own persisted
expiry, but full transactional Windows firewall recovery requires the Phase 1
privileged broker and isolated VM validation.

For the privacy/security consequence experiment, a finding creates an incident
and records the decision plus four-gate authority verdict. The bundled
`privacy-consequence-future-dns` playbook is dry-run and requires both verdicts
to be `block`. It does not mutate intelligence memory directly.

Pre-execution process, pre-write file/registry, and general packet-level
enforcement are OS-LIMITED until a signed/attested driver or WFP component is
deployed and tested.
