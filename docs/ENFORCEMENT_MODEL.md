# Enforcement Model

## Status: IMPLEMENTED (DNS response); EXPERIMENTAL (unified consequence)

The actual user-mode real-time boundary is DNS. DNS decisions can block or
deceive a query inline. `block_domain` is reversible and audited through the
response manager.

For the privacy/security consequence experiment, a finding creates an incident
and records the decision plus four-gate authority verdict. The bundled
`privacy-consequence-future-dns` playbook is dry-run and requires both verdicts
to be `block`. It does not mutate intelligence memory directly.

Pre-execution process, pre-write file/registry, and general packet-level
enforcement are OS-LIMITED until a signed/attested driver or WFP component is
deployed and tested.
