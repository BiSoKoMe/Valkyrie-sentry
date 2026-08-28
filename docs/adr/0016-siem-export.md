# ADR 0016 - SIEM export (CEF / JSON Lines)

Date: 2026-07-19 . Status: accepted

## Context

Enterprises run SOCs on Splunk/Sentinel/QRadar/Elastic; a security product
they cannot see inside their log pipeline is unadoptable. Valkyrie's EDR
already correlates detections into incidents on one bus (`EdrEngine`
pub/sub) - the platform lacked only a standards-compliant way to stream
them out. Ranked the top remaining gap after threat intel (ADR 0015):
high enterprise value, honestly buildable locally, zero new architecture.

## Decision

`valkyrie/siem.py` - `SiemExporter`, one destination per process:

- **Formats**: CEF 0 (ArcSight standard, spec-compliant escaping, severity
  mapped to 0-10) and JSON Lines. Pure formatting functions, unit-tested.
- **Transports**: `udp://` (classic syslog), `tcp://` (newline-framed),
  `tls://` (system trust store), `file://` (append-only JSONL for
  air-gapped environments).
- **Sources**: EDR incidents always (new + escalations, flagged by
  `valkyrieNew`); blocked/flagged DNS events only with a *second* opt-in
  (`--siem-dns`) because that path carries domains off the machine.
  Allowed traffic is never exportable - there is no code path for it.
- **Reliability**: bounded queue (2048) with drop-oldest + drop counter;
  background sender with exponential backoff reconnect; peer-close
  detection via zero-timeout `MSG_PEEK` before every stream send (a closed
  TCP peer otherwise swallows one event silently - found by test, fixed by
  design). Enqueue is ~16 µs and never blocks or raises into the pipeline.
- **Wiring**: `--siem URL --siem-format cef|json [--siem-dns]`;
  `AppContext.siem`; `GET /api/siem/status` (sent/dropped/errors/queue).

## Security & privacy analysis

- OFF by default; enabling is an explicit operator command that names the
  destination. Only the operator's own infrastructure receives events.
- Incident records carry process names/entities - not browsing history.
  Domain-bearing DNS exports require the separate flag.
- `tls://` provides transport confidentiality/authenticity for cross-network
  export; plain `udp`/`tcp` are documented as LAN-only patterns.
- The exporter holds no secrets and accepts no inbound connections.

## Rollback

Omit `--siem` (default). The exporter is an `Optional` context service; no
other component references it.

## Honest boundary

One destination, no delivery guarantee beyond bounded buffering (syslog
semantics - drops are counted and visible in status), no RFC 5424
structured-data framing, no built-in Splunk HEC/HTTP client. All are clean
extensions of `_send`/`_format` if a deployment needs them.
