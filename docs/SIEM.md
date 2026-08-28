# SIEM Integration

`valkyrie/siem.py` . ADR 0016 . tests: `tests/test_siem.py`

Stream Valkyrie EDR incidents into any enterprise log pipeline in **CEF**
(Splunk, Microsoft Sentinel, QRadar, ArcSight, Elastic all ingest it) or
**JSON Lines**. Off by default - enabling it is an explicit decision to send
security-event data to infrastructure you name.

## Usage

```powershell
# Classic syslog over UDP, CEF format
python -m valkyrie --web --siem udp://10.0.0.5:514

# TCP stream, JSON Lines
python -m valkyrie --web --siem tcp://10.0.0.5:514 --siem-format json

# TLS for cross-network export (server cert verified via system trust store)
python -m valkyrie --web --siem tls://siem.corp.example:6514

# Air-gapped: append JSONL to a file your collector tails
python -m valkyrie --web --siem file:///C:/logs/valkyrie.jsonl --siem-format json

# ALSO export blocked/flagged DNS events (contains domains — separate opt-in)
python -m valkyrie --web --siem udp://10.0.0.5:514 --siem-dns
```

Observability: `GET /api/siem/status` -> `{sent, dropped, errors, last_error,
queued, running, url, format}`.

## What gets exported

| Event | When | Contains |
|---|---|---|
| EDR incident (new + severity escalations) | always when `--siem` is set | id, title, severity, category, entity, process name, detection count, status |
| DNS blocked/behavioral/flagged | only with `--siem-dns` | domain, decision, process, reason |
| Allowed traffic | **never** - no code path exists for it | - |

CEF example line:

```
CEF:0|Valkyrie|Valkyrie|0.2.0|ransomware|canary tripped|10|externalId=0f3a… sproc=bad.exe cs1=C:\\Users\\x cs1Label=entity cnt=1 start=2026-07-19T… cat=incident valkyrieNew=True status=open
```

Severity mapping: info->2, low->3, medium->5, high->8, critical->10.

## Reliability model (syslog semantics, honestly stated)

- Emitters enqueue (~16 µs) and return; a background thread does all I/O.
  A dead SIEM can never stall or crash the protection pipeline.
- Bounded queue (2048): when the destination is down long enough, the
  **oldest** events drop and the drop count is visible in status - newest
  events are always preferred.
- TCP/TLS reconnect with exponential backoff (1s->60s). Peer-close is
  detected with a zero-timeout `MSG_PEEK` before each send, so a restarted
  receiver doesn't silently swallow an event.
- This is at-most-once delivery, standard for syslog transports. If a
  deployment needs guaranteed delivery, the seam is `_send` (e.g. a
  disk-spool transport) - not claimed until built.

## Threat & privacy analysis

- **Off by default.** No export without `--siem`. Domain-bearing DNS export
  requires the second flag; incident export carries process/entity metadata,
  not browsing history.
- **Destination is operator-chosen**; Valkyrie ships no cloud endpoint.
- Use `tls://` whenever the SIEM is not on a trusted local segment -
  plain udp/tcp are cleartext like all classic syslog.
- The exporter never listens; attack surface is outbound-only.
- Zero-log mode composes: incidents exported live still leave no local disk
  trace beyond your SIEM's own record.
