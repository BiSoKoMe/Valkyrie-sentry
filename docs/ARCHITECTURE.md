# Valkyrie Platform Architecture

**The enterprise security platform vision, mapped onto what actually exists —
with every capability marked as shipped, buildable-locally, or an honest
infrastructure boundary.** This document is the reference the continuous
gap-analysis cycle (docs/GAP_ANALYSIS.md) selects work from. Nothing here is
marketing; every "Shipped" row has code, tests, and an ADR behind it.

## 1. One architecture, not bolted-together products

Every capability — DNS filtering, endpoint sensors, ransomware defense,
threat intel, SIEM export, fleet — plugs into the **same four spines**:

```
                    ┌──────────────────────────────────────────────┐
   sensors ───────▶ │  TelemetryEvent (normalized schema, ADR 0011) │
   (proc/net/      └──────────────┬───────────────────────────────┘
    persist/ETW/                  ▼
    ransomware/    ┌──────────────────────────────────────────────┐
    DNS pipeline)  │  EventBus (thread-safe pub/sub, ADR 0007)     │
                   └──────────────┬───────────────────────────────┘
                                  ▼
                   ┌──────────────────────────────────────────────┐
                   │  EdrEngine — correlation → Incident + timeline│
                   │  (dedup window, severity escalation, MITRE)   │
                   └──────┬───────────────┬───────────────┬───────┘
                          ▼               ▼               ▼
                   SQLite Store      SIEM export      App UI / API
                   (one DB, RAM-able) (CEF/JSONL)     (AppContext DI)
```

**Plugin contract (ADR 0021).** Every subsystem also registers with the
`ComponentRegistry` (valkyrie/components.py), which adapts its existing
lifecycle into one uniform surface — health, metrics, config, independent
restart, and health-transition events on the bus — exposed at
`GET /api/components`. This is the plugin host the vision calls for; it wraps
services rather than rewriting them, and composes with (never duplicates) the
self-heal watchdog's curated recovery.

Rules that keep it one platform:

1. **One event schema.** Every sensor emits `TelemetryEvent`
   (valkyrie/telemetry.py). New sensors never invent formats.
2. **One correlation engine.** Detections become `Incident`s only through
   `EdrEngine` — the ransomware shield, ETW sensors, and network collector
   all use the same `ingest_telemetry`/`report_detection` seams.
3. **One store.** A single SQLite database (RAM-mapped in zero-log mode)
   holds events, incidents, baselines, learned intelligence. Deterministic
   handle lifecycle (close-on-exit sessions; RAM anchor connection).
4. **One composition root.** `__main__.py` builds `AppContext` and injects
   it; services are `Optional` and every consumer degrades gracefully —
   removing any module never breaks another (fault isolation by design).
5. **One UI surface.** The Electron desktop app; the FastAPI layer on
   loopback is its backend, not a second product.

## 2. Capability map (honest status)

### Shipped — code + tests + ADR in this repo
| Pillar | Implementation |
|---|---|
| DNS intelligence | Sinkhole resolver, process attribution, Unbound local recursion, no-leak fail-closed mode |
| Behavioral detection | Entropy/rate/TLD heuristics + self-learning baseline, anomaly signatures, threat graph, co-occurrence (all offline) |
| Threat intelligence | abuse.ch IOC feeds matched locally at 3 seams (ADR 0015); ~1 µs lookups |
| EDR | Correlation engine, incidents/timelines, MITRE labels, threat hunting, response actions, plugin trust gate (ADR 0009) |
| Endpoint telemetry | Process (cmdline/ancestry), network, persistence/ASEP collectors (ADR 0002/0012/0013/0014) |
| Kernel-sourced telemetry | ETW-backed channels: PowerShell 4104, WMI-Activity, Sysmon passthrough, with watchdogged SensorManager (ADR 0003) |
| Ransomware protection | Canary + entropy + I/O attribution, reversible suspend, CRITICAL incidents |
| SIEM integration | CEF + JSON Lines over udp/tcp/tls/file, queue-buffered, reconnecting (ADR 0016) |
| Privacy engine | Telemetry killer, MAC randomizer, TCP/IP fingerprint normalization, DoH-bypass detection, zero-log RAM mode, Meeting Mode kill switch |
| Fleet management | Self-hosted control plane; metadata-only heartbeats (never domains), token-hash auth, signed policy push, multi-tenant isolation |
| Secure updates | Ed25519 manifest verification (verify-only by design; apply is deliberately human-gated) |
| Application firewall | netsh + in-process CIDR sets (Rust-accelerated lookup, ADR 0010), bogon never-block guard (ADR 0002) |
| Platform engineering | Event bus, DI context, normalized schema, preflight + heartbeat self-tests, self-healing watchdogs, windowless service, audit-gated installer |

### Buildable next — locally honest, on existing seams
| Pillar | Seam it extends |
|---|---|
| Digital forensics triage collection | EDR incident → artifact bundle (process tree, ASEP snapshot, event slice) |
| Memory/exploit signals (partial) | ETW channels + AMSI provider; documented as partial without a driver |
| Browser protection | TLS inspector (exists, opt-in) + URLhaus full-URL IOCs |
| SOAR-style automation | EDR response actions + rules engine already exist; add playbooks |
| Compliance reporting | Store + incident history → report generator |
| Vulnerability visibility | Installed-software inventory vs. local CVE feed (OSV/NVD mirrors) |
| AI assistant (explain/summarize) | `edr/investigate.py` seam exists (`use_ai=` flag); AI only explains, never detects — per AI philosophy |

### Infrastructure boundaries — documented, never faked
| Pillar | Why it can't be honest single-endpoint code | Extension point |
|---|---|---|
| Kernel minifilter / ELAM / pre-write blocking | Requires signed driver + Microsoft attestation | `report_detection()` seam; ADR-documented |
| File signature AV / global malware cloud | Needs planet-scale sample telemetry | Integrate OS AMSI/Defender instead |
| Cloud/SaaS/container/K8s posture | Valkyrie runs on Windows endpoints today; these need collectors in those environments | Same TelemetryEvent schema is the contract a future collector must emit |
| Identity provider protection (AD/Entra) | Needs domain-controller/IdP vantage point | Fleet control plane is the aggregation seam |
| Global ML / crowd intelligence | Needs millions of endpoints | Local learning ships; federated design is paper-only until scale exists |
| Managed-service trust (SOC2, pentest, 24/7) | Organizational, not code | docs/PLATFORM_ROADMAP.md |

## 3. The non-negotiable design invariants

- **Privacy before telemetry.** Data leaves the machine only by explicit
  operator opt-in (list downloads, fleet metadata, SIEM export). Nothing
  per-query ever goes to a third party. Zero-log mode must keep working for
  every new feature.
- **Layered detection.** No single-source verdicts: lists, intel, behavior,
  learned baselines, and telemetry corroborate; user rules always win.
- **Fail toward availability for the user, toward caution for threats.**
  Sinkhole failures never break the internet (start_all verifies before DNS
  takeover; stop_all always restores); feed outages keep stale caches;
  broken sensors are isolated and restarted.
- **Explainability.** Every block/incident carries its reason string and
  provenance (`threat_intel:urlhaus:malware_distribution`, timeline entries,
  MITRE technique labels). Any future AI layer explains — it never silently
  decides.
- **No silent success.** Release-blocking audits, honest capability
  boundaries in every doc, and tests that verify live behavior, not mocks
  of our own assumptions.
