# Endpoint Telemetry

Valkyrie's endpoint sensors give the EDR pipeline visibility beyond DNS. All
sensors normalize into one [`TelemetryEvent`](../valkyrie/telemetry.py) and flow
through `EventBus → EdrEngine.ingest_telemetry → correlation → incident`. Design
and boundaries: [ADR 0002](adr/0002-endpoint-telemetry.md).

## What is collected today

| Sensor | Module | Signals |
|---|---|---|
| **Process** | `process_telemetry.py` | New process starts with **full command line**, **parent-process chain**, and heuristics: LOLBins, Office→shell, temp/download-path execution, **encoded PowerShell**, **download cradles**, **hidden-window** flags. |
| **Network** | `network_telemetry.py` | Outbound connections; flags connections to threat-intel IPs (hard-coded-IP C2 DNS never sees). |
| **Persistence (ASEP)** | `persistence_telemetry.py` | New **registry Run/RunOnce/Winlogon** entries, **Windows services**, **Scheduled Tasks**, **Startup-folder** items. |
| **DNS** | `dns_interceptor.py` | Every resolution decision (existing). |

Each event carries a MITRE technique label (mapped in
`edr/engine.py::_TELEMETRY_TECHNIQUE`) and only medium-or-above / flagged events
escalate to incidents — plain visibility events don't create noise.

## Enabling
Endpoint collectors run under the engine's `--endpoint` flag. The shipped
`ValkyrieShield` service now launches with it
(`--port 53 --web --no-ui --web-port 8090 --endpoint`, see
`installer/payload/service-install.ps1`). From source:

```
python -m valkyrie --web --endpoint
```

## Observability
- `GET /api/telemetry/endpoint` — which collectors are wired + persistence running.
- Incidents (with the process command line, parent chain, and persistence
  command in the timeline) appear in the EDR incident feed / dashboard Threats page.
- `AppContext.components()` reports every collector's wired state.

## Performance
Persistence polls every 15 s; a full ASEP snapshot of ~900 entries is ~7 ms.
Process enrichment does one `cmdline()` lookup per *new* process only. Steady-state
overhead is negligible.

## Extending (the seam for real-time / kernel sensors)
Add a new sensor by emitting a `TelemetryEvent` and calling
`edr_engine.ingest_telemetry(ev)` — nothing downstream changes. Concretely:

1. Build the event: `TelemetryEvent(category=…, activity=…, actor_*=…,
   target={…}, severity=…, labels=[…], source="my_collector")`.
2. Add any new label → MITRE mapping in `_TELEMETRY_TECHNIQUE`.
3. Wire the collector in `valkyrie/__main__.py` under the `--endpoint` block,
   pass it into `AppContext`, and register it with the self-heal `healer` if it
   runs a thread.

Planned next sensors (all via this seam): DLL/module loads, WMI event-consumer
persistence, PowerShell script-block logging, and ETW-backed real-time registry/
file operations. See the ADR's boundary table for the honest feasibility notes.

## Real-time sensor tier (ETW-backed) — implemented

The polling collectors above are now joined by a **real-time sensor tier** under
`valkyrie/etw/`, hosted by a resilient `SensorManager`:

- **`framework.py`** — `Sensor` base + `SensorManager` providing failure
  isolation, a per-sensor watchdog (auto-restart, registered with the global
  self-heal loop), bounded backpressure (drop-oldest + counters), a bounded
  de-dup LRU, clean shutdown, and metrics (`/api/sensors/status`).
- **`wineventlog.py`** — a dependency-free, no-console `ChannelReader` over
  `wevtapi` (ctypes `EvtQuery`/`EvtNext`/`EvtRender`) that incrementally reads
  ETW-backed Windows Event Log channels by `EventRecordID` bookmark, plus a pure
  `parse_event_xml` helper.
- **`powershell.py`** — `PowerShellSensor` consuming 4104 script-block events;
  classifies the deobfuscated script (encoded command, download cradle, AMSI/
  Defender tampering, credential access, injection primitives, task persistence)
  and emits a normalized `TelemetryEvent` into the **same** EDR pipeline.

Everything flows through `TelemetryEvent → EventBus → EdrEngine → correlation →
Incident` — no parallel pipeline. Full design, threat model, security/privacy
analysis, benchmarks, and the honest kernel-ETW / script-block-logging
boundaries are in `docs/adr/0003-etw-realtime-sensors.md`.
