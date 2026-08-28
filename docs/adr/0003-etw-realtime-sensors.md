# ADR 0003 - Real-time ETW-backed endpoint sensors

- **Status:** Accepted (2026-07-18)
- **Context builds on:** the polling collectors (process, network, persistence)
  and the `TelemetryEvent -> EventBus -> EdrEngine -> correlation -> Incident`
  pipeline. This ADR adds *real-time* signal without a parallel pipeline.

## Context

Valkyrie's endpoint visibility was 100% **polling** (psutil, registry scans).
Polling misses short-lived activity between intervals and cannot see script
content or in-memory behavior at all. The single highest-value real-time signal
on Windows that polling fundamentally cannot obtain is **PowerShell script-block
logging (event 4104)** - the *deobfuscated* script text the engine is about to
run. We need a real-time sensor tier, hosted resiliently, feeding the existing
pipeline.

## Decision

Introduce a **sensor framework** (`valkyrie/etw/framework.py`) and **ETW-backed
sensors** that emit the same `TelemetryEvent` into the same EDR pipeline.

### Why event-log channels, not a raw NT-Kernel-Logger ETW session
Modern Event Log channels (PowerShell/Operational, WMI-Activity, Sysmon, ...) are
**ETW-backed**: providers emit ETW events the log service persists to a channel.
Reading a channel via `wevtapi` (`EvtQuery`/`EvtNext`/`EvtRender`) therefore
yields real ETW-sourced telemetry with **no third-party dependency**, **no
console/subprocess** (unlike shelling out to `wevtutil`/`Get-WinEvent`), and
**incremental near-real-time** delivery (poll by `EventRecordID` bookmark, ~1.5s).

A raw real-time ETW session (kernel process/image/network/registry/file
providers) would need either a native trace consumer (`pywintrace`/`krabsetw`,
adding a native build to the frozen exe) or a driver. We **defer** that behind a
clean seam rather than fake it - see "Honest boundaries".

### Framework guarantees (Phase 5 concerns, once, for all sensors)
- **Failure isolation** - a sensor raising never affects others or the host.
- **Watchdog** - a dead sensor is restarted (bounded, backoff); the manager
  registers `is_healthy` with the global self-heal loop (no parallel watchdog).
- **Backpressure** - sensors submit into a *bounded* `deque(maxlen)`; a single
  dispatcher forwards to the sink. Overflow drops the oldest and is counted, so
  a burst never blocks a sensor and memory stays bounded.
- **De-duplication** - a bounded LRU of fingerprints collapses re-delivered /
  cross-sensor repeats.
- **Clean shutdown** - sensors stopped, queue drained, dispatcher joined.
- **Observability** - `stats()` (per-sensor + aggregate) at `/api/sensors/status`.

### First sensor
`PowerShellSensor` consumes 4104, classifies the script with explainable rules
(encoded command, download cradle, AMSI/Defender tampering, credential-access
tooling, injection primitives, scheduled-task persistence -> MITRE T1027 / T1105 /
T1059.001 / T1562.001 / T1003 / T1055 / T1053.005), and emits a `TelemetryEvent`.
Medium+ becomes a correlated incident automatically.

## Threat model

- **Adversary:** local malware / operator running PowerShell (fileless attacks,
  LOLBins, download cradles, Defender tampering, credential dumping).
- **What this raises the bar on:** obfuscated one-liners are logged *deobfuscated*
  at 4104 and scored in real time, correlating with the process/persistence/DNS
  signals for higher-confidence incidents (e.g. *Office -> PowerShell -> Network*).
- **Evasion honestly acknowledged:**
  - *Disabling script-block logging.* An attacker with admin can turn 4104 off;
    then we see nothing on this channel. (Detecting that tamper is itself a
    future persistence/registry signal.) Mitigation: enable the Script-Block-
    Logging policy (below); consider monitoring the policy key.
  - *Non-PowerShell execution* (C#, native loaders) is out of this sensor's
    scope - covered by the process collector and future image-load ETW.
  - *Log flooding* to evict our bookmark is bounded by backpressure + dedup and
    is itself anomalous.
- **Trust boundary:** the sensor runs in the engine (SYSTEM service). It only
  *reads* a local channel; it never executes logged content.

## Security analysis
- **No new attack surface exposed:** read-only `wevtapi` calls; no network, no
  new listener, no subprocess, no console (ADR 0001 preserved).
- **Bounded resource use** under adversarial input (see backpressure/dedup).
- **ctypes safety:** buffer sizing via the documented two-call `EvtRender`
  pattern; all handles closed in `finally`; every failure path degrades the
  sensor to `available()=False` rather than raising.

## Privacy analysis
- **Local-first, no exfiltration:** events flow only to the local EDR store and
  loopback dashboard - consistent with Valkyrie's privacy posture.
- **Sensitive content:** 4104 script text can contain secrets (a script with an
  inline password). We (a) truncate the dashboard `command` snippet to 300 chars,
  (b) cap the stored `script` field at 8 KB, and (c) keep everything on-box. The
  raw channel already contains this text regardless of Valkyrie.
- **Script-block logging is opt-in coverage:** we do **not** silently enable
  full logging (it would log *all* script content). We document the one-line
  policy for operators who want complete coverage and leave it to them.

## Benchmarks (this machine, single core)
| Path | Throughput | Per-event |
|---|---|---|
| `classify_powershell` | ~55,000/s | ~18 µs |
| `parse_event_xml` | ~20,000/s | ~48 µs |
| framework dispatch -> sink | ~23,000/s | - |
| poll interval | 1.5 s | negligible CPU (one incremental `EvtQuery`) |

Idle overhead is one bookmarked `EvtQuery` per 1.5 s (microseconds); the reader
only renders records newer than the bookmark, so steady-state cost tracks event
volume, not channel size.

## Verification
- `tests/test_etw_sensors.py` - 17 tests: classifier, XML parser, sensor mapping,
  dedup, bounded backpressure, watchdog restart, failure isolation, clean
  shutdown, benchmarks, live-channel smoke. All green.
- **Live-verified** on this machine: `ChannelReader` read 20 real 4104 events
  with full deobfuscated `ScriptBlockText` from the actual PowerShell/Operational
  channel, incrementally by `EventRecordID`.

## Sensors implemented (all on this framework, one pipeline)
| Sensor | Source | Signal | MITRE | Notes |
|---|---|---|---|---|
| `PowerShellSensor` | PS/Operational 4104 | deobfuscated script blocks | T1059.001/T1027/T1562.001/T1105/T1003/T1055/T1053.005 | needs script-block-logging policy for full coverage |
| `WmiActivitySensor` | WMI-Activity/Operational 5861/5860/5859 | permanent WMI event-subscription persistence | T1546.003 / T1047 | parses `<UserData>` binding; cross-applies the PS classifier to consumer commands |
| `SysmonSensor` | Sysmon/Operational (optional) | process(+hashes/signature/integrity/parent), network, image load, CreateRemoteThread, **LSASS access**, registry/startup persistence, process tampering | T1055 / T1003.001 / T1574 / T1547.001 / T1055.012 | **auto-detected**; `available()` uses `EvtOpenChannelConfig` so a missing channel returns False and the manager skips it - Sysmon is never required |

**Avoiding duplication.** Sysmon EID 1 (process creation) overlaps the polling
process collector, so `SysmonSensor` emits process-creation **only when
suspicious** (enriched with SHA-256 / signature / integrity / parent), and
otherwise focuses on events the pollers cannot see (network-with-process,
image loads, injection, LSASS access). Within the framework, the bounded dedup
LRU collapses re-delivered/cross-sensor repeats by fingerprint. Cross-*collector*
dedup (framework sensor vs. non-framework poller) is a documented limitation:
the correlation engine merges them into one incident by entity/process anyway.

**Correlation chains these unlock** (each hop is now a real, MITRE-tagged
detection feeding `EdrEngine` correlation): *Office -> PowerShell (AMSI bypass) ->
WMI/Scheduled-Task persistence -> outbound connection*; *Unsigned image load ->
CreateRemoteThread -> LSASS access (credential dumping)*. The EDR engine already
groups detections sharing an entity/process within a window into one incident,
so these arrive as a single high-confidence incident rather than scattered alerts.

## Honest boundaries & next increments (same framework, no rewrite)
1. **Full 4104 coverage** requires enabling *Script Block Logging*
   (`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\
   EnableScriptBlockLogging=1`). Without it Windows logs only a suspicious
   subset. Documented; not force-enabled (privacy).
2. ~~WMI-Activity sensor~~ - **DONE** (`WmiActivitySensor`, T1546.003/T1047).
3. ~~Sysmon passthrough~~ - **DONE** (`SysmonSensor`, auto-detected, optional).
4. **Kernel ETW session** (process/image/network/registry/file/thread/driver
   load with no policy or Sysmon dependency) - needs a native real-time trace
   consumer (`pywintrace`/`krabsetw`) bundled into the frozen exe, or a driver.
   This is the documented seam; the `Sensor`/`SensorManager` contract is exactly
   what such a consumer plugs into (it would emit the same `TelemetryEvent`).
   Deferred, not faked.
5. **Native-path endpoint context** - when NOT using Sysmon, enrich the polling
   collectors' events with SHA-256 / Authenticode signature / integrity level /
   token elevation (hashlib + WinVerifyTrust + win32security). Next increment;
   Sysmon already provides this context when present.
