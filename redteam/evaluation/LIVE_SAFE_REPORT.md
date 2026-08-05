# Valkyrie Live-Safe Evaluation (ADR 0048, Part 2)

Real read-only commands, executed on this host, scored against the real running EDR incident store. See `redteam/evaluation/live_safe.py` module docstring for the safety model and the two architectural caveats (native-4688-vs-poller, burst-only Discovery scoring).

## RUN A — degraded-Sysmon baseline

Generated: 20260805T084234Z  
Capture rate: **11/12 (92%)**  
Latency: median 5601 ms, p95 36368 ms  
Detector sources: {'edr.sequence': 9, 'etw.native': 2}

Sysmon at run time: service_state=`Stopped`, collection_live=`False`, configured_eids=`[]`  
native_audit already enabled: `True`

| Technique | Executed | Captured | Latency (ms) | Detector | Incident |
|---|---|---|---:|---|---|
| T1033 System Owner/User Discovery (whoami /priv) | `whoami /priv` | **CAPTURED** | 39446 | edr.sequence | inc_58836de57f4440f8 |
| T1082 System Information Discovery | `systeminfo` | **CAPTURED** | 33291 | edr.sequence | inc_58836de57f4440f8 |
| T1057 Process Discovery | `tasklist /v` | **CAPTURED** | 28038 | edr.sequence | inc_58836de57f4440f8 |
| T1018 Remote System Discovery (net view) | `net view` | **CAPTURED** | 25571 | edr.sequence | inc_58836de57f4440f8 |
| T1087.001 Account Discovery: Local Account (net user) | `net user` | **CAPTURED** | 8685 | edr.sequence | inc_58836de57f4440f8 |
| T1482 Domain Trust Discovery (nltest) | `nltest /dclist` | **CAPTURED** | 2368 | etw.native | inc_358720690b484fb2 |
| T1016 System Network Configuration Discovery (ipconfig) | `ipconfig /all` | **CAPTURED** | 5601 | edr.sequence | inc_58836de57f4440f8 |
| T1049 System Network Connections Discovery (netstat) | `netstat -ano` | **CAPTURED** | 4057 | edr.sequence | inc_58836de57f4440f8 |
| T1082 System Information Discovery (hostname) | `hostname` | **CAPTURED** | 2524 | edr.sequence | inc_58836de57f4440f8 |
| T1012 Query Registry (reg query) | `reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` | **CAPTURED** | 995 | edr.sequence | inc_58836de57f4440f8 |
| T1007 System Service Discovery (sc query) | `sc query eventlog` | **CAPTURED** | 0 | etw.native | inc_82473d4c26c142b6 |
| T1016 System Network Configuration Discovery (arp -a) | `arp -a` | missed | — | — | — |

## RUN B — healthy-Sysmon baseline

_not yet run_

