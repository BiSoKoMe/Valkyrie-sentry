# Valkyrie Live-Safe Evaluation (ADR 0048, Part 2)

Real read-only commands, executed on this host, scored against the real running EDR incident store. See `redteam/evaluation/live_safe.py` module docstring for the safety model and the two architectural caveats (native-4688-vs-poller, burst-only Discovery scoring).

## RUN A — degraded-Sysmon baseline

Generated: 20260805T082858Z  
Capture rate: **11/12 (92%)**  
Latency: median 2917 ms, p95 32022 ms  
Detector sources: {'edr.sequence': 11}

Sysmon at run time: service_state=`Stopped`, collection_live=`False`, configured_eids=`[]`  
native_audit already enabled: `True`

| Technique | Executed | Captured | Latency (ms) | Detector | Incident |
|---|---|---|---:|---|---|
| T1033 System Owner/User Discovery (whoami /priv) | `whoami /priv` | **CAPTURED** | 34995 | edr.sequence | inc_f8a3b8c93af14210 |
| T1082 System Information Discovery | `systeminfo` | **CAPTURED** | 29049 | edr.sequence | inc_f8a3b8c93af14210 |
| T1057 Process Discovery | `tasklist /v` | **CAPTURED** | 23820 | edr.sequence | inc_f8a3b8c93af14210 |
| T1018 Remote System Discovery (net view) | `net view` | **CAPTURED** | 21426 | edr.sequence | inc_f8a3b8c93af14210 |
| T1087.001 Account Discovery: Local Account (net user) | `net user` | **CAPTURED** | 4470 | edr.sequence | inc_f8a3b8c93af14210 |
| T1482 Domain Trust Discovery (nltest) | `nltest /dclist` | **CAPTURED** | 2917 | edr.sequence | inc_f8a3b8c93af14210 |
| T1016 System Network Configuration Discovery (ipconfig) | `ipconfig /all` | **CAPTURED** | 1385 | edr.sequence | inc_f8a3b8c93af14210 |
| T1049 System Network Connections Discovery (netstat) | `netstat -ano` | **CAPTURED** | 0 | edr.sequence | inc_f8a3b8c93af14210 |
| T1082 System Information Discovery (hostname) | `hostname` | **CAPTURED** | 0 | edr.sequence | inc_f8a3b8c93af14210 |
| T1012 Query Registry (reg query) | `reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` | **CAPTURED** | 0 | edr.sequence | inc_f8a3b8c93af14210 |
| T1007 System Service Discovery (sc query) | `sc query eventlog` | **CAPTURED** | 0 | edr.sequence | inc_f8a3b8c93af14210 |
| T1016 System Network Configuration Discovery (arp -a) | `arp -a` | missed | — | — | — |

## RUN B — healthy-Sysmon baseline

_not yet run_

