# Valkyrie Live-Safe Evaluation (ADR 0048, Part 2)

Real read-only commands, executed on this host, scored against the real running EDR incident store. See `redteam/evaluation/live_safe.py` module docstring for the safety model and the two architectural caveats (native-4688-vs-poller, burst-only Discovery scoring).

## RUN A — degraded-Sysmon baseline

Generated: 20260805T081311Z  
Capture rate: **6/12 (50%)**  
Latency: median 466 ms, p95 9696 ms  
Detector sources: {'edr.sequence': 6}

Sysmon at run time: service_state=`Stopped`, collection_live=`False`, configured_eids=`[]`  
native_audit already enabled: `True`

| Technique | Executed | Captured | Latency (ms) | Detector | Incident |
|---|---|---|---:|---|---|
| T1033 System Owner/User Discovery (whoami /priv) | `whoami /priv` | **CAPTURED** | 10936 | edr.sequence | inc_30d8fc13f9b744b6 |
| T1082 System Information Discovery | `systeminfo` | **CAPTURED** | 5975 | edr.sequence | inc_30d8fc13f9b744b6 |
| T1057 Process Discovery | `tasklist /v` | **CAPTURED** | 932 | edr.sequence | inc_30d8fc13f9b744b6 |
| T1018 Remote System Discovery (net view) | `net view` | **CAPTURED** | 0 | edr.sequence | inc_30d8fc13f9b744b6 |
| T1087.001 Account Discovery: Local Account (net user) | `net user` | **CAPTURED** | 0 | edr.sequence | inc_30d8fc13f9b744b6 |
| T1482 Domain Trust Discovery (nltest) | `nltest /dclist` | **CAPTURED** | 0 | edr.sequence | inc_30d8fc13f9b744b6 |
| T1016 System Network Configuration Discovery (ipconfig) | `ipconfig /all` | missed | — | — | — |
| T1049 System Network Connections Discovery (netstat) | `netstat -ano` | missed | — | — | — |
| T1082 System Information Discovery (hostname) | `hostname` | missed | — | — | — |
| T1012 Query Registry (reg query) | `reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` | missed | — | — | — |
| T1007 System Service Discovery (sc query) | `sc query eventlog` | missed | — | — | — |
| T1016 System Network Configuration Discovery (arp -a) | `arp -a` | missed | — | — | — |

## RUN B — healthy-Sysmon baseline

_not yet run_

