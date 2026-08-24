# Valkyrie Live-Safe Evaluation (ADR 0048, Part 2)

Real read-only commands, executed on this host, scored against the real running EDR incident store. See `redteam/evaluation/live_safe.py` module docstring for the safety model and the two architectural caveats (native-4688-vs-poller, burst-only Discovery scoring).

## RUN A — degraded-Sysmon baseline

Generated: 20260807T024531Z  
Capture rate: **11/12 (92%)**  
Latency: median 4869 ms, p95 33132 ms  
Detector sources: {'edr.sequence': 9, 'etw.native': 2}

Sysmon at run time: service_state=`Stopped`, collection_live=`False`, configured_eids=`[]`  
native_audit already enabled: `True`

| Technique | Executed | Captured | Latency (ms) | Detector | Incident |
|---|---|---|---:|---|---|
| T1033 System Owner/User Discovery (whoami /priv) | `whoami /priv` | **CAPTURED** | 33912 | edr.sequence | inc_f017dc95a5db45d8 |
| T1082 System Information Discovery | `systeminfo` | **CAPTURED** | 32352 | edr.sequence | inc_f017dc95a5db45d8 |
| T1057 Process Discovery | `tasklist /v` | **CAPTURED** | 27115 | edr.sequence | inc_f017dc95a5db45d8 |
| T1018 Remote System Discovery (net view) | `net view` | **CAPTURED** | 24836 | edr.sequence | inc_f017dc95a5db45d8 |
| T1087.001 Account Discovery: Local Account (net user) | `net user` | **CAPTURED** | 7968 | edr.sequence | inc_f017dc95a5db45d8 |
| T1482 Domain Trust Discovery (nltest) | `nltest /dclist` | **CAPTURED** | 3753 | etw.native | inc_8012b668353c4f4b |
| T1016 System Network Configuration Discovery (ipconfig) | `ipconfig /all` | **CAPTURED** | 4869 | edr.sequence | inc_f017dc95a5db45d8 |
| T1049 System Network Connections Discovery (netstat) | `netstat -ano` | **CAPTURED** | 3312 | edr.sequence | inc_f017dc95a5db45d8 |
| T1082 System Information Discovery (hostname) | `hostname` | **CAPTURED** | 1771 | edr.sequence | inc_f017dc95a5db45d8 |
| T1012 Query Registry (reg query) | `reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` | **CAPTURED** | 236 | edr.sequence | inc_f017dc95a5db45d8 |
| T1007 System Service Discovery (sc query) | `sc query eventlog` | **CAPTURED** | 2191 | etw.native | inc_4f60c9bd23914a9c |
| T1016 System Network Configuration Discovery (arp -a) | `arp -a` | missed | — | — | — |

## RUN B — healthy-Sysmon baseline

_not yet run_

