# Valkyrie Live-Safe Evaluation (ADR 0048, Part 2)

Real read-only commands, executed on this host, scored against the real running EDR incident store. See `redteam/evaluation/live_safe.py` module docstring for the safety model and the two architectural caveats (native-4688-vs-poller, burst-only Discovery scoring).

## RUN A — degraded-Sysmon baseline

Generated: 20260805T075017Z  
Capture rate: **0/12 (0%)**  
Latency: median — ms, p95 — ms  
Detector sources: {}

Sysmon at run time: service_state=`Stopped`, collection_live=`False`, configured_eids=`[]`  
native_audit already enabled: `True`

| Technique | Executed | Captured | Latency (ms) | Detector | Incident |
|---|---|---|---:|---|---|
| T1033 System Owner/User Discovery (whoami /priv) | `whoami /priv` | missed | — | — | — |
| T1082 System Information Discovery | `systeminfo` | missed | — | — | — |
| T1057 Process Discovery | `tasklist /v` | missed | — | — | — |
| T1018 Remote System Discovery (net view) | `net view` | missed | — | — | — |
| T1087.001 Account Discovery: Local Account (net user) | `net user` | missed | — | — | — |
| T1482 Domain Trust Discovery (nltest) | `nltest /dclist` | missed | — | — | — |
| T1016 System Network Configuration Discovery (ipconfig) | `ipconfig /all` | missed | — | — | — |
| T1049 System Network Connections Discovery (netstat) | `netstat -ano` | missed | — | — | — |
| T1082 System Information Discovery (hostname) | `hostname` | missed | — | — | — |
| T1012 Query Registry (reg query) | `reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` | missed | — | — | — |
| T1007 System Service Discovery (sc query) | `sc query eventlog` | missed | — | — | — |
| T1016 System Network Configuration Discovery (arp -a) | `arp -a` | missed | — | — | — |

## RUN B — healthy-Sysmon baseline

_not yet run_

