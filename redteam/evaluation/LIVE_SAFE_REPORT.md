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

Generated: 20260823T201416Z
Capture rate: **11/12 (92%)**
Latency: median 7270 ms, p95 33501 ms
Detector sources: {'edr.sequence': 8, 'etw.sysmon': 3}

Sysmon at run time: service_state=`Running`, collection_live=`True`, configured_eids=`[1, 3, 7, 8, 10]`
native_audit already enabled: `True`

| Technique | Executed | Captured | Latency (ms) | Detector | Incident |
|---|---|---|---:|---|---|
| T1033 System Owner/User Discovery (whoami /priv) | `whoami /priv` | **CAPTURED** | 34286 | edr.sequence | inc_7c906cdbeb9a49b4 |
| T1082 System Information Discovery | `systeminfo` | **CAPTURED** | 32717 | edr.sequence | inc_7c906cdbeb9a49b4 |
| T1057 Process Discovery | `tasklist /v` | **CAPTURED** | 10394 | etw.sysmon | inc_a98471a1b97540ed |
| T1018 Remote System Discovery (net view) | `net view` | **CAPTURED** | 26286 | edr.sequence | inc_7c906cdbeb9a49b4 |
| T1087.001 Account Discovery: Local Account (net user) | `net user` | **CAPTURED** | 9330 | edr.sequence | inc_7c906cdbeb9a49b4 |
| T1482 Domain Trust Discovery (nltest) | `nltest /dclist` | **CAPTURED** | 7270 | etw.sysmon | inc_a9621f3cde3643c9 |
| T1016 System Network Configuration Discovery (ipconfig) | `ipconfig /all` | **CAPTURED** | 6228 | edr.sequence | inc_7c906cdbeb9a49b4 |
| T1049 System Network Connections Discovery (netstat) | `netstat -ano` | **CAPTURED** | 4684 | edr.sequence | inc_7c906cdbeb9a49b4 |
| T1082 System Information Discovery (hostname) | `hostname` | **CAPTURED** | 3142 | edr.sequence | inc_7c906cdbeb9a49b4 |
| T1012 Query Registry (reg query) | `reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` | **CAPTURED** | 1613 | edr.sequence | inc_7c906cdbeb9a49b4 |
| T1007 System Service Discovery (sc query) | `sc query eventlog` | **CAPTURED** | 1613 | etw.sysmon | inc_3880b8da71624908 |
| T1016 System Network Configuration Discovery (arp -a) | `arp -a` | missed | — | — | — |

## DELTA — the measured value of the Sysmon dependency

Capture rate: 11/12 (92%) -> 11/12 (92%)
Median latency: 4869 ms -> 7270 ms
p95 latency: 33132 ms -> 33501 ms

| Technique | Poller-only | Sysmon | Changed |
|---|---|---|---|
| T1033 System Owner/User Discovery (whoami /priv) | CAPTURED | CAPTURED | same |
| T1082 System Information Discovery | CAPTURED | CAPTURED | same |
| T1057 Process Discovery | CAPTURED | CAPTURED | same |
| T1018 Remote System Discovery (net view) | CAPTURED | CAPTURED | same |
| T1087.001 Account Discovery: Local Account (net user) | CAPTURED | CAPTURED | same |
| T1482 Domain Trust Discovery (nltest) | CAPTURED | CAPTURED | same |
| T1016 System Network Configuration Discovery (ipconfig) | CAPTURED | CAPTURED | same |
| T1049 System Network Connections Discovery (netstat) | CAPTURED | CAPTURED | same |
| T1082 System Information Discovery (hostname) | CAPTURED | CAPTURED | same |
| T1012 Query Registry (reg query) | CAPTURED | CAPTURED | same |
| T1007 System Service Discovery (sc query) | CAPTURED | CAPTURED | same |
| T1016 System Network Configuration Discovery (arp -a) | missed | missed | same |
