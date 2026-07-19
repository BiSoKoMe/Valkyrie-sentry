# Valkyrie — Capability Gap Analysis (honest)

Reviewed 2026-07-18. Compares Valkyrie's **actual implemented** capability against
CrowdStrike, Microsoft Defender, SentinelOne, Palo Alto, Cisco, Google, Apple,
Bitdefender, Sophos, Malwarebytes, Proton, Cloudflare. No feature is claimed that
does not exist in code.

## Where Valkyrie is genuinely competitive (local, no external scale needed)
| Capability | Status | Notes |
|---|---|---|
| DNS filtering / sinkhole | Strong local | Real resolver + sinkhole; competitive with Pi-hole/NextDNS. Gap: blocklist breadth. |
| Telemetry reduction | Strong local | Registry/service edits, reversible (cf. O&O ShutUp10). |
| Windows privacy hardening | Strong local | MAC randomization, DoH-bypass detection, telemetry killer. |
| Local-first privacy | Strong | Everything on-box, no cloud account. Genuine differentiator. |
| Application firewall | Moderate | `netsh advfirewall` outbound rules; works, not kernel-level. |

## Where Valkyrie is materially weaker (ranked)
Ranked by (security impact × user value × **honest local feasibility**). Items
needing global scale (signature clouds, ML from millions of endpoints) are marked
"needs infra" — per project policy we do **not** fake those.

| Rank | Gap | Security | User value | Local feasibility | Verdict |
|---|---|---|---|---|---|
| **1** | **Ransomware protection** | **Critical** | **Very high** | **High** (behavioral canary + entropy + I/O attribution is a real local technique) | **✅ SHIPPED** (Ransomware Shield) |
| 2 | Threat intelligence (local IOC feeds) | High | Med | High (pull real public feeds: URLhaus, Feodo, ThreatFox) | **✅ SHIPPED** 2026-07-18 (ADR 0015, `valkyrie/threat_intel.py`) |
| 3 | Behavioral detection depth | High | Med | Med (ETW process/file/registry sensors) | Iterative |
| 4 | SIEM integration (CEF/syslog export) | Med | Med (enterprise) | High | Cheap win later |
| 5 | Digital forensics / triage collection | Med | Med | High | Later |
| 6 | Malware detection (files) | Critical | High | **Needs infra** | Integrate OS AMSI/Defender; don't build a signature engine |
| 7 | Exploit / memory-attack detection | Critical | High | Low–Med (ETW/AMSI, no kernel driver) | Partial only; honest boundary |
| 8 | Kernel protection (minifilter/ELAM) | Critical | High | **Needs signed driver** | Document as extension point |
| 9 | Cloud analytics / global ML | High | Med | **Needs infra** | Architecture only, privacy-preserving |

## Selected highest-value improvement: **Ransomware Shield**
Rationale: it is the most destructive endpoint threat, Valkyrie currently has
**zero** coverage, every named competitor ships it, and — critically — a strong
version is achievable **locally and honestly**:

- **Canary tripwires**: decoy files in real users' document folders; ransomware
  that enumerates and encrypts files hits them, giving a near-zero-false-positive
  high-confidence signal. (Used by CryptoDrop, parts of Malwarebytes/Acronis.)
- **Entropy confirmation**: encrypted output is ~7.99 bits/byte — corroborates.
- **Behavioral rate**: mass file modification bursts as a secondary signal.
- **Response**: attribute the writer via per-process disk-I/O, then **suspend**
  (reversible, halts encryption in place) and raise a CRITICAL incident.

### Honest capability boundary (what commercial adds that we do NOT claim)
- **Kernel minifilter (real-time write blocking + exact PID attribution).** Our
  attribution is a documented I/O heuristic; a signed filesystem minifilter is
  required for deterministic pre-write blocking. → Documented extension point in
  `docs/RANSOMWARE_SHIELD.md`.
- **VSS/rollback of already-encrypted files.** We halt in place; we do not yet
  restore. Extension point noted.
- **Global ransomware-family intelligence.** Out of scope without infra.

Result: the strongest *local* ransomware defense we can honestly ship, with clean
seams for the kernel/rollback/intel upgrades that require more than one endpoint.

## Cycle 2026-07-18: Threat-intel IOC feeds — SHIPPED
Rank-2 gap closed per plan: `valkyrie/threat_intel.py` pulls Feodo Tracker,
URLhaus, and ThreatFox (SSLBL evaluated and rejected — deprecated 2025-01-03),
caches on disk, matches locally at ~1 µs, and enforces at three seams: DNS
decision (before the learned known-good fast path), resolved-answer C2-IP
sinkholing, and network-collector → EDR incidents. See ADR 0015 and
docs/THREAT_INTEL.md. Live verification: 2,394 IOCs from 3/3 feeds in 1.8 s.

**Next candidates (re-ranked)**: (a) SIEM/CEF export — cheap, enterprise
value; (b) behavioral detection depth via more ETW channels; (c) digital
forensics triage collection. URL-path IOC matching unlocks when the TLS
inspector exposes URLs to the intel engine.
