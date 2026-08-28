# ADR 0015 - Threat-intelligence IOC feeds, matched locally

Date: 2026-07-18 . Status: accepted

## Context

Valkyrie's list-based defenses covered two threat classes: ad/tracker
domains (seed + StevenBlack/OISD blocklist) and network-hygiene CIDR
ranges (FireHOL/Spamhaus via the firewall). Neither covers *active
threat infrastructure* - botnet C2 servers and live malware-distribution
hosts - which rotates on an hours scale and is exactly what every
commercial EDR (CrowdStrike, Defender, SentinelOne) sources from intel
pipelines. The gap analysis ranked this the highest-value improvement
achievable honestly on one endpoint (rank 2, after the shipped
Ransomware Shield).

## Decision

New module `valkyrie/threat_intel.py`: a `ThreatIntelManager` that
downloads curated public IOC feeds, caches them on disk, and answers
O(1) local match queries. Feeds (all abuse.ch, no account, no API key):

| feed | kind | category | source |
|---|---|---|---|
| `feodo_c2` | ip | botnet_c2 | Feodo Tracker ipblocklist.txt |
| `urlhaus` | domain | malware_distribution | URLhaus hostfile |
| `threatfox_c2` | ip | botnet_c2 | ThreatFox recent CSV (ip:port) |

SSLBL's IP blacklist was evaluated and **rejected** - abuse.ch
deprecated it on 2025-01-03 (verified live); shipping a dead feed would
violate the no-fake-parity rule. ThreatFox replaces it.

Enforcement points (all existing seams - no parallel architecture):

1. **DNS decision pipeline** (`dns_interceptor._decide`, step 2a): an
   intel domain hit blocks with reason `threat_intel:<feed>:<category>`.
   Placed after user rules (user sovereignty) but **before** the learned
   known-good fast path, so a previously trusted domain that appears in
   a C2 feed still blocks (compromised-infrastructure case).
2. **Resolved-answer screening** (`_answer_blocked_ip`): an allowed
   domain resolving to an intel C2 IP is sinkholed - the fast-flux /
   rotated-frontend case.
3. **Network collector reputation** (`__main__._ip_bad`): live outbound
   connections to intel IPs are flagged SEV_HIGH and correlate into EDR
   incidents through the existing `threat_intel_ip` path.
4. **Dashboard**: `GET /api/intel/status` reports per-feed freshness and
   counts; `AppContext.threat_intel` carries the service.

## Key properties

- **Local-first / privacy**: the only network traffic is the periodic
  feed download (opt-in via `USE_EXTERNAL_LISTS`/`--download-lists`,
  same policy as every other list). Matching is set membership on-box;
  no queried domain, IP, or indicator ever leaves the machine. No
  per-query cloud lookups, ever.
- **Fault isolation**: fetch failures and empty/changed feed bodies keep
  the previous cache (verified by tests); the refresh thread survives
  all exceptions; a missing cache degrades to "no intel layer" without
  touching DNS/behavioral operation.
- **Untrusted input**: feed bodies AND on-disk caches are revalidated
  line-by-line; private/loopback/link-local/reserved IPs and
  dotless/localhost names can never enter the match sets - a poisoned
  feed cannot induce blocking of internal infrastructure.
- **Performance**: ~1 µs per lookup at 100k indicators (measured), well
  inside the DNS hot-path budget; refresh of all three live feeds takes
  ~2 s off the hot path in a daemon thread every 6 h.

## Rollback

Remove `threat_intel` from the three wiring points in `__main__.py` (or
run with downloads off and delete `data/threat_intel/`) - every consumer
treats the service as `Optional` and degrades to prior behavior.

## Honest boundary

This is feed-based IOC matching, not a global intel cloud: no
first-party sightings network, no reputation scoring, no URL-path
matching (the TLS inspector is the future seam for URLhaus full URLs).
Those need infrastructure Valkyrie does not have; per project policy we
do not fake them.
