# Threat Intelligence — local IOC feed engine

`valkyrie/threat_intel.py` · ADR 0015 · tests: `tests/test_threat_intel.py`

Valkyrie pulls real, curated indicators of active threat infrastructure
(botnet C2 IPs, live malware-distribution domains) from public abuse.ch
feeds and matches them **entirely on-box**. A hit is incident-grade —
distinct from an ad/tracker block — and flows into DNS blocking, resolved-
answer sinkholing, and EDR incident correlation.

## What it does

```
                 ┌────────────────────────────┐  opt-in, every 6 h
   abuse.ch ────▶│ ThreatIntelManager.refresh │──▶ data/threat_intel/*.txt
   (3 feeds)     └────────────────────────────┘        (atomic writes)
                                │ rebuild (revalidated line-by-line)
                                ▼
                    frozenset[ip] · frozenset[domain] · provenance map
                                │  O(1), ~1 µs/lookup
      ┌─────────────────────────┼──────────────────────────┐
      ▼                         ▼                          ▼
 DNS decide (2a)      resolved-answer screen      network collector
 domain hit → block   answer IP is C2 → sinkhole  live conn to C2 IP
 "threat_intel:…"     (fast-flux case)            → SEV_HIGH → EDR incident
```

Feeds (`config.THREAT_INTEL_SOURCES`):

| name | kind | category | source | live check 2026-07-18 |
|---|---|---|---|---|
| `feodo_c2` | ip | botnet_c2 | feodotracker.abuse.ch ipblocklist.txt | 5 IOCs |
| `urlhaus` | domain | malware_distribution | urlhaus.abuse.ch hostfile | 631 IOCs |
| `threatfox_c2` | ip | botnet_c2 | threatfox.abuse.ch csv/ip-port/recent | 1,758 IOCs |

(SSLBL's IP blacklist was deprecated by abuse.ch on 2025-01-03 and is
deliberately not shipped.)

## Threat model

| Threat | Mitigation |
|---|---|
| Malware beacons to C2 by domain | DNS pipeline blocks at step 2a, before resolution; learned "known good" cannot mask it |
| Compromised legit domain (learned good, later in feed) | Intel check runs **before** the intelligence fast path |
| Fast-flux: clean domain resolving to known C2 IP | Resolved-answer screening sinkholes the reply |
| Hard-coded-IP C2 (no DNS at all) | Network collector flags the live connection → EDR incident (`threat_intel_ip`) |
| Poisoned/corrupt feed or cache tries to block internal infra | Every line revalidated on parse AND on cache read; private/loopback/link-local/reserved IPs and localhost/dotless names can never enter the match sets |
| Feed outage / format change | Fetch failure or 0-indicator body keeps the previous cache; stale beats empty |
| Feed operator observes users | Only feed *downloads* touch the network (opt-in); no per-query lookups — queried domains/IPs never leave the machine |

## Privacy analysis

- Downloads obey the global opt-in (`USE_EXTERNAL_LISTS` /
  `--download-lists`); default posture is offline, cache-only.
- The fetch sends no identifiers beyond a static User-Agent
  (`Valkyrie-ThreatIntel/1.0`); feeds are fetched whole, so the operator
  learns nothing about what this machine queries.
- All matching is local set membership. Zero-log mode is unaffected:
  intel state is plain public feed data on disk, never user data.

## Performance (measured 2026-07-18, this machine)

- Lookup: **~1.0 µs** (100,000 mixed lookups over 100k indicators,
  985k lookups/s) — DNS hot-path budget is 50 µs.
- Live refresh, all 3 feeds: **1.8 s**, off the hot path in a daemon
  thread every `THREAT_INTEL_REFRESH_SECONDS` (6 h).
- Memory: 2,394 live IOCs ≈ a few hundred KB of frozensets.

## Operations

- Status: `GET /api/intel/status` → total/per-feed counts + freshness.
- Refresh cadence: `THREAT_INTEL_MAX_AGE_HOURS` (6) staleness gate,
  checked every 6 h; `valkyrie --update` also refreshes feeds.
- Cache: `data/threat_intel/<feed>.txt` (+ `.meta.json`); delete the
  directory to reset.
- Rollback: run without `--download-lists` and delete the cache dir, or
  unwire `threat_intel` in `__main__.py` — every consumer is `Optional`.

## Extension points (honest boundaries)

- **URL-path IOCs**: URLhaus carries full URLs; matching them requires
  the TLS inspector's URL visibility. Seam exists; not yet wired.
- **More feeds**: `THREAT_INTEL_SOURCES` is data-driven — any
  bare/hosts/CSV feed parses without code changes.
- **Global intel cloud / sightings**: needs multi-endpoint
  infrastructure; per the no-fake-parity rule, not claimed.
