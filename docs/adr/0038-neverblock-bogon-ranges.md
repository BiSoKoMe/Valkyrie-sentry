# ADR 0038 — Never firewall reserved / bogon IP ranges

- **Status:** Accepted
- **Phase:** 0 (security correctness)
- **Date:** 2026-07-12

## Context

`FirewallManager` loads CIDR ranges from third-party threat-intel feeds and
enforces them (kernel rules on Linux, in-process screening on Windows). Feeds are
not clean: they intermittently list **reserved, documentation, or bogon** ranges.
RFC 5737 test-nets (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) are
frequent offenders, and one such range in a live feed was caught firewall-blocking
`198.51.100.0/24` during testing.

Before this change, `FIREWALL_NEVER_BLOCK` only protected RFC 1918, loopback,
link-local, and the upstream resolver. Nothing stopped a feed from causing
Valkyrie to block:

- `169.254.0.0/16` link-local → breaks DHCP/APIPA fallback,
- `100.64.0.0/10` CGNAT → breaks carrier-grade NAT (common on mobile/router
  deployments — a first-class Valkyrie target),
- `224.0.0.0/4` multicast → breaks mDNS/SSDP discovery,
- `240.0.0.0/4` incl. `255.255.255.255` broadcast.

For a product that aspires to protect critical infrastructure, silently
firewalling core networking ranges on a bad feed line is an unacceptable failure
mode.

## Decision

1. Expand `config.FIREWALL_NEVER_BLOCK` to the full IANA special-use set (RFC 6890
   and friends): `0.0.0.0/8`, `100.64.0.0/10`, `192.0.0.0/24`, the three RFC 5737
   test-nets, `198.18.0.0/15`, `224.0.0.0/4`, `240.0.0.0/4`, alongside the existing
   private/loopback/link-local entries.
2. Apply the never-block filter on the **cache-read path** in `load_ip_blocklist`,
   not only at feed-parse time. The on-disk cache is untrusted input like any
   feed; a stale cache written before this fix must not be able to enforce a
   protected range. `_IPSet.load()` is deliberately left unfiltered so unit tests
   can still load a documentation IP as a synthetic "bad" address.

## Change report

- **What changed:** `valkyrie/config.py` (`FIREWALL_NEVER_BLOCK` expanded, with
  rationale comments); `valkyrie/firewall.py` (`load_ip_blocklist` now drops
  protected ranges from the cache and reports the count).
- **Why:** prevent collateral firewalling of reserved/bogon ranges from dirty
  feeds — a real availability/safety bug.
- **Security impact:** positive. Removes a feed-poisoning vector that could break
  host networking (a denial-of-service via a single bad feed line).
- **Performance impact:** negligible. The filter runs once per list load
  (`O(ranges × protected)`, protected ≈ 16), never on the per-packet hot path.
- **Compatibility impact:** none for legitimate feeds — public ranges are
  unaffected. Any range that *should* never have been blocked simply no longer is.
- **Risks:** vanishingly small — only that a user deliberately wanted to block a
  documentation range (no legitimate reason to). Accepted.
- **Tests added:** `tests/test_bogon_neverblock.py` — pins every special-use range
  as protected, confirms genuine public IPs are not, and verifies a poisoned
  cache is sanitized on load. Existing `test_firewall` / `test_ip_leak` still pass.
- **Rollback plan:** revert the two edits; `git revert` is clean. No data
  migration involved (the cache is regenerated on the next refresh).

## Consequences

Threat-intel ingestion is now fail-safe against the most common class of feed
error. This is a prerequisite for trusting automated feed updates at fleet scale
(Phase 4), where one poisoned feed would otherwise fan out to every endpoint.
