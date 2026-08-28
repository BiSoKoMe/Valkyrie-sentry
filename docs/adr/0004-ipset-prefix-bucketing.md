# ADR 0004 - O(<=32) CIDR membership via prefix-length bucketing

- **Status:** Accepted
- **Phase:** 0 (performance bottleneck, no rewrite)
- **Date:** 2026-07-12

## Context

`_IPSet.contains` is on a hot path: `dns_interceptor` screens **every allowed
answer IP** against the firewall's threat-intel ranges. The implementation was a
linear scan:

```python
return any(addr in net for net in self._networks)
```

With ~12k ranges loaded this measured **~1,673 µs per lookup** (50k lookups took
84 seconds). At any realistic DNS query rate this is catastrophic - the answer-IP
screening that the audit praised as clever was, in practice, a throughput cliff
and a trivial DoS amplifier (each query forces a 12k-element scan).

## Decision

Replace the linear scan with **prefix-length bucketing**:

- Group loaded networks into `{prefix_length: set(network_int)}`.
- Precompute the bitmask for each present prefix length.
- To test an address, for each distinct prefix length present, mask the address
  and probe the corresponding hash set.

There are at most 32 distinct IPv4 prefix lengths, so a lookup is
**O(distinct lengths) <= 32 hash probes, independent of range count**. Memory is
just the network integers in sets - deliberately *not* a binary trie, whose node
explosion would hurt on the Raspberry Pi / router targets. The public API
(`load` / `contains` / `count`) and exact semantics are unchanged.

## Change report

- **What changed:** `valkyrie/firewall.py` - `_IPSet` internals rewritten
  (host set of ints + per-prefix-length network sets + masks). No API change.
- **Why:** eliminate an O(n) per-lookup cost on the DNS hot path.
- **Security impact:** positive. Removes a DoS amplification vector (a flood of
  resolvable queries previously multiplied into 12k comparisons each) and makes
  answer-IP screening cheap enough to always leave enabled.
- **Performance impact:** **~780x faster** - 1,673 µs -> **2.14 µs per lookup**
  (measured, 12k ranges, 50k probes). Lookup cost is now independent of list
  size, so growing the feed set no longer degrades the datapath. Load time and
  memory are comparable (network integers vs. `IPv4Network` objects - actually
  lighter).
- **Compatibility impact:** none. `load`/`contains`/`count` behave identically;
  verified by a randomized differential test against a brute-force oracle
  (20,000 probes, 0 mismatches) plus boundary cases. No test referenced the old
  private attributes.
- **Risks:** low. The one subtlety - matching the old `count()` semantics
  (`len(hosts)+len(networks)`) - is covered by tests. IPv4-only behavior is
  preserved (IPv6/malformed input still returns `False`, never raises).
- **Tests added:** `tests/test_ipset_lookup.py` - hand-picked boundary cases,
  a 20k-probe randomized differential vs. brute force, and empty-set behavior.
  Existing `test_firewall` / `test_ip_leak` / `test_bogon_neverblock` still pass.
- **Rollback plan:** revert the single `_IPSet` edit. No callers or persisted
  state change; `git revert` is clean.

## Consequences

Answer-IP screening is now effectively free, which unblocks two future steps:
enabling it unconditionally, and growing threat-intel coverage (Phase 4) without
a datapath penalty. The bucketing structure also ports directly to the Rust core
in Phase 2.
