# ADR 0014 - Network connection telemetry collector

- **Status:** Accepted (module + tests + live wiring)
- **Phase:** 3 (real endpoint telemetry)
- **Date:** 2026-07-12

> **Update (same day):** now wired into the live pipeline. Under `--endpoint`,
> `__main__` starts the `NetworkCollector` with `emit -> edr.ingest_telemetry`
> and `ip_reputation = firewall.is_blocked_ip`, alongside the process collector;
> `AppContext` gains a `network_collector` service. `test_endpoint_integration`
> now also asserts a flagged threat-intel connection becomes an incident, and a
> live outbound connection was verified captured. So the "deferred wiring" noted
> below is done.

## Context

The DNS sinkhole only sees traffic that resolves a name first. Malware that
connects to a **hard-coded IP** skips DNS entirely, and on Windows the IP
blocklist is enforced in-process rather than in the kernel - so such a connection
can slip past. This is a specific, named gap from the architecture audit. A
network collector that watches outbound connections and flags those to
threat-intel IPs closes it, and reuses the firewall's existing CIDR reputation
set (`is_blocked_ip`) - itself the Rust-accelerated `_IPSet`.

## Decision

Add `valkyrie/network_telemetry.py`, mirroring the process collector's shape:

- **`classify_connection(ip, port, blocked)`** - pure/tested. The high-value,
  low-noise signal is a connection to a known threat-intel IP -> high severity,
  `threat_intel_ip` label. Clean destinations are info-level.
- **`NetworkCollector`** - polls `psutil.net_connections`, diffs for new outbound
  connections, and by default emits only **flagged** (threat-intel) connections
  so normal traffic doesn't flood the pipeline (`emit_all=True` surfaces
  everything for visibility). `ip_reputation(ip)->bool` is injected (typically
  `FirewallManager.is_blocked_ip`). Emits normalized `TelemetryEvent`s
  (`category=network`, `activity=connect`) via a callback.

Same honesty as the process collector: userland poller, not a kernel flow sensor;
can miss very short-lived connections; no-op without psutil; never raises.

**Scope of this increment:** the module + tests only. It is **not yet wired** into
`__main__`/EDR - that live wiring (feeding `edr.ingest_telemetry`, likely under
`--endpoint`) is a follow-up. Committed now, tested and additive, so nothing
imports it and runtime behavior is unchanged.

Also fixes a latent baseline bug shared with the process collector: the
"first snapshot" check used truthiness, so an **empty** first snapshot would
re-seed forever instead of becoming a valid baseline. Both collectors now use a
`None` sentinel.

## Change report

- **What changed:** new `valkyrie/network_telemetry.py` (+ tests);
  `process_telemetry.py` baseline sentinel fix for consistency/correctness.
- **Why:** detect hard-coded-IP C2 that bypasses DNS - a named audit gap - and
  correct the empty-baseline edge case.
- **Security impact:** positive once wired - surfaces connections to threat-intel
  IPs even with no DNS lookup, the exact Windows in-process-firewall blind spot.
  The sentinel fix prevents a collector from silently never emitting if its first
  snapshot is empty (e.g. transient access-denied).
- **Performance impact:** none (unwired). When wired, a ~3s connection-table poll,
  off the DNS hot path; reputation check is the O(<=32) `_IPSet` lookup.
- **Compatibility impact:** none - additive module; the process-collector fix is
  behavior-preserving for all existing (non-empty-baseline) cases, verified green.
- **Risks:** low. Connection polling can be noisy on busy hosts - mitigated by
  emitting flagged-only by default. Short-lived connections can be missed
  (documented; kernel flow sensor is the roadmap).
- **Tests added:** `tests/test_network_telemetry.py` - classification (blocked vs
  clean), `to_event`, `diff_snapshots`, flagged-only vs `emit_all`, and
  emitter-exception isolation. Full suite: 31 passed, 0 failed, 2 skipped.
- **Rollback plan:** delete the module + test (and optionally revert the
  process-collector sentinel line). Nothing imports it. Clean `git revert`.

## Consequences

The network signal source exists and is proven; wiring it into `--endpoint`
alongside the process collector will give Valkyrie DNS + process + network
telemetry, all correlated through one engine - and specifically covers the
no-DNS, hard-coded-IP C2 path.
