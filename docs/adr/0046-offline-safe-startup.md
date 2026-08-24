# ADR 0046 — Protection must never wait on the network

Date: 2026-08-04 · Status: accepted

## Context

A full-repository debugging sweep (86 test modules, all packages compile- and
import-checked) found one regression **introduced earlier in the same session**,
plus two stale-assertion bugs of a class this codebase has now hit three times.

## The regression I introduced

ADR 0044's cycle flipped `USE_EXTERNAL_LISTS` from `False` to `True` — correct
intent: threat feeds that never run protect nobody, and shipping them off by
default understated real detection.

The implementation was wrong. `BlocklistManager.load(allow_download=True)`
calls `update_blocklist()` **synchronously on the startup path**, so the engine
began blocking on a ~500,000-domain download before protecting anything.
`ThreatIntelManager.load()` had the identical shape for three IOC feeds.

Consequences, in order of severity:

1. **Offline and air-gapped machines stall.** Three feeds × a 30-second urllib
   timeout is up to 90 seconds of dead startup — in an environment this product
   *specifically targets* (ADR 0044's positioning).
2. **On a slow link it is indistinguishable from a hang** for a security agent
   the user is trusting to come up.
3. `test_startup_smoke` went from **9/9 passing to failing outright**, which is
   how it was caught. Verified against a stashed clean tree: baseline 9/9 with
   zero downloads, changed tree 1 check and a failure.

## Decision

**Startup loads seed + cache only. Every network refresh runs on a background
thread and hot-swaps under the lock the DNS path already reads through.**

- New `BlocklistManager.start_background_refresh()` — daemon thread, skips
  entirely when the cache is fresh, reloads via `_read_from_disk()` (atomic swap
  under `self._lock`), and swallows its own errors so a failed refresh can never
  affect a running engine.
- `ThreatIntelManager._refresh_loop` gained `_INITIAL_REFRESH_DELAY = 20s`. The
  loop previously waited a full `THREAT_INTEL_REFRESH_SECONDS` (6 h) before its
  first pass, so making startup cache-only would have left a machine that had
  been offline for weeks with stale IOCs for six more hours. Short first pass,
  then the normal cadence.
- `__main__` passes `allow_download=True if args.update else False` to both.
  `--update` stays synchronous — there the user explicitly asked to refresh and
  exit.

Net effect: feeds remain **on by default** (the detection value ADR 0044
wanted) while startup is instant and offline-safe.

`tests/test_startup_no_network_block.py` pins all of it: no download without an
explicit flag, the refresh thread is a daemon that swaps atomically and eats its
own exceptions, the initial delay is short but non-zero, and `__main__` gates
both loads on `args.update` rather than on the download policy.

## Two stale-assertion bugs (same class, third and fourth instances)

**`test_ip_leak` §3 asserted against the wrong API surface.** It failed all five
DoH-resolver checks, which reads as "DoH-bypass protection is broken." It is not.
There are two surfaces and they differ *by design*:

| Surface | Question it answers | `1.1.1.1` |
|---|---|---|
| `_ipset.contains()` | Is this IP enforced (kernel rule installed)? | **True** |
| `is_blocked_ip()` | Should traffic here be treated as malicious? | **False** |

`is_blocked_ip()` exempts public resolvers via `trust.is_public_resolver_ip`,
added in the FP-cleanup pass (5418a61), because Valkyrie's own upstream DNS goes
to exactly those addresses — without the exemption the network collector flags
the engine's own resolver traffic as C2. The test asserted the reputation
surface and read a deliberate safety guard as a failure. Corrected to assert
enforcement, **and** to pin the exemption itself so removing it fails loudly.

**`FLEET_*` settings specs were silent no-ops.** `settings.py` still exposed
three user-settable knobs for the frozen fleet control plane: the operator sets
one, validation accepts it, nothing happens. Removed; the underlying `config.py`
constants stay because `experimental/fleet` imports them.

## A change this codebase's own tests correctly rejected

I also removed the fleet-token and WireGuard entries from
`secure_file._secret_paths()`, reasoning that listing paths core can no longer
create implies coverage that does not exist. `test_secret_hygiene` failed, and
it was right: **an upgrader who ran an older build still has a real
`fleet_agent.json` device token and a `wg0.conf` containing a WireGuard
PrivateKey on disk.** Dropping them from the hardening sweep would stop
protecting secrets that already exist — a genuine exposure — whereas hardening
an absent path is a harmless no-op the module already tolerates by design.
Reverted, with the reasoning recorded inline so it is not re-attempted.

## Confirmed NOT bugs

- `test_dns` / `test_resolver` — integration tests needing live external state;
  `run_tests.py` already excludes them via `_INTEGRATION`. They only failed in a
  raw glob sweep.
- `test_rust_accel` / `test_telemetry` / `test_tls` — honest environmental skips
  (no Rust toolchain, needs Administrator, mitmproxy absent). Each reports
  "SKIPPED — this is NOT a pass", which is the correct behaviour.
- `test_firewall` — deliberately not run. Its §9 installs live `netsh` rules and
  previously took the developer's WiFi down; the `VALKYRIE_TEST_LIVE_FIREWALL=1`
  gate was verified still present.

## Result

| | |
|---|---|
| Modules compiled / imported | 87 core, all packages, clean |
| Test modules swept | 86 (excl. `test_firewall`) |
| Passing | **82** |
| Failing | **0** |
| Skips (honest, reported as non-passes) | 3 |

## The pattern, now four instances deep

Every non-trivial finding in this session was **a correct product and a lying
measurement**:

1. stale `delivery` labels under-reported the red-team score (ADR 0043);
2. a stale verdict list under-reported DNS recall by 60 points (ADR 0045);
3. `"behavioral"` — a second instance of (2), found by the regression test
   written for it;
4. `test_ip_leak` asserting a reputation API and reading a safety guard as a
   failure.

Plus the inverse here: a green test suite that went red for a *real* reason and
caught a regression before it shipped. **Measurements need regression tests as
much as detectors do**, and a test that fails is worth more than one that was
never wired to the thing it claims to measure.
