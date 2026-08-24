# ADR 0055 - Host safety invariant: Valkyrie must never strand the host

Date: 2026-08-24 . Status: accepted . Follows: ADR 0054 (evidence librarian)
Informed by: docs/VALKYRIE_COMPETITIVE_ENGINEERING_PLAN.md (P0 #1)

## Context

On 2026-08-23 Valkyrie's DNS interception left a real host's Wi-Fi adapter
pointed at 127.0.0.1 with no local resolver answering. The link was up at
1.2 Gbps; every lookup failed; the host looked offline. For a privacy tool that
sits in front of all DNS this is disqualifying: the enterprise-readiness bar is
"a billion-dollar company runs it with no complaint," and a tool that can strand
a client's network fails that bar regardless of its detection quality.

The current Python source does not itself set adapter DNS (the OS redirect is
external), so the bad state came from a legacy/external redirect with no restore
path - and `DnsInterceptor.stop()` only closed its socket, restoring nothing. A
graceful-cleanup handler would not have helped anyway: the cases that actually
strand a host are the ungraceful ones - crash, `kill -9`, power loss mid-redirect,
an OS reboot, a replaced build.

## Decision

New `valkyrie/host_safety.py` - a fail-safe network guard whose correctness does
NOT depend on how the bad state arose.

**Pure decision core.** `decide_dns_action(current_servers, resolver_alive,
saved_original)` returns exactly one of LEAVE / SAVE_ORIGINAL / RESTORE_ORIGINAL
/ RESET_TO_AUTO, biased to connectivity at every branch:

- adapter not loopback-routed -> LEAVE (and SAVE_ORIGINAL the first time we see
  the host's real DNS, so a later restore is exact, not guessed);
- loopback-routed AND resolver answering -> LEAVE (healthy interception);
- loopback-routed AND resolver dead -> RESTORE_ORIGINAL if a clean original is
  known, else RESET_TO_AUTO (DHCP - the universal safe state).

Loopback detection is ALL-servers, not ANY: a mixed config still resolves via
its public server, so the host is not stranded and is left alone.

**Watchdog, not cleanup.** `DnsWatchdog.tick()` runs observe->decide->act on a
cadence and heals the strand the instant it appears - including a cold start
after a prior process died without cleanup (it still frees the host via
RESET_TO_AUTO with nothing saved). It never raises (a watchdog that can crash is
not a safety device), never acts on a healthy interception, and does nothing if
it cannot even read the adapter (no blind acts). `restore_on_stop()` handles the
graceful path, idempotently.

**Pure core, injected executor.** All OS calls (read/set/reset adapter DNS) are
behind an injected `DnsExecutor`, the same separation `authority.py` uses. 25
checks in `test_host_safety.py`, including the keystone that reproduces the exact
2026-08-23 strand and proves the host is freed.

## Consequences

- The specific failure that broke a real host is now a passing regression test.
- The design generalizes: the same invariant ("never leave the host worse than
  we found it") is the template for firewall and file operations (the
  `isolate_host` responder already snapshots/restores firewall state; this makes
  the pattern explicit and first-class).

## Deliberately NOT done this session

The OS shim that writes the real adapter (`netsh` / `Set-DnsClientServerAddress`)
is **not wired to run**. It manipulates live host networking, cannot be tested
non-elevated, and already caused one strand; activating an autonomous
DNS-writing watchdog unsupervised is the exact risk this ADR exists to prevent.
The tested pure logic ships now; the OS shim and its activation are a supervised,
reviewed step. Shipping the safety *logic* before the safety *actuator* is the
correct order for a device whose failure mode is breaking the host.

## Honesty

This adds no detection and raises no score. It is the foundation the score sits
on: for a solo tool with no logo and no support contract, structural safety -
alongside the evidence librarian (ADR 0054) and no-fake-parity - is how trust is
earned. It is the moat, not overhead.
