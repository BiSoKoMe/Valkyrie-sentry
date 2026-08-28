# ADR 0007 - A single event-bus primitive

- **Status:** Accepted
- **Phase:** 1 (core architecture)
- **Date:** 2026-07-12

## Context

Valkyrie had **two independent, hand-rolled publish/subscribe implementations**:

- `Store` - fans committed DNS-decision events out to the EDR engine and the web
  dashboard (`_subscribers` list + `_sub_lock` + a manual "swallow exceptions"
  loop in the writer thread).
- `EdrEngine` - fans correlated incident updates out to the web dashboard
  (`_subscribers` list + `_sub_lock` + an identical `_notify` loop).

Two copies of the same non-trivial concurrency code (snapshot-under-lock,
exception isolation so one bad subscriber can't stall ingestion) is a maintenance
and correctness hazard: a fix or hardening applied to one is easily missed in the
other, and there was no test of the delivery contract itself. It also blocks the
next architectural steps - a shared bus for cross-module decoupling and the DI
wiring - which need one canonical event mechanism.

## Decision

Add `valkyrie/eventbus.py` - a small, thread-safe `EventBus` with the exact
delivery contract the existing loops relied on:

- best-effort, **exception-isolated** delivery (a raising subscriber never
  affects others or the publisher);
- **thread-safe** (handlers snapshotted under a lock so the set may mutate during
  delivery - publish runs on the Store writer thread);
- **synchronous, in-order** on the publishing thread.

`Store` and `EdrEngine` adopt it internally. Their public `subscribe` /
`unsubscribe` methods and the `{"type": ..., ...}` dict payloads are **unchanged**,
so every existing subscriber (the EDR engine, the dashboard's `broadcast_sync`)
keeps working with no modification.

New capability, unused by current callers but available going forward: a
subscriber may filter by event `type`, so one shared bus can carry several event
kinds without every subscriber seeing all of them. `types=None` (default)
reproduces the old "deliver everything" behavior exactly.

Deliberately **out of scope** (kept synchronous for now): async fan-out and
back-pressure remain the transport layer's job (e.g. the WebSocket's bounded
queue), not the bus's - matching today's behavior and avoiding a risky semantics
change.

## Change report

- **What changed:** new `valkyrie/eventbus.py`; `store.py` and `edr/engine.py`
  now delegate their pub/sub to an internal `EventBus`; the two hand-rolled
  subscriber lists/locks/loops are deleted.
- **Why:** remove duplicated concurrency code, get one tested delivery contract,
  and lay the primitive the shared-bus/DI steps need.
- **Security impact:** neutral-to-positive. The exception-isolation guarantee
  (ingestion cannot be stalled by a faulty subscriber) is now centralized and
  test-covered rather than duplicated by hand.
- **Performance impact:** negligible. Same synchronous in-order delivery; the
  Store writer now publishes per event (snapshotting handlers per call) instead
  of once per flush - an extra lock acquire per event, dwarfed by the SQLite
  commit, and still gated by `has_subscribers()` so nothing is built when nobody
  listens.
- **Compatibility impact:** none. Public APIs and payload shapes are identical;
  verified by the existing EDR/store/web tests plus a new end-to-end check.
- **Risks:** low. The one behavioral nuance - `unsubscribe` now removes by object
  identity (all registrations of the same handler) rather than the first
  `list.remove` match - is strictly safer and matches every real caller (each
  subscribes a single handler once). Covered by tests.
- **Tests added:** `tests/test_eventbus.py` - ordered delivery, type filtering,
  exception isolation, idempotent unsubscribe, a concurrent publish/(un)subscribe
  thread-safety smoke, and an end-to-end Store->bus->subscriber delivery of a
  committed event. Full suite: 24 passed, 0 failed, 2 skipped.
- **Rollback plan:** revert the three edits and delete `eventbus.py`; `Store` and
  `EdrEngine` return to their inline subscriber lists. Clean `git revert`.

## Consequences

There is now one event primitive with a tested contract. The next steps - a
shared bus owned by an application context, and dependency-injection wiring so
publishers/subscribers no longer hold direct references to each other - build
directly on this, and the type-filtering support is what lets a single shared bus
carry DNS events, incidents, and (later) endpoint-sensor events without coupling
every consumer to every producer.
