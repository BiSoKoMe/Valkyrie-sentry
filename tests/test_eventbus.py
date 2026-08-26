#!/usr/bin/env python3
"""EventBus primitive + its adoption by Store (ADR-0007).

Covers the delivery contract the old hand-rolled loops relied on - best-effort,
isolated, in-order, thread-safe - plus the new type-filtering capability, and
proves end-to-end that a committed Store event still reaches a subscriber over
the bus (the wiring the refactor changed).
"""

from __future__ import annotations

import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def main() -> int:
    from valkyrie.eventbus import EventBus

    print("\n=== EventBus primitive ===\n")

    print("[1] Basic publish/subscribe, in order")
    bus = EventBus("t")
    seen: list[dict] = []
    bus.subscribe(seen.append)
    bus.publish({"type": "a", "n": 1})
    bus.publish({"type": "b", "n": 2})
    _check("both events delivered", len(seen) == 2)
    _check("delivered in order", [e["n"] for e in seen] == [1, 2])
    _check("subscriber_count == 1", bus.subscriber_count() == 1)

    print("\n[2] Type filtering")
    bus = EventBus("t")
    only_a: list[dict] = []
    everything: list[dict] = []
    bus.subscribe(only_a.append, types=["a"])
    bus.subscribe(everything.append)
    bus.publish({"type": "a"})
    bus.publish({"type": "b"})
    bus.publish({"type": "c"})
    _check("filtered subscriber saw only 'a'", len(only_a) == 1)
    _check("unfiltered subscriber saw all 3", len(everything) == 3)

    print("\n[3] Exception isolation")
    bus = EventBus("t")
    good: list[dict] = []

    def _boom(_e):
        raise RuntimeError("subscriber blew up")

    bus.subscribe(_boom)          # registered first
    bus.subscribe(good.append)    # must still receive despite _boom raising
    try:
        bus.publish({"type": "x"})
        published_ok = True
    except Exception:
        published_ok = False
    _check("publish did not propagate subscriber exception", published_ok)
    _check("healthy subscriber still received event", len(good) == 1)

    print("\n[4] Unsubscribe is idempotent and complete")
    bus = EventBus("t")
    got: list[dict] = []
    bus.subscribe(got.append)
    bus.unsubscribe(got.append)             # different bound method object...
    # ...so identity-based removal only drops the exact object we registered:
    h = got.append
    bus2 = EventBus("t2")
    bus2.subscribe(h)
    bus2.unsubscribe(h)
    bus2.publish({"type": "x"})
    _check("removed handler receives nothing", len(got) == 0)
    bus2.unsubscribe(h)   # second unsubscribe must not raise
    _check("double unsubscribe is safe", True)
    _check("has_subscribers() False when empty", not bus2.has_subscribers())

    print("\n[5] Thread-safety smoke (concurrent publish + (un)subscribe)")
    bus = EventBus("t")
    counter = {"n": 0}
    lock = threading.Lock()

    def handler(_e):
        with lock:
            counter["n"] += 1

    bus.subscribe(handler)
    stop = False

    # Reuse ONE handler object so the subscriber list stays bounded - this
    # exercises the lock under concurrent add/remove without growing the list.
    def _noop(_e):
        pass

    def churn():
        while not stop:
            bus.subscribe(_noop)
            bus.unsubscribe(_noop)

    def spam():
        for _ in range(2000):
            bus.publish({"type": "x"})

    ch = threading.Thread(target=churn, daemon=True)
    ch.start()
    threads = [threading.Thread(target=spam) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    stop = True
    ch.join(timeout=1)
    # The stable handler is registered once and never removed, so it must see
    # exactly every publish regardless of the concurrent churn.
    _check("all 8000 publishes delivered to the stable handler", counter["n"] == 8000)

    print("\n[6] Store integration — committed event reaches a bus subscriber")
    from valkyrie.store import Store, DnsEvent
    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "bus.db")
        store.start()
        received: list[dict] = []
        store.subscribe(received.append)
        store.log(DnsEvent.now(
            domain="example.com", decision="allowed", process_name="chrome.exe",
            process_pid=123, process_path="/x", reason="", suspicion=0.0,
            raw_category=""))
        # Writer flushes on the 0.25s empty-queue timeout; poll up to 3s.
        deadline = time.monotonic() + 3.0
        while not received and time.monotonic() < deadline:
            time.sleep(0.05)
        store.stop()
        _check("subscriber received one committed event", len(received) == 1)
        if received:
            msg = received[0]
            _check("event has type 'event'", msg.get("type") == "event")
            _check("payload carries the domain",
                   msg.get("event", {}).get("domain") == "example.com")

    print("\n" + "=" * 52)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
