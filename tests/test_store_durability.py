"""The event writer must never stop writing.

`store.py` owns the audit trail: every DNS decision, every detection, every
response action. Nothing else records them. If the background writer thread
dies, the product keeps running and keeps *looking* healthy while nothing at
all is being recorded - for a security tool, losing the audit trail without
saying so is close to the worst quiet failure available.

The bug this file was written around (verified, not assumed): `_writer_loop`
caught only `queue.Empty`. Any SQLite error escaped the loop, killed the
thread, AND skipped the `conn.close()` after it. A single event carrying an
unbindable value was enough:

    writer alive before : True     events logged : 1
    writer alive after  : False    events logged : 1   <- everything after
                                                          was silently lost

`executemany` is all-or-nothing, so one malformed row also discarded the
entire batch around it. And `__main__` registered `store_writer` with the
self-healing watchdog with a health check but NO recovery action, so the
watchdog could see the writer was dead and do nothing.

All three are now fixed and asserted here.
"""

from __future__ import annotations

import queue
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks
from valkyrie.store import DnsEvent, Store


def _event(domain: str) -> DnsEvent:
    return DnsEvent.now(domain=domain, decision="allowed", process_name="p.exe",
                        process_pid=1, process_path="", reason="",
                        suspicion=0.0, raw_category="dns")


def _poison() -> DnsEvent:
    """An event SQLite cannot bind - stands in for any malformed row."""
    e = _event("poison.test")
    try:
        e.suspicion = {"not": "bindable"}
    except Exception:                      # frozen dataclass
        object.__setattr__(e, "suspicion", {"not": "bindable"})
    return e


def main() -> int:
    c = Checks("store durability", expect_min=10)
    tmp = Path(tempfile.mkdtemp(prefix="valkyrie_store_dur_"))
    store = Store(db_path=tmp / "t.db")
    store.start()

    try:
        # --- Baseline ---
        print("\n[1] the writer works normally to begin with")
        store.log(_event("before.test"))
        time.sleep(0.8)
        c.check("the writer thread is alive", store.is_writing())
        c.check("a normal event is persisted",
                store.stats().get("total_24h", 0) >= 1)

        # --- REGRESSION: a malformed row must not kill the writer ---
        print("\n[2] REGRESSION: a malformed event must not kill the writer")
        for _ in range(60):                # force a batch flush
            store.log(_poison())
        time.sleep(2.0)
        alive = store.is_writing()
        c.check("the writer SURVIVED a batch of unbindable events", alive)

        # --- And logging must still work afterwards ---
        print("\n[3] logging still works after the bad batch")
        before = store.stats().get("total_24h", 0)
        store.log(_event("after.test"))
        time.sleep(0.8)
        after = store.stats().get("total_24h", 0)
        c.check(f"an event logged AFTER the failure is persisted "
                f"({before} -> {after})", after > before)
        c.check(f"the dropped rows were COUNTED, not hidden "
                f"({store.write_errors()} write errors)",
                store.write_errors() > 0)

        # --- Good rows in a mixed batch must survive ---
        print("\n[4] one bad row must not discard the good rows beside it")
        base = store.stats().get("total_24h", 0)
        store.log(_event("mixed-a.test"))
        store.log(_poison())
        store.log(_event("mixed-b.test"))
        for _ in range(60):                # push the batch through
            store.log(_event("filler.test"))
        time.sleep(2.0)
        grew = store.stats().get("total_24h", 0)
        c.check(f"good rows in a mixed batch were still written "
                f"({base} -> {grew})", grew > base + 1)

        # --- The watchdog can actually recover a dead writer ---
        print("\n[5] a dead writer can be recovered (the watchdog's action)")
        c.check("restart_writer() exists for the watchdog to call",
                callable(getattr(store, "restart_writer", None)))
        c.check("restart_writer() is a no-op while the writer is healthy",
                store.restart_writer() is False)

        # Kill it deliberately and prove recovery works.
        store._queue.put(None)             # sentinel -> writer exits cleanly
        time.sleep(1.0)
        c.check("precondition: the writer is now stopped", not store.is_writing())
        c.check("restart_writer() brings it back", store.restart_writer() is True)
        time.sleep(0.5)
        c.check("the recovered writer is alive", store.is_writing())

        recovered_before = store.stats().get("total_24h", 0)
        store.log(_event("recovered.test"))
        time.sleep(0.8)
        c.check("the recovered writer persists new events",
                store.stats().get("total_24h", 0) > recovered_before)

    finally:
        try:
            store.stop()
        except Exception:
            pass

    # --- queue_stats() must count drops, not hide them (Beta 1/Nyx audit:
    # sustained real load found log()'s "drop under extreme load rather
    # than block" comment was true but silent - no counter existed) ---
    print("\n[6] queue_stats() counts events log() had to drop, instead of "
          "hiding the drop the way a bare `except queue.Full: pass` does")
    store2 = Store(db_path=tmp / "t2.db")
    # Swap in a maxsize=1 queue BEFORE start(), so nothing drains it yet -
    # every log() past the first is a deterministic queue.Full, not a race
    # against how fast the writer thread happens to be scheduled.
    store2._queue = queue.Queue(maxsize=1)
    try:
        before = store2.queue_stats()
        c.check("a fresh store reports zero dropped events",
                before["dropped"] == 0 and before["maxsize"] == 1)
        store2.log(_event("fill.test"))            # occupies the only slot
        for i in range(5):
            store2.log(_event(f"burst-{i}.test"))   # writer not running yet -> must drop
        after = store2.queue_stats()
        c.check(f"log() past a full queue is COUNTED, not silently "
                f"swallowed ({after['dropped']} dropped)", after["dropped"] >= 5)
        c.check("depth never exceeds the configured maxsize",
                after["depth"] <= after["maxsize"])

        store2.start()   # now let it drain - the store must still work afterward
        time.sleep(0.8)
        c.check("the store still writes normally after recovering from a "
                "full queue", store2.stats().get("total_24h", 0) >= 1)
    finally:
        try:
            store2.stop()
        except Exception:
            pass

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
