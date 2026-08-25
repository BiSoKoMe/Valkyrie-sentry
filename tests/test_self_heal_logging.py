#!/usr/bin/env python3
"""Self-healing watchdog: honest claims, bounded logging (self_heal.py).

The reported symptom was the Recent Events list filled top to bottom with:

    web_dashboard unhealthy (health check returned False) - attempting recovery

repeated identically, forever. Three separate faults produced that one line:

1. The probe hit ``/api/stats`` -- a five-query 24h aggregate measured at 2.5s
   alone, 6.3s concurrent -- with a 3s timeout, so a HEALTHY server failed its
   own health check. (Fixed in __main__.py by probing /api/ping instead.)

2. "attempting recovery" was logged for a component registered with NO
   recover_fn. Nothing was attempted. Announcing a recovery that no code will
   perform makes an unattended failure look handled.

3. Every check wrote another row. At 30s that is 2,880 rows/day into the same
   events table the UI renders and /api/stats aggregates -- so watchdog noise
   evicts real detections from the primary detection surface, and the growing
   table slows the very endpoint whose slowness caused the failure. The
   symptom fed the cause.

Pure in-process: fake components, a recording fake store. No sockets, no
sleeping, no host state.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402


class _RecordingStore:
    def __init__(self) -> None:
        self.rows: list[str] = []

    def log(self, event) -> None:
        self.rows.append(getattr(event, "reason", str(event)))


def main() -> int:
    c = Checks("self-heal logging (honest claims, bounded volume)",
               expect_min=14)

    from valkyrie.intelligence.self_heal import SelfHealing, _should_log_failure

    # ------------------------------------------------------------------ [1]
    print("\n[1] a component with NO recover_fn never claims recovery")
    store = _RecordingStore()
    h = SelfHealing(store=store)
    h.register("web_dashboard", lambda: False)        # no recover_fn
    h.check_now()
    first = store.rows[0] if store.rows else ""
    c.check("the failure is still reported", "unhealthy" in first)
    c.check("but it does NOT say 'attempting recovery' — nothing is attempted, "
            "and claiming otherwise makes an unattended failure look handled",
            "attempting recovery" not in first)
    c.check("it says so explicitly instead",
            "no recovery action is registered" in first)

    # ------------------------------------------------------------------ [2]
    print("\n[2] a component WITH a recover_fn still reports the attempt")
    store2 = _RecordingStore()
    h2 = SelfHealing(store=store2)
    calls = {"n": 0}

    def recover():
        calls["n"] += 1

    h2.register("dns_interceptor", lambda: False, recover)
    h2.check_now()
    c.check("recovery actually ran", calls["n"] == 1)
    c.check("and the attempt is logged",
            any("attempting recovery" in r for r in store2.rows))

    # ------------------------------------------------------------------ [3]
    print("\n[3] a PERSISTENT failure does not write a row every cycle")
    store3 = _RecordingStore()
    h3 = SelfHealing(store=store3)
    h3.register("web_dashboard", lambda: False)
    for _ in range(200):
        h3.check_now()
    n = len(store3.rows)
    c.check(f"200 consecutive failed checks produced {n} log rows, not 200 — "
            f"at a 30s interval the old behaviour wrote 2,880 rows/day into "
            f"the same table the UI renders", n < 15)
    c.check("the first failures ARE logged immediately, when they matter",
            n >= 3)

    # ------------------------------------------------------------------ [4]
    print("\n[4] backing off the LOGGING must not hide the STATE")
    st = h3.status()["web_dashboard"]
    c.check("status still reports it as down", st["ok"] is False)
    c.check("with the true, un-rate-limited failure count",
            st["failures"] == 200 and st["consecutive"] == 200)
    c.check("and says plainly that nothing can recover it",
            st["recoverable"] is False)

    # ------------------------------------------------------------------ [5]
    print("\n[5] RECOVERY is logged — it used to be silent, which reads "
          "identically to 'still broken, watchdog gave up'")
    store4 = _RecordingStore()
    h4 = SelfHealing(store=store4)
    alive = {"v": False}
    h4.register("web_dashboard", lambda: alive["v"])
    h4.check_now()
    h4.check_now()
    alive["v"] = True
    h4.check_now()
    c.check("the comeback is recorded",
            any("recovered" in r for r in store4.rows))
    c.check("and it names how long it was down",
            any("recovered after 2" in r for r in store4.rows))
    st4 = h4.status()["web_dashboard"]
    c.check("the consecutive run resets on recovery",
            st4["ok"] is True and st4["consecutive"] == 0)

    # ------------------------------------------------------------------ [6]
    print("\n[6] a flapping component logs each new failure run, not silence")
    store5 = _RecordingStore()
    h5 = SelfHealing(store=store5)
    up = {"v": True}
    h5.register("x", lambda: up["v"])
    for _ in range(3):
        up["v"] = False
        h5.check_now()
        up["v"] = True
        h5.check_now()
    c.check("each separate outage is visible — backoff is per-run, so a "
            "flapping component is never silently swallowed",
            sum(1 for r in store5.rows if "unhealthy" in r) == 3)

    # ------------------------------------------------------------------ [7]
    print("\n[7] the backoff schedule itself")
    logged = [i for i in range(1, 65) if _should_log_failure(i)]
    c.check(f"logs at {logged} — immediate for the first failures, then "
            f"powers of two", logged[:6] == [1, 2, 4, 8, 16, 32])

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
