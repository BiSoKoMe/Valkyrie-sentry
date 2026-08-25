"""Tests for valkyrie/intelligence/self_heal.py

Regression coverage for the watchdog that keeps Valkyrie's components alive.
The component previously shipped with ZERO dedicated tests - the exact
blind-spot pattern that let the MAC randomizer's silent failure ship (see
docs/VPN_SELFHEAL_AUDIT_REPORT.md). These tests lock in:

  1. The watchdog THREAD survives a check_fn raising BaseException
     (SystemExit / KeyboardInterrupt), not just ordinary Exception.
  2. A recover_fn that itself raises BaseException does not kill the thread.
  3. recover_fn is actually invoked on failure and `recoveries` increments.
  4. all_ok() / status() reflect a failed component instead of freezing.
  5. One component failing never stops the others' checks (fault isolation).

No network, no real components - everything is exercised with tiny callables.
Usage: python tests/test_self_heal.py
"""

import sys
import time
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PASS = 0
FAIL = 0


def check(label: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  + [PASS]  {label}")
    else:
        FAIL += 1
        print(f"  X [FAIL]  {label}" + (f"  ({detail})" if detail else ""))


print("Valkyrie self-healing watchdog test")
print("=" * 50)

from valkyrie.intelligence.self_heal import SelfHealing


def _raise(exc):
    """Return a zero-arg callable that raises `exc` when invoked."""
    def _fn():
        raise exc
    return _fn


# --- Test 1: check_now() isolates a check raising SystemExit ---
print("\n-- BaseException isolation in check_now() -------------")
h = SelfHealing(store=None, interval=0.05)
h.register("boom", _raise(SystemExit("boom")))
h.register("fine", lambda: True)
try:
    h.check_now()
    check("check_now() does not propagate SystemExit from a check_fn", True)
except BaseException as e:   # noqa: BLE001 - the whole point is nothing escapes
    check("check_now() does not propagate SystemExit from a check_fn", False,
          f"escaped: {e!r}")

st = h.status()
check("failing component recorded as not ok", st["boom"]["ok"] is False)
check("failing component recorded a last_error", bool(st["boom"]["last_error"]))
check("healthy sibling still checked and ok", st["fine"]["ok"] is True)
check("all_ok() is False when one component failed", h.all_ok() is False)


# --- Test 2: the watchdog THREAD survives a SystemExit in a check ---
print("\n-- Watchdog thread survives SystemExit in check_fn ----")
h2 = SelfHealing(store=None, interval=0.02)
h2.register("suicidal", _raise(SystemExit))
h2.start()
time.sleep(0.15)   # several loop iterations
check("watchdog thread still alive after SystemExit in check_fn",
      h2._thread.is_alive() is True)
check("component still marked failed after repeated SystemExit",
      h2.status()["suicidal"]["ok"] is False)
h2.stop()


# --- Test 3: recover_fn raising BaseException does not kill the thread ---
print("\n-- Watchdog survives KeyboardInterrupt in recover_fn --")
h3 = SelfHealing(store=None, interval=0.02)
h3.register("bad_recover", lambda: False, _raise(KeyboardInterrupt))
h3.start()
time.sleep(0.15)
check("watchdog thread alive after KeyboardInterrupt in recover_fn",
      h3._thread.is_alive() is True)
check("recovery failure is recorded in last_error",
      "recovery raised" in h3.status()["bad_recover"]["last_error"])
h3.stop()


# --- Test 4: recover_fn is invoked on failure; recoveries increments ---
print("\n-- Recovery is actually invoked ----------------------")
recovered = {"n": 0}
healthy = {"v": False}


def _flaky_check():
    return healthy["v"]


def _recover():
    recovered["n"] += 1
    healthy["v"] = True   # recovery makes the next check pass


h4 = SelfHealing(store=None, interval=0.02)
h4.register("flaky", _flaky_check, _recover)
h4.check_now()   # first pass: unhealthy -> recover() called
check("recover_fn invoked exactly once after first failure", recovered["n"] == 1)
check("recoveries counter incremented", h4.status()["flaky"]["recoveries"] == 1)
h4.check_now()   # second pass: now healthy
check("component reports ok after successful recovery",
      h4.status()["flaky"]["ok"] is True)
check("all_ok() True once the only component recovered", h4.all_ok() is True)


# --- Test 5: fault isolation across many components ---
print("\n-- Fault isolation across components -----------------")
h5 = SelfHealing(store=None, interval=0.05)
order = []
h5.register("a", lambda: (order.append("a"), True)[1])
h5.register("b", _raise(RuntimeError("b broke")))
h5.register("c", lambda: (order.append("c"), True)[1])
h5.check_now()
check("component before the raiser was checked", "a" in order)
check("component after the raiser was still checked (isolation)", "c" in order)
check("raiser marked failed", h5.status()["b"]["ok"] is False)
check("neighbours stay ok", h5.status()["a"]["ok"] and h5.status()["c"]["ok"])


# --- Summary ---
print(f"\n{'=' * 50}")
print(f"  {PASS} passed  /  {FAIL} failed")
if FAIL:
    print("  RESULT: SOME TESTS FAILED")
    sys.exit(1)
else:
    print("  RESULT: ALL TESTS PASSED")
    sys.exit(0)
