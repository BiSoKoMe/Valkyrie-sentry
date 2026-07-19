#!/usr/bin/env python3
"""Component platform — the uniform plugin contract, offline tests.

  [1] Adapter introspection: available()/is_healthy()/is_running()/status()
      map to the normalized health + metrics surface
  [2] Fault isolation: a service whose health/metrics probe RAISES becomes
      an 'error'/'_error' report — never propagates
  [3] Independent restart: restart() stops+starts one component; a failing
      start is reported, not raised
  [4] Aggregate: overall() picks the worst non-disabled state; disabled is
      not counted as a fault
  [5] Event-driven: health-state transitions publish a 'component' event
  [6] Real services register and report (Store as a live component)
  [7] Registry never crashes on a component that throws everywhere
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


class _Healthy:
    def __init__(self): self.started = 0; self.stopped = 0
    def is_healthy(self): return True
    def status(self): return {"emitted": 42}
    def start(self): self.started += 1
    def stop(self): self.stopped += 1


class _Running:
    def __init__(self, up=True): self._up = up
    def is_running(self): return self._up
    def stats(self): return {"depth": 3}


class _Unavailable:
    def available(self): return False


class _Exploding:
    def is_healthy(self): raise RuntimeError("probe boom")
    def status(self): raise ValueError("metrics boom")


class _BadStart:
    def is_running(self): return False
    def start(self): raise OSError("cannot start")
    def stop(self): pass


def main() -> int:
    from valkyrie.components import (
        Component, ComponentRegistry, Health,
        STATE_UP, STATE_DOWN, STATE_DEGRADED, STATE_DISABLED, STATE_ERROR,
    )
    from valkyrie.eventbus import EventBus

    print("\n=== component platform ===\n")

    print("[1] Adapter introspection")
    up = Component("up", _Healthy(), kind="sensor")
    _check("is_healthy -> up", up.health().state == STATE_UP)
    _check("status -> metrics", up.metrics() == {"emitted": 42})
    _check("start+stop -> restartable", up.restartable is True)
    down = Component("down", _Running(up=False))
    _check("is_running False -> down", down.health().state == STATE_DOWN)
    _check("stats -> metrics", down.metrics() == {"depth": 3})
    dis = Component("dis", _Unavailable())
    _check("available False -> disabled", dis.health().state == STATE_DISABLED)
    none_c = Component("none", None)
    _check("None service -> down + not restartable",
           none_c.health().state == STATE_DOWN and none_c.restartable is False)
    custom = Component("c", object(),
                       health_fn=lambda: Health(STATE_DEGRADED, "slow"),
                       metrics_fn=lambda: {"x": 1})
    _check("custom health_fn honored", custom.health().state == STATE_DEGRADED)

    print("\n[2] Fault isolation on probes")
    boom = Component("boom", _Exploding())
    _check("raising health -> error state",
           boom.health().state == STATE_ERROR and "probe boom" in boom.health().detail)
    _check("raising metrics -> _error, no raise",
           "_error" in boom.metrics())

    print("\n[3] Independent restart")
    svc = _Healthy()
    comp = Component("r", svc)
    res = comp.restart()
    _check("restart stops then starts",
           res["ok"] and svc.stopped == 1 and svc.started == 1)
    bad = Component("bad", _BadStart())
    r2 = bad.restart()
    _check("failing start reported, not raised",
           r2["ok"] is False and "cannot start" in r2["error"])
    notr = Component("notr", _Running())
    _check("non-restartable rejects restart",
           notr.restart()["ok"] is False)

    print("\n[4] Aggregate overall()")
    reg = ComponentRegistry()
    reg.register(Component("a", _Healthy()))
    reg.register(Component("b", _Unavailable()))       # disabled
    reg.register(Component("c", _Running(up=False)))   # down
    ov = reg.overall()
    _check("worst non-disabled state wins", ov["state"] == STATE_DOWN)
    _check("disabled counted separately, not as fault",
           ov["counts"].get(STATE_DISABLED) == 1 and ov["total"] == 3)

    print("\n[5] Event-driven transitions")
    bus = EventBus("t")
    events: list = []
    bus.subscribe(events.append)
    flip = _Running(up=True)
    reg2 = ComponentRegistry(bus=bus)
    reg2.register(Component("flip", flip))
    reg2.health()                 # first probe: up, no transition event
    _check("no event on first probe", len(events) == 0)
    flip._up = False
    reg2.health()                 # up -> down transition
    _check("transition publishes component event",
           len(events) == 1 and events[0]["type"] == "component"
           and events[0]["state"] == STATE_DOWN
           and events[0]["previous"] == STATE_UP)

    print("\n[6] Real Store as a live component")
    from valkyrie.store import Store
    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "c.db")
        store.start()
        reg3 = ComponentRegistry()
        reg3.register_service("store", store, kind="storage")
        snap = reg3.snapshot()
        _check("store registered and probed",
               len(snap) == 1 and snap[0]["name"] == "store")
        _check("store reports up while writer alive",
               snap[0]["health"]["state"] == STATE_UP)
        _check("skip_if_missing drops a None service",
               reg3.register_service("nope", None, skip_if_missing=True) is None
               and "nope" not in reg3.names())
        store.stop()

    print("\n[7] Registry survives a fully-broken component")
    reg4 = ComponentRegistry()
    reg4.register(Component("boom", _Exploding()))
    reg4.register(Component("ok", _Healthy()))
    snap4 = reg4.snapshot()
    states = {s["name"]: s["health"]["state"] for s in snap4}
    _check("broken component isolated, healthy one still up",
           states["boom"] == STATE_ERROR and states["ok"] == STATE_UP)
    _check("overall reflects the error", reg4.overall()["state"] == STATE_ERROR)

    print("\n" + "=" * 48)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
