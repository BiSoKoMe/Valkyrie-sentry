#!/usr/bin/env python3
"""Sensor tamper detection (ADR 0048) — fires on healthy->unhealthy transitions
only, never on a host that never had the sensor, never twice for one death.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks


def main() -> int:
    c = Checks("sensor tamper detection", expect_min=12)

    import valkyrie.sensor_tamper as st
    from valkyrie.sensor_tamper import SensorHealth, SensorTamperMonitor

    # ------------------------------------------------------------------
    print("[1] _sysmon_health classifies present/live/EID-complete correctly")
    from valkyrie.sysmon_manager import SysmonEnvironment

    def _env(present=True, live=True, eids=(1, 3, 7, 8, 10)):
        return SysmonEnvironment(present=present, service_state="Running" if present else "not-found",
                                 log_enabled=live, collection_live=live,
                                 configured_eids=tuple(eids),
                                 detail=f"present={present} live={live} eids={eids}")

    with mock.patch.object(st, "probe_sysmon", lambda: _env()):
        h = st._sysmon_health()
        c.check("fully healthy host -> healthy", h.healthy)

    with mock.patch.object(st, "probe_sysmon", lambda: _env(present=False)):
        h = st._sysmon_health()
        c.check("absent host -> unhealthy", not h.healthy)

    with mock.patch.object(st, "probe_sysmon", lambda: _env(live=False)):
        h = st._sysmon_health()
        c.check("present but not collecting -> unhealthy", not h.healthy)

    with mock.patch.object(st, "probe_sysmon", lambda: _env(eids=(1, 3, 7))):
        h = st._sysmon_health()
        c.check("missing an EID Valkyrie needs (8, 10) -> unhealthy", not h.healthy)
        c.check("reason names the missing config", "CreateRemoteThread" in h.detail
                or "ProcessAccess" in h.detail)

    # ------------------------------------------------------------------
    print("\n[2] Fires ONLY on healthy -> unhealthy transitions")
    emitted: list = []
    mon = SensorTamperMonitor(emit=emitted.append, interval=30.0)

    healthy = SensorHealth("sysmon", True, "ok")
    unhealthy = SensorHealth("sysmon", False, "driver gone")

    with mock.patch.object(st, "_CHECKS", (lambda: healthy,)):
        n = mon.poll_once()
        c.check("first poll (healthy, unknown baseline) does not fire",
                n == 0 and not emitted)

    with mock.patch.object(st, "_CHECKS", (lambda: healthy,)):
        n = mon.poll_once()
        c.check("healthy -> healthy does not fire", n == 0 and not emitted)

    with mock.patch.object(st, "_CHECKS", (lambda: unhealthy,)):
        n = mon.poll_once()
        c.check("healthy -> unhealthy fires exactly once", n == 1 and len(emitted) == 1)

    with mock.patch.object(st, "_CHECKS", (lambda: unhealthy,)):
        n2 = mon.poll_once()
        c.check("unhealthy -> unhealthy does NOT re-fire (no incident spam)",
                n2 == 0 and len(emitted) == 1)

    ev = emitted[0]
    c.check("severity is CRITICAL", ev.severity == "critical")
    c.check("technique is T1562.001", "T1562.001" in ev.fields.get("technique", ""))
    c.check("labeled sensor_tamper", "sensor_tamper" in ev.labels)
    c.check("reason names the sensor and what happened",
            "sysmon" in ev.reason and "driver gone" in ev.reason)

    # ------------------------------------------------------------------
    print("\n[3] A host that starts unhealthy and STAYS unhealthy never fires")
    mon2 = SensorTamperMonitor(emit=(lambda ev: emitted2.append(ev)), interval=30.0)
    emitted2: list = []
    with mock.patch.object(st, "_CHECKS", (lambda: unhealthy,)):
        mon2.start()   # seeds baseline synchronously as unhealthy
        mon2.poll_once()
        mon2.poll_once()
    c.check("never-healthy host never raises a transition incident",
            emitted2 == [])
    mon2.stop()

    # ------------------------------------------------------------------
    print("\n[4] A broken checker cannot take the monitor down")
    def _boom():
        raise RuntimeError("checker exploded")
    mon3 = SensorTamperMonitor(emit=lambda ev: None)
    with mock.patch.object(st, "_CHECKS", (_boom,)):
        try:
            mon3.poll_once()
            c.check("a raising checker does not propagate", True)
        except Exception:
            c.check("a raising checker does not propagate", False)

    print("\n[5] A raising emitter cannot take the monitor down")
    mon4 = SensorTamperMonitor(emit=lambda ev: (_ for _ in ()).throw(RuntimeError("x")))
    with mock.patch.object(st, "_CHECKS", (lambda: healthy,)):
        mon4.poll_once()
    with mock.patch.object(st, "_CHECKS", (lambda: unhealthy,)):
        try:
            mon4.poll_once()
            c.check("a raising emit() does not propagate", True)
        except Exception:
            c.check("a raising emit() does not propagate", False)

    print("\n[6] current_status() reflects the last poll, not a fresh probe")
    mon5 = SensorTamperMonitor(emit=lambda ev: None)
    with mock.patch.object(st, "_CHECKS", (lambda: healthy,)):
        mon5.start()
    c.check("current_status reports the seeded baseline",
            mon5.current_status() == {"sysmon": True})
    mon5.stop()

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
