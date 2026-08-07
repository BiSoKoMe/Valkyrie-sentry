#!/usr/bin/env python3
"""Control taxonomy tests (valkyrie/control_taxonomy.py, IIBA §4.2.3).

Guards the two real findings this classification pass surfaced (decoys.py
never named as deterrent; compensating was empty until sensor_tamper.py
gained a real activation hook) and, more durably, guards against silent
drift: every ``Control.module`` path must resolve to something that still
exists, so a rename/removal elsewhere in the codebase breaks THIS test
instead of leaving the taxonomy quietly describing code that is gone.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from harness import Checks   # noqa: E402

from valkyrie.control_taxonomy import (   # noqa: E402
    CATEGORIES, COMPENSATING, CONTROLS, DETERRENT, by_category, gaps,
)

c = Checks("control taxonomy", expect_min=15)


def _resolves(dotted: str) -> bool:
    """True if `dotted` is an importable module, or a module path with
    trailing attribute access(es) that all resolve."""
    parts = dotted.split(".")
    for split in range(len(parts), 0, -1):
        mod_path = ".".join(parts[:split])
        try:
            obj = importlib.import_module(mod_path)
        except ImportError:
            continue
        for attr in parts[split:]:
            try:
                obj = getattr(obj, attr)
            except AttributeError:
                return False
        return True
    return False


def test_every_module_path_resolves() -> None:
    print("\n[1] every Control.module path resolves to real code")
    for ctl in CONTROLS:
        c.check(f"'{ctl.name}' -> {ctl.module} resolves",
                _resolves(ctl.module))


def test_categories_are_valid() -> None:
    print("\n[2] every Control uses a real category")
    for ctl in CONTROLS:
        c.check(f"'{ctl.name}' primary category '{ctl.category}' is valid",
                ctl.category in CATEGORIES)
        for sec in ctl.secondary:
            c.check(f"'{ctl.name}' secondary category '{sec}' is valid",
                    sec in CATEGORIES)


def test_no_undisclosed_gaps() -> None:
    print("\n[3] gaps() matches reality — no category silently empty")
    grouped = by_category()
    empty_categories = gaps()
    for cat in CATEGORIES:
        has_primary = any(ctl.category == cat for ctl in CONTROLS)
        c.check(f"'{cat}' gap-status matches its actual primary-control count",
                (cat in empty_categories) == (not has_primary))
    c.check("by_category() covers all 7 CATEGORIES keys",
            set(grouped.keys()) == set(CATEGORIES))


def test_decoys_named_as_deterrent() -> None:
    print("\n[4] decoys.py is explicitly classified deterrent (the finding)")
    decoy = next((x for x in CONTROLS if x.name == "decoys"), None)
    c.check("decoys.py has a Control entry", decoy is not None)
    c.check("decoys.py's PRIMARY category is deterrent",
            decoy is not None and decoy.category == DETERRENT)


def test_compensating_is_not_empty_and_is_honest() -> None:
    print("\n[5] compensating control exists for Sysmon and states its limits")
    comp = [x for x in CONTROLS if x.category == COMPENSATING]
    c.check("at least one compensating control is registered", len(comp) >= 1)
    sysmon_comp = next((x for x in comp if "sysmon" in x.name.lower()), None)
    c.check("a Sysmon-specific compensating control exists", sysmon_comp is not None)
    if sysmon_comp:
        c.check("it names what it does NOT cover (honest about partial coverage)",
                "does not" in sysmon_comp.note.lower()
                or "not compensate" in sysmon_comp.note.lower())


def test_sensor_tamper_actually_wires_the_compensation() -> None:
    print("\n[6] sensor_tamper.py's compensation hook is real code, not just prose")
    from unittest.mock import MagicMock

    from valkyrie.sensor_tamper import SensorTamperMonitor
    from valkyrie.telemetry import SEV_INFO

    activate = MagicMock()
    deactivate = MagicMock()
    mon = SensorTamperMonitor(emit=lambda ev: None, interval=9999,
                              compensations={"sysmon": (activate, deactivate)})

    class _FakeHealth:
        def __init__(self, name, healthy, detail=""):
            self.name, self.healthy, self.detail = name, healthy, detail

    # Simulate: healthy -> unhealthy -> healthy, driving poll_once() logic
    # directly via the same private state poll_once() mutates, without
    # depending on a live Sysmon probe.
    mon._last["sysmon"] = True
    h_down = _FakeHealth("sysmon", False, "mock down")
    mon._activate_compensation(h_down)
    c.check("compensation activates on the down transition", activate.called)
    c.check("current_compensation() reports it active",
            mon.current_compensation().get("sysmon") is True)

    h_up = _FakeHealth("sysmon", True, "mock recovered")
    mon._deactivate_compensation(h_up)
    c.check("compensation deactivates on recovery", deactivate.called)
    c.check("current_compensation() reports it inactive again",
            mon.current_compensation().get("sysmon") is False)

    # A broken compensating action must not raise out of the monitor.
    boom_mon = SensorTamperMonitor(
        emit=lambda ev: None, interval=9999,
        compensations={"sysmon": (MagicMock(side_effect=RuntimeError("boom")),
                                  MagicMock())})
    try:
        boom_mon._activate_compensation(h_down)
        c.check("a raising compensating action does not propagate", True)
    except Exception:                                        # noqa: BLE001
        c.fail("a raising compensating action does not propagate")
    c.check("a failed activation is reported as inactive, not silently True",
            boom_mon.current_compensation().get("sysmon") is False)

    # SEV_INFO import above is exercised implicitly by sensor_tamper module
    # import succeeding; keep the reference so linting doesn't flag it.
    assert SEV_INFO == "info"


def main() -> int:
    print("=" * 60)
    print("Control taxonomy (IIBA §4.2.3)")
    print("=" * 60)
    test_every_module_path_resolves()
    test_categories_are_valid()
    test_no_undisclosed_gaps()
    test_decoys_named_as_deterrent()
    test_compensating_is_not_empty_and_is_honest()
    test_sensor_tamper_actually_wires_the_compensation()
    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
