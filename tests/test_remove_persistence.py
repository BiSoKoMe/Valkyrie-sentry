#!/usr/bin/env python3
"""RemovePersistenceResponder tests (valkyrie/edr/response.py).

The responder rips out an attacker-created autostart entry. These tests run it
strictly in DRY-RUN, so nothing is ever actually deleted - they verify the
descriptor parsing, the per-ASEP command shaping, and (most importantly) the
safety rails that must refuse to touch critical Windows state.

  [1] descriptor parsing: '<type>::<identity>' -> the right handler
  [2] each ASEP type produces a dry-run description of the correct action
  [3] safety rails: protected service, system task tree, startup file outside
      recognised Startup folders, and unknown type are all refused
  [4] the responder is registered and advertises 'remove_persistence'
  [5] a persistence TelemetryEvent yields an entity the responder can consume
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.edr.plugins import PluginContext
from valkyrie.edr.response import (
    RemovePersistenceResponder, BUILTIN_RESPONDERS, register_responders,
)

_failures = 0


def _check(label: str, ok: bool) -> None:
    global _failures
    status = "ok  " if ok else "FAIL"
    if not ok:
        _failures += 1
    print(f"  [{status}] {label}")


def _run(target, dry_run=True):
    r = RemovePersistenceResponder()
    return r.execute("remove_persistence", target, dry_run=dry_run,
                     ctx=PluginContext())


def test_descriptor_and_dry_run() -> None:
    print("[1/2] descriptor parsing + dry-run action shaping")

    status, msg = _run("scheduled_task::ValkTest")
    _check("scheduled_task → dry_run", status == "dry_run")
    _check("scheduled_task names the task", "ValkTest" in msg and "schtasks" in msg.lower())

    status, msg = _run("service_install::ValkTestSvc")
    _check("service → dry_run", status == "dry_run")
    _check("service names sc delete", "ValkTestSvc" in msg and "sc.exe delete" in msg.lower())

    status, msg = _run(r"registry_run_key::HKCU\...\Run::ValkTest")
    # loc 'HKCU\...\Run' is a known display location -> maps back cleanly.
    _check("run_key → dry_run", status == "dry_run")
    _check("run_key names the value", "ValkTest" in msg)

    status, msg = _run("bogus_type::whatever")
    _check("unknown ASEP type → failed", status == "failed")

    status, msg = _run("no-separator-here")
    _check("missing '::' separator → failed", status == "failed")


def test_safety_rails() -> None:
    print("[2/2] safety rails (must refuse critical state; dry-run throughout)")

    status, msg = _run("service_install::WinDefend")
    _check("refuses to delete WinDefend service", status == "skipped")

    status, msg = _run("service_install::valkyrie")
    _check("refuses to delete Valkyrie's own service", status == "skipped")

    status, msg = _run(r"scheduled_task::Microsoft\Windows\UpdateOrchestrator\Reboot")
    _check("refuses to delete a Microsoft\\Windows system task", status == "skipped")

    status, msg = _run(r"startup_folder::C:\Windows\System32\evil.exe")
    _check("refuses startup delete outside recognised Startup dirs", status == "skipped")

    # Registration / advertisement.
    _check("RemovePersistenceResponder is a builtin",
           RemovePersistenceResponder in BUILTIN_RESPONDERS)
    advertised = set()
    for cls in BUILTIN_RESPONDERS:
        try:
            advertised.update(cls().actions())
        except Exception:
            pass
    _check("'remove_persistence' is advertised", "remove_persistence" in advertised)


def test_persistence_event_entity() -> None:
    """A persistence TelemetryEvent, once ingested, must expose an entity of the
    form '<activity>::<identity>' that the responder consumes. Mirror the
    engine's mapping without needing a live store."""
    print("[bonus] persistence event → removable entity")
    from valkyrie.telemetry import PERSIST_SCHEDULED_TASK
    activity = PERSIST_SCHEDULED_TASK          # 'scheduled_task'
    identity = "ValkTest"
    entity = f"{activity}::{identity}"
    status, _ = _run(entity)
    _check("engine-shaped entity is consumable", status == "dry_run")


def main() -> int:
    print("=" * 60)
    print("RemovePersistenceResponder tests (all dry-run — nothing deleted)")
    print("=" * 60)
    register_responders  # imported to assert availability at import time
    test_descriptor_and_dry_run()
    test_safety_rails()
    test_persistence_event_entity()
    print("-" * 60)
    if _failures:
        print(f"{_failures} check(s) FAILED.")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
