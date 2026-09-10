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
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.edr.plugins import PluginContext
from tests.winreg_constants import constants as registry_constants
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


@patch.dict(sys.modules, {"winreg": registry_constants})
@patch("valkyrie.persistence_telemetry._WINREG", True)
@patch("valkyrie.persistence_telemetry.winreg", registry_constants, create=True)
@patch("valkyrie.persistence_telemetry._enum_loaded_user_sids", return_value=[])
def test_descriptor_and_dry_run(_sids=None) -> None:
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


def test_never_removes_valkyries_own_asep() -> None:
    """Valkyrie must not delete its own auto-start entries.

    Seen live 2026-09-10 on a real install: the persistence collector reported
    the app's own ValkyrieArm/ValkyrieDisarm tasks as "new auto-start entry
    created" (medium), and the enforce-mode remove-persistence playbook deleted
    both about a second after registration - twice, weeks apart. The user-facing
    symptom was Start Protection never arming DNS, because the no-prompt tasks
    it needs had been eaten by Valkyrie itself.
    """
    print("[3/3] never removes Valkyrie's own autostart entries")
    from valkyrie.edr import response as resp  # noqa: F401  (module under test)

    # The guard asks whether the task's action runs from our install root, so
    # the fixture only has to carry that root somewhere in the XML. Derived
    # here rather than read back from the module under test, so this fails on
    # the BEHAVIOUR (our own task getting deleted) rather than on a missing
    # helper - running from source, this is the same directory the responder
    # resolves to.
    repo_root = Path(__file__).resolve().parents[1]
    assert (repo_root / "valkyrie" / "edr" / "response.py").exists(), repo_root
    # Lowercased only for the comparison the responder makes (Windows paths are
    # case-insensitive); never for touching the filesystem, which on a
    # case-sensitive checkout - CI clones into .../Valkyrie-sentry/ - would then
    # look for a directory that does not exist.
    root = str(repo_root).lower()
    ours = (
        "<Task><Actions><Exec><Command>wscript.exe</Command>"
        f"<Arguments>//B //NoLogo '{root}/run-hidden.vbs' "
        f"'{root}/arm-protection.ps1'</Arguments></Exec></Actions></Task>"
    )
    theirs = ("<Task><Actions><Exec><Command>C:/Users/Public/eviL.exe"
              "</Command></Exec></Actions></Task>")

    def query_returns(xml, code=0):
        def fake_run(cmd, *a, **kw):
            if "/xml" in cmd:
                return SimpleNamespace(returncode=code, stdout=xml, stderr="")
            raise AssertionError(f"a protected task must never reach: {cmd}")
        return fake_run

    # 1. Our own task, identified by where its action runs from - not by name.
    with patch("subprocess.run", query_returns(ours)):
        status, detail = _run("scheduled_task::ValkyrieArm", dry_run=False)
    _check("our own arm task is refused, not deleted", status == "skipped")
    _check("the refusal says why", "own scheduled task" in detail)

    # 2. Dry-run must report the refusal too, or a playbook preview would
    #    promise a deletion that (correctly) never happens.
    with patch("subprocess.run", query_returns(ours)):
        status, _ = _run("scheduled_task::ValkyrieArm", dry_run=True)
    _check("dry-run reports the refusal rather than 'would delete'",
           status == "skipped")

    # 3. A hostile task merely NAMED like ours is still removable: ownership is
    #    decided by the action path, so the guard cannot be used as cover.
    deleted = []

    def fake_run(cmd, *a, **kw):
        if "/xml" in cmd:
            return SimpleNamespace(returncode=0, stdout=theirs, stderr="")
        deleted.append(cmd)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", fake_run):
        status, _ = _run("scheduled_task::ValkyrieArm", dry_run=False)
    _check("an impostor task with our name is NOT protected", status == "succeeded")
    _check("the impostor was actually deleted",
           any("/delete" in c for c in deleted))

    # 4. Unreadable definition + one of our names -> refuse (fail-safe): one
    #    uncleaned task beats deleting our own control plane.
    with patch("subprocess.run", query_returns("", code=1)):
        status, _ = _run("scheduled_task::ValkyrieDisarm", dry_run=False)
    _check("unreadable + our name is refused", status == "skipped")

    # 5. The engine's own SERVICE is ValkyrieShield; the bare "valkyrie" entry
    #    never matched it, so remove_persistence could delete the service
    #    hosting the engine running it.
    status, detail = _run("service_install::ValkyrieShield", dry_run=False)
    _check("the engine's own service is protected", status == "skipped")
    _check("service refusal names it protected", "protected service" in detail)


def main() -> int:
    print("=" * 60)
    print("RemovePersistenceResponder tests (all dry-run — nothing deleted)")
    print("=" * 60)
    register_responders  # imported to assert availability at import time
    test_descriptor_and_dry_run()
    test_safety_rails()
    test_persistence_event_entity()
    test_never_removes_valkyries_own_asep()
    print("-" * 60)
    if _failures:
        print(f"{_failures} check(s) FAILED.")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
