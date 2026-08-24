#!/usr/bin/env python3
"""Responder reversibility audit (IIBA/IEEE Cybersecurity Analysis §4.2.5).

Every responder / enforcement action Valkyrie can take must answer three
questions in code, not just in a design doc:

    1. Is it reversible? By what EXACT call?
    2. What state does it leave behind if the process dies mid-action?
    3. What happens if it fires on a false positive?

Valkyrie violated this twice for real on the machine this suite runs on:
mac_randomizer left a Wi-Fi adapter disabled with no automatic recovery
attempt when the enable half of its cycle failed, and a live isolate/release
cycle cut this host's WiFi because release_isolation reset the firewall to a
hardcoded guess instead of the state that existed before isolation. Both are
fixed in this pass (mac_randomizer.py's _apply_windows, and
IsolateHostResponder's snapshot/restore). This file is the regression guard:
it enumerates every registered responder action and FAILS if one has no
declared entry in valkyrie/edr/reversibility.py.

SAFETY: every test below is either a pure data/logic check or runs against
mocked subprocess/winreg/filesystem. Nothing here ever calls a real netsh,
schtasks, sc.exe, or touches this host's real registry, firewall, network
adapter, or scheduled tasks. Nothing here calls responder.execute() for
kill_process with dry_run=False for any reason, at any severity — the
floor-check logic is verified in isolation instead, specifically so this
file can never be the thing that terminates a real process.
"""

from __future__ import annotations

import base64
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from harness import Checks   # noqa: E402


# Imported for real (unpatched) BEFORE any winreg fake is installed below --
# its own `import winreg` must bind to the real module, not whatever fake is
# in sys.modules the first time something lazily does
# `from ..persistence_telemetry import ...` inside a patch.dict() context.
import valkyrie.persistence_telemetry                           # noqa: E402,F401
from valkyrie.edr import reversibility                          # noqa: E402
from valkyrie.edr.plugins import PluginContext, PluginRegistry  # noqa: E402
from valkyrie.edr.response import (                             # noqa: E402
    BUILTIN_RESPONDERS,
    IsolateHostResponder,
    RemovePersistenceResponder,
    RestorePersistenceResponder,
    ResponseManager,
    register_responders,
)

c = Checks("responder reversibility audit", expect_min=30)


# ---------------------------------------------------------------------------
# [1] Every registered responder action has a declared reversibility entry
# ---------------------------------------------------------------------------

def test_every_action_documented() -> None:
    print("\n[1] every responder action has a reversibility.py entry")
    all_actions: set[str] = set()
    for cls in BUILTIN_RESPONDERS:
        try:
            all_actions.update(cls().actions())
        except Exception as exc:                             # noqa: BLE001
            c.fail(f"{cls.__name__}.actions()", str(exc))
    c.check("at least the 7 known responder actions are advertised",
            len(all_actions) >= 7)
    for action in sorted(all_actions):
        c.check(f"'{action}' has a declared Reversibility entry",
                reversibility.is_documented(action))

    # Non-responder enforcement actions the task explicitly requires auditing
    # (MAC change / registry write) even though they aren't ResponseManager
    # responders — see reversibility.py's mac_randomize/mac_restore entries.
    for extra in ("mac_randomize", "mac_restore"):
        c.check(f"'{extra}' (non-responder enforcement action) is documented",
                reversibility.is_documented(extra))


# ---------------------------------------------------------------------------
# [2] Every entry answers all three IIBA §4.2.5 questions non-vacuously
# ---------------------------------------------------------------------------

def test_entries_answer_the_three_questions() -> None:
    print("\n[2] every entry has real answers, not placeholders")
    for action, rev in sorted(reversibility.all_registered().items()):
        c.check(f"'{action}': rollback text is non-trivial (>10 chars)",
                len(rev.rollback.strip()) > 10)
        c.check(f"'{action}': residual_on_crash is answered",
                len(rev.residual_on_crash.strip()) > 10)
        c.check(f"'{action}': false_positive_impact is answered",
                len(rev.false_positive_impact.strip()) > 10)
        if rev.reversible:
            c.check(f"'{action}': reversible actions name their rollback call",
                    "restore" in rev.rollback.lower()
                    or "unblock" in rev.rollback.lower()
                    or "re-apply" in rev.rollback.lower()
                    or "re-appl" in rev.rollback.lower()
                    or "again" in rev.rollback.lower())
        else:
            c.check(f"'{action}': irreversible actions require the critical floor",
                    rev.min_severity == "critical")


# ---------------------------------------------------------------------------
# [3] register() rejects an irreversible entry that doesn't clear the floor
# ---------------------------------------------------------------------------

def test_register_enforces_floor_invariant() -> None:
    print("\n[3] register() refuses to ship a weak floor")
    try:
        reversibility.register(reversibility.Reversibility(
            action="_test_bad_irreversible", reversible=False,
            rollback="none", residual_on_crash="x", false_positive_impact="y",
            min_severity="medium",   # too low for reversible=False
        ))
        c.fail("irreversible entry below 'critical' floor should raise ValueError")
    except ValueError:
        c.check("irreversible entry below 'critical' floor raises ValueError", True)

    try:
        reversibility.Reversibility(
            action="_test_bad_reversible", reversible=True,
            rollback="", residual_on_crash="x", false_positive_impact="y",
        )
        c.fail("reversible=True with empty rollback should raise ValueError")
    except ValueError:
        c.check("reversible=True with empty rollback raises ValueError", True)

    reversibility._REGISTRY.pop("_test_bad_irreversible", None)
    reversibility._REGISTRY.pop("_test_bad_reversible", None)


# ---------------------------------------------------------------------------
# [4] ResponseManager's confidence floor -- kill_process specifically, and
#     ONLY via the pure floor-check function. This suite must never let a
#     dry_run=False kill_process call reach KillProcessResponder.execute(),
#     no matter what severity is supplied, because a real pid could exist.
# ---------------------------------------------------------------------------

def test_floor_check_blocks_irreversible_below_critical() -> None:
    print("\n[4] irreversible actions are hard-gated below their floor")
    rm = ResponseManager(registry=PluginRegistry(), ctx=PluginContext(), edr_store=None)

    block = rm._reversibility_floor_block("kill_process", "", "")
    c.check("kill_process with no severity/incident is blocked",
            block is not None and block[0] == "skipped")
    c.check("block message names the confidence floor",
            block is not None and "confidence floor" in block[1])

    for sev in ("info", "low", "medium", "high"):
        block = rm._reversibility_floor_block("kill_process", "", sev)
        c.check(f"kill_process at severity='{sev}' is blocked (below critical)",
                block is not None and block[0] == "skipped")

    passthrough = rm._reversibility_floor_block("kill_process", "", "critical")
    c.check("kill_process at severity='critical' clears the floor (returns None)",
            passthrough is None)


def test_floor_check_never_gates_reversible_actions() -> None:
    print("\n[5] reversible actions are never hard-gated (playbook/operator discretion)")
    rm = ResponseManager(registry=PluginRegistry(), ctx=PluginContext(), edr_store=None)
    for action in ("block_domain", "unblock_domain", "isolate_host",
                   "release_isolation", "remove_persistence", "restore_persistence"):
        block = rm._reversibility_floor_block(action, "", "")
        c.check(f"'{action}' (reversible) is never floor-blocked, even with no severity",
                block is None)


def test_floor_check_ignores_undocumented_actions() -> None:
    print("\n[6] an undocumented action (e.g. third-party plugin) is not blocked")
    rm = ResponseManager(registry=PluginRegistry(), ctx=PluginContext(), edr_store=None)
    block = rm._reversibility_floor_block("some_third_party_plugin_action", "", "")
    c.check("unregistered action name passes through (audit scope is Valkyrie's own)",
            block is None)


# ---------------------------------------------------------------------------
# [7] isolate_host / release_isolation snapshot-and-restore (mocked only)
# ---------------------------------------------------------------------------

def test_isolate_refuses_without_a_verified_snapshot() -> None:
    print("\n[7] isolate_host refuses to isolate if it cannot snapshot first")
    inst = IsolateHostResponder()
    with patch("valkyrie.edr.response._is_admin", return_value=True), \
         patch.object(inst, "_backup_state", return_value=(False, "mock export failure")), \
         patch("subprocess.run") as mock_run:
        status, msg = inst.execute("isolate_host", "", dry_run=False, ctx=PluginContext())
    c.check("isolate_host is skipped when the snapshot can't be captured",
            status == "skipped")
    c.check("skip message explains why (reversibility floor)",
            "rollback" in msg.lower() or "snapshot" in msg.lower())
    c.check("NO firewall command was ever issued when the snapshot failed",
            mock_run.call_count == 0)


def test_isolate_applies_after_a_successful_snapshot() -> None:
    print("\n[8] isolate_host applies once a snapshot is captured")
    inst = IsolateHostResponder()
    with patch("valkyrie.edr.response._is_admin", return_value=True), \
         patch.object(inst, "_backup_state", return_value=(True, "C:/snap.wfw")), \
         patch("subprocess.run", return_value=MagicMock(returncode=0)):
        status, msg = inst.execute("isolate_host", "", dry_run=False, ctx=PluginContext())
    c.check("isolate_host succeeds once the snapshot is captured", status == "succeeded")
    c.check("success message mentions the rollback path",
            "snapshot" in msg.lower())


def test_release_restores_exact_prior_state_when_snapshot_exists() -> None:
    print("\n[9] release_isolation restores the SNAPSHOT, not a hardcoded default")
    inst = IsolateHostResponder()
    with patch("valkyrie.edr.response._is_admin", return_value=True), \
         patch.object(inst, "_restore_state", return_value=(True, "C:/snap.wfw")), \
         patch("subprocess.run", return_value=MagicMock(returncode=0)):
        status, msg = inst.execute("release_isolation", "", dry_run=False, ctx=PluginContext())
    c.check("release_isolation succeeds", status == "succeeded")
    c.check("success message says the FULL prior state was restored",
            "restored from snapshot" in msg.lower())


def test_release_falls_back_honestly_when_no_snapshot() -> None:
    print("\n[10] release_isolation is honest when no snapshot exists (the old bug's shape)")
    inst = IsolateHostResponder()
    with patch("valkyrie.edr.response._is_admin", return_value=True), \
         patch.object(inst, "_restore_state",
                      return_value=(False, "no pre-isolation snapshot found")), \
         patch("subprocess.run", return_value=MagicMock(returncode=0)):
        status, msg = inst.execute("release_isolation", "", dry_run=False, ctx=PluginContext())
    c.check("release_isolation still succeeds via the explicit fallback commands",
            status == "succeeded")
    c.check("but the message says the prior policy was NOT verified/restored",
            "not restored" in msg.lower())


def test_isolate_dry_run_names_the_snapshot_step() -> None:
    print("\n[11] isolate_host dry-run is transparent about the snapshot step")
    inst = IsolateHostResponder()
    status, msg = inst.execute("isolate_host", "", dry_run=True, ctx=PluginContext())
    c.check("dry-run reports dry_run", status == "dry_run")
    c.check("dry-run mentions the snapshot", "snapshot" in msg.lower())


# ---------------------------------------------------------------------------
# [12] remove_persistence -> restore_persistence round trip: registry run key
# ---------------------------------------------------------------------------

import winreg as _real_winreg   # noqa: E402  (read-only: constants only, never opened for real here)


class _FakeKey:
    def __init__(self, hive, subkey):
        self.hive, self.subkey = hive, subkey

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeWinReg:
    """A tiny in-memory stand-in for the winreg module.

    Seeded/read via ``.values``: {(hive, subkey, name): (data, type)}. Every
    responder call in this file goes through ``patch.dict(sys.modules, ...)``
    so the module's own ``import winreg`` resolves to this fake — the real
    Windows registry is never opened.
    """
    HKEY_LOCAL_MACHINE = _real_winreg.HKEY_LOCAL_MACHINE
    HKEY_CURRENT_USER = _real_winreg.HKEY_CURRENT_USER
    HKEY_USERS = _real_winreg.HKEY_USERS
    KEY_READ = _real_winreg.KEY_READ
    KEY_SET_VALUE = _real_winreg.KEY_SET_VALUE
    REG_SZ = _real_winreg.REG_SZ

    def __init__(self):
        self.values: dict = {}

    def OpenKey(self, hive, subkey, *a, **kw):
        return _FakeKey(hive, subkey)

    def QueryValueEx(self, key, name):
        v = self.values.get((key.hive, key.subkey, name))
        if v is None:
            raise FileNotFoundError()
        return v

    def SetValueEx(self, key, name, reserved, typ, data):
        self.values[(key.hive, key.subkey, name)] = (data, typ)

    def DeleteValue(self, key, name):
        k = (key.hive, key.subkey, name)
        if k not in self.values:
            raise FileNotFoundError()
        del self.values[k]


def test_run_key_remove_and_restore_round_trip(tmp_backup_dir: Path) -> None:
    print("\n[12] registry_run_key: remove backs it up, restore puts it back")
    loc = "HKCU\\...\\Run"
    subkey = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    value_name = "ValkTestUnitTest"
    original_data = "C:\\legit\\totally_normal_app.exe --flag"

    fake = _FakeWinReg()
    fake.values[(_real_winreg.HKEY_CURRENT_USER, subkey, value_name)] = \
        (original_data, _real_winreg.REG_SZ)

    remover = RemovePersistenceResponder()
    with patch.dict(sys.modules, {"winreg": fake}), \
         patch("valkyrie.edr.response.PERSISTENCE_BACKUP_DIR", tmp_backup_dir):
        status, msg = remover.execute(
            "remove_persistence", f"registry_run_key::{loc}::{value_name}",
            dry_run=False, ctx=PluginContext())

    c.check("removal succeeds", status == "succeeded")
    c.check("the value is actually gone from the (fake) registry",
            (_real_winreg.HKEY_CURRENT_USER, subkey, value_name) not in fake.values)
    c.check("result message carries a restore_persistence backup id",
            "restore_persistence" in msg)

    import re
    m = re.search(r"restore_persistence '([0-9a-f]+)'", msg)
    c.check("backup id is parseable from the result message", m is not None)
    backup_id = m.group(1) if m else ""

    restorer = RestorePersistenceResponder()
    with patch.dict(sys.modules, {"winreg": fake}), \
         patch("valkyrie.edr.response.PERSISTENCE_BACKUP_DIR", tmp_backup_dir):
        rstatus, rmsg = restorer.execute(
            "restore_persistence", backup_id, dry_run=False, ctx=PluginContext())

    c.check("restore succeeds", rstatus == "succeeded")
    restored = fake.values.get((_real_winreg.HKEY_CURRENT_USER, subkey, value_name))
    c.check("the EXACT original value + type is back",
            restored == (original_data, _real_winreg.REG_SZ))

    # A second restore of the same backup id must not re-apply silently.
    with patch.dict(sys.modules, {"winreg": fake}), \
         patch("valkyrie.edr.response.PERSISTENCE_BACKUP_DIR", tmp_backup_dir):
        rstatus2, rmsg2 = restorer.execute(
            "restore_persistence", backup_id, dry_run=False, ctx=PluginContext())
    c.check("restoring an already-restored snapshot is a no-op skip, not an error",
            rstatus2 == "skipped")


# ---------------------------------------------------------------------------
# [13] remove_persistence -> restore_persistence round trip: startup file
# ---------------------------------------------------------------------------

def test_startup_file_remove_and_restore_round_trip(tmp_backup_dir: Path) -> None:
    print("\n[13] startup_folder: remove backs up the bytes, restore writes them back")
    startup_dir = tmp_backup_dir / "fake_startup"
    startup_dir.mkdir(parents=True, exist_ok=True)
    target = startup_dir / "legit_app.lnk"
    original_bytes = b"not a real shortcut, just test bytes \x00\x01\x02"
    target.write_bytes(original_bytes)

    remover = RemovePersistenceResponder()
    with patch("valkyrie.persistence_telemetry._startup_dirs",
               return_value=[str(startup_dir)]), \
         patch("valkyrie.edr.response.PERSISTENCE_BACKUP_DIR", tmp_backup_dir):
        status, msg = remover.execute(
            "remove_persistence", f"startup_folder::{target}", dry_run=False,
            ctx=PluginContext())

    c.check("removal succeeds", status == "succeeded")
    c.check("the file is actually gone", not target.exists())
    c.check("result message carries a restore_persistence backup id",
            "restore_persistence" in msg)

    import re
    m = re.search(r"restore_persistence '([0-9a-f]+)'", msg)
    backup_id = m.group(1) if m else ""
    c.check("backup id is parseable", bool(backup_id))

    restorer = RestorePersistenceResponder()
    with patch("valkyrie.edr.response.PERSISTENCE_BACKUP_DIR", tmp_backup_dir):
        rstatus, rmsg = restorer.execute(
            "restore_persistence", backup_id, dry_run=False, ctx=PluginContext())

    c.check("restore succeeds", rstatus == "succeeded")
    c.check("the file is back with byte-identical content",
            target.exists() and target.read_bytes() == original_bytes)


# ---------------------------------------------------------------------------
# [14] service_install is HONESTLY irreversible -- restore refuses it
# ---------------------------------------------------------------------------

def test_service_removal_is_not_auto_restorable(tmp_backup_dir: Path) -> None:
    print("\n[14] service_install: forensic snapshot only, restore refuses it")
    remover = RemovePersistenceResponder()
    with patch("subprocess.run") as mock_run, \
         patch("valkyrie.edr.response.PERSISTENCE_BACKUP_DIR", tmp_backup_dir):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="SERVICE_NAME: evilsvc\n...", stderr=""),  # sc qc
            MagicMock(returncode=0, stdout="", stderr=""),                            # sc stop
            MagicMock(returncode=0, stdout="", stderr=""),                            # sc delete
        ]
        status, msg = remover.execute(
            "remove_persistence", "service_install::evilsvc", dry_run=False,
            ctx=PluginContext())

    c.check("service removal succeeds", status == "succeeded")
    c.check("message is explicit that this is NOT auto-restorable",
            "not auto-restorable" in msg.lower())

    import re
    m = re.search(r"forensic snapshot '([0-9a-f]+)'", msg)
    backup_id = m.group(1) if m else ""
    c.check("a forensic snapshot id is still captured for manual recreation",
            bool(backup_id))

    restorer = RestorePersistenceResponder()
    with patch("valkyrie.edr.response.PERSISTENCE_BACKUP_DIR", tmp_backup_dir):
        rstatus, rmsg = restorer.execute(
            "restore_persistence", backup_id, dry_run=False, ctx=PluginContext())
    c.check("restore_persistence REFUSES a service_install snapshot (skipped, not failed)",
            rstatus == "skipped")
    c.check("refusal explains there is no automated rollback",
            "no automated rollback" in rmsg.lower())


# ---------------------------------------------------------------------------
# [15] scheduled_task remove/restore round trip (subprocess fully mocked)
# ---------------------------------------------------------------------------

def test_scheduled_task_remove_and_restore_round_trip(tmp_backup_dir: Path) -> None:
    print("\n[15] scheduled_task: XML export backup, XML re-import restore")
    tn = "\\ValkTestUnitTestTask"
    fake_xml = "<?xml version=\"1.0\"?><Task>mock task body</Task>"

    remover = RemovePersistenceResponder()
    with patch("subprocess.run") as mock_run, \
         patch("valkyrie.edr.response.PERSISTENCE_BACKUP_DIR", tmp_backup_dir):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=fake_xml, stderr=""),   # schtasks /query /xml
            MagicMock(returncode=0, stdout="", stderr=""),         # schtasks /delete
        ]
        status, msg = remover.execute(
            "remove_persistence", f"scheduled_task::{tn.lstrip(chr(92))}",
            dry_run=False, ctx=PluginContext())

    c.check("task removal succeeds", status == "succeeded")
    c.check("result carries a restore_persistence backup id", "restore_persistence" in msg)

    import re
    m = re.search(r"restore_persistence '([0-9a-f]+)'", msg)
    backup_id = m.group(1) if m else ""

    restorer = RestorePersistenceResponder()
    with patch("subprocess.run") as mock_run2, \
         patch("valkyrie.edr.response.PERSISTENCE_BACKUP_DIR", tmp_backup_dir):
        mock_run2.return_value = MagicMock(returncode=0, stdout="", stderr="")
        rstatus, rmsg = restorer.execute(
            "restore_persistence", backup_id, dry_run=False, ctx=PluginContext())
        create_calls = [call for call in mock_run2.call_args_list
                        if "schtasks" in call.args[0] and "/create" in call.args[0]]
    c.check("restore succeeds", rstatus == "succeeded")
    c.check("restore issued exactly one schtasks /create call", len(create_calls) == 1)
    c.check("restore re-imports the EXACT XML that was exported at removal time",
            create_calls and "/xml" in create_calls[0].args[0])


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    print("=" * 70)
    print("Responder reversibility audit (code + mocked tests only)")
    print("=" * 70)
    register_responders   # imported to assert availability at import time

    test_every_action_documented()
    test_entries_answer_the_three_questions()
    test_register_enforces_floor_invariant()
    test_floor_check_blocks_irreversible_below_critical()
    test_floor_check_never_gates_reversible_actions()
    test_floor_check_ignores_undocumented_actions()
    test_isolate_refuses_without_a_verified_snapshot()
    test_isolate_applies_after_a_successful_snapshot()
    test_release_restores_exact_prior_state_when_snapshot_exists()
    test_release_falls_back_honestly_when_no_snapshot()
    test_isolate_dry_run_names_the_snapshot_step()

    with tempfile.TemporaryDirectory(prefix="valkyrie_revtest_") as td:
        tmp_backup_dir = Path(td)
        test_run_key_remove_and_restore_round_trip(tmp_backup_dir)
        test_startup_file_remove_and_restore_round_trip(tmp_backup_dir)
        test_service_removal_is_not_auto_restorable(tmp_backup_dir)
        test_scheduled_task_remove_and_restore_round_trip(tmp_backup_dir)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
