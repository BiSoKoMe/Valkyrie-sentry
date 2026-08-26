"""Tests for telemetry_killer's backup/restore lifecycle.

`test_telemetry.py` requires Administrator and skips entirely without it -
which, on any dev machine or CI runner, is always. So the module that edits
a user's Windows privacy settings had effectively no coverage of the one
property that matters most: **can the user get their settings back?**

This file tests that lifecycle against a simulated registry, so it runs
anywhere, with no elevation and without touching a single real key.

The bug it was written around (found 2026-07-30, verified not assumed):
`kill()` rebuilt the backup from whatever the registry held at that moment
and wrote it unconditionally. A SECOND kill therefore read back the values
the first kill had written and recorded THOSE as the "originals",
permanently destroying the user's real settings. `restore()` then reported
success while handing back the killed values. Reachable with two clicks of
the Privacy page's "Kill Telemetry" button.

For a privacy tool, silently making a system change irreversible is close to
the worst non-security failure available - the user trusted it to be undoable.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks, skip_file
import valkyrie.telemetry_killer as tk


class _FakeRegistry:
    """A registry that records writes, so restore can be checked exactly."""

    def __init__(self, initial: dict):
        self.values = dict(initial)
        self.services = {}
        self.deleted = []

    def install(self):
        tk._read_value = lambda h, sk, n: self.values.get((h, sk, n))
        tk._write_value = self._write
        tk._delete_value = self._delete
        tk._is_admin = lambda: True
        tk._service_start_mode = lambda s: self.services.get(s, "AUTO_START")
        tk._set_service_start = self._set_service

    def _write(self, h, sk, n, vtype, value):
        self.values[(h, sk, n)] = value
        return True

    def _delete(self, h, sk, n):
        self.deleted.append((h, sk, n))
        self.values.pop((h, sk, n), None)
        return True

    def _set_service(self, service, disabled):
        self.services[service] = "DISABLED" if disabled else "AUTO_START"
        return True


def main() -> int:
    if not tk._WINREG_OK:
        return skip_file("telemetry restore",
                         "winreg unavailable (non-Windows host)")

    c = Checks("telemetry restore", expect_min=12)
    spec = tk._spec()
    orig_fns = (tk._read_value, tk._write_value, tk._delete_value,
                tk._is_admin, tk._service_start_mode, tk._set_service_start)

    try:
        # The user's real settings before Valkyrie ever ran. Deliberately NOT
        # the values kill() writes, so a restore-to-killed-value is detectable.
        h, sk, vn, vt, killed = spec["telemetry_level"]
        h2, sk2, vn2, vt2, killed2 = spec["advertising_id"]
        pristine = {(h, sk, vn): 3, (h2, sk2, vn2): 1}

        # --- One kill, one restore: the basic contract ---
        print("\n[1] a single kill/restore round-trip returns the originals")
        with tempfile.TemporaryDirectory() as td:
            reg = _FakeRegistry(pristine); reg.install()
            k = tk.TelemetryKiller(backup_path=Path(td) / "b.json")
            k.kill()
            c.check("kill() actually changed the setting",
                    reg.values[(h, sk, vn)] == killed)
            c.check("kill() recorded the TRUE original in the backup",
                    (k._load_backup() or {})["registry"]["telemetry_level"]["original"] == 3)
            k.restore()
            c.check("restore() puts the original value back",
                    reg.values[(h, sk, vn)] == 3)
            c.check("restore() also restores a second setting",
                    reg.values[(h2, sk2, vn2)] == 1)

        # --- REGRESSION: a second kill must not destroy the originals ---
        print("\n[2] REGRESSION: kill() twice must not eat the real settings")
        with tempfile.TemporaryDirectory() as td:
            reg = _FakeRegistry(pristine); reg.install()
            bp = Path(td) / "b.json"
            tk.TelemetryKiller(backup_path=bp).kill()
            tk.TelemetryKiller(backup_path=bp).kill()          # the killer case
            k2 = tk.TelemetryKiller(backup_path=bp)
            recorded = (k2._load_backup() or {})["registry"]["telemetry_level"]["original"]
            c.check(f"after TWO kills the backup still says 3, not {killed} "
                    f"(got {recorded})", recorded == 3)
            k2.restore()
            c.check("restore() after two kills still returns the TRUE original",
                    reg.values[(h, sk, vn)] == 3)

        # --- Three kills, for good measure ---
        print("\n[3] repeated kills stay safe")
        with tempfile.TemporaryDirectory() as td:
            reg = _FakeRegistry(pristine); reg.install()
            bp = Path(td) / "b.json"
            for _ in range(3):
                tk.TelemetryKiller(backup_path=bp).kill()
            tk.TelemetryKiller(backup_path=bp).restore()
            c.check("three kills then restore still yields the original",
                    reg.values[(h, sk, vn)] == 3)

        # --- A setting that did NOT exist must be deleted, not invented ---
        print("\n[4] a setting absent beforehand is removed, not set to a value")
        with tempfile.TemporaryDirectory() as td:
            reg = _FakeRegistry({})            # nothing pre-existing at all
            reg.install()
            bp = Path(td) / "b.json"
            k = tk.TelemetryKiller(backup_path=bp)
            k.kill()
            c.check("kill() created the value", (h, sk, vn) in reg.values)
            k.restore()
            c.check("restore() DELETED it rather than leaving a value behind",
                    (h, sk, vn) not in reg.values)
            c.check("the deletion was recorded against the right key",
                    (h, sk, vn) in reg.deleted)

        # --- Backup lifecycle ---
        print("\n[5] the backup is cleared only after a full restore")
        with tempfile.TemporaryDirectory() as td:
            reg = _FakeRegistry(pristine); reg.install()
            bp = Path(td) / "b.json"
            k = tk.TelemetryKiller(backup_path=bp)
            k.kill()
            c.check("a backup exists after kill()", bp.exists())
            k.restore()
            c.check("the backup is cleared after a successful restore "
                    "(so a later kill records fresh originals)", not bp.exists())

        # --- Restore with no backup must be a no-op, not a crash ---
        print("\n[6] restore() with no backup is a safe no-op")
        with tempfile.TemporaryDirectory() as td:
            reg = _FakeRegistry(pristine); reg.install()
            k = tk.TelemetryKiller(backup_path=Path(td) / "missing.json")
            res = k.restore()
            c.check("restore() with no backup returns {} and changes nothing",
                    res == {} and reg.values[(h, sk, vn)] == 3)

    finally:
        (tk._read_value, tk._write_value, tk._delete_value, tk._is_admin,
         tk._service_start_mode, tk._set_service_start) = orig_fns

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
