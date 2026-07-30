"""Tier 3.17 — telemetry_killer's logic, verified without Administrator.

`test_telemetry.py` needs elevation and skips without it, which left this
module at 21% and — until tier 0 — made that skip look like a passing test. The
whole "randomizer" pillar was effectively unverified on every unelevated
machine, which is most of them, including CI.

The fix is not to demand elevation. It is to notice that most of what can be
wrong here needs no registry access at all:

  * the SPEC — which keys are touched, what they are set to, and that the
    "killed" values are actually the privacy-preserving ones. A typo here
    silently disables the wrong setting, or worse, enables telemetry while
    reporting success. No elevation needed to check it.
  * the BACKUP round-trip — restore() can only work if the backup written by
    kill() reloads exactly. A backup that silently fails to parse means the
    machine can never be put back, and the user has permanently altered system
    settings on the promise that it was reversible.
  * the DEGRADATION contract — the module docstring promises scan/kill/restore
    "degrade gracefully (return {} / all-False) when not elevated rather than
    raising". That is precisely what an unelevated test can verify.

Nothing here writes to the registry or touches a service. The paths that do
belong to the VM pass (TEST_PLAN tier 4).
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks
import valkyrie.telemetry_killer as tk


def main() -> int:
    c = Checks("telemetry killer (pure)", expect_min=22)
    print(f"winreg available: {tk._WINREG_OK}   admin: {tk.is_admin()}\n")

    # ── 1. Degradation contract — the documented promise, unelevated ────────
    print("[1] degrades gracefully without elevation (the documented contract)")
    with tempfile.TemporaryDirectory() as td:
        killer = tk.TelemetryKiller(backup_path=Path(td) / "backup.json")
        if tk.is_admin():
            c.check("running elevated — degradation path not exercised here",
                    True)
        else:
            try:
                s = killer.scan()
                c.check("scan() returns {} rather than raising", s == {})
            except Exception as exc:                   # noqa: BLE001
                c.check(f"scan() returns {{}} rather than raising ({exc})", False)
            # kill()/restore() are safe to CALL unelevated precisely because
            # they must refuse; that refusal is the thing being tested.
            try:
                k = killer.kill()
                c.check("kill() refuses unelevated, returning {}", k == {})
            except Exception as exc:                   # noqa: BLE001
                c.check(f"kill() refuses unelevated ({exc})", False)
            try:
                r = killer.restore()
                c.check("restore() refuses unelevated, returning {}", r == {})
            except Exception as exc:                   # noqa: BLE001
                c.check(f"restore() refuses unelevated ({exc})", False)
            c.check("a refused kill() writes no backup file",
                    not (Path(td) / "backup.json").exists())

    # ── 2. The spec is well-formed and privacy-correct ──────────────────────
    print("\n[2] the settings spec")
    spec = tk._spec()
    if not tk._WINREG_OK:
        c.check("no winreg on this platform, so the spec is empty by design",
                spec == {})
        c.check("_spec() returns a dict even without winreg", isinstance(spec, dict))
    else:
        c.check(f"the spec is non-empty ({len(spec)} settings)", len(spec) > 0)
        malformed = [k for k, v in spec.items() if not isinstance(v, tuple)
                     or len(v) != 5]
        c.check(f"every entry is a 5-tuple ({malformed[:3] or 'clean'})",
                not malformed)
        bad_key = [k for k, (_h, sub, _n, _t, _v) in spec.items()
                   if not sub or not isinstance(sub, str)]
        c.check(f"every entry names a registry subkey ({bad_key[:3] or 'clean'})",
                not bad_key)
        bad_name = [k for k, (_h, _s, name, _t, _v) in spec.items()
                    if not name or not isinstance(name, str)]
        c.check(f"every entry names a value ({bad_name[:3] or 'clean'})",
                not bad_name)
        # Keys are never deleted, only values — assert no subkey is a bare hive
        # root, which would be a catastrophic edit.
        rooty = [k for k, (_h, sub, _n, _t, _v) in spec.items()
                 if sub.strip("\\").count("\\") < 1]
        c.check(f"no entry targets a hive root ({rooty[:3] or 'clean'})", not rooty)

        # The privacy assertions: these specific values must be the
        # telemetry-OFF ones. Getting one inverted would disable the wrong
        # thing while reporting success.
        def killed(name):
            return spec[name][4] if name in spec else None

        c.check("AllowTelemetry is killed to 0 (off), not 1",
                killed("telemetry_level") == 0)
        c.check("advertising ID is killed to 0 (disabled)",
                killed("advertising_id") == 0)
        c.check("activity feed is killed to 0", killed("activity_feed") == 0)
        c.check("location consent is killed to 'Deny'",
                killed("location_consent") == "Deny")
        c.check("Cortana is killed to 0", killed("cortana") == 0)
        c.check("web search is killed to 1 (DisableWebSearch=1 means disabled)",
                killed("cortana_web_search") == 1)
        c.check("error reporting is killed to 1 (Disabled=1)",
                killed("error_reporting") == 1)
        c.check("Defender SpyNet reporting is killed to 0",
                killed("defender_spynet_reporting") == 0)
        # Sample submission 2 == "never send" in Microsoft's scheme; 1 would be
        # "send safe samples", i.e. still uploading.
        c.check("Defender sample submission is 2 (never send), not 1",
                killed("defender_sample_submission") == 2)

        # Settings sharing a subkey must not disagree about the hive.
        by_key: dict[str, set] = {}
        for _k, (hive, sub, _n, _t, _v) in spec.items():
            by_key.setdefault(sub, set()).add(hive)
        conflict = [s for s, hives in by_key.items() if len(hives) > 1]
        c.check(f"no subkey is claimed under two hives ({conflict[:2] or 'clean'})",
                not conflict)

    # ── 3. Backup round-trip — restore() is only as good as this ────────────
    print("\n[3] backup round-trip (restore depends entirely on it)")
    with tempfile.TemporaryDirectory() as td:
        bpath = Path(td) / "nested" / "backup.json"
        killer = tk.TelemetryKiller(backup_path=bpath)
        sample = {
            "telemetry_level": {"existed": True, "value": 1, "type": 4},
            "advertising_id": {"existed": False, "value": None, "type": None},
            "service_DiagTrack": {"existed": True, "value": "AUTO_START"},
        }
        killer._save_backup(sample)
        c.check("saving creates the file, making parent dirs as needed",
                bpath.exists())
        c.check("the backup round-trips exactly", killer._load_backup() == sample)
        c.check("the backup is valid JSON on disk",
                json.loads(bpath.read_text(encoding="utf-8")) == sample)
        # The distinction restore() depends on: a value that did not exist
        # before must be REMOVED on restore, not written as some default. If
        # this flag does not survive the round-trip, restore leaves debris.
        reloaded = killer._load_backup()
        c.check("the 'did not exist beforehand' flag survives the round-trip",
                reloaded["advertising_id"]["existed"] is False)
        c.check("a pre-existing value's original data survives",
                reloaded["telemetry_level"]["value"] == 1)

        # Corruption must degrade to None, never raise: restore() runs when the
        # user is trying to undo changes, and an exception there strands the
        # machine in the modified state.
        bpath.write_text("{ this is not json", encoding="utf-8")
        c.check("a corrupt backup loads as None rather than raising",
                killer._load_backup() is None)
        bpath.write_text("", encoding="utf-8")
        c.check("an empty backup loads as None", killer._load_backup() is None)
        bpath.unlink()
        c.check("a missing backup loads as None", killer._load_backup() is None)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
