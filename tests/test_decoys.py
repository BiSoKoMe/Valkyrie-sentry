#!/usr/bin/env python3
"""Decoy honeytoken placement (valkyrie/decoys.py).

Regression for a live VM finding: DecoyManager.target_dirs() used
os.path.expanduser("~"), which resolves to the CALLING PROCESS's own home —
for Valkyrie's shipped default (a Windows service with no configured logon
account, so nssm runs it as LocalSystem), that is
C:\\Windows\\System32\\config\\systemprofile, a folder no real user or intruder
ever browses. A VM re-test confirmed exactly this: Get-ChildItem under the
interactive user's real Desktop/Documents found ZERO decoy files, because they
were being planted somewhere no one would ever look.

The fix enumerates every real user profile under %SystemDrive%\\Users instead,
mirroring persistence_telemetry._startup_dirs's existing, already-correct
pattern for the identical service-vs-interactive-user problem. These tests pin
that enumeration (including the skip-list for non-user profile folders) and
that planted files/tokens are still detected regardless of which directory
they end up in.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.decoys import DecoyManager

_fail = 0


def _check(label, ok):
    global _fail
    if not ok:
        _fail += 1
    print(f"  [{'ok  ' if ok else 'FAIL'}] {label}")


def main() -> int:
    print("=" * 60)
    print("Decoy honeytoken placement")
    print("=" * 60)

    print("[1] target_dirs() enumerates real users under %SystemDrive%\\Users, "
          "not the calling process's own home")
    tmp = Path(tempfile.mkdtemp(prefix="valkyrie_decoy_test_"))
    users_root = tmp / "Users"
    for name in ("alice", "bob", "Public", "Default", "All Users", "defaultuser0"):
        (users_root / name).mkdir(parents=True, exist_ok=True)

    orig_sysdrive = os.environ.get("SystemDrive")
    # target_dirs() computes Path(SystemDrive + "\\") / "Users" — point it at our
    # fake root (strip the trailing "\Users" tempfile already gave us).
    os.environ["SystemDrive"] = str(tmp)
    try:
        mgr = DecoyManager(manifest_path=tmp / "decoys.json")
        dirs = mgr.target_dirs()
        dir_strs = [str(d) for d in dirs]

        _check("alice's Desktop is a target",
               any(str(users_root / "alice" / "Desktop") == d for d in dir_strs))
        _check("alice's Documents is a target",
               any(str(users_root / "alice" / "Documents") == d for d in dir_strs))
        _check("bob's Desktop is a target",
               any(str(users_root / "bob" / "Desktop") == d for d in dir_strs))
        _check("Public is skipped (not a real user)",
               not any("Public" in d for d in dir_strs))
        _check("Default is skipped",
               not any(str(users_root / "Default") in d for d in dir_strs))
        _check("All Users is skipped",
               not any("All Users" in d for d in dir_strs))
        _check("defaultuser0 is skipped",
               not any("defaultuser0" in d for d in dir_strs))
        _check(f"exactly 2 real users x 3 subdirs = 6 target dirs (got {len(dirs)})",
               len(dirs) == 6)

        print("\n[2] deploy() actually plants files at the enumerated targets")
        n = mgr.deploy()
        # 5 templates x 6 target dirs (2 users x {Desktop, Documents, Documents/Private})
        _check(f"deploy() planted files (5 templates x 6 dirs = 30, got {n})",
               n == 30)
        _check("a file exists under alice's Desktop",
               (users_root / "alice" / "Desktop" / "passwords.txt").exists())
        _check("a file exists under bob's Documents",
               (users_root / "bob" / "Documents" / "id_rsa").exists())

        print("\n[3] detection is directory-independent (token/path substring match)")
        tok = next(iter(mgr.tokens()))
        _check("a command line referencing a planted token is detected",
               mgr.references_decoy(f"type C:\\Users\\alice\\Desktop\\passwords.txt # {tok}") == tok)
        _check("unrelated text is not a hit",
               mgr.references_decoy("notepad.exe C:\\Users\\alice\\Desktop\\notes.txt") is None)
    finally:
        if orig_sysdrive is None:
            os.environ.pop("SystemDrive", None)
        else:
            os.environ["SystemDrive"] = orig_sysdrive

    print("\n[4] fallback: no %SystemDrive%\\Users at all → falls back to "
          "the calling process's own home (non-Windows dev run)")
    tmp2 = Path(tempfile.mkdtemp(prefix="valkyrie_decoy_test2_"))
    os.environ["SystemDrive"] = str(tmp2 / "does_not_exist_as_a_drive_letter")
    try:
        mgr2 = DecoyManager(manifest_path=tmp2 / "decoys.json")
        dirs2 = mgr2.target_dirs()
        home = Path(os.path.expanduser("~"))
        _check("falls back to expanduser('~') when no Users folder is found",
               any(str(home / "Desktop") == str(d) for d in dirs2))
    finally:
        if orig_sysdrive is None:
            os.environ.pop("SystemDrive", None)
        else:
            os.environ["SystemDrive"] = orig_sysdrive

    print("-" * 60)
    if _fail:
        print(f"{_fail} check(s) FAILED.")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
