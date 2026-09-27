#!/usr/bin/env python3
"""ACL hardening on %ProgramData%\\Valkyrie (installer/payload/service-install.ps1).

Windows' own default ACL on %ProgramData% grants BUILTIN\\Users write access on
new subfolders - that is the folder's documented purpose, historically, for
per-machine shared app data. Left inherited, that means the SYSTEM-privileged
ValkyrieShield service reads its own detection policy (playbooks.yaml, the
rules file, the control token the desktop app authenticates with) from a
directory ANY standard-user account or process on the machine can write into.
No admin rights needed to disable enforcement, plant an exclusion for a
specific binary, or read the control token and drive the loopback API's
mutation endpoints directly - the exact HTTP-layer version of this gap is
docs/ENGINEERING_ROADMAP_2026-09-05.md's #1 release blocker (SEC-01).

These checks run the SAME icacls invocation the installer script uses, against
a throwaway temp directory - never the real %ProgramData%\\Valkyrie - and
assert on the resulting ACL via Get-Acl, not on icacls's exit code alone.

  [1] the script still contains the hardening step (regex on source)
  [2] running it strips BUILTIN\\Users down to Read+Execute, no write
  [3] SYSTEM and Administrators keep FullControl (the service must still work)
  [4] a failed icacls call must not abort the installer (ErrorActionPreference)
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks, skip_file

SCRIPT = Path(__file__).resolve().parent.parent / "installer" / "payload" / "service-install.ps1"


def _icacls(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["icacls.exe", *args], capture_output=True, text=True, timeout=20)


def main() -> int:
    if sys.platform != "win32":
        return skip_file("service-install ACL hardening",
                          "icacls/Get-Acl are Windows-only")

    c = Checks("service-install.ps1 data-directory ACL hardening", expect_min=6)

    print("[1] the hardening step is present in the installer script")
    src = SCRIPT.read_text(encoding="utf-8")
    c.check("service-install.ps1 exists", SCRIPT.is_file())
    c.check("removes inherited ACLs before granting (icacls /inheritance:r)",
            "/inheritance:r" in src)
    c.check("grants Users Read+Execute only, not write",
            bool(re.search(r"Users:\(OI\)\(CI\)\(RX\)", src)))
    c.check("grants SYSTEM and Administrators FullControl",
            "SYSTEM:(OI)(CI)F" in src and "Administrators:(OI)(CI)F" in src)
    # Scoped to just the hardening block (its own Write-Host banner through the
    # closing brace of its warning), not the whole rest of the file - a later,
    # unrelated "exit 1" (missing nssm.exe/valkyrie.exe) is legitimate and must
    # not make this check false-fail.
    block_match = re.search(
        r"Restricting write access.*?\n\}\n", src, re.DOTALL)
    c.check("the hardening block itself is present and self-contained",
            block_match is not None)
    # A real `exit <digit>` statement, not the word "exit" in the warning's
    # own prose ("... (exit $LASTEXITCODE) ...") or in $LASTEXITCODE itself.
    aborts = bool(block_match) and re.search(r"(?<![\w$])exit\s+\d",
                                             block_match.group(0))
    c.check("a failed hardening step logs a warning instead of aborting install",
            bool(block_match) and not aborts
            and "WARNING" in block_match.group(0))

    print("\n[2] running it against a throwaway directory actually removes "
          "the write grant (never touches the real data directory)")
    with tempfile.TemporaryDirectory(prefix="vlk-acl-test-") as td:
        target = Path(td) / "Valkyrie"
        target.mkdir()

        before = _icacls(str(target))
        c.check("icacls can read the pre-hardening ACL",
                before.returncode == 0)

        r1 = _icacls(str(target), "/inheritance:r")
        c.check("icacls /inheritance:r succeeds", r1.returncode == 0)
        r2 = _icacls(str(target), "/grant:r", "SYSTEM:(OI)(CI)F",
                     "Administrators:(OI)(CI)F", "Users:(OI)(CI)(RX)", "/T", "/C")
        c.check("icacls /grant:r succeeds", r2.returncode == 0)

        after = _icacls(str(target)).stdout
        # icacls text output: "BUILTIN\Users:(OI)(CI)(RX)" style lines. A
        # write-capable grant carries a bare W, M, or F flag inside the
        # parens - check the exact resulting ACL rather than trusting icacls's
        # exit code, which is 0 even for a wrong grant.
        users_lines = [ln for ln in after.splitlines() if "Users" in ln]
        c.check("Users appears in the resulting ACL at all",
                bool(users_lines))
        write_capable = re.compile(r"\([^)]*\b[WMF]\b[^)]*\)")
        users_can_write = any(write_capable.search(ln) for ln in users_lines)
        c.check("BUILTIN\\Users can no longer write, modify, or fully control it",
                not users_can_write)

        print("\n[3] SYSTEM and Administrators still have full control "
              "(the service must keep working after this)")
        c.check("SYSTEM keeps FullControl",
                any("SYSTEM" in ln and "(F)" in ln for ln in after.splitlines()))
        c.check("Administrators keep FullControl",
                any("Administrators" in ln and "(F)" in ln
                    for ln in after.splitlines()))

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
