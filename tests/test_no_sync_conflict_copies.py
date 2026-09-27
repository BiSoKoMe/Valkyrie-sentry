#!/usr/bin/env python3
"""No cloud-sync conflict copy may sit in the working tree.

This repository lives inside a OneDrive-synced folder. When OneDrive cannot
reconcile two versions of a file it does not merge them and it does not warn:
it silently writes a second file beside the original, named
``<stem>-<COMPUTERNAME><ext>`` -- and because that name is untracked, git says
nothing either. The result is a fork of the working tree that is invisible to
every tool the project relies on.

That is not hypothetical. On 2026-09-23 nine such copies were found here, one
of them three weeks NEWER than its tracked counterpart, and between them they
held:

  * ``valkyrie/etw/sysmon.py`` -- the SignatureStatus wiring that makes every
    ``Rule.signed`` rule reachable from the real-time Sysmon path (without it
    those rules could only fire through the ~2s poller),
  * ``tests/test_experimental_isolation.py`` -- the zombie-caller check, which
    on recovery immediately caught two frozen API routes the UI was still
    polling (every poll a guaranteed 404),
  * ``tests/test_powershell_encoding.py`` -- the dot-directory skip.

All of it was real work that had been done, lost, and was silently absent from
the product for weeks.

The fix for the ROOT cause is to stop hosting a git working tree inside a
sync-on-write cloud folder. Until that happens, this test is the tripwire: it
fails loudly the moment a conflict copy appears, so the fork is caught while
the two versions are still reconcilable.

Deliberately NOT solved with a .gitignore rule. Ignoring these files would make
them invisible to `git status` as well, which is precisely the failure mode
that let them accumulate unnoticed in the first place.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks                                        # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent

_SKIP_DIRS = {"node_modules", "dist", "dist_installer", ".git", "graphify-out",
              "build", "__pycache__", ".venv", "venv", "brag-output"}

# Source we actually care about forking. A conflict copy of a .png is a
# nuisance; a conflict copy of a .py is a silently divergent program.
_SOURCE_SUFFIXES = {".py", ".js", ".ts", ".tsx", ".css", ".html", ".ps1",
                    ".json", ".md", ".bat", ".yml", ".yaml", ".c", ".h"}

# OneDrive's conflict suffix is the machine name: "-LAPTOP-56ETIOCV",
# "-DESKTOP-ABC1234". Upper-case alphanumerics and hyphens, at least 5 chars,
# so ordinary hyphenated names ("test-utils", "vm-lab") cannot match.
#
# Matched against a CANDIDATE SUFFIX, never against the whole stem with a
# greedy prefix: a machine name usually contains its own hyphen, so
# "sysmon-LAPTOP-56ETIOCV" greedily splits to base="sysmon-LAPTOP" +
# host="56ETIOCV", looks for a nonexistent "sysmon-LAPTOP.py", and finds
# nothing. Every split point has to be tried instead.
_HOST_RE = re.compile(r"^[A-Z0-9][A-Z0-9-]{4,}$")


def _candidates() -> list[Path]:
    out = []
    for p in _ROOT.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in _SOURCE_SUFFIXES:
            continue
        rel = p.relative_to(_ROOT)
        if any(part in _SKIP_DIRS or part.startswith(".") for part in rel.parts):
            continue
        out.append(p)
    return out


def _conflict_copies() -> list[tuple[Path, Path]]:
    """Return (conflict_copy, original) pairs.

    The sibling check is what makes this precise: a file only counts as a
    conflict copy when the SAME directory also holds the un-suffixed original.
    A legitimately-named file has no such twin, so this cannot fire on one.
    """
    found = []
    for p in _candidates():
        stem = p.stem
        # Try every hyphen as the split point, longest suffix first, so
        # "-LAPTOP-56ETIOCV" is considered before "-56ETIOCV".
        for i, ch in enumerate(stem):
            if ch != "-" or i == 0:
                continue
            base, host = stem[:i], stem[i + 1:]
            if not _HOST_RE.match(host):
                continue
            original = p.with_name(base + p.suffix)
            if original.exists():
                found.append((p, original))
                break
    return found


def main() -> int:
    c = Checks("No cloud-sync conflict copy in the working tree", expect_min=2)

    files = _candidates()
    c.check(f"found source files to inspect ({len(files)})", len(files) > 50)

    pairs = _conflict_copies()
    if pairs:
        listing = ", ".join(str(p.relative_to(_ROOT)) for p, _ in pairs)
        c.check(f"no sync conflict copies present -- found {len(pairs)}: "
                f"{listing}", False)
        print("\n  A cloud-sync fork is present. Do NOT delete these blindly:")
        print("  diff each against its original first -- the conflict copy has")
        print("  previously been the NEWER of the two, holding work that never")
        print("  reached the tracked file.\n")
        for conflict, original in pairs:
            print(f"    {conflict.relative_to(_ROOT)}")
            print(f"      vs {original.relative_to(_ROOT)}")
    else:
        c.check("no sync conflict copies present", True)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
