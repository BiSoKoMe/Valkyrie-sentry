#!/usr/bin/env python3
"""No .ps1 may be UTF-8 without a BOM while containing non-ASCII characters.

That combination does not merely look untidy - it stops the script running.
Windows PowerShell 5.1 (the shipping product's shell: NSSM, the installer,
build_app.ps1, update_install.ps1) reads a .ps1 with no byte-order mark using
the machine's ANSI codepage, not UTF-8. On a Western install that is CP1252,
where an em-dash's UTF-8 bytes ``E2 80 94`` decode as three separate
characters ending in ``0x94`` = U+201D, a RIGHT DOUBLE QUOTATION MARK. And
PowerShell accepts curly quotes as string delimiters.

So one em-dash inside a string silently opens a string that never closes.
Everything after it is mis-parsed, and the script dies at load with an error
pointing somewhere else entirely - the real failure looked like:

    install_sentry.ps1
      L183  Missing closing '}' in statement block or type definition.
      L198  The string is missing the terminator: ".

Neither line had anything wrong with it. The actual cause was an em-dash on
L184, inside ``"[WARN] Web UI not responding on port $WebPort - may still be
starting"``. Two scripts in this repo were broken this way and nobody noticed,
because the machine that wrote them read them back as UTF-8 and they parsed
fine there.

This tests the INVARIANT, not the two files: any future script that picks up a
smart quote from a doc, an arrow from a diagram, or a section sign from a
checklist inherits exactly the same defect. ASCII-only is the simplest rule
that cannot break, and it is what every .ps1 here already satisfies. A BOM is
accepted as the alternative fix for a script that genuinely needs non-ASCII.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks, skip_file  # noqa: E402

_UTF8_BOM = b"\xef\xbb\xbf"
_SKIP_DIRS = {"node_modules", "dist_installer", "dist", ".git", "graphify-out"}

# Characters CP1252 turns into something PowerShell parses as a delimiter.
# Not exhaustive; the ASCII rule below is the real guard.
_QUOTE_LIKE = "\u201c\u201d\u2018\u2019"


def _scripts() -> list[Path]:
    return [p for p in _ROOT.rglob("*.ps1")
            if not any(part in _SKIP_DIRS for part in p.parts)]


def main() -> int:
    scripts = _scripts()
    if not scripts:
        return skip_file("powershell encoding", "no .ps1 files found")

    c = Checks("PowerShell scripts must survive an ANSI-codepage read",
               expect_min=2)
    c.check(f"found .ps1 files to inspect ({len(scripts)})", len(scripts) >= 5)

    offenders = []
    for p in scripts:
        raw = p.read_bytes()
        if raw.startswith(_UTF8_BOM):
            continue                      # BOM present: PowerShell reads UTF-8
        non_ascii = [b for b in raw if b > 127]
        if non_ascii:
            text = raw.decode("utf-8", errors="replace")
            chars = sorted({ch for ch in text if ord(ch) > 127})
            offenders.append(
                f"{p.relative_to(_ROOT)} "
                f"({len(non_ascii)} bytes: "
                + " ".join(f"U+{ord(ch):04X}" for ch in chars[:6]) + ")"
            )

    c.check(
        "no BOM-less .ps1 contains non-ASCII (such a file is re-read as "
        "CP1252 and its em-dashes become string delimiters) -- offenders: "
        + ("; ".join(offenders) if offenders else "none"),
        not offenders,
    )

    # Stronger, platform-gated: ask the real parser. Catches anything the
    # byte-level rule above would miss, and proves the rule is sufficient.
    if sys.platform == "win32":
        ps = (Path(__import__("os").environ.get("SystemRoot", r"C:\Windows"))
              / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")
        if ps.exists():
            bad = []
            for p in scripts:
                script = (
                    "$e=$null;$t=$null;"
                    "[System.Management.Automation.Language.Parser]::ParseFile("
                    f"'{p}',[ref]$t,[ref]$e)|Out-Null;"
                    "if($e -and $e.Count){exit 1}else{exit 0}"
                )
                try:
                    r = subprocess.run([str(ps), "-NoProfile", "-Command", script],
                                       capture_output=True, timeout=60)
                    if r.returncode != 0:
                        bad.append(str(p.relative_to(_ROOT)))
                except (OSError, subprocess.TimeoutExpired):
                    break
            else:
                c.check(
                    f"every .ps1 parses with the real PowerShell parser "
                    f"-- failing: {', '.join(bad) if bad else 'none'}",
                    not bad,
                )

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
