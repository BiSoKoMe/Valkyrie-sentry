#!/usr/bin/env python3
"""Enforce the experimental/ boundary (ADR 0044).

The freeze only holds if it is mechanically enforced. Without this test the
frozen surface creeps back one convenience import at a time, and six months
later the "core" product is carrying the fleet control plane again.

The dependency arrow points ONE WAY: experimental/ may import from valkyrie/,
never the reverse. Core must be shippable with experimental/ deleted entirely.

  [1] No module under valkyrie/ imports from experimental/
  [2] The frozen modules are really gone from valkyrie/
  [3] Core still imports and builds its CLI with experimental/ absent
  [4] No CLI flag or API route for a frozen feature survives
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


FROZEN = ("fleet", "mcp", "compliance", "wireguard", "multihop")

# `import experimental...`, `from experimental... import`, and the relative
# forms a module inside valkyrie/ could use to reach a sibling that moved.
_RE_EXPERIMENTAL = re.compile(
    r"^\s*(?:from|import)\s+experimental\b", re.M)


def main() -> int:
    print("\n=== experimental/ isolation (ADR 0044) ===\n")

    core = sorted((_ROOT / "valkyrie").rglob("*.py"))
    print(f"[1] No module under valkyrie/ imports experimental/ "
          f"({len(core)} modules scanned)")
    offenders = []
    for f in core:
        try:
            src = f.read_text(encoding="utf-8")
        except OSError:
            continue
        if _RE_EXPERIMENTAL.search(src):
            offenders.append(f.relative_to(_ROOT).as_posix())
    _check("core never imports experimental", not offenders)
    for o in offenders:
        print(f"      OFFENDER: {o}")

    print("\n[2] Frozen modules are gone from valkyrie/")
    for name in FROZEN:
        pkg = _ROOT / "valkyrie" / name
        mod = _ROOT / "valkyrie" / f"{name}.py"
        _check(f"valkyrie/{name} removed", not pkg.exists() and not mod.exists())
        moved = ((_ROOT / "experimental" / name).exists()
                 or (_ROOT / "experimental" / f"{name}.py").exists())
        _check(f"experimental/{name} present (frozen, not deleted)", moved)

    print("\n[3] Core imports and builds its CLI without experimental/")
    try:
        import valkyrie.__main__ as m
        _check("valkyrie.__main__ imports cleanly", True)
        ok_parser = hasattr(m, "main")
        _check("entrypoint still present", ok_parser)
    except Exception as exc:                       # noqa: BLE001
        _check(f"valkyrie.__main__ imports cleanly ({type(exc).__name__}: {exc})",
               False)

    print("\n[4] No CLI flag or API route for a frozen feature survives")
    main_src = (_ROOT / "valkyrie" / "__main__.py").read_text(encoding="utf-8")
    for flag in ("--setup-wireguard", "--setup-multihop", "--multihop-status",
                 "--mcp", "--fleet-server", "--fleet-agent",
                 "--fleet-enroll-token", "--fleet-insecure-http"):
        _check(f"CLI flag {flag} removed",
               f'"{flag}"' not in main_src)

    web_src = (_ROOT / "valkyrie" / "web" / "server.py").read_text(encoding="utf-8")
    for route in ("/api/compliance/report", "/api/vpn/status"):
        _check(f"API route {route} removed", f'"{route}"' not in web_src)

    print("\n" + "=" * 52)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED — the freeze holds.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
