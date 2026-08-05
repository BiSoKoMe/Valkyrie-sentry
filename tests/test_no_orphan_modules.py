#!/usr/bin/env python3
"""Every valkyrie/*.py module must have at least one real (non-test) importer.

Why this exists: a module with zero product-code importers is either dead
code nobody noticed yet, or a capability that was half-wired and forgotten
-- both are exactly the kind of thing that hides in a codebase this size
until someone goes looking (see valkyrie/updater.py below, found by hand
during ADR 0048 Part 2's live-execution work and confirmed here). A
repo-wide AST import scan makes "is anything actually calling this?" a
question this suite answers on every run, not a one-off investigation.

METHOD. Parses every .py file in the repo with `ast` (no execution, no
sandboxing needed) and resolves every Import/ImportFrom node -- absolute
(`import valkyrie.x`, `from valkyrie.x import y`) and relative
(`from . import x`, `from .x import y`, walked against the importing file's
own package path) -- into a dotted module name. A valkyrie/*.py module
"has an importer" if any OTHER file outside tests/ references it or one of
its attributes. Being imported ONLY by its own unit test does not count --
that is exactly the "half-wired and forgotten" shape this test exists to
catch, not a pass.

WHAT DOES NOT COUNT AS AN ORPHAN.
  * __init__.py files. Importing any submodule of a package implicitly
    executes that package's __init__.py -- it does not need a direct
    `import valkyrie.edr` reference anywhere to be "used", and reliably
    distinguishing a meaningful __init__.py (real re-exports) from an
    empty one is a fuzzier problem than this test needs to solve. Skipped
    unconditionally, matching the task's own instruction to allowlist them.
  * Anything in `_ALLOWLIST` below, each entry with a comment saying why --
    never a bare name with no explanation.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks

_ROOT = Path(__file__).resolve().parent.parent
_VALKYRIE = _ROOT / "valkyrie"

# Directories never scanned for either module targets or importers -- vendored
# code, build output, and version-control internals, none of which is this
# product's own wiring.
_SKIP_DIR_NAMES = {".git", "__pycache__", "node_modules", "build", "dist",
                  "dist_installer", "old", ".ruff_cache"}


def _module_name(path: Path) -> str:
    rel = path.relative_to(_ROOT).with_suffix("")
    parts = rel.parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _iter_py_files():
    for p in _ROOT.rglob("*.py"):
        if _SKIP_DIR_NAMES & set(p.relative_to(_ROOT).parts):
            continue
        yield p


def _resolve_relative(importing_module: str, is_package: bool,
                      dotted: str, level: int) -> str:
    """Turn `from ..x.y import z` (level=2) into an absolute dotted module,
    anchored at the IMPORTING file's own package -- a package's __init__.py
    anchors at itself (level 1 == its own directory), a plain module anchors
    at its parent directory."""
    parts = importing_module.split(".")
    trim = level - 1 if is_package else level
    base = parts[: len(parts) - trim] if trim else parts
    if dotted:
        base = base + dotted.split(".")
    return ".".join(base)


def build_importer_graph() -> dict[str, set[tuple[str, bool]]]:
    """Return {valkyrie_module: {(importing_file, is_test), ...}}."""
    valkyrie_modules = {
        _module_name(p): p for p in _VALKYRIE.rglob("*.py")
        if "__pycache__" not in p.parts
    }
    package_dirs = {_module_name(p) for p in _VALKYRIE.rglob("__init__.py")}
    importers: dict[str, set[tuple[str, bool]]] = {m: set() for m in valkyrie_modules}

    for f in _iter_py_files():
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"),
                             filename=str(f))
        except SyntaxError:
            continue                                  # not this test's concern
        this_module = _module_name(f)
        is_pkg = this_module in package_dirs
        is_test = "tests" in f.relative_to(_ROOT).parts
        referenced: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    referenced.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    resolved = _resolve_relative(this_module, is_pkg,
                                                 node.module or "", node.level)
                    referenced.add(resolved)
                    for alias in node.names:
                        referenced.add(f"{resolved}.{alias.name}")
                elif node.module:
                    referenced.add(node.module)
                    for alias in node.names:
                        referenced.add(f"{node.module}.{alias.name}")
        for name in referenced:
            for vm in valkyrie_modules:
                if name == vm or name.startswith(vm + "."):
                    importers[vm].add((str(f), is_test))
    return importers


# Every entry here MUST carry a reason. No bare names.
_ALLOWLIST = {
    # Confirmed zero non-test importers by this exact scan while diagnosing
    # ADR 0048 Part 2's live-execution work (2026-08-05). Signed-update
    # verification in a security product with no caller is a real finding,
    # not nothing -- tracked as its own investigation (see the commit that
    # adds this entry) rather than silently wired or deleted to satisfy
    # this test. Remove this entry the moment it gets a real caller or is
    # deliberately retired.
    "valkyrie.updater": "zero non-test importers, confirmed; under "
                        "investigation, not yet wired or removed",
}


def main() -> int:
    c = Checks("no orphan modules (repo-wide AST import scan)", expect_min=4)

    importers = build_importer_graph()
    package_dirs = {_module_name(p) for p in _VALKYRIE.rglob("__init__.py")}

    c.check("the scan actually found valkyrie modules to check",
            len(importers) > 50)

    orphans: list[str] = []
    test_only: list[str] = []
    for mod in sorted(importers):
        if mod in package_dirs:
            continue                                  # __init__.py, see docstring
        if mod in _ALLOWLIST:
            continue
        imps = importers[mod]
        if not imps:
            orphans.append(mod)
        elif all(is_test for _, is_test in imps):
            test_only.append(mod)

    c.check(f"no modules with ZERO importers at all "
            f"({len(orphans)} found: {orphans})", not orphans)
    c.check(f"no modules imported ONLY by their own test "
            f"({len(test_only)} found: {test_only})", not test_only)

    print(f"\n{len(importers)} valkyrie modules scanned, "
         f"{len(package_dirs)} __init__.py skipped, "
         f"{len(_ALLOWLIST)} allowlisted (see reasons above the dict).")
    for mod, reason in _ALLOWLIST.items():
        present = mod in importers
        c.check(f"allowlisted module '{mod}' still exists (stale entry check)",
                present)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
