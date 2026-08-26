#!/usr/bin/env python3
"""Static guard: a function-local import must not shadow a module-level one.

THE BUG THIS EXISTS TO PREVENT
------------------------------
`valkyrie/__main__.py` imported DATA_DIR at module scope, and then — 250 lines
into the same function — did::

    from .config import DATA_DIR

That inner import makes DATA_DIR a LOCAL name for the entire function, so every
*earlier* use of it in that function raises UnboundLocalError, even though the
module-level import is sitting right there in plain sight.

It cost a Tier B run. The engine bound liveness, answered exactly one health
probe, and then died on a line 250 lines above the import that broke it. The
evaluation waited the full 420 seconds and reported "API never became LIVE",
which points at startup performance and not at a NameError.

Nothing catches this cheaply:
  * `py_compile` accepts it — it is syntactically perfect.
  * importing the module accepts it — the function never runs at import time.
  * every unit test in the suite passed, because none of them start the engine.

So it is caught statically here. The rule is narrow and has no false positives
by construction: a name is only reported when it is imported at module scope,
imported AGAIN inside a function, and USED in that function before the local
import binds it. A function that imports a name locally and only uses it
afterwards is fine and is not flagged.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402


def _module_level_imports(tree: ast.Module) -> set:
    """Names bound by imports at MODULE scope only."""
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                if a.name == "*":
                    continue
                names.add(a.asname or a.name.split(".")[0])
    return names


def _offences_in_function(fn: ast.AST, module_names: set) -> list:
    """Names this function re-imports locally AND uses before that import."""
    local_imports: dict = {}
    for node in ast.walk(fn):
        # don't descend into nested functions - they have their own scope
        if node is not fn and isinstance(node, (ast.FunctionDef,
                                                ast.AsyncFunctionDef)):
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                if a.name == "*":
                    continue
                nm = a.asname or a.name.split(".")[0]
                if nm in module_names:
                    local_imports.setdefault(nm, node.lineno)

    if not local_imports:
        return []

    out = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            line = local_imports.get(node.id)
            if line is not None and node.lineno < line:
                out.append((node.id, node.lineno, line))
    return out


def scan(path: Path) -> list:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"),
                         filename=str(path))
    except SyntaxError:
        return []
    module_names = _module_level_imports(tree)
    if not module_names:
        return []
    found = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for name, used_line, import_line in _offences_in_function(
                    node, module_names):
                found.append({"file": path, "func": node.name, "name": name,
                              "used_line": used_line, "import_line": import_line})
    return found


def main() -> int:
    c = Checks("Static guard — no function-local import shadows a module import",
               expect_min=4)

    # --- the detector must actually detect ------------------------------
    print("\n[1] the detector catches the exact shape that broke Tier B")
    import tempfile
    bad = Path(tempfile.mkdtemp()) / "bad.py"
    bad.write_text(
        "from .config import DATA_DIR\n"
        "def run():\n"
        "    p = DATA_DIR / 'x.json'\n"      # used here...
        "    from .config import DATA_DIR\n"  # ...but bound here -> UnboundLocalError
        "    return p\n", encoding="utf-8")
    hits = scan(bad)
    c.check("a use-before-local-reimport is reported", len(hits) == 1)
    c.check("it names the variable and both line numbers",
            hits and hits[0]["name"] == "DATA_DIR"
            and hits[0]["used_line"] < hits[0]["import_line"])

    print("\n[2] and does NOT report the legitimate shapes")
    ok = Path(tempfile.mkdtemp()) / "ok.py"
    ok.write_text(
        "from .config import DATA_DIR\n"
        "def a():\n"
        "    from .config import DATA_DIR\n"   # local import, used only after
        "    return DATA_DIR\n"
        "def b():\n"
        "    return DATA_DIR\n"                # plain module-level use
        "def c():\n"
        "    from .other import SOMETHING\n"   # not a module-level name
        "    return SOMETHING\n", encoding="utf-8")
    c.check("a local import used only AFTER binding is not flagged",
            scan(ok) == [])

    # --- the real codebase ----------------------------------------------
    print("\n[3] the shipped package is clean")
    offences = []
    for py in sorted((_ROOT / "valkyrie").rglob("*.py")):
        if "__pycache__" in str(py):
            continue
        offences.extend(scan(py))

    if offences:
        print("\n  LATENT UnboundLocalError(s):")
        for o in offences:
            rel = o["file"].relative_to(_ROOT)
            print(f"    {rel}:{o['used_line']}  in {o['func']}()  "
                  f"uses {o['name']!r} before the local import at "
                  f"line {o['import_line']}")
    c.check(f"no shadowed imports across valkyrie/ ({len(offences)} found)",
            not offences)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
