#!/usr/bin/env python3
"""EDR plugin trust gate (ADR-0009).

Discovered plugins execute with Valkyrie's privileges. This pins the SHA-256
allowlist behavior: with an allowlist in force only approved modules load
(fail-closed), and without one modules still load but are flagged unverified with
full provenance - never silent arbitrary execution.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


_PLUGIN_SRC = '''
from valkyrie.edr.plugins import DetectionPlugin

class _Demo(DetectionPlugin):
    name = "demo.test"
    def analyze(self, event, ctx):
        return []

def register(registry):
    registry.register(_Demo())
'''


def main() -> int:
    from valkyrie.edr.plugins import PluginRegistry, sha256_file

    print("\n=== EDR plugin trust gate ===\n")

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        plugin = d / "demo_plugin.py"
        plugin.write_text(_PLUGIN_SRC, encoding="utf-8")
        digest = sha256_file(plugin)

        print("[1] No allowlist -> loads, but flagged unverified + warned")
        reg = PluginRegistry()
        loaded = reg.discover(d)
        _check("plugin loaded", "demo_plugin" in loaded)
        prov = reg.loaded_plugins()
        _check("provenance records sha256", prov and prov[0]["sha256"] == digest)
        _check("flagged verified=False", prov and prov[0]["verified"] is False)
        _check("an unverified warning was recorded",
               any("without hash" in e["error"].lower()
                   or "plugin-trust" in e["plugin"] for e in reg.errors()))

        print("\n[2] Allowlist WITH the digest -> loads, verified=True")
        reg = PluginRegistry()
        loaded = reg.discover(d, allowlist=[digest])
        _check("plugin loaded under allowlist", "demo_plugin" in loaded)
        _check("flagged verified=True", reg.loaded_plugins()[0]["verified"] is True)

        print("\n[3] Allowlist WITHOUT the digest -> skipped (fail closed)")
        reg = PluginRegistry()
        loaded = reg.discover(d, allowlist=["0" * 64])
        _check("plugin NOT loaded", loaded == [])
        _check("nothing registered", reg.all() == [])
        _check("skip recorded with reason",
               any("not in allowlist" in e["error"].lower() for e in reg.errors()))

        print("\n[4] Empty allowlist loads nothing (fail closed)")
        reg = PluginRegistry()
        _check("empty allowlist -> no load", reg.discover(d, allowlist=[]) == [])

        print("\n[5] In-dir allowed.sha256 manifest is honored")
        (d / "allowed.sha256").write_text(
            f"# approved plugins\n{digest}  # demo\n", encoding="utf-8")
        reg = PluginRegistry()
        loaded = reg.discover(d)   # no explicit allowlist -> reads manifest
        _check("manifest-approved plugin loaded", "demo_plugin" in loaded)
        _check("manifest load is verified", reg.loaded_plugins()[0]["verified"] is True)

        print("\n[6] Manifest present but digest wrong -> skipped")
        (d / "allowed.sha256").write_text("deadbeef\n", encoding="utf-8")
        reg = PluginRegistry()
        _check("wrong-manifest plugin skipped", reg.discover(d) == [])

    print("\n" + "=" * 46)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
