#!/usr/bin/env python3
"""Version-aware playbook seeding/migration (valkyrie/config.py).

A client never runs a manual step, so the product must arm itself on install in
EVERY case — fresh install and upgrade over an older build. These tests pin that
contract against temp files (no touching the real %ProgramData% copy):

  [1] Fresh install (no file)        → bundled armed default copied verbatim
  [2] Upgrade (old/no version)       → built-ins refreshed to the armed set,
                                        user-added playbooks preserved, backup made
  [3] Current or user-ahead version  → file left untouched (deliberate edits kept)
"""

from __future__ import annotations

import sys
import tempfile
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml
from valkyrie.config import _seed_or_migrate_playbooks, DEFAULT_PLAYBOOKS_PATH

_failures = 0


def _check(label: str, ok: bool) -> None:
    global _failures
    if not ok:
        _failures += 1
    print(f"  [{'ok  ' if ok else 'FAIL'}] {label}")


def _ids(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {str(p.get("id")): p for p in (data.get("playbooks") or [])}


def _shipped_version() -> int:
    data = yaml.safe_load(DEFAULT_PLAYBOOKS_PATH.read_text(encoding="utf-8")) or {}
    return int(data.get("version", 0))


def test_fresh_install() -> None:
    print("[1] fresh install → armed default copied verbatim")
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "playbooks.yaml"
        _seed_or_migrate_playbooks(path=path)
        _check("file created", path.exists())
        ids = _ids(path)
        _check("remove-persistence present", "remove-persistence" in ids)
        _check("kill-critical-process is enforce",
               ids.get("kill-critical-process", {}).get("mode") == "enforce")


def test_upgrade_preserves_user_playbooks() -> None:
    print("[2] upgrade from stale/no-version → armed, user playbooks preserved")
    stale = textwrap.dedent("""
        playbooks:
          - id: kill-malicious-process
            min_severity: critical
            categories: [process]
            mode: dry_run
            actions: [{action: kill_process, target_from: process_pid}]
          - id: my-custom
            min_severity: high
            categories: [process]
            mode: enforce
            actions: [{action: block_domain, target_from: entity}]
    """)
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "playbooks.yaml"
        path.write_text(stale, encoding="utf-8")
        _seed_or_migrate_playbooks(path=path)
        ids = _ids(path)
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        _check("migrated to shipped version", int(data.get("version", 0)) == _shipped_version())
        _check("armed built-in now present", "remove-persistence" in ids)
        _check("critical kill armed to enforce",
               ids.get("kill-critical-process", {}).get("mode") == "enforce")
        _check("user-added playbook preserved", "my-custom" in ids)
        _check("backup of old file made", any(Path(d).glob("*.bak")))


def test_current_version_untouched() -> None:
    print("[3] already-current version → left untouched (edits kept)")
    v = _shipped_version()
    custom = textwrap.dedent(f"""
        version: {v}
        playbooks:
          - id: kill-critical-process
            min_severity: critical
            categories: [process]
            mode: dry_run
            actions: [{{action: kill_process, target_from: process_pid}}]
    """)
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "playbooks.yaml"
        path.write_text(custom, encoding="utf-8")
        _seed_or_migrate_playbooks(path=path)
        ids = _ids(path)
        # Same version → the user's deliberate dry_run edit must survive.
        _check("user's dry_run edit preserved at current version",
               ids.get("kill-critical-process", {}).get("mode") == "dry_run")
        _check("no backup made when nothing migrated", not any(Path(d).glob("*.bak")))


def main() -> int:
    print("=" * 60)
    print("Playbook version-aware seeding/migration tests")
    print("=" * 60)
    test_fresh_install()
    test_upgrade_preserves_user_playbooks()
    test_current_version_untouched()
    print("-" * 60)
    if _failures:
        print(f"{_failures} check(s) FAILED.")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
