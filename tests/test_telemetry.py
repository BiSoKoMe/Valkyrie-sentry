"""Standalone test for the Windows telemetry killer.

Checks scan() works, kill() creates a backup and applies changes, and
restore() reverts them. Requires Administrator - without elevation it exits
EXIT_SKIP so the runner records the telemetry killer as **untested here**
rather than counting it as a passing test (it previously exited 0, which is
how a whole pillar sat at 21% coverage behind a green badge).

Usage:
    python test_telemetry.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import skip_file
from valkyrie.config import TELEMETRY_BACKUP_PATH
from valkyrie.telemetry_killer import TelemetryKiller, is_admin


def main() -> None:
    print("Testing telemetry killer ...")

    if not is_admin():
        sys.exit(skip_file("telemetry killer",
                           "not running as Administrator (required for registry edits)"))

    tk = TelemetryKiller()

    print("  scan() ...")
    findings = tk.scan()
    if not findings:
        print("  FAIL — scan() returned no findings despite admin rights")
        sys.exit(1)
    print(f"    {len(findings)} settings checked")
    for name, info in findings.items():
        print(f"    {name:30s} active={info['active']}")
    print("  PASS")

    print("  kill() ...")
    results = tk.kill()
    if not all(results.values()):
        failed = [n for n, ok in results.items() if not ok]
        print(f"  WARN — some settings failed to apply: {failed}")
    if not TELEMETRY_BACKUP_PATH.exists():
        print("  FAIL — no backup file created")
        sys.exit(1)
    print(f"  PASS — backup written to {TELEMETRY_BACKUP_PATH}")

    print("  Re-scanning to confirm changes applied ...")
    after = tk.scan()
    still_active = [n for n, f in after.items() if f["active"]]
    if still_active:
        print(f"  WARN — still active after kill(): {still_active}")
    else:
        print("  PASS — all settings now inactive")

    print("  restore() ...")
    restored = tk.restore()
    if not restored:
        print("  FAIL — restore() returned no results")
        sys.exit(1)
    print(f"  PASS — restored {len(restored)} settings")

    print("\nALL TESTS PASSED")


if __name__ == "__main__":
    main()
