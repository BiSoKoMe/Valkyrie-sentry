"""Standalone test for the Windows service integration.

Checks service_manager.py status helpers and, optionally, drives
install_service.bat / uninstall_service.bat end-to-end (requires admin
and is skipped unless --install is passed, since it touches the real SCM).

Usage:
    python test_service.py                # status helpers only
    python test_service.py --install      # full install/status/uninstall cycle (admin)
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from valkyrie.service_manager import get_service_status, is_running_as_service


def test_status_helpers() -> bool:
    print("Testing service_manager helpers ...")
    status = get_service_status()
    print(f"  get_service_status() -> {status!r}")
    if status not in ("running", "stopped", "not installed"):
        print("  FAIL — unexpected status value")
        return False

    as_service = is_running_as_service()
    print(f"  is_running_as_service() -> {as_service!r}")
    if not isinstance(as_service, bool):
        print("  FAIL — not a bool")
        return False

    print("  PASS")
    return True


def test_install_cycle() -> bool:
    root = Path(__file__).resolve().parent
    print("Running install_service.bat (requires admin) ...")
    r = subprocess.run(["cmd", "/c", str(root / "install_service.bat")],
                        capture_output=True, text=True, timeout=120)
    print(r.stdout)
    if r.returncode != 0:
        print("  FAIL — install_service.bat exited non-zero")
        print(r.stderr)
        return False

    time.sleep(2)
    status = get_service_status()
    print(f"  Status after install: {status!r}")
    if status != "running":
        print("  FAIL — service not running after install")
        return False

    print("Running uninstall_service.bat ...")
    r = subprocess.run(["cmd", "/c", str(root / "uninstall_service.bat")],
                        capture_output=True, text=True, timeout=60)
    print(r.stdout)
    if get_service_status() != "not installed":
        print("  FAIL — service still present after uninstall")
        return False

    print("  PASS")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Test Valkyrie Windows service integration")
    parser.add_argument("--install", action="store_true",
                         help="Also run the full install/uninstall cycle (requires admin)")
    args = parser.parse_args()

    ok = test_status_helpers()
    if args.install:
        ok = test_install_cycle() and ok

    print("\n" + ("ALL TESTS PASSED" if ok else "SOME TESTS FAILED"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
