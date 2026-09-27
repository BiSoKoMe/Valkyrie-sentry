"""Smoke-test the read-only host gate without provisioning or touching a VM."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path


def main() -> int:
    script = Path(__file__).resolve().parent.parent / "tools" / "vm_lab_preflight.ps1"
    result = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "-AsJson"],
        capture_output=True, text=True, check=True,
    )
    report = json.loads(result.stdout)
    assert isinstance(report["ready_for_live_validation"], bool)
    names = {check["name"] for check in report["checks"]}
    assert {"virtualbox_service", "isolated_network", "recovery_snapshot"} <= names
    assert report["next"]
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
