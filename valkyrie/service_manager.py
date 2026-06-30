"""Windows service status helpers.

Valkyrie itself never installs/manages the NSSM service in-process — that is
done by install_service.bat / uninstall_service.bat at the project root.
This module only answers "am I running as a service right now?" and "what
does Windows' Service Control Manager say about ValkyrieShield?".
"""

from __future__ import annotations

import os
import subprocess

from .config import SERVICE_NAME


def is_running_as_service() -> bool:
    """True if the current process has no attached console (typical of
    services launched by the Service Control Manager / NSSM)."""
    if os.name != "nt":
        return False
    try:
        import ctypes
        return ctypes.windll.kernel32.GetConsoleWindow() == 0
    except Exception:
        return False


def get_service_status() -> str:
    """Return "running" | "stopped" | "not installed".

    Queries `sc query <SERVICE_NAME>` — works whether or not NSSM is present,
    since the service is registered with the Windows SCM either way.
    """
    if os.name != "nt":
        return "not installed"
    try:
        result = subprocess.run(
            ["sc", "query", SERVICE_NAME],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return "not installed"

    out = result.stdout.upper()
    if "FAILED" in out or result.returncode != 0:
        return "not installed"
    if "RUNNING" in out:
        return "running"
    if "STOPPED" in out:
        return "stopped"
    return "not installed"
