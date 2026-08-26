"""Windows service status helpers.

Valkyrie itself never installs/manages the NSSM service in-process - that is
done by install_service.bat / uninstall_service.bat at the project root.
This module only answers "am I running as a service right now?" and "what
does Windows' Service Control Manager say about ValkyrieShield?".
"""

from __future__ import annotations

import os
import re
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


# sc.exe STATE codes -> our status strings. Covers every real SCM state, not
# just RUNNING/STOPPED - a paused, throttled, or transitioning service must
# never be misreported as "not installed".
_SC_STATE_MAP = {
    "1": "stopped",          # STOPPED
    "2": "starting",         # START_PENDING
    "3": "stopping",         # STOP_PENDING
    "4": "running",          # RUNNING
    "5": "continuing",       # CONTINUE_PENDING
    "6": "pausing",          # PAUSE_PENDING
    "7": "paused",           # PAUSED
}

_STATE_LINE_RE = re.compile(r"STATE\s*:\s*(\d+)")


def get_service_status() -> str:
    """Return one of: "running", "stopped", "paused", "starting", "stopping",
    "continuing", "pausing", or "not installed".

    Queries `sc query <SERVICE_NAME>` - works whether or not NSSM is present,
    since the service is registered with the Windows SCM either way. Parses
    the numeric STATE code directly rather than loose substring matching, so
    every real SCM state (including PAUSED, which a throttled/crash-looping
    NSSM-wrapped service enters) is reported accurately instead of falling
    through to "not installed".
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

    # `sc query` on a service that truly doesn't exist returns a nonzero exit
    # code and no STATE line at all - that's the only real "not installed"
    # case. A service that exists but is in some non-RUNNING state still
    # returns exit code 0 with a valid STATE line, so don't gate on
    # returncode/"FAILED" text alone.
    match = _STATE_LINE_RE.search(result.stdout)
    if not match:
        return "not installed"
    return _SC_STATE_MAP.get(match.group(1), "not installed")
