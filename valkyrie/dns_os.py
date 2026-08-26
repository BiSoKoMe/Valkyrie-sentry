"""The real OS calls behind host_safety.py's DnsWatchdog — Windows, one place.

host_safety.py's own docstring asks for exactly this: "the real netsh /
Set-DnsClientServerAddress calls live in ONE reviewed place ... never
scattered." This is that place.

DOES NOT INVENT A SECOND WAY TO CHANGE DNS
-------------------------------------------
The product already arms/disarms DNS interception via
installer/payload/arm-protection.ps1 and disarm-protection.ps1, triggered as
the no-UAC-prompt scheduled tasks ValkyrieArm/ValkyrieDisarm (see
electron/src/main/engine.js's runTask). Those scripts are already tested,
already deployed, and arm-protection.ps1 already verifies the engine answers
before touching the adapter.

What they do NOT do is keep watching afterward. Arming checks liveness once,
at arm time. If the interceptor dies later - which this project proved
tonight it genuinely can, under real load - nothing notices or restores. This
module gives host_safety.py's DnsWatchdog the real hands to close that gap,
by calling the SAME scheduled task the app already uses for the "go safe"
path, not a second implementation of it.

reset_auto() therefore runs `schtasks /run /tn ValkyrieDisarm` - the exact
call electron/src/main/engine.js's stop() makes - falling back to invoking
disarm-protection.ps1 directly only when that task is not registered (running
from source, or in CI, where the installer's scheduled tasks do not exist).

set_servers() (the RESTORE_ORIGINAL path) is implemented for interface
completeness and is exercised by tests, but is not reachable through the
live product today: arm-protection.ps1 records only the adapter alias it
changed, not the DNS servers that were there before, so decide_dns_action's
saved_original is never populated in production and it always resolves to
RESET_TO_AUTO. Teaching arm-protection.ps1 to save the true pre-arm servers is
future work, not this task - it would mean changing a script that is already
tested and already deployed, for a path this fix does not require reaching.

FAIL SOFT, ALWAYS
-----------------
Every function here returns a safe default (empty tuple, False) instead of
raising. DnsWatchdog.tick() already treats a read failure as "do nothing this
tick" and a dead executor call as logged-and-moved-on - so raising from here
would not add safety, it would just make the watchdog's own try/except do the
same job less legibly.
"""

from __future__ import annotations

import socket
import subprocess
from pathlib import Path
from typing import Optional

from .host_safety import DnsExecutor

_SCHTASKS = r"C:\Windows\System32\schtasks.exe"
_POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
_TIMEOUT_S = 5

# Same probe shape as arm-protection.ps1's Test-DnsPort and self_test.py's
# _probe_dns - a minimal, self-contained UDP round-trip. Kept independent
# (not importing dns_interceptor / self_test) so this module works even when
# no interceptor object exists in this process, e.g. a future standalone
# watchdog.
_HEALTH_QUERY = bytes([
    0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x01,
])


def _run_ps(script: str, timeout: float = _TIMEOUT_S) -> Optional[str]:
    try:
        r = subprocess.run(
            [_POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.stdout if r.returncode == 0 else None
    except Exception:   # noqa: BLE001 — a shim call failing is data, not a crash
        return None


def read_servers() -> tuple:
    """Current IPv4 DNS servers on whichever adapter is actually online."""
    out = _run_ps(
        "Get-DnsClientServerAddress -AddressFamily IPv4 | "
        "Where-Object { $_.ServerAddresses } | Select-Object -First 1 "
        "-ExpandProperty ServerAddresses"
    )
    if not out:
        return ()
    return tuple(s.strip() for s in out.splitlines() if s.strip())


def resolver_alive() -> bool:
    """Is something answering DNS on 127.0.0.1:53 right now?"""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.5)
        sock.sendto(_HEALTH_QUERY, ("127.0.0.1", 53))
        data, _ = sock.recvfrom(512)
        return len(data) >= 12
    except Exception:   # noqa: BLE001
        return False
    finally:
        if sock is not None:
            sock.close()


def set_servers(servers: tuple) -> bool:
    """Set the adapter's DNS to an EXACT list of servers (RESTORE_ORIGINAL).

    Not reachable in production today - see module docstring. Implemented so
    the DnsExecutor interface is complete and testable, not because the live
    arm/disarm flow currently exercises it.
    """
    if not servers:
        return False
    adapter = _read_adapter_state()
    if not adapter:
        return False
    addrs = ",".join(f"'{s}'" for s in servers)
    out = _run_ps(
        f"Set-DnsClientServerAddress -InterfaceAlias '{adapter}' "
        f"-ServerAddresses @({addrs}); 'ok'"
    )
    return out is not None and "ok" in out


def reset_auto() -> bool:
    """Go to the universal safe state: DHCP/automatic.

    Calls the SAME scheduled task the desktop app already uses to disarm
    (schtasks /run /tn ValkyrieDisarm -> disarm-protection.ps1), so there is
    exactly one code path that ever performs this on a real install. Falls
    back to running disarm-protection.ps1 directly only when that task is not
    registered - source checkouts and CI, where no installer ran.
    """
    try:
        r = subprocess.run(
            [_SCHTASKS, "/run", "/tn", "ValkyrieDisarm"],
            capture_output=True, text=True, timeout=_TIMEOUT_S,
        )
        if r.returncode == 0:
            return True
    except Exception:   # noqa: BLE001
        pass

    script = (Path(__file__).resolve().parent.parent
             / "installer" / "payload" / "disarm-protection.ps1")
    if not script.exists():
        return False
    try:
        r = subprocess.run(
            [_POWERSHELL, "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-File", str(script)],
            capture_output=True, text=True, timeout=15,
        )
        return r.returncode == 0
    except Exception:   # noqa: BLE001
        return False


def _read_adapter_state() -> str:
    """The adapter alias arm-protection.ps1 recorded, if any."""
    import os
    state = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Valkyrie" / "valkyrie_dns_adapter.txt"
    try:
        return state.read_text(encoding="utf-8").strip()
    except Exception:   # noqa: BLE001
        return ""


def make_executor() -> DnsExecutor:
    """The real Windows DnsExecutor, wired to the product's actual arm/disarm
    mechanism. This is the one line the rest of the product should import."""
    return DnsExecutor(
        read_servers=read_servers,
        resolver_alive=resolver_alive,
        set_servers=set_servers,
        reset_auto=reset_auto,
    )
