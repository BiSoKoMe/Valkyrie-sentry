"""Unbound local recursive DNS resolver manager.

Starts Unbound as a subprocess listening on 127.0.0.1:5301.
When running, dns_interceptor.py forwards allowed queries here
instead of to an external resolver like 8.8.8.8.

This means DNS resolution is fully local — root nameservers are
contacted directly, and no plaintext query leaves the machine to
a third-party resolver.

Admin / root requirement
------------------------
Linux:   Unbound needs to bind a port.  Port 5301 is unprivileged
         (>1024), so root is not required.  If DNSSEC validation is
         enabled and the root trust anchor needs writing, root may
         be needed on first run.
Windows: Unbound for Windows runs as a service; launching it as a
         subprocess with a custom config requires Administrator.

Install
-------
Linux (Debian/Ubuntu):   sudo apt install unbound
Linux (Fedora/RHEL):     sudo dnf install unbound
macOS:                   brew install unbound
Windows:                 https://nlnetlabs.nl/projects/unbound/download/
"""

from __future__ import annotations

import platform
import subprocess
import time
from pathlib import Path
from typing import Optional

from .config import DATA_DIR, DNS_TIMEOUT, UNBOUND_CONF_PATH, UNBOUND_PORT

_SYSTEM = platform.system()

# ---------------------------------------------------------------------------
# Config template
# ---------------------------------------------------------------------------

_UNBOUND_CONF_TEMPLATE = """\
# Valkyrie — generated Unbound configuration
# Do not edit by hand; regenerated on each startup.

server:
    interface: 127.0.0.1
    port: {port}

    # Answer queries only from localhost
    access-control: 0.0.0.0/0 refuse
    access-control: 127.0.0.0/8 allow

    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes

    # Privacy hardening
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    use-caps-for-id: yes

    # Performance
    prefetch: yes
    num-threads: 2
    msg-cache-size: 32m
    rrset-cache-size: 64m
    cache-min-ttl: 300

    # Logging — keep quiet
    verbosity: 0
    logfile: "{logfile}"

    # Root hints for true recursive resolution
    root-hints: "{root_hints}"

    # DNSSEC
    auto-trust-anchor-file: "{trust_anchor}"

# Fallback forward zone — used only if recursion fails
# Remove this block for pure recursive (no upstream) mode.
forward-zone:
    name: "."
    forward-addr: 9.9.9.9@53  # Quad9 — no-log, DNSSEC-validating
    forward-addr: 149.112.112.112@53
"""

_ROOT_HINTS_URL = "https://www.internic.net/domain/named.root"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _which(binary: str) -> Optional[str]:
    """Return full path to binary or None."""
    import shutil
    return shutil.which(binary)


def _fetch_root_hints(dest: Path) -> None:
    """Download the IANA root hints file if absent or older than 30 days."""
    import urllib.request
    from datetime import datetime, timezone

    if dest.exists():
        age = (datetime.now(tz=timezone.utc) -
               datetime.fromtimestamp(dest.stat().st_mtime, tz=timezone.utc)).days
        if age < 30:
            return
    try:
        with urllib.request.urlopen(_ROOT_HINTS_URL, timeout=10) as r:
            dest.write_bytes(r.read())
    except Exception:
        # Non-fatal — Unbound has built-in hints as fallback
        pass


def _install_hint(_system: str) -> str:
    if _system == "Linux":
        return (
            "  Debian/Ubuntu : sudo apt install unbound\n"
            "  Fedora/RHEL   : sudo dnf install unbound\n"
            "  Arch          : sudo pacman -S unbound"
        )
    if _system == "Darwin":
        return "  macOS         : brew install unbound"
    if _system == "Windows":
        return (
            "  Windows installer:\n"
            "  https://nlnetlabs.nl/projects/unbound/download/\n"
            "  (after install, ensure 'unbound' is in your PATH)"
        )
    return "  See: https://nlnetlabs.nl/projects/unbound/download/"


# ---------------------------------------------------------------------------
# UnboundManager
# ---------------------------------------------------------------------------

class UnboundManager:
    """Manages a local Unbound recursive resolver subprocess.

    Usage::

        mgr = UnboundManager()
        if mgr.start():
            # dns_interceptor should now forward to 127.0.0.1:5301
            pass
        # later …
        mgr.stop()
    """

    def __init__(
        self,
        port: int        = UNBOUND_PORT,
        conf_path: Path  = UNBOUND_CONF_PATH,
        console          = None,
    ) -> None:
        self._port      = port
        self._conf_path = conf_path
        self._console   = console
        self._proc: Optional[subprocess.Popen] = None

    def _print(self, msg: str) -> None:
        if self._console:
            self._console.print(msg)
        else:
            # Strip Rich markup for plain stdout
            import re
            print(re.sub(r"\[/?[^\]]+\]", "", msg))

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """Start Unbound.  Returns True if it is listening after startup."""
        unbound_bin = _which("unbound")
        if not unbound_bin:
            self._print(
                "[yellow]Unbound not found[/yellow] — using external DNS resolver.\n"
                "Install Unbound to enable local recursive resolution:\n"
                + _install_hint(_SYSTEM)
            )
            return False

        self._write_conf()
        self._proc = self._launch(unbound_bin)
        if self._proc is None:
            return False

        # Give it up to 3 seconds to come up
        for _ in range(6):
            time.sleep(0.5)
            if self._probe():
                self._print(
                    f"[green]✓[/green] Unbound resolver listening on "
                    f"127.0.0.1:{self._port} (local recursive DNS)"
                )
                return True

        self._print(
            f"[yellow]Unbound started but not responding on port {self._port}[/yellow] "
            "— falling back to external DNS"
        )
        self.stop()
        return False

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None

    def is_running(self) -> bool:
        return (
            self._proc is not None
            and self._proc.poll() is None
            and self._probe()
        )

    def upstream_addr(self) -> tuple[str, int]:
        """Return (host, port) to use as DNS upstream."""
        return ("127.0.0.1", self._port)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _write_conf(self) -> None:
        root_hints  = DATA_DIR / "named.root"
        trust_anchor = DATA_DIR / "root.key"
        log_path    = DATA_DIR / "unbound.log"

        _fetch_root_hints(root_hints)

        conf = _UNBOUND_CONF_TEMPLATE.format(
            port         = self._port,
            logfile      = str(log_path).replace("\\", "/"),
            root_hints   = str(root_hints).replace("\\", "/"),
            trust_anchor = str(trust_anchor).replace("\\", "/"),
        )
        self._conf_path.write_text(conf, encoding="utf-8")

    def _launch(self, binary: str) -> Optional[subprocess.Popen]:
        cmd = [binary, "-c", str(self._conf_path), "-d"]  # -d = foreground
        try:
            proc = subprocess.Popen(
                cmd,
                stdout = subprocess.DEVNULL,
                stderr = subprocess.PIPE,
            )
            # Quick check — if it dies immediately it's a config error
            time.sleep(0.3)
            if proc.poll() is not None:
                stderr = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
                self._print(
                    f"[red]Unbound exited immediately:[/red]\n{stderr[:400]}"
                )
                return None
            return proc
        except (OSError, PermissionError) as exc:
            self._print(f"[red]Could not launch Unbound:[/red] {exc}")
            return None

    def _probe(self) -> bool:
        """Send a minimal UDP DNS query; return True if we get any response."""
        import socket
        import struct

        # Minimal A-record query for "." (root) — always valid
        txid     = 0xABCD
        query    = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        query   += b"\x00\x00\x01\x00\x01"  # root ".", QTYPE A, QCLASS IN
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        try:
            sock.sendto(query, ("127.0.0.1", self._port))
            data, _ = sock.recvfrom(512)
            return len(data) >= 12
        except (socket.timeout, OSError):
            return False
        finally:
            sock.close()
