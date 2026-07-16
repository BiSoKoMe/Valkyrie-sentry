"""Unbound local recursive DNS resolver manager.

Two modes, tried in order:

1. Adopt an already-running Unbound instance. If something is already
   listening on 127.0.0.1:53 (most commonly Unbound installed as a native
   OS service — e.g. the Windows Unbound service), we use it directly as
   the upstream resolver rather than spawning a second instance, which
   would simply fail to bind the already-owned port.
2. Spawn our own subprocess on UNBOUND_PORT (5301) with a generated config,
   as before — used when no system-level Unbound is present.

Either way, dns_interceptor.py forwards allowed queries to whichever
address upstream_addr() returns instead of to an external resolver like
8.8.8.8 — so the overall chain is:

    OS DNS client -> Valkyrie (sinkhole/filter, port 5300/5353)
                   -> Unbound (real recursive resolution, port 53 or 5301)

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

from .config import DATA_DIR, UNBOUND_CONF_PATH, UNBOUND_PORT

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
{tls_cert_directive}
{forward_zone}"""

_ROOT_HINTS_URL = "https://www.internic.net/domain/named.root"

# DoT forward-zone (Quad9, no-log + DNSSEC-validating): used only when a real
# certificate-validation source is confirmed present on this machine — see
# _resolve_tls_cert_directive(). Otherwise plaintext keeps recursion working
# instead of risking a silent SERVFAIL storm from an unverifiable TLS handshake.
_DOT_FORWARD_ZONE = """\
forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-addr: 9.9.9.9@853#dns.quad9.net
    forward-addr: 149.112.112.112@853#dns.quad9.net
"""

_PLAINTEXT_FORWARD_ZONE = """\
forward-zone:
    name: "."
    forward-addr: 9.9.9.9@53  # Quad9 — no-log, DNSSEC-validating
    forward-addr: 149.112.112.112@53
"""

# Common system CA bundle locations, checked in order — first one that
# actually exists on this machine is used for tls-cert-bundle.
_LINUX_CA_BUNDLE_CANDIDATES = [
    "/etc/ssl/certs/ca-certificates.crt",  # Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",    # Fedora/RHEL
    "/etc/ssl/cert.pem",                   # macOS / Alpine
]


def _resolve_tls_cert_directive() -> Optional[str]:
    """Return the Unbound directive needed to validate upstream DoT certs on
    this machine, or None if no usable certificate source was found.

    Writing a tls-cert-bundle path that doesn't exist makes Unbound fail
    every upstream TLS handshake (a silent SERVFAIL storm) — so this only
    ever returns a directive whose precondition is verified right now,
    on this machine, not assumed.
    """
    if _SYSTEM == "Windows":
        # Built into Windows (Vista+) — always available, no file to check.
        return "    tls-win-cert: yes"
    for path in _LINUX_CA_BUNDLE_CANDIDATES:
        if Path(path).exists():
            return f'    tls-cert-bundle: "{path}"'
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Unbound's Windows installer does not add itself to PATH by default —
# shutil.which() alone misses a real, working install at this location
# (confirmed: this is exactly why resolver.py's spawn mode was silently
# unable to launch Unbound on this machine). Checked only as a fallback.
_WINDOWS_KNOWN_PATHS = [
    r"C:\Program Files\Unbound\unbound.exe",
    r"C:\Program Files (x86)\Unbound\unbound.exe",
]


def _which(binary: str) -> Optional[str]:
    """Return full path to binary or None."""
    import shutil
    found = shutil.which(binary)
    if found:
        return found
    if _SYSTEM == "Windows" and binary == "unbound":
        for candidate in _WINDOWS_KNOWN_PATHS:
            if Path(candidate).exists():
                return candidate
    return None


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

    # Native OS-service Unbound always answers on the standard DNS port.
    _SYSTEM_UNBOUND_PORT = 53

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
        self._adopted_existing = False

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
        """Start Unbound.  Returns True if it is listening after startup.

        Checks for an already-running system-level Unbound on port 53 first
        (e.g. installed as a native Windows service) and adopts it directly
        rather than spawning a second instance — which would simply fail to
        bind a port the OS service already owns.
        """
        if self._detect_existing_unbound():
            self._port = self._SYSTEM_UNBOUND_PORT
            self._adopted_existing = True
            self._print(
                f"[green]✓[/green] Using existing Unbound service on port "
                f"{self._SYSTEM_UNBOUND_PORT}"
            )
            return True

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
        # Never touch an adopted system-level service — Valkyrie didn't
        # start it and has no business stopping it on exit.
        if self._adopted_existing:
            self._adopted_existing = False
            return
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None

    def is_running(self) -> bool:
        if self._adopted_existing:
            return self._probe()
        return (
            self._proc is not None
            and self._proc.poll() is None
            and self._probe()
        )

    def upstream_addr(self) -> tuple[str, int]:
        """Return (host, port) to use as DNS upstream."""
        return ("127.0.0.1", self._port)

    # ------------------------------------------------------------------
    # Existing-service detection
    # ------------------------------------------------------------------

    def _detect_existing_unbound(self) -> bool:
        """True if something is already answering DNS on 127.0.0.1:53.

        Probing the port directly is the reliable, OS-agnostic signal — it's
        true regardless of whether Unbound got there via a Windows service,
        systemd, or a manually-started process. On Windows we also check the
        Service Control Manager by name purely for clearer logging; its
        absence doesn't change the result, since the port probe is what
        actually matters (a service named something else, or a manually
        started binary, is just as valid an "already running" resolver).
        """
        if not self._probe_port(self._SYSTEM_UNBOUND_PORT):
            return False
        if _SYSTEM == "Windows":
            state = self._windows_service_state("Unbound")
            if state:
                self._print(f"[dim]  Windows service 'Unbound' state: {state}[/dim]")
        return True

    @staticmethod
    def _windows_service_state(name: str) -> Optional[str]:
        """Return the SCM state word (e.g. "RUNNING") for a named Windows
        service, or None if it can't be determined. Windows-only."""
        if _SYSTEM != "Windows":
            return None
        try:
            import re
            result = subprocess.run(
                ["sc", "query", name],
                capture_output=True, text=True, timeout=5,
            )
            match = re.search(r"STATE\s*:\s*\d+\s+(\w+)", result.stdout)
            if match:
                return match.group(1)
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _write_conf(self) -> None:
        root_hints  = DATA_DIR / "named.root"
        trust_anchor = DATA_DIR / "root.key"
        log_path    = DATA_DIR / "unbound.log"

        _fetch_root_hints(root_hints)

        tls_directive = _resolve_tls_cert_directive()
        if tls_directive:
            forward_zone = _DOT_FORWARD_ZONE
            self._print(
                "[green]✓[/green] DoT upstream forwarding enabled "
                "(encrypted on 853, not plaintext 53)"
            )
        else:
            forward_zone = _PLAINTEXT_FORWARD_ZONE
            self._print(
                "[yellow]No usable TLS certificate store found[/yellow] — "
                "upstream forwarding stays plaintext (port 53) rather than "
                "risk an unverifiable TLS handshake"
            )

        conf = _UNBOUND_CONF_TEMPLATE.format(
            port               = self._port,
            logfile            = str(log_path).replace("\\", "/"),
            root_hints         = str(root_hints).replace("\\", "/"),
            trust_anchor       = str(trust_anchor).replace("\\", "/"),
            tls_cert_directive = tls_directive or "",
            forward_zone       = forward_zone,
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
        """Send a minimal UDP DNS query to our own configured port; return
        True if we get any response."""
        return self._probe_port(self._port)

    @staticmethod
    def _probe_port(port: int) -> bool:
        """Send a minimal UDP DNS query to 127.0.0.1:<port>; return True if
        we get any response. Used both for our own spawned instance and for
        detecting a pre-existing resolver on the standard DNS port."""
        import socket
        import struct

        # Minimal A-record query for "." (root) — always valid
        txid     = 0xABCD
        query    = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        query   += b"\x00\x00\x01\x00\x01"  # root ".", QTYPE A, QCLASS IN
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        try:
            sock.sendto(query, ("127.0.0.1", port))
            data, _ = sock.recvfrom(512)
            return len(data) >= 12
        except (socket.timeout, OSError):
            return False
        finally:
            sock.close()
