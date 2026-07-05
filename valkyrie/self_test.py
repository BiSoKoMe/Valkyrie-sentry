"""Startup self-test and continuous protection heartbeat.

Two independent roles:

1. ``preflight()`` runs BEFORE any service starts. It returns a list of
   :class:`Check` results so ``__main__`` can refuse to announce "protected"
   when something critical is broken (missing dependencies, an unwritable data
   directory). Non-critical problems are reported but do not block startup.

2. :class:`HeartbeatMonitor` runs AFTER startup. It re-checks, on an interval,
   that protection is *actually live* — the DNS sinkhole is still answering —
   so a silent mid-session failure flips the dashboard into a loud DEGRADED
   state instead of continuing to claim everything is fine. For a privacy tool
   the worst failure mode is not a crash; it is silently not protecting while
   the UI still says ACTIVE.
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .config import BLOCKLIST_PATH, DATA_DIR, TLS_CA_CERT_PATH


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

@dataclass
class Check:
    """One preflight check result."""
    name:     str
    ok:       bool
    detail:   str  = ""
    critical: bool = False   # True => startup should abort if this fails


def _probe_dns(host: str, port: int, timeout: float = 1.0) -> bool:
    """Send a minimal UDP DNS query and return True if we get any answer.

    Uses a hand-built wire packet (query for "google.com" A) so it works with
    or without dnspython and never depends on the rest of the app.
    """
    wire = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x06google\x03com\x00\x00\x01\x00\x01")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(wire, (host, port))
        data, _ = sock.recvfrom(4096)
        return len(data) >= 12
    except OSError:
        return False
    finally:
        sock.close()


def _port_bindable(host: str, port: int) -> tuple[bool, str]:
    """Return (bindable, detail). Distinguishes 'already in use' from
    'permission denied' so the message is actionable."""
    bind_host = "0.0.0.0" if host in ("127.0.0.1", "localhost") else host
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((bind_host, port))
        return True, "available"
    except PermissionError:
        return False, f"permission denied (port {port} may need Administrator)"
    except OSError as exc:
        # WSAEADDRINUSE (10048) on Windows, EADDRINUSE (98) on Linux
        if getattr(exc, "winerror", None) == 10048 or exc.errno in (48, 98):
            return False, f"port {port} already in use by another process"
        return False, str(exc)
    finally:
        sock.close()


def preflight(
    *,
    port: int,
    host: str = "127.0.0.1",
    want_dns: bool = True,
    want_unbound: bool = True,
    want_tls: bool = False,
) -> list[Check]:
    """Run all startup checks and return their results.

    Args:
        port:         DNS listen port the interceptor will bind.
        host:         DNS listen host.
        want_dns:     whether the DNS interceptor is going to start.
        want_unbound: whether a local Unbound resolver is expected on :53.
        want_tls:     whether TLS inspection is requested (checks CA presence).

    Returns:
        A list of :class:`Check`. Callers should abort only when a check with
        ``critical=True`` has ``ok=False``.
    """
    checks: list[Check] = []

    # 1. Core Python dependencies importable (critical).
    missing = []
    for mod in ("psutil", "rich", "yaml", "dns"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    checks.append(Check(
        "Dependencies", not missing,
        "all present" if not missing else f"missing: {', '.join(missing)}",
        critical=True,
    ))

    # 2. data/ directory writable (critical — we cannot log or cache otherwise).
    writable, detail = True, str(DATA_DIR)
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        probe = DATA_DIR / ".selftest_write"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        writable, detail = False, f"{DATA_DIR} not writable: {exc}"
    checks.append(Check("Data directory", writable, detail, critical=True))

    # 3. DNS port bindable (advisory — the real bind has its own handling, and
    #    a false abort would be worse than letting it try).
    if want_dns:
        ok, detail = _port_bindable(host, port)
        checks.append(Check(f"DNS port {port}", ok, detail, critical=False))

    # 4. Blocklist present and non-empty (advisory — the scanner still blocks
    #    trackers without it, just with less coverage).
    bl_ok, bl_detail = False, "not found (will download on first run)"
    try:
        if BLOCKLIST_PATH.exists() and BLOCKLIST_PATH.stat().st_size > 0:
            bl_ok = True
            bl_detail = f"{BLOCKLIST_PATH.name} present"
    except OSError:
        pass
    checks.append(Check("Blocklist", bl_ok, bl_detail, critical=False))

    # 5. Unbound reachable if we intend to adopt it (advisory — falls back to
    #    public upstream when absent).
    if want_unbound:
        up = _probe_dns("127.0.0.1", 53, timeout=0.8)
        checks.append(Check(
            "Unbound :53", up,
            "answering" if up else "not detected (will use public upstream)",
            critical=False,
        ))

    # 6. TLS CA present if TLS inspection requested (advisory — mitmproxy
    #    generates one on first run).
    if want_tls:
        ca_ok = TLS_CA_CERT_PATH.exists()
        checks.append(Check(
            "TLS CA cert", ca_ok,
            "present" if ca_ok else "will be generated on first run",
            critical=False,
        ))

    return checks


def critical_failures(checks: list[Check]) -> list[Check]:
    """Return the subset of checks that are critical and failed."""
    return [c for c in checks if c.critical and not c.ok]


# ---------------------------------------------------------------------------
# Continuous heartbeat
# ---------------------------------------------------------------------------

class HeartbeatMonitor:
    """Background thread that re-verifies the DNS sinkhole is still answering.

    On every transition between healthy and unhealthy it invokes an optional
    callback and logs an event, so the dashboard can surface a live DEGRADED
    banner the moment protection silently drops.
    """

    def __init__(
        self,
        dns_host: str,
        dns_port: int,
        interval: float = 15.0,
        store=None,
        on_change: Optional[Callable[[bool], None]] = None,
    ) -> None:
        """Args:
            dns_host:  host the interceptor is answering on (usually 127.0.0.1).
            dns_port:  DNS port to probe.
            interval:  seconds between probes.
            store:     optional Store for logging health-change events.
            on_change: optional callback(healthy: bool) fired on each transition.
        """
        self._host      = dns_host if dns_host not in ("0.0.0.0", "") else "127.0.0.1"
        self._port      = dns_port
        self._interval  = interval
        self._store     = store
        self._on_change = on_change
        self._healthy   = True
        self._last_ok:   float = 0.0
        self._last_check: float = 0.0
        self._fail_count = 0
        self._lock       = threading.Lock()
        self._stop       = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="heartbeat")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def check_once(self) -> bool:
        """Run a single probe now and update state. Returns current health."""
        healthy = _probe_dns(self._host, self._port, timeout=1.0)
        now = time.time()
        changed = False
        with self._lock:
            self._last_check = now
            if healthy:
                self._last_ok = now
                self._fail_count = 0
            else:
                self._fail_count += 1
            # Require two consecutive failures before declaring unhealthy, so a
            # single dropped UDP packet doesn't cause a false alarm.
            new_state = healthy or self._fail_count < 2
            if new_state != self._healthy:
                self._healthy = new_state
                changed = True
        if changed:
            self._emit(new_state)
        return self._healthy

    def status(self) -> dict:
        with self._lock:
            return {
                "healthy":      self._healthy,
                "last_ok":      self._last_ok,
                "last_check":   self._last_check,
                "fail_count":   self._fail_count,
                "dns_port":     self._port,
            }

    def is_healthy(self) -> bool:
        with self._lock:
            return self._healthy

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _loop(self) -> None:
        # First probe immediately so status is meaningful right away.
        self.check_once()
        while not self._stop.wait(self._interval):
            self.check_once()

    def _emit(self, healthy: bool) -> None:
        if self._on_change:
            try:
                self._on_change(healthy)
            except Exception:
                pass
        if self._store is not None:
            try:
                from .store import DnsEvent
                self._store.log(DnsEvent.now(
                    domain       = "localhost",
                    decision     = "allowed" if healthy else "flagged",
                    process_name = "valkyrie",
                    process_pid  = 0,
                    process_path = "",
                    reason       = ("protection heartbeat OK" if healthy
                                    else "protection heartbeat FAILED — DNS sinkhole not answering"),
                    suspicion    = 0.0 if healthy else 1.0,
                    raw_category = "heartbeat",
                ))
            except Exception:
                pass
