"""Startup self-test and continuous protection heartbeat.

Two independent roles:

1. ``preflight()`` runs BEFORE any service starts. It returns a list of
   :class:`Check` results so ``__main__`` can refuse to announce "protected"
   when something critical is broken (missing dependencies, an unwritable data
   directory). Non-critical problems are reported but do not block startup.

2. :class:`HeartbeatMonitor` runs AFTER startup. It re-checks, on an interval,
   that protection is *actually live* - the DNS sinkhole is still answering -
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

from .config import BLOCKLIST_PATH, DATA_DIR, HEALTH_PROBE_DOMAIN, TLS_CA_CERT_PATH


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


def _encode_qname(qname: str) -> bytes:
    """Encode a dotted name into DNS wire QNAME form (len-prefixed labels + root)."""
    out = bytearray()
    for label in qname.split("."):
        if not label:
            continue
        b = label.encode("ascii", "ignore")[:63]
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def _probe_dns(host: str, port: int, timeout: float = 1.0,
               qname: str = "google.com") -> bool:
    """Send a minimal UDP DNS query and return True if we get any answer.

    Hand-builds the wire packet so it works with or without dnspython and never
    depends on the rest of the app. The default name is a real domain (used by
    the preflight Unbound check); the heartbeat passes HEALTH_PROBE_DOMAIN, which
    the interceptor answers locally without upstream - so this probe confirms the
    sinkhole is answering even on an offline machine, instead of timing out
    against dead upstreams and raising a false "protection failed" alarm.
    """
    header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    wire = header + _encode_qname(qname) + b"\x00\x01\x00\x01"   # QTYPE=A, QCLASS=IN
    # Socket creation is inside the guard on purpose. It was outside, where an
    # OSError from fd exhaustion escaped this function, propagated through
    # check_once() and killed the heartbeat thread - after which is_healthy()
    # kept returning the last state (typically True) forever while nothing was
    # being probed at all. That is the failure this module's own docstring
    # calls the worst one: silently not protecting while the UI says ACTIVE.
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(wire, (host, port))
        data, _ = sock.recvfrom(4096)
        return len(data) >= 12
    except Exception:
        # Any failure to probe is a failure to confirm protection. Fail toward
        # "cannot confirm", never toward "fine".
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


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

    # 2. data/ directory writable (critical - we cannot log or cache otherwise).
    writable, detail = True, str(DATA_DIR)
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        probe = DATA_DIR / ".selftest_write"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        writable, detail = False, f"{DATA_DIR} not writable: {exc}"
    checks.append(Check("Data directory", writable, detail, critical=True))

    # 3. DNS port bindable (advisory - the real bind has its own handling, and
    #    a false abort would be worse than letting it try).
    if want_dns:
        ok, detail = _port_bindable(host, port)
        checks.append(Check(f"DNS port {port}", ok, detail, critical=False))

    # 4. Blocklist present and non-empty (advisory - the scanner still blocks
    #    trackers without it, just with less coverage).
    bl_ok, bl_detail = False, "not found (will download on first run)"
    try:
        if BLOCKLIST_PATH.exists() and BLOCKLIST_PATH.stat().st_size > 0:
            bl_ok = True
            bl_detail = f"{BLOCKLIST_PATH.name} present"
    except OSError:
        pass
    checks.append(Check("Blocklist", bl_ok, bl_detail, critical=False))

    # 5. Unbound reachable if we intend to adopt it (advisory - falls back to
    #    public upstream when absent).
    if want_unbound:
        up = _probe_dns("127.0.0.1", 53, timeout=0.8)
        checks.append(Check(
            "Unbound :53", up,
            "answering" if up else "not detected (will use public upstream)",
            critical=False,
        ))

    # 6. TLS CA present if TLS inspection requested (advisory - mitmproxy
    #    generates one on first run).
    if want_tls:
        ca_ok = TLS_CA_CERT_PATH.exists()
        checks.append(Check(
            "TLS CA cert", ca_ok,
            "present" if ca_ok else "will be generated on first run",
            critical=False,
        ))

        # 6b. The CA PRIVATE KEY must not be readable by other local accounts.
        #     This is critical=True on purpose: an exposed CA key lets any local
        #     account mint a trusted certificate for any domain and impersonate
        #     it to this machine with a valid padlock. Unlike a missing cert
        #     (which regenerates harmlessly), this one is a live compromise of
        #     every HTTPS connection the machine makes, so it must fail the
        #     self-test loudly rather than appear as an advisory note.
        try:
            from . import secure_file
            from .config import TLS_CA_KEY_PATH
            if TLS_CA_KEY_PATH.exists():
                key_ok, key_detail = secure_file.verify(TLS_CA_KEY_PATH)
                checks.append(Check(
                    "TLS CA private key protected", key_ok,
                    key_detail if key_ok
                    else f"EXPOSED — {key_detail}; other local accounts could "
                         f"impersonate any HTTPS site to this machine",
                    critical=True,
                ))
        except Exception as exc:      # noqa: BLE001 - never break the self-test
            checks.append(Check("TLS CA private key protected", False,
                                f"could not verify: {exc}", critical=False))

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
        startup_grace: float = 45.0,
    ) -> None:
        """Args:
            dns_host:  host the interceptor is answering on (usually 127.0.0.1).
            dns_port:  DNS port to probe.
            interval:  seconds between probes.
            store:     optional Store for logging health-change events.
            on_change: optional callback(healthy: bool) fired on each transition.
            startup_grace: seconds after start() during which a failed probe is
                treated as "still starting", not "failed" - the sinkhole may not
                have finished binding yet, and a cold boot otherwise logs a false
                PROTECTION-FAILED before the first successful probe.
        """
        self._host      = dns_host if dns_host not in ("0.0.0.0", "") else "127.0.0.1"
        self._port      = dns_port
        self._interval  = interval
        self._store     = store
        self._on_change = on_change
        self._startup_grace = startup_grace
        self._started_at: float = 0.0
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
        self._started_at = time.time()
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="heartbeat")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def check_once(self) -> bool:
        """Run a single probe now and update state. Returns current health.

        Never raises: a probe that blows up is treated as a failed probe, not
        as an error for the caller to handle. The caller is a daemon thread
        whose death would freeze the health signal at its last value.
        """
        try:
            # Probe the reserved local health name: the interceptor answers it
            # without upstream, so an offline machine still reads HEALTHY.
            healthy = _probe_dns(self._host, self._port, timeout=1.0,
                                 qname=HEALTH_PROBE_DOMAIN)
        except Exception:
            healthy = False
        now = time.time()
        changed = False
        with self._lock:
            self._last_check = now
            # Startup grace: until the first successful probe within the grace
            # window, a failure means "sinkhole still binding," not "protection
            # down." Without this, a cold boot logs a false PROTECTION-FAILED
            # (heartbeat fires seconds before the DNS listener is ready).
            in_grace = (self._started_at
                        and self._last_ok == 0.0
                        and (now - self._started_at) < self._startup_grace)
            if healthy:
                self._last_ok = now
                self._fail_count = 0
            elif in_grace:
                pass                      # don't count startup-race failures
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

    # How far past the probe interval a check may be before the health signal
    # is considered stale rather than good. Generous, so a slow probe or a
    # loaded box does not flap the dashboard; the point is to catch a monitor
    # that has stopped entirely, not one that is merely late.
    _STALE_INTERVALS = 4

    def _is_stale(self, now: float) -> bool:
        """True if no probe has landed recently enough to trust the answer.

        Without this, a heartbeat thread that dies for any reason freezes the
        signal at its last value - and 'healthy' is the value it is most likely
        to be frozen at, since that is the starting state. The user would see
        ACTIVE indefinitely while nothing was being checked. Absence of a
        recent check is not evidence of health.
        """
        if not self._last_check:
            return False          # never probed yet - start() has not run
        return (now - self._last_check) > (self._interval * self._STALE_INTERVALS)

    def status(self) -> dict:
        with self._lock:
            stale = self._is_stale(time.time())
            return {
                "healthy":      self._healthy and not stale,
                "last_ok":      self._last_ok,
                "last_check":   self._last_check,
                "fail_count":   self._fail_count,
                "dns_port":     self._port,
                "stale":        stale,
            }

    def is_healthy(self) -> bool:
        with self._lock:
            return self._healthy and not self._is_stale(time.time())

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _loop(self) -> None:
        # Defense in depth over check_once()'s own guard: this thread must
        # outlive ANY failure, because a dead heartbeat does not report itself
        # as dead - is_healthy() simply keeps returning whatever it last saw.
        # A monitor that stops monitoring must never look like a healthy one.
        try:
            self.check_once()      # probe immediately so status is meaningful
        except Exception:
            pass
        while not self._stop.wait(self._interval):
            try:
                self.check_once()
            except Exception:
                pass

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
