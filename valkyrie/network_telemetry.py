"""Network connection telemetry — catch what DNS can't see.

The DNS sinkhole only sees traffic that *resolves a name first*. Malware that
connects to a hard-coded IP skips DNS entirely, and on Windows the IP blocklist
is enforced in-process (not in the kernel), so such a connection can slip by. This
collector closes that gap: it watches outbound connections and, when one targets
an IP on the threat-intel blocklist, emits a high-severity ``network`` telemetry
event that the EDR correlator turns into an incident.

Same shape and honesty as the process collector: a userland poller (psutil), not
a kernel flow sensor — it samples connections on an interval and can miss very
short-lived ones. It needs no privileges for the current user's sockets, degrades
to a no-op without psutil, and never raises into the caller.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from .telemetry import (
    ACT_FLAGGED, ACT_OBSERVED, CAT_NETWORK,
    SEV_HIGH, SEV_INFO, TelemetryEvent,
)

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False


def classify_connection(ip: str, port: int,
                        blocked: bool) -> tuple[str, list[str], str]:
    """Return (severity, labels, reason) for an outbound connection.

    Pure and deterministic. The high-value, low-noise signal is a connection to a
    known threat-intel IP — precisely the hard-coded-IP-C2 case DNS misses.
    """
    if blocked:
        return (SEV_HIGH, ["threat_intel_ip"],
                f"outbound connection to threat-intel IP {ip}:{port}")
    return (SEV_INFO, [], "")


@dataclass(frozen=True)
class ConnInfo:
    pid: int
    name: str
    raddr_ip: str
    raddr_port: int

    def key(self) -> tuple[int, str, int]:
        return (self.pid, self.raddr_ip, self.raddr_port)

    def to_event(self, blocked: bool) -> TelemetryEvent:
        severity, labels, reason = classify_connection(
            self.raddr_ip, self.raddr_port, blocked)
        action = ACT_FLAGGED if labels else ACT_OBSERVED
        return TelemetryEvent(
            category=CAT_NETWORK, activity="connect", action=action,
            actor_pid=self.pid, actor_name=self.name,
            target={"ip": self.raddr_ip, "port": self.raddr_port, "proto": "tcp"},
            severity=severity, reason=reason, source="network_collector",
            labels=labels,
        )


def diff_snapshots(old: dict, new: dict) -> list[ConnInfo]:
    return [c for k, c in new.items() if k not in old]


class NetworkCollector:
    """Polls outbound connections; emits telemetry for new ones.

    ``ip_reputation(ip) -> bool`` decides whether a destination is known-bad
    (typically ``FirewallManager.is_blocked_ip``). Only *flagged* connections are
    emitted by default, so a busy host's normal traffic doesn't flood the
    pipeline — set ``emit_all=True`` to emit every new connection (visibility).
    The first poll seeds a baseline silently.
    """

    def __init__(self, emit: Callable[[TelemetryEvent], None],
                 ip_reputation: Optional[Callable[[str], bool]] = None,
                 interval: float = 3.0, emit_all: bool = False) -> None:
        self._emit = emit
        self._rep = ip_reputation or (lambda _ip: False)
        self._interval = max(0.5, float(interval))
        self._emit_all = emit_all
        # None = no baseline yet. Using a sentinel (not truthiness) means an
        # empty snapshot is a valid baseline — otherwise an empty first poll
        # would keep re-seeding and never diff.
        self._last: Optional[dict] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def available(self) -> bool:
        return _PSUTIL

    def snapshot(self) -> dict:
        out: dict = {}
        if not _PSUTIL:
            return out
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            return out   # access denied / unsupported -> disabled, no raise
        names: dict[int, str] = {}
        for c in conns:
            try:
                if not c.raddr or c.pid is None:
                    continue
                # Outbound, actually-connected sockets only.
                if getattr(c, "status", "") not in ("ESTABLISHED", "SYN_SENT", "NONE", ""):
                    continue
                pid = int(c.pid)
                if pid not in names:
                    try:
                        names[pid] = psutil.Process(pid).name()
                    except Exception:
                        names[pid] = ""
                ci = ConnInfo(pid=pid, name=names.get(pid, ""),
                              raddr_ip=c.raddr.ip, raddr_port=int(c.raddr.port))
                out[ci.key()] = ci
            except Exception:
                continue
        return out

    def poll_once(self) -> int:
        new = self.snapshot()
        if self._last is None:
            self._last = new
            return 0
        fresh = diff_snapshots(self._last, new)
        self._last = new
        emitted = 0
        for ci in fresh:
            try:
                blocked = bool(self._rep(ci.raddr_ip))
            except Exception:
                blocked = False
            if not blocked and not self._emit_all:
                continue
            try:
                self._emit(ci.to_event(blocked))
                emitted += 1
            except Exception:
                pass
        return emitted

    def start(self) -> None:
        if self._running or not _PSUTIL:
            return
        self._last = self.snapshot()
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="network-collector")
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def _loop(self) -> None:
        while self._running:
            time.sleep(self._interval)
            if not self._running:
                break
            try:
                self.poll_once()
            except Exception:
                pass
