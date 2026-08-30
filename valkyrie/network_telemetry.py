"""Network connection telemetry - catch what DNS can't see.

The DNS sinkhole only sees traffic that *resolves a name first*. Malware that
connects to a hard-coded IP skips DNS entirely, and on Windows the IP blocklist
is enforced in-process (not in the kernel), so such a connection can slip by. This
collector closes that gap: it watches outbound connections and, when one targets
an IP on the threat-intel blocklist, emits a high-severity ``network`` telemetry
event that the EDR correlator turns into an incident.

Same shape and honesty as the process collector: a userland poller (psutil), not
a kernel flow sensor - it samples connections on an interval and can miss very
short-lived ones. It needs no privileges for the current user's sockets, degrades
to a no-op without psutil, and never raises into the caller.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from .network_score import ConnFacts, classify_connection_anomaly
from .process_telemetry import _SUSPICIOUS_PATHS
from .resolution_log import was_resolved
from .telemetry import (
    ACT_FLAGGED, ACT_OBSERVED, CAT_NETWORK,
    SEV_HIGH, SEV_INFO, TelemetryEvent, severity_rank,
)
from .trust import is_trusted_os_path

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False


class NetworkBaseline:
    """Per-process-image count of prior outbound connections (S4's baseline).

    Pure in-memory, like behavior_score.AncestryBaseline - the caller decides
    persistence. No warmup gate: unlike ancestry-pair rarity (which needs
    enough history to know what's normal FOR THIS HOST), "this binary has
    connected before" is unambiguous from the very first observation.
    """

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}

    def history_for(self, name: str) -> int:
        """Connections observed for this image BEFORE this call."""
        return self._counts.get((name or "").lower(), 0)

    def observe(self, name: str) -> None:
        key = (name or "").lower()
        self._counts[key] = self._counts.get(key, 0) + 1


def classify_connection(ip: str, port: int,
                        blocked: bool) -> tuple[str, list[str], str]:
    """Return (severity, labels, reason) for an outbound connection.

    Pure and deterministic. The high-value, low-noise signal is a connection to a
    known threat-intel IP - precisely the hard-coded-IP-C2 case DNS misses.
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
    path: str = ""

    def key(self) -> tuple[int, str, int]:
        return (self.pid, self.raddr_ip, self.raddr_port)

    def to_event(self, blocked: bool, anomaly: Optional[dict] = None) -> TelemetryEvent:
        """Build the telemetry event. `anomaly` (network_score's list-free
        verdict, if it fired) is additive to the list-based `blocked` check -
        either can raise severity/labels, neither can suppress the other."""
        severity, labels, reason = classify_connection(
            self.raddr_ip, self.raddr_port, blocked)
        if anomaly is not None:
            if severity_rank(anomaly["severity"]) > severity_rank(severity):
                severity = anomaly["severity"]
            labels = list(dict.fromkeys(labels + anomaly["labels"]))
            reason = "; ".join(r for r in (reason, anomaly["reason"]) if r)
        action = ACT_FLAGGED if labels else ACT_OBSERVED
        return TelemetryEvent(
            category=CAT_NETWORK, activity="connect", action=action,
            actor_pid=self.pid, actor_name=self.name,
            target={"ip": self.raddr_ip, "port": self.raddr_port, "proto": "tcp"},
            severity=severity, reason=reason, source="network_collector",
            labels=labels,
        )


def pid_for_local_port(port: int) -> Optional[tuple[int, str, str]]:
    """Resolve the process bound to a given LOCAL TCP port, via the same
    userland psutil connection table ``NetworkCollector`` already polls (there
    keyed on remote address for reputation; here keyed on local port to
    identify the process that opened a connection *out*, e.g. to a local
    interception proxy).

    Best-effort and racy by construction: the local port may already have been
    reused by a different process between the connection opening and this
    lookup running, and a non-elevated poller cannot always read another
    process's name/path. Returns None rather than guessing when no
    established match exists - the same "drop, don't guess" discipline
    ``edr/causality.py``'s ``attribute()`` already enforces on its side.
    """
    if not _PSUTIL or not port:
        return None
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return None
    for c in conns:
        try:
            if not c.laddr or int(c.laddr.port) != int(port):
                continue
            if getattr(c, "status", "") not in ("ESTABLISHED", "SYN_SENT", "NONE", ""):
                continue
            if c.pid is None:
                continue
            pid = int(c.pid)
            name = ""
            proc = None
            try:
                proc = psutil.Process(pid)
                name = proc.name()
            except Exception:
                pass
            path = ""
            try:
                path = proc.exe() if proc is not None else ""
            except Exception:
                pass
            return pid, name, path
        except Exception:
            continue
    return None


def diff_snapshots(old: dict, new: dict) -> list[ConnInfo]:
    return [c for k, c in new.items() if k not in old]


class NetworkCollector:
    """Polls outbound connections; emits telemetry for new ones.

    ``ip_reputation(ip) -> bool`` decides whether a destination is known-bad
    (typically ``FirewallManager.is_blocked_ip``). Only *flagged* connections are
    emitted by default, so a busy host's normal traffic doesn't flood the
    pipeline - set ``emit_all=True`` to emit every new connection (visibility).
    The first poll seeds a baseline silently.
    """

    def __init__(self, emit: Callable[[TelemetryEvent], None],
                 ip_reputation: Optional[Callable[[str], bool]] = None,
                 interval: float = 3.0, emit_all: bool = False,
                 baseline: Optional["NetworkBaseline"] = None) -> None:
        self._emit = emit
        self._rep = ip_reputation or (lambda _ip: False)
        self._interval = max(0.5, float(interval))
        self._emit_all = emit_all
        # Caller-injectable so a test (or a future persistence layer) can
        # supply its own; defaults to a fresh in-memory one, same pattern as
        # behavior_score.AncestryBaseline.
        self._baseline = baseline if baseline is not None else NetworkBaseline()
        # None = no baseline yet. Using a sentinel (not truthiness) means an
        # empty snapshot is a valid baseline - otherwise an empty first poll
        # would keep re-seeding and never diff.
        self._last: Optional[dict] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        # See ProcessCollector's identical field: updated at the end of every
        # poll_once() call, so a reliability watchdog can tell "still making
        # progress" apart from "thread alive but stuck."
        self.last_poll_completed_at: float = 0.0
        # See ProcessCollector's identical field: counts a poll cycle that
        # raised all the way out to _loop()'s outer guard, the one failure
        # shape every per-connection swallow inside poll_once() itself
        # cannot hide.
        self.exception_count: int = 0

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
        paths: dict[int, str] = {}
        for c in conns:
            try:
                if not c.raddr or c.pid is None:
                    continue
                # Outbound, actually-connected sockets only.
                if getattr(c, "status", "") not in ("ESTABLISHED", "SYN_SENT", "NONE", ""):
                    continue
                pid = int(c.pid)
                if pid not in names:
                    proc = None
                    try:
                        proc = psutil.Process(pid)
                        names[pid] = proc.name()
                    except Exception:
                        names[pid] = ""
                    try:
                        # Best-effort: AccessDenied on many system processes
                        # from a non-elevated context. Missing path just means
                        # network_score treats actor_trusted as unknown (None),
                        # never as untrusted - an access failure must not read
                        # as a signal.
                        paths[pid] = proc.exe() if proc is not None else ""
                    except Exception:
                        paths[pid] = ""
                ci = ConnInfo(pid=pid, name=names.get(pid, ""), path=paths.get(pid, ""),
                              raddr_ip=c.raddr.ip, raddr_port=int(c.raddr.port))
                out[ci.key()] = ci
            except Exception:
                continue
        return out

    def _score(self, ci: ConnInfo) -> Optional[dict]:
        """The list-free verdict for one new connection (network_score.py).

        Reads the baseline BEFORE observing this connection (a binary's very
        first connection must report history=0, not 1) and always observes
        exactly once per fresh connection regardless of the outcome, so the
        baseline reflects real traffic whether or not anything fired.
        """
        history = self._baseline.history_for(ci.name)
        self._baseline.observe(ci.name)
        p = (ci.path or "").lower().replace("\\", "/")
        facts = ConnFacts(
            process_name=ci.name, process_path=ci.path,
            raddr_ip=ci.raddr_ip, raddr_port=ci.raddr_port,
            resolved=was_resolved(ci.raddr_ip),
            actor_trusted=(is_trusted_os_path(ci.path) if ci.path else None),
            actor_low_trust_path=bool(p) and any(f in p for f in _SUSPICIOUS_PATHS),
            process_net_history=history,
            intel_hit=bool(self._rep(ci.raddr_ip)),
        )
        return classify_connection_anomaly(facts)

    def poll_once(self) -> int:
        try:
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
                try:
                    anomaly = self._score(ci)
                except Exception:
                    anomaly = None
                if not blocked and anomaly is None and not self._emit_all:
                    continue
                try:
                    self._emit(ci.to_event(blocked, anomaly))
                    emitted += 1
                except Exception:
                    pass
            return emitted
        finally:
            self.last_poll_completed_at = time.time()

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

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def status(self) -> dict:
        return {
            "running": self.is_running(),
            "baseline_ready": self._last is not None,
            "poll_interval_s": self._interval,
            "last_poll_completed_at": self.last_poll_completed_at,
            "exception_count": self.exception_count,
        }

    def _loop(self) -> None:
        while self._running:
            time.sleep(self._interval)
            if not self._running:
                break
            try:
                self.poll_once()
            except Exception:
                self.exception_count += 1
