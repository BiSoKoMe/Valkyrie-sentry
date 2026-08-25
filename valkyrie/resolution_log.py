"""Resolution history - what IPs did Valkyrie actually hand out?

This is the small piece that unlocks Valkyrie's strongest LIST-FREE network
signal, and it exists only because Valkyrie owns both layers: it is the DNS
resolver AND it sees outbound connections.

The question it answers:

    A process just connected to 45.32.11.9.
    Did anything on this machine ever ASK for that address by name?

Legitimate software resolves a name, gets an answer, then connects. Malware
carrying a hardcoded C2 address does not - which is precisely why the DNS
sinkhole never sees it. So "this destination was never resolved here" is a
strong, intrinsic signal that needs no blocklist, no feed, and no cloud.

Design:
  * Bounded (`max_entries`) with LRU-ish eviction - an unbounded map of every
    IP ever seen is a memory leak on a long-running agent.
  * TTL-aware: an answer is only evidence for as long as it could plausibly
    still be in use. A resolution from three days ago does not justify a
    connection today.
  * Thread-safe: the interceptor writes from resolver threads, the network
    collector reads from its own poll thread.
  * Pure lookups, no I/O. This is a hot path.

HONEST BOUNDARY: absence of a resolution is *suspicion, not proof*. NTP,
Windows Update, P2P, games, and anything with a literal IP in its config
legitimately connect without a lookup. This module produces one signal for
`network_score.py` to weigh - it never decides anything by itself.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Optional

# How long a DNS answer remains evidence that a later connection was expected.
# Deliberately generous: applications cache answers well past the record TTL,
# and a false "never resolved" is the failure mode we care about avoiding.
DEFAULT_EVIDENCE_TTL = 3600.0        # seconds
DEFAULT_MAX_ENTRIES = 8192


class ResolutionLog:
    """Bounded IP -> (domain, timestamp) history of answers Valkyrie returned."""

    def __init__(self, max_entries: int = DEFAULT_MAX_ENTRIES,
                 ttl: float = DEFAULT_EVIDENCE_TTL) -> None:
        self._max = max(64, int(max_entries))
        self._ttl = float(ttl)
        self._lock = threading.Lock()
        # ip -> (domain, ts). OrderedDict gives O(1) LRU eviction.
        self._by_ip: "OrderedDict[str, tuple[str, float]]" = OrderedDict()
        self._recorded = 0
        self._evicted = 0

    # -- write path (called from the resolver) -----------------------------
    def record(self, domain: str, ips, ts: Optional[float] = None) -> int:
        """Remember that `domain` resolved to `ips`. Returns how many recorded.

        Called for ALLOWED resolutions only - a sinkholed answer (0.0.0.0)
        is not evidence that a real destination was expected.
        """
        d = (domain or "").strip().rstrip(".").lower()
        if not d:
            return 0
        now = float(ts if ts is not None else time.time())
        n = 0
        with self._lock:
            for ip in ips or ():
                key = (ip or "").strip()
                if not key:
                    continue
                self._by_ip[key] = (d, now)
                self._by_ip.move_to_end(key)
                n += 1
                self._recorded += 1
                while len(self._by_ip) > self._max:
                    self._by_ip.popitem(last=False)   # evict least-recent
                    self._evicted += 1
        return n

    # -- read path (hot; called per connection) ----------------------------
    def domain_for(self, ip: str, now: Optional[float] = None) -> Optional[str]:
        """The domain this IP was resolved from, or None if never/expired."""
        key = (ip or "").strip()
        if not key:
            return None
        t = float(now if now is not None else time.time())
        with self._lock:
            hit = self._by_ip.get(key)
            if hit is None:
                return None
            domain, ts = hit
            if t - ts > self._ttl:
                # Stale: too old to justify a connection happening now.
                self._by_ip.pop(key, None)
                return None
            self._by_ip.move_to_end(key)
            return domain

    def was_resolved(self, ip: str, now: Optional[float] = None) -> bool:
        return self.domain_for(ip, now) is not None

    def stats(self) -> dict:
        with self._lock:
            return {"tracked": len(self._by_ip), "recorded": self._recorded,
                    "evicted": self._evicted, "max_entries": self._max,
                    "ttl_seconds": self._ttl}


# Module singleton so the interceptor and the network collector share one view
# without threading it through every constructor (same pattern as decoys.py).
_active: Optional[ResolutionLog] = None


def set_active(log: Optional[ResolutionLog]) -> None:
    global _active
    _active = log


def get_active() -> Optional[ResolutionLog]:
    return _active


def record_resolution(domain: str, ips, ts: Optional[float] = None) -> int:
    """Convenience for the resolver hot path. No-op when not deployed."""
    lg = _active
    return lg.record(domain, ips, ts) if lg is not None else 0


def was_resolved(ip: str, now: Optional[float] = None) -> Optional[bool]:
    """True/False when a log is active; None when we simply don't know.

    The tri-state matters: 'no log deployed' must NEVER be scored the same as
    'this IP was never resolved', or every connection looks malicious the
    moment the feature is off.
    """
    lg = _active
    return lg.was_resolved(ip, now) if lg is not None else None
