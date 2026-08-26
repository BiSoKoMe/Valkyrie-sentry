"""DNS tunnelling / exfiltration detection - unique-subdomain flood analysis.

The signature this module hunts (MITRE T1048.003 - Exfiltration Over
Alternative Protocol, and the transport layer of T1071.004 - DNS C2):

    payload-chunk-1.evil.example   ┐
    payload-chunk-2.evil.example   │  many NEVER-SEEN, machine-generated
    payload-chunk-3.evil.example   │  labels under ONE base, in seconds
    ...                            ┘

Ordinary browsing never does this. A page load queries a handful of distinct
*bases*; a CDN queries repeated or slowly-rotating shard names; only DNS
tunnelling (exfil, C2 heartbeats, or red-team simulations of them - e.g.
Atomic Red Team's `atomicredteam-<rand>.<ip>.nip.io` probes) produces a
sustained stream of unique cryptic labels under a single registrable base.

Why the older layers missed this shape (measured, not guessed - this module
exists because an Atomic Red Team DNS burst sailed through as "allowed"):

  * ``classify_dga`` deliberately judges only the REGISTRABLE label, so a
    payload hidden in the subdomain of a legitimate base (nip.io) is
    invisible to it by design.
  * per-label entropy is a combining signal capped below the flag threshold,
    so each individual query scored 0.3 and was allowed.
  * the per-process rate limiter needs >30 queries/10s; a tunnel can idle
    along far slower and still move data.

The flood detector closes the gap by scoring the *aggregate shape* - unique
label count per base per window - which no single-query signal can see.

Precision guards (this product's rule: a false positive breaks someone's
site, so precision beats aggression):

  * only "cryptic" labels count - length >= 10 AND (>=3 digits OR Shannon
    entropy > 3.2), and never a common service label (www, api, cdn, ...);
  * media/CDN roots that legitimately fan out shard hostnames are exempt
    (config.TUNNEL_EXEMPT_ROOTS) as are Microsoft trusted roots;
  * thresholds: 3 unique cryptic labels/60s is only a combining signal,
    5 is required before the flood alone can block.

Thread-safe; all state is in-memory and bounded (per-base deques, evicted by
the sliding window; the base map itself is pruned when it grows past a cap).
"""

from __future__ import annotations

import collections
import ipaddress
import math
import re
import threading
import time
from typing import Optional

from .config import (
    COMMON_SUBDOMAIN_LABELS,
    DYNDNS_WILDCARD_ROOTS,
    MS_TRUSTED_ROOTS,
    TUNNEL_BLOCK_UNIQUE,
    TUNNEL_EXEMPT_ROOTS,
    TUNNEL_FLAG_UNIQUE,
    TUNNEL_WINDOW_SECONDS,
)

# Dotted IPv4 embedded anywhere in a hostname ("...127.0.0.1.nip.io").
_EMBEDDED_IP_RE = re.compile(r"(?:^|\.)((?:\d{1,3}\.){3}\d{1,3})(?:\.|$)")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = collections.Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def registrable_base(domain: str) -> str:
    """Last two labels - same registrable-domain convention the scanner uses."""
    parts = domain.lower().rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


def is_dyndns_root(domain: str) -> bool:
    """True when the registrable base is a wildcard IP-echo DNS provider."""
    return registrable_base(domain) in DYNDNS_WILDCARD_ROOTS


def effective_label(domain: str) -> str:
    """The leftmost label - the attacker-controlled payload slot on a
    wildcard provider, where the registrable label is the provider's own."""
    return domain.lower().rstrip(".").split(".")[0]


def embedded_ip(domain: str) -> Optional[str]:
    """Return a dotted IPv4 embedded in the hostname's labels, if valid."""
    m = _EMBEDDED_IP_RE.search(domain.lower().rstrip("."))
    if not m:
        return None
    try:
        ipaddress.IPv4Address(m.group(1))
    except ipaddress.AddressValueError:
        return None
    return m.group(1)


def embedded_private_ip(domain: str) -> Optional[str]:
    """An embedded IPv4 that is loopback/private/link-local - a hostname that
    publicly resolves into the caller's own network (rebinding-adjacent, and
    the shape of localhost-targeted test/malware traffic)."""
    ip = embedded_ip(domain)
    if ip is None:
        return None
    addr = ipaddress.IPv4Address(ip)
    if addr.is_loopback or addr.is_private or addr.is_link_local:
        return ip
    return None


def is_cryptic_label(label: str) -> bool:
    """A label that looks machine-generated rather than named by a human.

    Length >= 10 keeps ordinary shard names ("avatars0", "s3-us-west-2" - only
    two digits) out; the digit/entropy test then requires the label to carry
    actual encoded-data texture. Common service labels never qualify, and the
    entropy floor (3.5, same as ENTROPY_THRESHOLD) sits above ordinary English
    compounds like "downloadcenter" (~3.2) - encoded payloads (hex, base32/64
    chunks) virtually always carry digits and are caught by the digit test
    even when their entropy is modest.
    """
    label = label.lower()
    if label in COMMON_SUBDOMAIN_LABELS or len(label) < 10:
        return False
    digits = sum(ch.isdigit() for ch in label)
    return digits >= 3 or _shannon_entropy(label) > 3.5


class SubdomainFloodDetector:
    """Sliding-window count of unique cryptic labels per registrable base."""

    _MAX_BASES = 4096   # bound total memory across bases

    def __init__(self) -> None:
        # base -> deque[(monotonic_time, label)] - unique labels in window
        self._seen: dict[str, collections.deque] = {}
        self._lock = threading.RLock()

    def record_and_score(self, domain: str, now: Optional[float] = None) -> tuple[float, str]:
        """Record one query; return (score, reason) for the flood signal.

        score 0.75 -> block-alone (>= TUNNEL_BLOCK_UNIQUE unique labels)
        score 0.35 -> combining   (>= TUNNEL_FLAG_UNIQUE)
        score 0.0  -> no signal
        """
        domain = domain.lower().rstrip(".")
        base = registrable_base(domain)
        if base in TUNNEL_EXEMPT_ROOTS or base in MS_TRUSTED_ROOTS:
            return 0.0, ""
        label = effective_label(domain)
        if label == base.split(".")[0] or not is_cryptic_label(label):
            return 0.0, ""   # apex query, or a label with no data texture
        t = time.monotonic() if now is None else now
        with self._lock:
            dq = self._seen.get(base)
            if dq is None:
                if len(self._seen) >= self._MAX_BASES:
                    self._prune(t)
                dq = self._seen[base] = collections.deque()
            while dq and t - dq[0][0] > TUNNEL_WINDOW_SECONDS:
                dq.popleft()
            if label not in (l for _, l in dq):
                dq.append((t, label))
            unique = len(dq)
        if unique >= TUNNEL_BLOCK_UNIQUE:
            return 0.75, (f"DNS tunnelling pattern: {unique} unique generated "
                          f"subdomains of {base} in {int(TUNNEL_WINDOW_SECONDS)}s")
        if unique >= TUNNEL_FLAG_UNIQUE:
            return 0.35, (f"suspicious subdomain churn: {unique} unique generated "
                          f"labels under {base}")
        return 0.0, ""

    def _prune(self, now: float) -> None:
        """Drop bases whose whole window has expired (called under lock)."""
        stale = [b for b, dq in self._seen.items()
                 if not dq or now - dq[-1][0] > TUNNEL_WINDOW_SECONDS]
        for b in stale:
            del self._seen[b]
        # Still over the cap (a genuine flood of bases): drop oldest-touched.
        if len(self._seen) >= self._MAX_BASES:
            oldest = sorted(self._seen.items(), key=lambda kv: kv[1][-1][0])
            for b, _ in oldest[: len(self._seen) - self._MAX_BASES + 1]:
                del self._seen[b]
