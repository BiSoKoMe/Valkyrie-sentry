"""Behavioral heuristics engine.

Scores every DNS query on three axes before the blocklist check:
  1. Shannon entropy of the queried domain (high entropy → DGA / tracking pixel)
  2. Per-process query rate in a sliding window
  3. Domain age via lightweight WHOIS (optional; fails silently)

Returns a (score: float, reason: str) tuple.  Score is in [0.0, 1.0].
If score >= BEHAVIORAL_BLOCK_SCORE and domain is not allowlisted → block.
"""

from __future__ import annotations

import collections
import math
import threading
import time
from typing import Optional

from .config import (
    BEHAVIORAL_BLOCK_SCORE,
    ENTROPY_THRESHOLD,
    RATE_MAX_QUERIES,
    RATE_WINDOW_SECONDS,
)


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """Shannon entropy of string s in bits per character."""
    if not s:
        return 0.0
    counts = collections.Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def entropy_score(domain: str) -> tuple[float, str]:
    """Return (partial_score, reason) based on subdomain entropy.

    We score only the leftmost label so that long CDN hostnames like
    'a.b.cdn.example.com' don't trigger on the SLD itself.
    """
    label = domain.split(".")[0]
    entropy = _shannon_entropy(label)
    if entropy > ENTROPY_THRESHOLD:
        # Normalise: ENTROPY_THRESHOLD → 0.5,  6.0 → 1.0
        partial = min(1.0, 0.5 + (entropy - ENTROPY_THRESHOLD) / (6.0 - ENTROPY_THRESHOLD) * 0.5)
        return partial, f"high subdomain entropy ({entropy:.2f} bits)"
    return 0.0, ""


# ---------------------------------------------------------------------------
# Per-process rate limiter (sliding window)
# ---------------------------------------------------------------------------

class RateLimiter:
    """Sliding-window query rate tracker.  Thread-safe across concurrent DNS handler threads."""

    def __init__(self) -> None:
        # process_name → deque of timestamps
        self._windows: dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self._lock = threading.RLock()

    def record_and_score(self, process_name: str) -> tuple[float, str]:
        """Record a query and return (partial_score, reason).

        Evicts timestamps older than RATE_WINDOW_SECONDS before counting.
        """
        now = time.monotonic()
        with self._lock:
            dq = self._windows[process_name]
            # evict stale
            while dq and now - dq[0] > RATE_WINDOW_SECONDS:
                dq.popleft()
            dq.append(now)
            count = len(dq)
        if count > RATE_MAX_QUERIES:
            ratio   = min(1.0, count / (RATE_MAX_QUERIES * 2))
            partial = 0.4 + ratio * 0.4    # maps to 0.4–0.8
            return partial, f"query burst ({count} queries in {RATE_WINDOW_SECONDS}s)"
        return 0.0, ""


# ---------------------------------------------------------------------------
# Domain age (WHOIS — optional)
# ---------------------------------------------------------------------------

_whois_cache: dict[str, Optional[int]] = {}   # domain → age in days (None = unknown)

def _domain_age_days(domain: str) -> Optional[int]:
    """Return domain age in days via python-whois, or None if unavailable."""
    sld = ".".join(domain.rsplit(".", 2)[-2:])  # strip subdomains
    if sld in _whois_cache:
        return _whois_cache[sld]
    try:
        import whois                            # optional dependency
        import datetime
        info = whois.whois(sld)
        created = info.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            age = (datetime.datetime.utcnow() - created).days
            _whois_cache[sld] = age
            return age
    except Exception:
        pass
    _whois_cache[sld] = None
    return None


def age_score(domain: str, threshold_days: int = 30) -> tuple[float, str]:
    """Return (partial_score, reason) based on domain age.

    Returns (0, '') when WHOIS is unavailable or lookup fails.
    """
    age = _domain_age_days(domain)
    if age is None:
        return 0.0, ""
    if age < threshold_days:
        partial = max(0.3, 0.6 - age / threshold_days * 0.3)
        return partial, f"new domain ({age}d old)"
    return 0.0, ""


# ---------------------------------------------------------------------------
# Combined scorer
# ---------------------------------------------------------------------------

class BehavioralEngine:
    """Aggregates entropy + rate + age into a single suspicion score."""

    def __init__(self) -> None:
        self._rate = RateLimiter()

    def score(self, domain: str, process_name: str) -> tuple[float, str]:
        """Return (combined_score, reason_string).

        Scores are combined with a weighted max — a single strong signal
        can trip the threshold without all axes firing.
        """
        e_score, e_reason = entropy_score(domain)
        r_score, r_reason = self._rate.record_and_score(process_name)
        a_score, a_reason = age_score(domain)

        # Weighted combination (entropy carries most weight)
        combined = min(1.0, e_score * 0.5 + r_score * 0.35 + a_score * 0.15)

        reasons = [r for r in (e_reason, r_reason, a_reason) if r]
        reason  = "; ".join(reasons) if reasons else ""
        return combined, reason

    def should_block(self, domain: str, process_name: str) -> tuple[bool, float, str]:
        """Return (block, score, reason).

        The caller is responsible for checking the allowlist before acting.
        """
        score, reason = self.score(domain, process_name)
        return score >= BEHAVIORAL_BLOCK_SCORE, score, reason
