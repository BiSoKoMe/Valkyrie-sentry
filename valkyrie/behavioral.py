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

from .config import (
    BEHAVIORAL_BLOCK_SCORE,
    ENTROPY_THRESHOLD,
    RATE_MAX_QUERIES,
    RATE_WINDOW_SECONDS,
    SUSPICIOUS_TLDS,
    SUSPICIOUS_TLD_WEIGHT,
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
# TLD reputation (offline — replaces the old WHOIS domain-age signal)
# ---------------------------------------------------------------------------
#
# The former age signal depended on network WHOIS, which is unavailable in the
# offline / intelligence-only posture this product ships in, so it silently
# scored 0 on every domain while appearing active. It is replaced by a static,
# shipped set of abuse-heavy TLDs (config.SUSPICIOUS_TLDS) — an O(1) lookup with
# no network dependency, so this signal is genuinely live offline. See the
# config note for the sourcing and the deliberate exclusion of mainstream TLDs.

def _tld(domain: str) -> str:
    parts = domain.lower().rstrip(".").split(".")
    return parts[-1] if parts else ""


def tld_reputation_score(domain: str) -> tuple[float, str]:
    """Return (partial_score, reason) based on the domain's TLD reputation.

    Fully offline and deterministic: a domain on an abuse-heavy TLD contributes
    a small partial score; everything else contributes exactly 0. Unlike the
    old WHOIS age signal, a 0 here is a real "TLD is reputable" verdict, not a
    silent failure to look anything up.
    """
    tld = _tld(domain)
    if tld in SUSPICIOUS_TLDS:
        return 1.0, f"abuse-heavy TLD (.{tld})"
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
        t_score, t_reason = tld_reputation_score(domain)

        # Weighted combination (entropy carries most weight)
        combined = min(1.0, e_score * 0.5 + r_score * 0.35
                       + t_score * SUSPICIOUS_TLD_WEIGHT)

        reasons = [r for r in (e_reason, r_reason, t_reason) if r]
        reason  = "; ".join(reasons) if reasons else ""
        return combined, reason

    # ------------------------------------------------------------------
    # Signal health (no silent failures — see PHASE 0)
    # ------------------------------------------------------------------

    def signal_health(self) -> list[dict]:
        """Report each behavioral sub-signal's live status and firing condition.

        Every signal here is offline-viable; none can silently contribute 0
        while pretending to work. Returned so the intelligence layer can print a
        single ACTIVE/DISABLED audit at startup.
        """
        return [
            {"signal": "entropy", "active": True,
             "note": f"fires when leftmost-label Shannon entropy > {ENTROPY_THRESHOLD}"},
            {"signal": "query_rate", "active": True,
             "note": f"fires on > {RATE_MAX_QUERIES} queries/{RATE_WINDOW_SECONDS}s per process"},
            {"signal": "tld_reputation", "active": True,
             "note": f"offline static set of {len(SUSPICIOUS_TLDS)} abuse-heavy TLDs "
                     f"(replaces dead WHOIS age signal)"},
        ]

    def should_block(self, domain: str, process_name: str) -> tuple[bool, float, str]:
        """Return (block, score, reason).

        The caller is responsible for checking the allowlist before acting.
        """
        score, reason = self.score(domain, process_name)
        return score >= BEHAVIORAL_BLOCK_SCORE, score, reason
