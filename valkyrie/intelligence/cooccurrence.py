"""CoOccurrenceTracker - Bucket-B third-party co-occurrence signal.

Catches tracker subdomains on mixed-use parents (tr.snapchat.com,
events.reddit.com) that cannot be listed by parent SLD without breaking the
real site. See SIGNAL_DESIGN_REPORT.md for the full rationale and guards.

How it works
------------
A browser loads a page as a burst of DNS queries from one process: the main
document first (the *anchor* / first party), then its sub-resources and third
parties. This tracker treats the first host of each burst as the anchor and, for
every later host in the burst whose registrable domain differs from the anchor's,
records the anchor in that host's anchor-set. A host that accumulates many
*distinct* anchors across separate page loads is riding behind many unrelated
first parties - the behavioural signature of a third-party tracker, which is
exactly how EasyPrivacy classifies by hand.

Guards (all required to hold the zero-FP result)
------------------------------------------------
G1  infra/functional-third-party allowlist (config.INFRA_ALLOWLIST) - CDNs,
    font hosts, payment/captcha/error-reporting are exempt and never scored.
G2  known-good exemption - domains the machine has already promoted to
    known-good (injected via ``exempt_fn``) are never scored.
G3  FLAG-ONLY - the score is capped strictly below the block threshold
    (config.COOC_SCORE_CAP < ANOMALY_BLOCK_THRESHOLD). Combined with the
    classifier applying it only as an allow->flag upgrade, this signal can never
    cause a block on its own. HARD INVARIANT.
G4  ubiquity gate - no score until a host has been seen behind at least
    config.COOC_MIN_ANCHORS distinct anchors. One co-occurrence is nothing.

This signal is temporal/learned: it does not fire on first contact, and in a
single-query test (no burst) it contributes exactly 0 - by design.
"""

from __future__ import annotations

import threading
from collections import defaultdict

from ..config import (
    COOC_BURST_MAX,
    COOC_MIN_ANCHORS,
    COOC_QUIET_GAP,
    COOC_SCORE_BASE,
    COOC_SCORE_CAP,
    COOC_SCORE_STEP,
    INFRA_ALLOWLIST,
)


def _base_domain(host: str) -> str:
    """Registrable domain approximated as the last two labels.

    Consistent with site_scanner._root_domain. Note: this is a heuristic and is
    imprecise for multi-label public suffixes (e.g. co.uk); documented as a
    known limitation in the design report.
    """
    parts = host.lower().rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


class CoOccurrenceTracker:
    """Learns per-host third-party ubiquity across first-party anchors."""

    def __init__(self, exempt_fn=None) -> None:
        self._exempt_fn = exempt_fn or (lambda d: False)
        # process -> {"anchor": base, "start": ts, "last": ts}
        self._proc: dict[str, dict] = {}
        # candidate host -> set of distinct anchor base-domains seen behind it
        self._anchors: dict[str, set] = defaultdict(set)
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Observation (called on every DNS query, before the decision)
    # ------------------------------------------------------------------

    def observe(self, process: str, domain: str, timestamp: float) -> None:
        """Fold one query into per-process burst/anchor state. Never raises."""
        process = (process or "unknown").lower()
        domain  = domain.lower().rstrip(".")
        base    = _base_domain(domain)
        with self._lock:
            st = self._proc.get(process)
            new_burst = (
                st is None
                or (timestamp - st["last"]) >= COOC_QUIET_GAP
                or (timestamp - st["start"]) >= COOC_BURST_MAX
            )
            if new_burst:
                # First host of a burst = the navigation anchor (first party).
                self._proc[process] = {"anchor": base, "start": timestamp,
                                       "last": timestamp}
                return
            st["last"] = timestamp
            anchor = st["anchor"]
            # A later host on a different registrable domain is a third-party
            # candidate riding behind this anchor. Infra is not credited as an
            # anchor-bearing candidate (G1) so it can never accrue ubiquity.
            if base != anchor and not self._is_infra(base):
                self._anchors[domain].add(anchor)

    # ------------------------------------------------------------------
    # Scoring (called by the classifier; flag-only by construction)
    # ------------------------------------------------------------------

    def score(self, domain: str) -> tuple[float, str]:
        """Return (partial_score, reason). Score is always < block threshold."""
        domain = (domain or "").lower().rstrip(".")
        base   = _base_domain(domain)
        if self._is_infra(base):                       # G1
            return 0.0, ""
        if self._exempt_fn(domain):                    # G2
            return 0.0, ""
        with self._lock:
            n = len(self._anchors.get(domain, ()))
        if n < COOC_MIN_ANCHORS:                       # G4
            return 0.0, ""
        # G3: bounded strictly below the block threshold - flag-only.
        s = min(COOC_SCORE_CAP, COOC_SCORE_BASE + (n - COOC_MIN_ANCHORS) * COOC_SCORE_STEP)
        return s, f"third-party across {n} distinct first-party sites (co-occurrence)"

    def anchor_count(self, domain: str) -> int:
        with self._lock:
            return len(self._anchors.get((domain or "").lower().rstrip("."), ()))

    # ------------------------------------------------------------------

    @staticmethod
    def _is_infra(base: str) -> bool:
        return base in INFRA_ALLOWLIST
