"""Real-time domain analysis — positive-signal-only tracker detection.

Default is ALLOW.  Only domains with confirmed positive tracker evidence
get flagged or blocked.  Unknown / never-heard-of sites always load fine.

Signal weights:
  S1a known tracker SLD (ad-tech)     +0.7  → block alone
  S1b analytics SLD                   +0.4  → flag alone
  S2  tracker subdomain prefix        +0.7  → block alone
  S3  high-entropy random subdomain   +0.3  → combined
  S4  query-burst rate                +0.2  → combined
  S5  OS process + tracker prefix     +0.2  → combined with S2

Decision thresholds:
  >= SCANNER_BLOCK_THRESHOLD (0.7) → block
  >= SCANNER_FLAG_THRESHOLD  (0.4) → flag
  else                             → allow  ← DEFAULT
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .behavioral import RateLimiter, entropy_score
from .config import (
    ANALYTICS_SLDS,
    MS_TRUSTED_ROOTS,
    SCAN_CACHE_TTL_HOURS,
    SCANNER_BLOCK_THRESHOLD,
    SCANNER_FLAG_THRESHOLD,
    SYSTEM_PROCESSES,
    TRACKER_PREFIXES,
    TRACKER_SLDS,
)


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    decision:   str             # "allow" | "block" | "flag"
    confidence: float           # 0.0 – 1.0
    reasons:    list[str]       = field(default_factory=list)
    category:   str             = "unknown"

    @property
    def from_cache(self) -> bool:
        return getattr(self, "_from_cache", False)


# ---------------------------------------------------------------------------
# Domain helpers
# ---------------------------------------------------------------------------

def _root_domain(domain: str) -> str:
    parts = domain.lower().rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _sld(domain: str) -> str:
    parts = domain.lower().rstrip(".").split(".")
    return parts[-2] if len(parts) >= 2 else domain


def _first_label(domain: str) -> str:
    return domain.lower().rstrip(".").split(".")[0]


def _label_count(domain: str) -> int:
    return len(domain.lower().rstrip(".").split("."))


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class SiteScanner:
    """Scores domains on positive tracker signals only.  Default = allow."""

    def __init__(self, store=None) -> None:
        self._store = store
        self._rate  = RateLimiter()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, domain: str, process: str = "") -> ScanResult:
        domain  = domain.lower().rstrip(".")
        process = (process or "").lower()

        # Cache read (domain-only key; rate signal always runs live)
        if self._store is not None:
            cached = self._store.get_cached_scan(domain)
            if cached is not None:
                r = ScanResult(**cached)
                object.__setattr__(r, "_from_cache", True)
                r_score, r_reason = self._rate.record_and_score(process)
                if r_score > 0 and r.decision == "allow":
                    r.reasons.append(r_reason)
                    if r.confidence + r_score >= SCANNER_BLOCK_THRESHOLD:
                        r.decision = "block"
                    elif r.confidence + r_score >= SCANNER_FLAG_THRESHOLD:
                        r.decision = "flag"
                return r

        result = self._score(domain, process)

        if self._store is not None:
            self._store.set_cached_scan(
                domain,
                result.decision,
                result.confidence,
                result.reasons,
                result.category,
            )
        return result

    # ------------------------------------------------------------------
    # Scoring — only positive tracker signals contribute
    # ------------------------------------------------------------------

    def _score(self, domain: str, process: str) -> ScanResult:
        sld   = _sld(domain)
        first = _first_label(domain)
        root  = _root_domain(domain)
        parts = _label_count(domain)

        score:   float     = 0.0
        reasons: list[str] = []

        # S1a — pure ad-tech tracker SLD (+0.7, block alone)
        if sld in TRACKER_SLDS:
            score += 0.7
            reasons.append(f"tracker SLD: {sld}")

        # S1b — analytics / monitoring SLD (+0.4, flag alone)
        elif sld in ANALYTICS_SLDS:
            score += 0.4
            reasons.append(f"analytics SLD: {sld}")

        # S2 — tracker subdomain prefix (+0.7, block alone)
        # Only fires when the FIRST label exactly matches a known tracker prefix
        # AND the domain has at least 3 parts (subdomain.domain.tld).
        s2_fired = False
        if first in TRACKER_PREFIXES and parts >= 3:
            score += 0.7
            reasons.append(f"tracker subdomain prefix: {first}")
            s2_fired = True

        # S3 — high-entropy random subdomain (+0.3, combined signal only)
        # Only meaningful when there is already a subdomain (3+ parts).
        if parts >= 3:
            e_score, e_reason = entropy_score(domain)
            if e_score > 0:
                score += 0.3
                reasons.append(e_reason)

        # S4 — query burst from single process (+0.2, always live)
        r_score, r_reason = self._rate.record_and_score(process or "unknown")
        if r_score > 0:
            score += 0.2
            reasons.append(r_reason)

        # S5 — system process hitting a tracker-prefix subdomain (+0.2)
        # Requires S2 to have fired so that system processes reaching normal
        # websites are not penalised.
        if (s2_fired
                and process in SYSTEM_PROCESSES
                and root not in MS_TRUSTED_ROOTS):
            score += 0.2
            reasons.append(f"system process {process} on tracker subdomain")

        score = min(1.0, score)

        # Decision — default is ALLOW
        if score >= SCANNER_BLOCK_THRESHOLD:
            decision = "block"
            category = "tracker"
        elif score >= SCANNER_FLAG_THRESHOLD:
            decision = "flag"
            category = "tracker"
        else:
            decision = "allow"
            category = "legitimate"

        return ScanResult(
            decision=decision,
            confidence=round(score, 3),
            reasons=reasons,
            category=category,
        )
