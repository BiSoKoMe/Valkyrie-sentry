"""Real-time domain analysis - positive-signal-only tracker detection.

Default is ALLOW.  Only domains with confirmed positive tracker evidence
get flagged or blocked.  Unknown / never-heard-of sites always load fine.

Signal weights:
  S1a known tracker SLD (ad-tech)     +0.7  -> block alone
  S1b analytics SLD                   +0.4  -> flag alone
  S2  tracker subdomain prefix        +0.7  -> block alone
  S3  high-entropy random subdomain   +0.3  -> combined
  S4  query-burst rate                +0.2  -> combined
  S5  OS process + tracker prefix     +0.2  -> combined with S2

Decision thresholds:
  >= SCANNER_BLOCK_THRESHOLD (0.7) -> block
  >= SCANNER_FLAG_THRESHOLD  (0.4) -> flag
  else                             -> allow  <- DEFAULT
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
    TRACKER_SLD_PREFIXES,
    TRACKER_SLDS,
)
from .dga import classify_dga
from .dns_tunnel import (
    SubdomainFloodDetector,
    effective_label,
    embedded_private_ip,
    is_dyndns_root,
)


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    decision:   str             # "allow" | "block" | "flag"
    confidence: float           # 0.0 - 1.0
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
        self._tunnel = SubdomainFloodDetector()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, domain: str, process: str = "") -> ScanResult:
        domain  = domain.lower().rstrip(".")
        process = (process or "").lower()

        # Cache read (domain-only key; rate + flood signals always run live -
        # both score the query *stream*, which a per-domain cache can't see)
        if self._store is not None:
            cached = self._store.get_cached_scan(domain)
            if cached is not None:
                r = ScanResult(**cached)
                object.__setattr__(r, "_from_cache", True)
                r_score, r_reason = self._rate.record_and_score(process)
                t_score, t_reason = self._tunnel.record_and_score(domain)
                live = r_score + t_score
                if live > 0 and r.decision == "allow":
                    if r_reason:
                        r.reasons.append(r_reason)
                    if t_reason:
                        r.reasons.append(t_reason)
                    if r.confidence + live >= SCANNER_BLOCK_THRESHOLD:
                        r.decision = "block"
                        if t_score >= 0.75:
                            r.category = "tunnel"
                    elif r.confidence + live >= SCANNER_FLAG_THRESHOLD:
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
    # Scoring - only positive tracker signals contribute
    # ------------------------------------------------------------------

    def _score(self, domain: str, process: str) -> ScanResult:
        sld   = _sld(domain)
        first = _first_label(domain)
        root  = _root_domain(domain)
        parts = _label_count(domain)

        score:   float     = 0.0
        reasons: list[str] = []

        # S1a - pure ad-tech tracker SLD (+0.7, block alone)
        if sld in TRACKER_SLDS:
            score += 0.7
            reasons.append(f"tracker SLD: {sld}")

        # S1b - analytics / monitoring SLD (+0.4, flag alone)
        elif sld in ANALYTICS_SLDS:
            score += 0.4
            reasons.append(f"analytics SLD: {sld}")

        # S1c - compound SLD: a hyphen-joined component exactly matches a
        # known tracker/analytics SLD (e.g. "browser-intake-datadoghq"
        # contains "datadoghq"). Exact-word match on each component only -
        # never a substring match - so this can't collide with an unrelated
        # domain that merely contains similar-looking text.
        elif "-" in sld and any(c in TRACKER_SLDS for c in sld.split("-")):
            score += 0.7
            reasons.append(f"tracker SLD component: {sld}")
        elif "-" in sld and any(c in ANALYTICS_SLDS for c in sld.split("-")):
            score += 0.4
            reasons.append(f"analytics SLD component: {sld}")

        # S1d - SLD starts with a known distinctive tracker/analytics brand
        # name (e.g. "segmentapis" -> "segment", "taboolasyndication" ->
        # "taboola") - companies that register a variant apex domain for
        # infra/CDN use. Curated prefix list excludes generic English words.
        elif any(sld.startswith(p) for p in TRACKER_SLD_PREFIXES):
            score += 0.7
            reasons.append(f"tracker SLD prefix match: {sld}")

        # S2 - tracker subdomain prefix (+0.7, block alone)
        # Only fires when the FIRST label exactly matches a known tracker prefix
        # AND the domain has at least 3 parts (subdomain.domain.tld).
        s2_fired = False
        if first in TRACKER_PREFIXES and parts >= 3:
            score += 0.7
            reasons.append(f"tracker subdomain prefix: {first}")
            s2_fired = True

        # S3 - high-entropy random subdomain (+0.3, combined signal only)
        # Only meaningful when there is already a subdomain (3+ parts).
        if parts >= 3:
            e_score, e_reason = entropy_score(domain)
            if e_score > 0:
                score += 0.3
                reasons.append(e_reason)

        # S4 - query burst from single process (+0.2, always live)
        r_score, r_reason = self._rate.record_and_score(process or "unknown")
        if r_score > 0:
            score += 0.2
            reasons.append(r_reason)

        # S5 - system process hitting a tracker-prefix subdomain (+0.2)
        # Requires S2 to have fired so that system processes reaching normal
        # websites are not penalised.
        if (s2_fired
                and process in SYSTEM_PROCESSES
                and root not in MS_TRUSTED_ROOTS):
            score += 0.2
            reasons.append(f"system process {process} on tracker subdomain")

        # S6 - short/cryptic first label (<=2 alpha chars) on a subdomain
        # (3+ parts), e.g. "tr.snapchat.com", "cs.media.net", "l.sharethis.com".
        # Real trackers often use terse, meaningless-looking labels to stay
        # inconspicuous. WEAK combining signal only (0.25 alone stays under
        # the 0.4 flag threshold) - a single one-off query to a short-labeled
        # subdomain is still allowed by default; this only tips the balance
        # together with rate-burst or entropy evidence. Restricted to alpha-
        # only labels so numeric/alphanumeric infra shards (e.g. "s3", "c1")
        # used by legitimate CDNs don't match.
        if parts >= 3 and len(first) <= 2 and first.isalpha():
            score += 0.25
            reasons.append(f"short cryptic subdomain label: {first}")

        # S7 - confirmed DGA registrable label (T1568.002 - C2). This is a
        # different threat class from trackers (algorithmic malware C2, not
        # ad-tech), and is a corroborated, precision-first verdict - length +
        # entropy + bigram-implausibility must all agree - so it is strong
        # enough to block on its own. Evaluated on the REGISTRABLE label, so a
        # gibberish CDN hostname under a real parent (d1anzk....cloudfront.net)
        # never triggers it. See valkyrie/dga.py for the honest boundary.
        dga = classify_dga(domain)
        if dga.is_dga:
            score = max(score, dga.confidence)
            reasons.append(dga.reason)

        # S8 - wildcard IP-echo DNS provider (nip.io family). The registrable
        # base belongs to the provider, so S7's registrable-label analysis is
        # structurally blind here; re-run DGA on the LEFTMOST label (the only
        # slot an attacker controls) and add a combining signal for the
        # provider itself. A hostname that embeds a loopback/private IP -
        # publicly resolving into the caller's own network - adds more.
        dyndns_fired = is_dyndns_root(domain)
        if dyndns_fired:
            score += 0.35
            reasons.append(f"wildcard dynamic-DNS provider: {_root_domain(domain)}")
            eff = effective_label(domain)
            # Synthesize "<label>.com" so classify_dga treats the payload
            # label as the registrable label it was built to judge.
            eff_dga = classify_dga(f"{eff}.com")
            if eff_dga.is_dga:
                score = max(score, eff_dga.confidence)
                reasons.append(f"generated payload label on wildcard DNS: {eff_dga.reason}")
                dga = eff_dga
            if embedded_private_ip(domain):
                score += 0.2
                reasons.append("loopback/private IP embedded in hostname")

        # S9 - unique-subdomain flood (DNS tunnelling shape, T1048.003).
        # Aggregate signal no single query can show: many never-seen
        # machine-generated labels under one base inside the window. Runs
        # live on every query, like S4 - never from cache.
        t_score, t_reason = self._tunnel.record_and_score(domain)
        tunnel_fired = t_score >= 0.75
        if t_score > 0:
            score += t_score
            reasons.append(t_reason)

        score = min(1.0, score)

        # Decision - default is ALLOW. Category priority mirrors evidence
        # strength: a flood verdict is "tunnel" (T1048.003), a DGA verdict
        # "dga" (T1568.002), a wildcard-provider-driven verdict "dyndns"
        # (T1568 - Dynamic Resolution), otherwise a positive is a "tracker".
        threat_category = ("tunnel" if tunnel_fired
                           else "dga" if dga.is_dga
                           else "dyndns" if dyndns_fired else "tracker")
        if score >= SCANNER_BLOCK_THRESHOLD:
            decision = "block"
            category = threat_category
        elif score >= SCANNER_FLAG_THRESHOLD:
            decision = "flag"
            category = threat_category
        else:
            decision = "allow"
            category = "legitimate"

        return ScanResult(
            decision=decision,
            confidence=round(score, 3),
            reasons=reasons,
            category=category,
        )
