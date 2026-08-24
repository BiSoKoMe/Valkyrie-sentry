"""ThreatGraph — maps relationships between known threats so that new
domains sharing infrastructure with a confirmed threat are caught
automatically, before they ever appear on any list.

Relations scored by ``is_related``:
    exact domain already recorded          1.0
    shares base domain with a threat       0.65  (flag range — see note)
    IP in same /24 subnet as a threat      0.6
    same tracker-style subdomain prefix    0.5

Note on base-domain sharing: the spec example is
``telemetry.acme.com`` known bad → ``analytics.acme.com`` auto-FLAGGED.
A shared base alone therefore lands in the flag band, not the block
band — blocking every subdomain of a large mixed-use domain because one
subdomain tracked you would break real sites.  Combined with anomaly
signals the classifier can still push a related domain over the block
threshold.

Persistence: SQLite via the existing Store.
"""

from __future__ import annotations

import threading
from datetime import datetime

from ..config import TRACKER_PREFIXES
from ..popular_domains import is_infrastructure_domain, is_popular

R_EXACT  = 1.0
R_BASE   = 0.65
R_SUBNET = 0.6
R_PREFIX = 0.5


def _base_domain(domain: str) -> str:
    parts = domain.lower().rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _first_label(domain: str) -> str:
    return domain.lower().rstrip(".").split(".")[0]


def _subnet24(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else ""


class ThreatGraph:
    """Infrastructure-relationship graph over confirmed threats."""

    def __init__(self, store) -> None:
        self._store = store
        self._lock = threading.RLock()
        self._domains:  set[str] = set()          # exact threat domains
        self._bases:    dict[str, int] = {}       # base domain -> threat count
        self._subnets:  set[str] = set()          # /24 prefixes of threat IPs
        self._prefixes: set[str] = set()          # first labels of threats
        # Domains purged at startup because a popular/known-legitimate domain
        # was wrongly recorded as a threat. Exposed purely for operator-visible
        # logging (see Intelligence.start).
        self.purged_popular: list[str] = []

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        conn = self._store.connection()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS intel_threats (
                    domain      TEXT PRIMARY KEY,
                    ip          TEXT NOT NULL DEFAULT '',
                    base_domain TEXT NOT NULL DEFAULT '',
                    prefix      TEXT NOT NULL DEFAULT '',
                    added       TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_intel_threats_base
                    ON intel_threats(base_domain);
            """)
            conn.commit()
            rows = conn.execute(
                "SELECT domain, ip, base_domain, prefix FROM intel_threats"
            ).fetchall()
            # SELF-HEAL: a popular/known-legitimate domain must never sit in the
            # threat graph — see record_threat for why (base-domain self-
            # poisoning of large multi-tenant domains like microsoft.com, found
            # live: array508.prod.do.dsp.mp.microsoft.com had been recorded,
            # making every microsoft.com query "share infrastructure" with
            # itself). Purge at startup so an already-poisoned install is cured
            # the moment this build runs, no manual cleanup needed — same
            # pattern as IntelligenceMemory's popular/tracker self-heals.
            stale = [d for (d, _ip, _b, _p) in rows if is_popular(d)]
            if stale:
                conn.executemany("DELETE FROM intel_threats WHERE domain=?",
                                 [(d,) for d in stale])
                conn.commit()
                stale_set = set(stale)
                rows = [r for r in rows if r[0] not in stale_set]
        finally:
            conn.close()
        self.purged_popular = stale
        with self._lock:
            for domain, ip, base, prefix in rows:
                self._index(domain, ip, base, prefix)

    def _index(self, domain: str, ip: str, base: str, prefix: str) -> None:
        self._domains.add(domain)
        # NEVER index a reverse-DNS / local name's "base" (in-addr.arpa,
        # ip6.arpa). Their registrable base is the whole PTR namespace, so one
        # bad reverse lookup would make EVERY reverse lookup on the machine
        # "share infrastructure" with it — which is exactly the false positive
        # seen on real hardware (0.65 suspicion on every x.in-addr.arpa). The
        # exact domain is still recorded; only the poisonous base bucket is not.
        if not is_infrastructure_domain(domain):
            self._bases[base] = self._bases.get(base, 0) + 1
        if ip:
            subnet = _subnet24(ip)
            if subnet:
                self._subnets.add(subnet)
        if prefix:
            self._prefixes.add(prefix)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_threat(self, domain: str, ip: str = "") -> None:
        """Add a confirmed threat to the graph (idempotent)."""
        domain = domain.lower().rstrip(".")
        if not domain:
            return
        # A popular/known-legitimate domain (or any subdomain of one) must never
        # enter the graph — not even indirectly via its BASE-domain bucket. This
        # was previously unconditional here, so one odd-looking subdomain under
        # a huge multi-tenant domain (e.g. a Microsoft delivery-optimization
        # host whose name happened to read as ad-tech) poisoned "microsoft.com"
        # itself: every future microsoft.com query then "shared infrastructure"
        # with its own sibling subdomain and got flagged. Mirrors the identical
        # guard IntelligenceMemory.remember_bad already applies — a popular
        # domain's own subdomain being weird is not evidence its apex, or its
        # OTHER subdomains, are compromised infrastructure.
        if is_popular(domain):
            return
        base   = _base_domain(domain)
        prefix = _first_label(domain) if domain.count(".") >= 2 else ""
        with self._lock:
            already = domain in self._domains
            if not already:
                self._index(domain, ip, base, prefix)
        if already:
            return
        try:
            conn = self._store.connection()
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO intel_threats"
                    "(domain, ip, base_domain, prefix, added) VALUES (?,?,?,?,?)",
                    (domain, ip, base, prefix,
                     datetime.utcnow().isoformat(timespec="seconds")),
                )
                conn.commit()
            finally:
                conn.close()
        except Exception:
            pass    # persistence failure must never break the DNS path

    def forget(self, domains) -> int:
        """Remove domains from the threat graph and rebuild the in-RAM index.

        Used to un-poison tracker/telemetry domains that an old bug wrongly
        recorded as threats — otherwise legitimate sites keep 'sharing
        infrastructure' with them (the microsoft.com 0.65 false flag). Returns
        the number of domains removed. Best-effort; never raises.
        """
        want = {d.lower().rstrip(".") for d in (domains or []) if d}
        if not want:
            return 0
        removed = 0
        try:
            conn = self._store.connection()
            try:
                conn.executemany("DELETE FROM intel_threats WHERE domain=?",
                                 [(d,) for d in want])
                conn.commit()
                rows = conn.execute(
                    "SELECT domain, ip, base_domain, prefix FROM intel_threats"
                ).fetchall()
            finally:
                conn.close()
        except Exception:
            return 0
        # Rebuild the in-RAM index from the surviving rows so the base/subnet/
        # prefix buckets a purged threat contributed to are dropped too.
        with self._lock:
            before = len(self._domains)
            self._domains = set()
            self._bases = {}
            self._subnets = set()
            self._prefixes = set()
            for domain, ip, base, prefix in rows:
                self._index(domain, ip, base, prefix)
            removed = max(0, before - len(self._domains))
        return removed

    def is_related(self, domain: str, ip: str = "") -> float:
        """0.0–1.0 relatedness of a NEW domain/IP to known threats."""
        domain = domain.lower().rstrip(".")
        # Reverse-DNS / local names have no meaningful "shared infrastructure":
        # their base is the whole PTR namespace. The IP-subnet relation below is
        # still meaningful for a real IP, so only the base/prefix name-relations
        # are skipped here, not the whole function.
        infra = is_infrastructure_domain(domain)
        base   = _base_domain(domain)
        with self._lock:
            if domain in self._domains:
                return R_EXACT
            score = 0.0
            if not infra and self._bases.get(base, 0) > 0:
                score = max(score, R_BASE)
            if ip:
                subnet = _subnet24(ip)
                if subnet and subnet in self._subnets:
                    score = max(score, R_SUBNET)
            # Naming pattern: tracker-style first label that we have already
            # seen used by a confirmed threat (e.g. "telemetry", "beacon").
            label = _first_label(domain)
            if (domain.count(".") >= 2
                    and label in self._prefixes
                    and label in TRACKER_PREFIXES):
                score = max(score, R_PREFIX)
        return score

    def explain(self, domain: str, ip: str = "") -> str:
        domain = domain.lower().rstrip(".")
        infra  = is_infrastructure_domain(domain)
        base   = _base_domain(domain)
        with self._lock:
            if domain in self._domains:
                return f"{domain} is a recorded threat"
            if not infra and self._bases.get(base, 0) > 0:
                return (f"{domain} shares infrastructure ({base}) with "
                        f"{self._bases[base]} known threat(s)")
            if ip and _subnet24(ip) in self._subnets:
                return f"{ip} is in the same /24 subnet as a known threat"
            label = _first_label(domain)
            if label in self._prefixes and label in TRACKER_PREFIXES:
                return f"'{label}.' subdomain pattern matches known threats"
        return f"{domain}: no known threat relations"

    def count(self) -> int:
        with self._lock:
            return len(self._domains)
