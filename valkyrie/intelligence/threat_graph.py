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
        finally:
            conn.close()
        with self._lock:
            for domain, ip, base, prefix in rows:
                self._index(domain, ip, base, prefix)

    def _index(self, domain: str, ip: str, base: str, prefix: str) -> None:
        self._domains.add(domain)
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

    def is_related(self, domain: str, ip: str = "") -> float:
        """0.0–1.0 relatedness of a NEW domain/IP to known threats."""
        domain = domain.lower().rstrip(".")
        base   = _base_domain(domain)
        with self._lock:
            if domain in self._domains:
                return R_EXACT
            score = 0.0
            if self._bases.get(base, 0) > 0:
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
        base   = _base_domain(domain)
        with self._lock:
            if domain in self._domains:
                return f"{domain} is a recorded threat"
            if self._bases.get(base, 0) > 0:
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
