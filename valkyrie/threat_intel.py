"""Threat-intelligence feed engine - real IOCs, matched locally.

The seed/downloaded blocklists cover ads and trackers; the firewall CIDR
feeds cover network hygiene ranges. What neither covers is *active threat
infrastructure*: botnet command-and-control servers and live malware
distribution sites, which rotate in hours, not weeks. This module closes
that gap with curated public IOC feeds (abuse.ch) and purely local
matching:

  feodo_c2      - Feodo Tracker botnet C2 IPs (Emotet/Dridex/QakBot class)
  urlhaus       - URLhaus malware-distribution domains (hosts format)
  urlhaus_url   - URLhaus malware-distribution FULL URLs (path-level)
  sslbl_c2      - SSL Blacklist botnet C2 IPs (TLS-fingerprinted)

Three indicator kinds, three enforcement seams: an ``ip`` matches at the
firewall/network-collector, a ``domain`` matches at DNS, and a ``url``
matches only where a full URL is visible - the TLS inspector. URL matching
is what distinguishes a compromised-but-legitimate host (block the one
malicious path) from a wholly malicious domain (block the name); see
``ThreatIntelManager.match_url``.

Design contract (same posture as blocklist.py / firewall.py):

  * Downloads are opt-in (``USE_EXTERNAL_LISTS`` / --download-lists) and the
    only network traffic this module ever produces is the periodic feed
    fetch. Matching is O(1) set lookup on-box - no indicator, domain, or IP
    ever leaves the machine. There is no per-query cloud lookup, ever.
  * A previously downloaded cache on disk is always honoured offline.
  * Every fetch failure is contained: the stale cache stays in force and
    the caller never sees an exception (fault isolation).
  * Guard rails: private/loopback/reserved IPs and dotless or localhost
    names can never enter the match sets, even from a poisoned or corrupt
    cache - feeds are untrusted input like any other.

A hit is *incident-grade* signal, distinct from an ad-domain block:
``match_domain``/``match_ip`` return the feed and category so the DNS
pipeline and the EDR correlator can label the event ``threat_intel`` with
high severity.
"""

from __future__ import annotations

import ipaddress
import json
import threading
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from .config import (
    THREAT_INTEL_DIR,
    THREAT_INTEL_MAX_AGE_HOURS,
    THREAT_INTEL_REFRESH_SECONDS,
    THREAT_INTEL_SOURCES,
    USE_EXTERNAL_LISTS,
)

_SKIP_NAMES = {"localhost", "localhost.localdomain", "local", "broadcasthost"}


# ---------------------------------------------------------------------------
# Feed description + match result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IntelFeed:
    """One IOC source: where it lives and what kind of indicator it yields."""
    name:     str   # short id, also the cache filename stem
    kind:     str   # "ip" | "domain"
    category: str   # e.g. "botnet_c2", "malware_distribution"
    url:      str


@dataclass(frozen=True)
class IntelMatch:
    """A confirmed indicator hit - carries provenance for the incident."""
    indicator: str
    feed:      str
    category:  str

    @property
    def reason(self) -> str:
        return f"threat_intel:{self.feed}:{self.category}"


# ---------------------------------------------------------------------------
# Parsing (pure functions - unit-testable offline)
# ---------------------------------------------------------------------------

def _valid_public_ip(token: str) -> Optional[str]:
    """Return the normalized IP if token is a routable public address."""
    try:
        ip = ipaddress.ip_address(token.strip())
    except ValueError:
        return None
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified):
        return None
    return str(ip)


def _valid_domain(token: str) -> Optional[str]:
    """Return the normalized domain, or None for junk/guarded names."""
    d = token.strip().rstrip(".").lower()
    if not d or "." not in d or len(d) > 253 or d in _SKIP_NAMES:
        return None
    if _valid_public_ip(d) is not None or d.replace(".", "").isdigit():
        return None   # an IP is not a domain indicator
    if any(not part or len(part) > 63 for part in d.split(".")):
        return None
    if not all(c.isalnum() or c in ".-_" for c in d):
        return None
    return d


def normalize_url(token: str) -> Optional[str]:
    """Canonical form for URL matching: ``host[:port]/path[?query]``.

    Both sides of a comparison (the feed indicator and the live request) run
    through this, so a match is insensitive to scheme, case, a default port,
    a fragment, and a trailing slash - the differences that are noise, not
    identity. The QUERY IS KEPT: for malware distribution the query string is
    frequently the payload selector, so dropping it would over-match.

    Returns None for anything whose host fails the same guard rails as every
    other indicator (private/loopback/reserved IPs, dotless or localhost
    names) - a poisoned feed must never be able to make Valkyrie block
    internal infrastructure.
    """
    t = (token or "").strip()
    if not t or len(t) > 2048:
        return None
    # Strip scheme (feeds carry http:// and https:// for the same host+path).
    for scheme in ("http://", "https://"):
        if t.lower().startswith(scheme):
            t = t[len(scheme):]
            break
    t = t.split("#", 1)[0]                       # fragment is client-side only
    if not t:
        return None
    authority, sep, rest = t.partition("/")
    authority = authority.lower()
    # Reject embedded credentials rather than trying to interpret them.
    if "@" in authority:
        return None
    host, _, port = authority.partition(":")
    if port and not port.isdigit():
        return None
    if port in ("80", "443"):
        port = ""                                # default ports carry no identity
    # Same guard rails as the other indicator kinds - an IP host must be
    # public and routable, a name host must be a real dotted domain.
    if _valid_public_ip(host) is None and _valid_domain(host) is None:
        return None
    path = (sep + rest) if sep else ""
    if path == "/":
        path = ""                                # "host/" and "host" are the same
    out = host + (":" + port if port else "") + path
    return out or None


def parse_feed(text: str, kind: str) -> set[str]:
    """Extract indicators of ``kind`` from one feed body.

    Tolerant of the formats these feeds actually use - bare-value lines
    (Feodo), hosts format ``127.0.0.1<tab>domain`` (URLhaus hostfile), and
    CSV rows with the indicator in some column (SSLBL) - plus ``#``
    comments. Anything that fails validation is silently dropped; a feed
    can only ever contribute well-formed public indicators.
    """
    validate: Callable[[str], Optional[str]] = (
        _valid_public_ip if kind == "ip"
        else normalize_url if kind == "url"
        else _valid_domain)
    out: set[str] = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        # A URL feed is one full URL per line - splitting on whitespace/commas
        # would shred a URL that legitimately contains a comma in its query.
        if kind == "url":
            v = validate(line.strip('"'))
            if v is not None:
                out.add(v)
            continue
        # Hosts format: the sinkhole IP prefix is transport, not indicator.
        tokens = line.replace(",", " ").split()
        if kind == "domain" and len(tokens) >= 2 and tokens[0] in (
                "0.0.0.0", "127.0.0.1"):
            tokens = tokens[1:]
        for tok in tokens:
            tok = tok.strip('"')
            v = validate(tok)
            # ThreatFox CSV carries "ip:port" - strip the port and retry.
            # One colon only: an IPv6 literal has several and must not be
            # truncated into a bogus address.
            if v is None and kind == "ip" and tok.count(":") == 1:
                v = validate(tok.rsplit(":", 1)[0])
            if v is not None:
                out.add(v)
                break   # one indicator per line in every supported format
    return out


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class ThreatIntelManager:
    """Loads, caches, refreshes and matches the IOC feed set.

    Thread-safe: match sets are swapped atomically under a lock; a refresh
    never leaves a partially updated view. All failures degrade to the last
    good cache - this component can lose freshness but never break DNS or
    telemetry.
    """

    def __init__(self, feeds: Optional[list[IntelFeed]] = None,
                 cache_dir: Optional[Path] = None) -> None:
        self._feeds = feeds if feeds is not None else [
            IntelFeed(*f) for f in THREAT_INTEL_SOURCES]
        self._dir = Path(cache_dir) if cache_dir else THREAT_INTEL_DIR
        self._lock = threading.RLock()
        self._ips:     frozenset[str] = frozenset()
        self._domains: frozenset[str] = frozenset()
        self._urls:    frozenset[str] = frozenset()
        # indicator -> (feed, category); provenance for incident reasons
        self._origin: dict[str, tuple[str, str]] = {}
        self._feed_status: dict[str, dict] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._wake = threading.Event()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self, console=None, allow_download: Optional[bool] = None) -> int:
        """Read cached feeds (refreshing stale ones if downloads allowed).

        Returns total indicator count. Never raises.
        """
        if allow_download is None:
            allow_download = USE_EXTERNAL_LISTS
        if allow_download:
            self.refresh(console, only_stale=True)
        self._rebuild_from_cache()
        n = self.count()
        if console:
            if n:
                console.print(
                    f"[dim]Threat intel: {n:,} IOCs "
                    f"({len(self._domains):,} domains, {len(self._ips):,} IPs, "
                    f"{len(self._urls):,} URLs) "
                    f"from {sum(1 for s in self._feed_status.values() if s.get('count'))}"
                    f"/{len(self._feeds)} feeds[/dim]")
            else:
                console.print(
                    "[dim]Threat intel: no cached feeds"
                    + ("" if allow_download else " (downloads off)")
                    + " — DNS/behavioral layers unaffected[/dim]")
        return n

    def start(self, allow_download: Optional[bool] = None) -> None:
        """Begin periodic background refresh (no-op when downloads are off)."""
        if allow_download is None:
            allow_download = USE_EXTERNAL_LISTS
        if not allow_download or self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._refresh_loop, daemon=True, name="threat-intel")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    # ------------------------------------------------------------------
    # Matching (hot path - O(1) set membership, no I/O, no locks held long)
    # ------------------------------------------------------------------

    def match_ip(self, ip: str) -> Optional[IntelMatch]:
        # Never flag a well-known public DNS resolver (Google/Cloudflare/Quad9):
        # Valkyrie's own upstream forwarders live here, and a stale or over-broad
        # feed entry must not paint them as C2. See valkyrie/trust.py.
        from .trust import is_public_resolver_ip
        if is_public_resolver_ip(ip):
            return None
        with self._lock:
            if ip in self._ips:
                feed, cat = self._origin.get(ip, ("unknown", "ioc"))
                return IntelMatch(ip, feed, cat)
        return None

    def match_domain(self, domain: str) -> Optional[IntelMatch]:
        """Exact and parent-domain match (evil.example also hits x.evil.example)."""
        d = domain.rstrip(".").lower()
        parts = d.split(".")
        with self._lock:
            for i in range(len(parts) - 1):
                cand = ".".join(parts[i:])
                if cand in self._domains:
                    feed, cat = self._origin.get(cand, ("unknown", "ioc"))
                    return IntelMatch(cand, feed, cat)
        return None

    def match_url(self, url: str) -> Optional[IntelMatch]:
        """Exact match on a full URL (host[:port]/path[?query]).

        This is the path-level counterpart to ``match_domain``, and it is
        deliberately EXACT rather than prefix/parent-based: malware
        distribution is overwhelmingly hosted on otherwise-innocent
        compromised sites, so a hit on ``example.com/wp/uploads/x.exe`` says
        nothing about ``example.com`` itself. Matching the whole path is what
        makes it safe to act on - blocking the parent domain from a URL
        indicator would take down the legitimate site with it.

        Requires the TLS inspector (the only component that sees a full HTTPS
        URL); the DNS path can only ever match the domain.
        """
        norm = normalize_url(url)
        if norm is None:
            return None
        with self._lock:
            if norm in self._urls:
                feed, cat = self._origin.get(norm, ("unknown", "ioc"))
                return IntelMatch(norm, feed, cat)
        return None

    def count(self) -> int:
        with self._lock:
            return len(self._ips) + len(self._domains) + len(self._urls)

    def status(self) -> dict:
        """Dashboard/status surface: per-feed freshness and counts."""
        with self._lock:
            return {
                "total": len(self._ips) + len(self._domains) + len(self._urls),
                "domains": len(self._domains),
                "ips": len(self._ips),
                "urls": len(self._urls),
                "feeds": {k: dict(v) for k, v in self._feed_status.items()},
            }

    # ------------------------------------------------------------------
    # Refresh
    # ------------------------------------------------------------------

    def refresh(self, console=None, only_stale: bool = False) -> None:
        """Fetch feeds and update caches. Per-feed failures are contained."""
        def _print(msg: str) -> None:
            if console:
                console.print(msg)

        self._dir.mkdir(parents=True, exist_ok=True)
        for feed in self._feeds:
            cache = self._cache_path(feed)
            if only_stale and not self._is_stale(cache):
                continue
            try:
                req = urllib.request.Request(
                    feed.url, headers={"User-Agent": "Valkyrie-ThreatIntel/1.0"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    text = resp.read().decode("utf-8", errors="replace")
                indicators = parse_feed(text, feed.kind)
                if not indicators:
                    # An empty parse of a live fetch is a format change or an
                    # outage page - keep the stale cache rather than wiping
                    # protection (fail-safe, no silent success).
                    _print(f"  [yellow]threat intel {feed.name}: 0 indicators "
                           f"parsed — keeping previous cache[/yellow]")
                    continue
                tmp = cache.with_suffix(".tmp")
                tmp.write_text("\n".join(sorted(indicators)) + "\n",
                               encoding="utf-8")
                tmp.replace(cache)   # atomic on the same volume
                meta = {"fetched_at": datetime.now(timezone.utc).isoformat(),
                        "count": len(indicators), "url": feed.url}
                self._meta_path(feed).write_text(
                    json.dumps(meta), encoding="utf-8")
                _print(f"  threat intel {feed.name}: {len(indicators):,} IOCs")
            except Exception as exc:
                _print(f"  [yellow]threat intel {feed.name}: fetch failed "
                       f"({exc}) — keeping previous cache[/yellow]")
        self._rebuild_from_cache()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _cache_path(self, feed: IntelFeed) -> Path:
        return self._dir / f"{feed.name}.txt"

    def _meta_path(self, feed: IntelFeed) -> Path:
        return self._dir / f"{feed.name}.meta.json"

    def _is_stale(self, cache: Path) -> bool:
        try:
            age = time.time() - cache.stat().st_mtime
        except OSError:
            return True
        return age > THREAT_INTEL_MAX_AGE_HOURS * 3600

    def _rebuild_from_cache(self) -> None:
        """Re-derive the match sets from disk. Revalidates every line -
        the cache is untrusted input (defense in depth)."""
        ips: set[str] = set()
        domains: set[str] = set()
        urls: set[str] = set()
        origin: dict[str, tuple[str, str]] = {}
        status: dict[str, dict] = {}
        for feed in self._feeds:
            cache = self._cache_path(feed)
            entry: dict = {"count": 0, "fresh": False, "fetched_at": None,
                           "kind": feed.kind, "category": feed.category}
            try:
                text = cache.read_text(encoding="utf-8")
            except OSError:
                status[feed.name] = entry
                continue
            found = parse_feed(text, feed.kind)
            for ind in found:
                origin.setdefault(ind, (feed.name, feed.category))
            {"ip": ips, "url": urls}.get(feed.kind, domains).update(found)
            entry["count"] = len(found)
            entry["fresh"] = not self._is_stale(cache)
            try:
                entry["fetched_at"] = json.loads(
                    self._meta_path(feed).read_text(encoding="utf-8")
                ).get("fetched_at")
            except Exception:
                pass
            status[feed.name] = entry
        with self._lock:
            self._ips = frozenset(ips)
            self._domains = frozenset(domains)
            self._urls = frozenset(urls)
            self._origin = origin
            self._feed_status = status

    # Seconds to wait before the FIRST background refresh. Long enough for
    # startup to finish (so the fetch never competes with bringing protection
    # up), short enough that a machine which has been offline for weeks gets
    # current IOCs within a minute of booting - not in six hours.
    _INITIAL_REFRESH_DELAY = 20.0

    def _refresh_loop(self) -> None:
        # First pass runs on a SHORT delay, not the full 6h interval. Startup
        # deliberately loads cache-only (protection must never wait on the
        # network - an offline box would otherwise stall for up to 30s per
        # feed on urllib timeouts), so without this the first refresh of a
        # stale cache would be six hours away.
        first = True
        while self._running:
            self._wake.wait(timeout=(self._INITIAL_REFRESH_DELAY if first
                                     else THREAT_INTEL_REFRESH_SECONDS))
            first = False
            if not self._running:
                return
            try:
                self.refresh(only_stale=True)
            except Exception:
                pass   # loop must survive anything; next tick retries
