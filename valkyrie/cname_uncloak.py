"""CNAME-cloak uncloaking — the modern tracker-evasion countermeasure.

The single biggest way trackers evade DNS blocklists today is **CNAME cloaking**.
A site publishes a *first-party-looking* subdomain — e.g. ``metrics.brand.com`` —
as a CNAME to the tracker's own domain — e.g. ``brand.eulerian.net``. To every
DNS blocklist the queried name is ``metrics.brand.com``, which looks first-party
and is on no list; the answer IP is just the tracker's CDN, in no IP blocklist.
The tracker rides in on the CNAME chain, unseen. Criteo, Adobe (Experience
Cloud / Audience Manager), AT Internet, Keyade, Commanders Act and others all
ship this as a product.

Top-tier blockers (uBlock Origin, NextDNS, AdGuard) defeat it by **uncloaking**:
resolve the CNAME chain and apply the block decision to the *targets*, not just
the queried name. This module is the pure, list-driven core of that — the DNS
interceptor feeds it the CNAME targets parsed from an upstream answer and blocks
the reply if any target is a known first-party-disguised tracker (or trips the
normal scanner/blocklist/threat-intel checks).

Kept deliberately pure (no dnspython, no I/O) so it is unit-tested in isolation;
the wire parsing lives in dns_interceptor where the DNS library already is.
"""

from __future__ import annotations

from typing import Optional


# Curated apex domains of the well-known CNAME-cloaking tracker providers.
# These are almost never seen as a *queried* name (so they rarely appear on a
# general adblock domain list) — they exist only as CNAME targets behind a
# customer's first-party subdomain, which is exactly why uncloaking is needed to
# catch them. Sourced from the widely-used AdGuard / NextDNS "CNAME-cloaked
# trackers" sets; this is a seed that grows the same way a blocklist does.
CNAME_TRACKERS: frozenset = frozenset({
    # Adobe Experience Cloud / Audience Manager / Analytics
    "2o7.net", "omtrdc.net", "demdex.net", "everesttech.net", "adobedc.net",
    "hitbox.com", "adobe.com.ssl.d1.sc.omtrdc.net",
    # AT Internet / Piano Analytics
    "ati-host.net", "at-o.net", "aticdn.net",
    # Eulerian
    "eulerian.net",
    # Criteo
    "criteo.com", "criteo.net", "storetail.io", "dnsdelegation.io",
    # Keyade
    "keyade.com",
    # Commanders Act (TagCommander)
    "tagcommander.com", "commander1.com",
    # Webtrekk / Mapp
    "webtrekk.net", "wt-eu02.net", "mateti.net",
    # Act-On / Oracle Eloqua / Marketo / Pardot marketing automation
    "actonsoftware.com", "actonservice.com", "hs-analytics.net",
    "eloqua.com", "en25.com", "mktoresp.com", "pardot.com",
    # Others repeatedly documented as CNAME-cloaking
    "wizaly.com", "intentiq.com", "agkn.com", "affise.com",
    "gr-cdn.com", "dc-storm.com", "sailthru.com", "wa.st-a.net",
    "online-metrix.net", "brightcove.net.rtb", "partners.tremorhub.com",
})


def _norm(host: str) -> str:
    return (host or "").strip().rstrip(".").lower()


def suffix_match(host: str, apex_set: frozenset) -> Optional[str]:
    """Return the apex from *apex_set* that *host* is equal to or a subdomain of,
    else None. Boundary-safe: ``noteulerian.net`` does NOT match ``eulerian.net``
    (only ``x.eulerian.net`` or ``eulerian.net`` do)."""
    h = _norm(host)
    if not h:
        return None
    for apex in apex_set:
        if h == apex or h.endswith("." + apex):
            return apex
    return None


def matches_cname_tracker(host: str) -> Optional[str]:
    """Return the matched known-cloaking-tracker apex for *host*, else None."""
    return suffix_match(host, CNAME_TRACKERS)


def same_registrable(a: str, b: str) -> bool:
    """Cheap check that two hosts share the last two labels (registrable-ish).

    Used only to skip the *first-party* CNAME case (``www.brand.com`` →
    ``brand.com.edgekey.net`` shares nothing, but ``a.brand.com`` →
    ``b.brand.com`` does): a CNAME that stays within the queried site's own
    last-two-labels is not cloaking. This is a conservative helper, not a real
    PSL lookup — it only ever *suppresses* a match, and the curated tracker set
    is checked independently, so it cannot cause a tracker to be missed.
    """
    ha, hb = _norm(a).split("."), _norm(b).split(".")
    return len(ha) >= 2 and len(hb) >= 2 and ha[-2:] == hb[-2:]
