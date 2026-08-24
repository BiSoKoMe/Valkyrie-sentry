"""Popular-legitimate-domains guard — the false-positive floor.

A live test on a real machine found Valkyrie sinkholing microsoft.com, bing.com,
live.com, linkedin.com and paypal.com. Root cause: weak *behavioural* signals
(a per-process "query burst", "domain never seen from this process", "background
process") fire naturally on the highest-traffic legitimate domains — Windows and
background services hammer microsoft.com/live.com constantly — and once such a
domain is learned "bad" it is served from memory forever. A security tool that
blocks paypal.com is worse than useless; the user just turns it off.

This module is the floor that prevents that entire class of self-inflicted
false positive: a small, curated set of registrable domains that are, by
definition, not attacker infrastructure (they ARE the real companies). The
guard's rule is narrow and safe:

  * A popular domain may still be FLAGGED, and its subdomains may still be
    blocked by the EXPLICIT tracker/telemetry blocklist (that is a separate
    path — e.g. `telemetry.microsoft.com` stays blocked while `microsoft.com`
    does not). Threat-intel IOC feeds and user rules are also unaffected.
  * A popular domain is NEVER *learned bad* and never *blocked by behavioural /
    anomaly / rate heuristics alone*. Those signals are too weak to overrule the
    ground truth that paypal.com is PayPal.

This is exactly what mature blockers ship as a "do-not-block" / allowlist floor.
It is intentionally conservative — a few hundred registrable domains, not a
top-million — because every entry must be one nobody could argue is malicious.
"""

from __future__ import annotations

# Registrable domains that are, by definition, legitimate. Matched by suffix
# (a host equals one of these or is a subdomain of it). Curated toward the
# domains most likely to be hammered by background/system processes — the ones
# the behavioural heuristics false-positive on.
POPULAR_DOMAINS: frozenset = frozenset({
    # ── Microsoft / Windows / Office (the worst offenders: constant bg traffic)
    "microsoft.com", "windows.com", "windowsupdate.com", "live.com", "office.com",
    "office365.com", "outlook.com", "msn.com", "bing.com", "microsoftonline.com",
    "azure.com", "azureedge.net", "windows.net", "msftconnecttest.com",
    "msedge.net", "sharepoint.com", "onedrive.com", "skype.com", "xbox.com",
    "visualstudio.com", "github.com", "githubusercontent.com", "githubassets.com",
    # ── Apple
    "apple.com", "icloud.com", "mzstatic.com", "cdn-apple.com", "apple-dns.net",
    # ── Google
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "youtube.com", "ytimg.com", "ggpht.com",
    "android.com", "chrome.com", "withgoogle.com", "goo.gl", "gmail.com",
    # ── Amazon / AWS
    "amazon.com", "amazonaws.com", "aws.amazon.com", "media-amazon.com",
    "ssl-images-amazon.com", "cloudfront.net", "primevideo.com", "a2z.com",
    # ── CDNs / infra (blocking these breaks half the web)
    "cloudflare.com", "cloudflare-dns.com", "akamai.net", "akamaized.net",
    "akamaiedge.net", "edgekey.net", "edgesuite.net", "fastly.net", "fastlylb.net",
    "jsdelivr.net", "cdnjs.com", "unpkg.com",
    "digicert.com", "letsencrypt.org", "sectigo.com", "globalsign.com",
    "gvt1.com", "gvt2.com",
    # (Deliberately excluded: doubleclick.net, google-analytics.com and other
    #  ad/analytics hosts — those are trackers this floor must never protect.)
    # ── Social / comms
    "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.com", "messenger.com",
    "twitter.com", "x.com", "twimg.com", "linkedin.com", "licdn.com",
    "reddit.com", "redditstatic.com", "redd.it", "discord.com", "discordapp.com",
    "slack.com", "slack-edge.com", "zoom.us", "telegram.org", "t.me",
    "tiktok.com", "snapchat.com", "pinterest.com", "twitch.tv",
    # ── Payments / finance / commerce (blocking these is unacceptable)
    "paypal.com", "paypalobjects.com", "visa.com", "mastercard.com",
    "americanexpress.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "citi.com", "capitalone.com", "stripe.com", "squareup.com", "coinbase.com",
    "ebay.com", "ebayimg.com", "etsy.com", "shopify.com", "walmart.com",
    "target.com", "bestbuy.com", "aliexpress.com", "alibaba.com",
    # ── Media / streaming / productivity
    "netflix.com", "nflxvideo.net", "nflximg.net", "spotify.com", "scdn.co",
    "hulu.com", "disneyplus.com", "adobe.com", "adobe.io", "typekit.net",
    "dropbox.com", "dropboxstatic.com", "box.com", "atlassian.com", "atlassian.net",
    "notion.so", "figma.com", "canva.com", "zoom.com",
    # ── Dev / knowledge
    "stackoverflow.com", "stackexchange.com", "sstatic.net", "wikipedia.org",
    "wikimedia.org", "mozilla.org", "mozilla.net", "firefox.com", "npmjs.com",
    "pypi.org", "python.org", "docker.com", "docker.io", "gitlab.com",
    "wordpress.com", "wp.com", "medium.com", "gravatar.com",
    # ── Misc high-traffic legit
    "yahoo.com", "yahooapis.com", "duckduckgo.com", "cloudinary.com",
    "gstatic.cn", "office.net", "azurewebsites.net", "windows.microsoft.com",
})

# Registrable-domain suffixes that use a two-label public suffix, so a host's
# "registrable" part is the last THREE labels (bbc.co.uk, not co.uk).
_TWO_LEVEL_TLDS: frozenset = frozenset({
    "co.uk", "com.au", "co.jp", "co.nz", "co.in", "com.br", "co.za", "com.mx",
    "co.kr", "com.tr", "com.sg", "com.hk", "org.uk", "gov.uk", "ac.uk", "net.au",
})


def _norm(host: str) -> str:
    return (host or "").strip().rstrip(".").lower()


def is_popular(host: str) -> bool:
    """True if *host* equals or is a subdomain of a curated popular domain.

    Suffix-matched and boundary-safe: ``notmicrosoft.com`` does NOT match
    ``microsoft.com`` (only ``microsoft.com`` or ``x.microsoft.com`` do)."""
    h = _norm(host)
    if not h:
        return False
    if h in POPULAR_DOMAINS:
        return True
    for p in POPULAR_DOMAINS:
        if h.endswith("." + p):
            return True
    return False


# Non-navigable infrastructure names. A process does not "reach" these the way
# it reaches a website — they are reverse-DNS (PTR) lookups the OS performs
# constantly, and local-network resolution. Treating them as "a domain outside
# the baseline" is what produced a wall of `Baseline anomaly for <legit proc>`
# and `Beacon-like callbacks` false positives on real hardware (every Windows
# process does different PTR lookups all the time, and repeated ones look
# periodic without being C2).
#
# NOTE: this exempts only the *anomaly / beacon* heuristics. The DNS-tunnelling
# and DGA detectors are NOT gated on this, because tunnelling can abuse PTR
# queries and those detectors carry their own corroboration (unique-label
# flood, entropy+bigram agreement) rather than "unseen == suspicious".
_INFRA_SUFFIXES = (".in-addr.arpa", ".ip6.arpa", ".arpa", ".local",
                   ".home.arpa", ".localdomain")


def is_infrastructure_domain(host: str) -> bool:
    """True for reverse-DNS / local-resolution names that are not a threat
    signal on their own (so the baseline-anomaly and beacon heuristics skip
    them)."""
    h = _norm(host)
    if not h:
        return False
    if h in ("localhost", "wpad", "isatap"):
        return True
    return h.endswith(_INFRA_SUFFIXES)


# RFC 2606 reserved documentation/test domains — guaranteed non-real, never
# an actual site. A name under these can look exactly as suspicious as real
# attacker infrastructure by string alone (e.g. "malware-c2-test.example.com"
# is a stock red-team test lookup), so it must never be eligible for the
# "N consistently clean queries -> known-good" promotion in
# intelligence/classifier.py. That heuristic rewards patience, not
# legitimacy — a domain (red-team test or a genuinely patient C2) that is
# simply queried enough times without another signal firing would otherwise
# earn a durable whitelist entry that bypasses all future scanning.
_RESERVED_TEST_DOMAINS = frozenset({
    "example.com", "example.net", "example.org", "example.edu",
})
_RESERVED_TEST_SUFFIXES = (".example", ".test", ".invalid")


def is_reserved_test_domain(host: str) -> bool:
    """True for RFC 2606 reserved documentation/test domains."""
    h = _norm(host)
    if not h:
        return False
    if h in _RESERVED_TEST_DOMAINS:
        return True
    for d in _RESERVED_TEST_DOMAINS:
        if h.endswith("." + d):
            return True
    return h.endswith(_RESERVED_TEST_SUFFIXES)
