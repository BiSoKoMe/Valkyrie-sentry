"""Central configuration — all constants, paths, and defaults live here."""

import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
# Frozen-build awareness (PyInstaller). When packaged as valkyrie.exe the
# module lives inside an ephemeral temp extraction dir (sys._MEIPASS), so
# writable state (data/, rules, logs) MUST live next to the executable to
# persist across runs — while read-only bundled assets are read from the
# bundle dir. When running from source, both are the repo root, exactly as
# before, so nothing changes for the normal `python -m valkyrie` flow.
if getattr(sys, "frozen", False):
    BASE_DIR   = Path(sys.executable).resolve().parent            # next to the .exe
    BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", BASE_DIR))         # bundled assets
else:
    BASE_DIR   = Path(__file__).resolve().parent.parent
    BUNDLE_DIR = BASE_DIR

DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH        = DATA_DIR / "valkyrie.db"
BLOCKLIST_PATH = DATA_DIR / "blocklist.txt"
RULES_PATH     = BASE_DIR / "valkyrie_rules.yaml"
LOG_PATH       = DATA_DIR / "valkyrie.log"

# ---------------------------------------------------------------------------
# Fleet control plane (multi-device management)
# ---------------------------------------------------------------------------
# Turns Valkyrie from a single-machine tool into an agent that reports to a
# central control plane. Deliberately privacy-preserving: agents send status
# METADATA (health, counts, category tallies) — never raw domains or traffic —
# so the server never becomes a honeypot of client browsing history. See
# valkyrie/fleet/protocol.py for exactly what crosses the wire.
FLEET_DB_PATH             = DATA_DIR / "fleet.db"          # server-side device registry
FLEET_AGENT_IDENTITY_PATH = DATA_DIR / "fleet_agent.json"  # agent-side device id + token
FLEET_SERVER_PORT         = 8091
FLEET_HEARTBEAT_INTERVAL  = 30      # seconds between agent heartbeats
FLEET_OFFLINE_AFTER       = 90      # seconds without a heartbeat -> "offline"
# Env var the server reads for the pre-shared enrollment secret. Agents must
# present this once to enroll; it is NOT the per-device auth token (that is
# issued at enrollment and stored only as a hash server-side).
FLEET_ENROLL_TOKEN_ENV    = "VALKYRIE_FLEET_ENROLL_TOKEN"

# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------
DNS_LISTEN_HOST  = "127.0.0.1"
DNS_LISTEN_PORT  = 5300        # 5353 is taken by mDNS (Brave, svchost) on Windows
DNS_UPSTREAM     = "40.54.1.13"
DNS_UPSTREAM_PORT = 53
DNS_TIMEOUT      = 3.0         # seconds

# Ordered list of upstream resolvers tried in sequence on forward failure
UPSTREAM_SERVERS: list[str] = [
    "8.8.8.8",      # Google — primary
    "1.1.1.1",      # Cloudflare — fallback
    "9.9.9.9",      # Quad9 — fallback
    "40.54.1.13",   # ISP DNS — moved last (often unreachable off-network)
]

SINKHOLE_IPV4 = "0.0.0.0"
SINKHOLE_IPV6 = "::"

# No-leak DNS policy.
#   When the local recursive resolver (Unbound) is the upstream, allowed
#   queries must NOT silently fall back to public resolvers (8.8.8.8,
#   1.1.1.1, 9.9.9.9, ISP) — that would leak the very queries Unbound
#   exists to keep local.  With fallback disabled the interceptor only ever
#   contacts the configured local upstream and returns SERVFAIL on failure
#   (fail-closed), so a plaintext query can never reach a third-party
#   resolver.  This is auto-enabled whenever Unbound is active, and can be
#   forced on (even without Unbound) with --no-dns-leak.
DNS_LOCAL_ONLY = False   # default off → preserves external-resolver behaviour
                         # when the user has no local resolver configured

# ---------------------------------------------------------------------------
# Blocklist updater
# ---------------------------------------------------------------------------
BLOCKLIST_SOURCES = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://big.oisd.nl/domainswild",
]
BLOCKLIST_MAX_AGE_DAYS = 7

# ---------------------------------------------------------------------------
# Behavioral heuristics
# ---------------------------------------------------------------------------
ENTROPY_THRESHOLD      = 3.5    # Shannon entropy above this → suspicious
RATE_WINDOW_SECONDS    = 10     # sliding window for query-rate check
RATE_MAX_QUERIES       = 30     # queries per window per process → suspicious
BEHAVIORAL_BLOCK_SCORE = 0.7    # suspicion score at/above which we block

# TLD reputation — offline replacement for the old WHOIS domain-age signal.
#
# The previous "new domain" signal called python-whois over the network. That
# dependency is not installed and, more importantly, network WHOIS does not work
# in the offline / intelligence-only posture this product ships in — so it
# silently contributed 0 on every domain while looking active (the same class of
# bug as the DNS leak). It is replaced by this static, shipped set of TLDs that
# public abuse telemetry (Spamhaus "Most Abused TLDs", Interisle "Cybercrime
# Supply Chain") consistently rank as disproportionately used for spam, malware,
# phishing, and throwaway tracker infrastructure. Membership is an O(1) set
# lookup with no network dependency, so the signal is always live offline.
#
# Deliberately conservative: this set contains NONE of the mainstream registry
# TLDs (com/net/org/edu/gov/io/co and major ccTLDs) that legitimate sites use,
# so it cannot fire on the benign control set. It carries the same small 0.15
# weight the age signal had and therefore can never, on its own, reach the flag
# (0.40) or block (0.70) threshold — it only nudges a domain already suspicious
# on entropy/rate. It is a supplementary signal, not a primary tracker detector.
SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    # Freenom free-registration TLDs (historically the most abused)
    "tk", "ml", "ga", "cf", "gq",
    # New-gTLD bulk/cheap registrations dominant in abuse rankings
    "top", "xyz", "club", "work", "live", "click", "link", "gdn",
    "loan", "download", "stream", "rest", "buzz", "cyou", "sbs",
    "cfd", "icu", "monster", "quest", "bar", "wtf", "kim", "mom",
    "lol", "cam", "surf", "beauty", "hair", "makeup", "skin",
    "men", "date", "racing", "win", "review", "party", "trade",
    "science", "accountant", "cricket", "faith", "webcam",
})
SUSPICIOUS_TLD_WEIGHT = 0.15    # supplementary weight in the behavioral combine

# ---------------------------------------------------------------------------
# DoH bypass detection
# ---------------------------------------------------------------------------
DOH_PROVIDER_IPS = {
    "1.1.1.1",           # Cloudflare
    "1.0.0.1",           # Cloudflare secondary
    "8.8.8.8",           # Google
    "8.8.4.4",           # Google secondary
    "9.9.9.9",           # Quad9
    "9.9.9.10",          # Quad9 secondary
    "208.67.222.222",    # OpenDNS
    "208.67.220.220",    # OpenDNS secondary
    "94.140.14.14",      # AdGuard
    "94.140.15.15",      # AdGuard secondary
}
DOH_PORT = 443
DOH_SCAN_INTERVAL = 5.0   # seconds between scans

# ---------------------------------------------------------------------------
# Baseline profiler
# ---------------------------------------------------------------------------
BASELINE_WINDOW_HOURS = 24        # hours of data needed before baselines lock in
BASELINE_ANOMALY_LABEL = "anomaly"

# ---------------------------------------------------------------------------
# Store / event writer
# ---------------------------------------------------------------------------
STORE_QUEUE_SIZE   = 10_000
STORE_FLUSH_EVERY  = 50           # rows: flush to DB after this many events

# ---------------------------------------------------------------------------
# Firewall / IP blocker
# ---------------------------------------------------------------------------
FIREWALL_IP_SOURCES = [
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "https://www.spamhaus.org/drop/drop.txt",
    "https://www.spamhaus.org/drop/edrop.txt",
    "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt",
]
FIREWALL_DOH_IPS = [
    "1.1.1.1", "1.0.0.1",            # Cloudflare
    "8.8.8.8", "8.8.4.4",            # Google
    "9.9.9.9", "9.9.9.10",           # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "94.140.14.14", "94.140.15.15",  # AdGuard
]
FIREWALL_MAX_AGE_DAYS = 1            # refresh daily
FIREWALL_IP_PATH      = DATA_DIR / "blocked_ips.txt"

# CIDRs that must never be blocked, no matter what a threat-intel feed claims.
#
# Threat feeds are not clean: they occasionally list reserved, documentation, or
# bogon ranges (RFC 5737 test-nets show up surprisingly often). Firewalling those
# is at best pointless and at worst actively harmful — blocking 169.254.0.0/16
# breaks DHCP/APIPA fallback, 100.64.0.0/10 breaks carrier-grade NAT, 224.0.0.0/4
# breaks multicast (mDNS/SSDP). This set is applied at feed-parse time AND on the
# cache-read path (see firewall.load_ip_blocklist) so a protected range can never
# reach the enforcement set, whatever the source.
FIREWALL_NEVER_BLOCK = [
    # Private / local (RFC 1918) + loopback + link-local
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",   # link-local (RFC 3927) — APIPA
    # Special-use / documentation / bogon ranges that must never be treated as
    # routable threat destinations (RFC 6890 and friends).
    "0.0.0.0/8",        # "this network" (RFC 1122)
    "100.64.0.0/10",    # carrier-grade NAT (RFC 6598)
    "192.0.0.0/24",     # IETF protocol assignments (RFC 6890)
    "192.0.2.0/24",     # TEST-NET-1 documentation (RFC 5737)
    "198.18.0.0/15",    # benchmarking (RFC 2544)
    "198.51.100.0/24",  # TEST-NET-2 documentation (RFC 5737)
    "203.0.113.0/24",   # TEST-NET-3 documentation (RFC 5737)
    "224.0.0.0/4",      # multicast (RFC 5771) — mDNS/SSDP live here
    "240.0.0.0/4",      # reserved / future use, incl. 255.255.255.255 broadcast
    DNS_UPSTREAM,       # upstream resolver — blocking it breaks forwarding
]

# ---------------------------------------------------------------------------
# Unbound local resolver
# ---------------------------------------------------------------------------
UNBOUND_PORT      = 5301
UNBOUND_CONF_PATH = DATA_DIR / "unbound.conf"

# ---------------------------------------------------------------------------
# WireGuard config generator
# ---------------------------------------------------------------------------
WIREGUARD_CONF_PATH   = DATA_DIR / "wg0.conf"
WIREGUARD_CLIENT_PATH = DATA_DIR / "wg_client.conf"
WIREGUARD_PORT        = 51820
WIREGUARD_SUBNET      = "10.13.13.0/24"
WIREGUARD_SERVER_ADDR = "10.13.13.1/24"
WIREGUARD_CLIENT_ADDR = "10.13.13.2/24"

# ---------------------------------------------------------------------------
# Site scanner
# ---------------------------------------------------------------------------

# Pure ad-tech / tracking SLDs — score +0.7, block alone.
TRACKER_SLDS: frozenset[str] = frozenset({
    "doubleclick", "googlesyndication", "googleadservices",
    "googletagmanager", "googletagservices", "google-analytics",
    "fbcdn", "fbsbx", "amazon-adsystem", "amazonaax",
    "scorecardresearch", "quantserve", "comscore",
    "omtrdc", "2o7", "everesttech", "moatads",
    "criteo", "taboola", "outbrain", "adsrvr",
    "adnxs", "rubiconproject", "pubmatic", "openx",
    "telemetry",   # telemetry.* SLDs are pure tracker infra
})

# Analytics / monitoring SLDs — score +0.4, flag only.
ANALYTICS_SLDS: frozenset[str] = frozenset({
    "segment", "mixpanel", "amplitude", "heap",
    "hotjar", "mouseflow", "fullstory", "logrocket",
    "chartbeat", "parsely", "optimizely", "abtasty",
    "newrelic", "datadoghq", "rollbar", "heap-api",
})

# Subdomain prefixes that indicate tracker infrastructure — score +0.7, block alone.
# Only fires when the FIRST label of the domain exactly matches one of these
# AND the domain has 3+ parts (subdomain.domain.tld).
TRACKER_PREFIXES: frozenset[str] = frozenset({
    "tracker", "tracking", "telemetry", "analytics",
    "pixel", "beacon", "collect", "adserver", "adtrack",
})

# Distinctive tracker/analytics brand names for startswith-matching against
# an SLD (e.g. "segmentapis" -> "segment", "taboolasyndication" -> "taboola")
# — catches companies that register variant apex domains for infra/CDN use.
# Curated deliberately to distinctive brand strings only; generic English
# words already in TRACKER_SLDS/ANALYTICS_SLDS (e.g. "heap", "telemetry")
# are excluded here since a startswith match on those risks colliding with
# an unrelated legitimate domain.
TRACKER_SLD_PREFIXES: frozenset[str] = frozenset({
    "segment", "taboola", "outbrain", "criteo", "doubleclick",
    "rubiconproject", "pubmatic", "scorecardresearch", "quantserve",
    "everesttech", "moatads", "comscore", "mixpanel", "amplitude",
    "hotjar", "mouseflow", "fullstory", "logrocket", "chartbeat",
    "parsely", "optimizely", "abtasty", "newrelic", "rollbar",
    "datadoghq", "googlesyndication", "googleadservices",
    "googletagmanager", "googletagservices", "amazonaax",
})

SYSTEM_PROCESSES: frozenset[str] = frozenset({
    "wmiprvse.exe", "svchost.exe", "services.exe",
    "taskhost.exe", "taskhostw.exe", "backgroundtaskhost.exe",
})

MS_TRUSTED_ROOTS: frozenset[str] = frozenset({
    "microsoft.com", "windows.com", "windowsupdate.com",
    "live.com",
})

SCANNER_BLOCK_THRESHOLD: float = 0.7
SCANNER_FLAG_THRESHOLD:  float = 0.4
SCAN_CACHE_TTL_HOURS:    int   = 24
# NOTE: RATE_MAX_QUERIES is defined once under "Behavioral heuristics" above.

# ---------------------------------------------------------------------------
# Web dashboard
# ---------------------------------------------------------------------------
# Loopback by default. The dashboard exposes live DNS/browsing history, system
# status, and control buttons; binding 0.0.0.0 would let any device on the LAN
# read that feed. Opt into LAN / router-wide exposure explicitly with
# --web-host 0.0.0.0 — which then additionally requires the per-process control
# token for every off-loopback API and WebSocket call (see web/server.py).
WEB_HOST = "127.0.0.1"
WEB_PORT = 8090        # dashboard + /edr console; matches the daily-use scripts

# ---------------------------------------------------------------------------
# Windows service
# ---------------------------------------------------------------------------
SERVICE_NAME         = "ValkyrieShield"
SERVICE_DISPLAY_NAME = "Valkyrie Privacy Shield"
NSSM_PATH             = BASE_DIR / "tools" / "nssm.exe"

# ---------------------------------------------------------------------------
# TLS inspection (mitmproxy)
# ---------------------------------------------------------------------------
TLS_PROXY_PORT      = 8443
TLS_CA_CERT_PATH    = DATA_DIR / "valkyrie-ca.pem"
TLS_CA_KEY_PATH     = DATA_DIR / "valkyrie-ca.key"
TLS_MITMPROXY_CONF_DIR = DATA_DIR / "mitmproxy"

TRACKER_URL_PATTERNS = [
    "/pixel", "/track", "/beacon", "/collect", "/analytics",
    "/telemetry", "/ping",
]
FINGERPRINT_URL_PATTERNS = [
    "fingerprintjs", "evercookie", "fp.js", "fpjs", "canvas-fingerprint",
]
TRACKING_QUERY_PARAMS = [
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "msclkid", "mc_eid", "_ga", "_gid", "ref",
    "source", "medium", "campaign",
]
EXFIL_BODY_SIZE_BYTES = 1024   # POST body larger than this to a tracker domain → flagged

# ---------------------------------------------------------------------------
# Telemetry killer
# ---------------------------------------------------------------------------
TELEMETRY_BACKUP_PATH = DATA_DIR / "telemetry_backup.json"
TELEMETRY_SERVICES_TO_DISABLE = ["DiagTrack", "dmwappushservice"]

# ---------------------------------------------------------------------------
# Page content cleaner (tls_addon.py response hook)
# ---------------------------------------------------------------------------
TRACKING_SCRIPT_DOMAINS: list[str] = [
    "googletagmanager.com", "google-analytics.com",
    "googletagservices.com", "googlesyndication.com",
    "doubleclick.net", "connect.facebook.net",
    "facebook.net", "analytics.twitter.com",
    "static.ads-twitter.com", "snap.licdn.com",
    "bat.bing.com", "hotjar.com", "mouseflow.com",
    "fullstory.com", "logrocket.io", "segment.com",
    "mixpanel.com", "amplitude.com", "heap-api.com",
    "optimizely.com", "chartbeat.com", "parsely.com",
    "scorecardresearch.com", "quantserve.com",
    "moatads.com", "taboola.com", "outbrain.com",
    "criteo.com",
]

STRIP_PARAMS: list[str] = [
    "utm_source", "utm_medium", "utm_campaign",
    "utm_term", "utm_content", "fbclid", "gclid",
    "msclkid", "mc_eid", "_ga", "_gid", "ref",
]

MAX_RESPONSE_PROCESS_SIZE: int = 2 * 1024 * 1024   # 2 MB
RESPONSE_CACHE_TTL: int        = 300                 # seconds
FINGERPRINT_PROTECTION: bool   = True

# ---------------------------------------------------------------------------
# MAC randomization
# ---------------------------------------------------------------------------
REALISTIC_OUIS: list[str] = [
    "00:1A:2B",   # Cisco
    "00:50:56",   # VMware
    "AC:BC:32",   # Apple
    "DC:A6:32",   # Raspberry Pi
    "B8:27:EB",   # Raspberry Pi
    "00:0C:29",   # VMware
    "00:1B:21",   # Intel
    "8C:8D:28",   # Intel
]
MAC_BACKUP_PATH: Path = DATA_DIR / "mac_backup.json"
MAC_AUTO_RANDOMIZE: bool = False
MAC_NEVER_RANDOMIZE: frozenset[str] = frozenset({
    "lo", "localhost", "docker0", "vmnet0",
})

# ---------------------------------------------------------------------------
# Multi-hop VPN
# ---------------------------------------------------------------------------
WIREGUARD_HOP1_CONF = DATA_DIR / "wg_hop1.conf"
WIREGUARD_HOP2_CONF = DATA_DIR / "wg_hop2.conf"
MULTIHOP_SUBNET_1   = "10.13.13.0/24"
MULTIHOP_SUBNET_2   = "10.13.14.0/24"

# ---------------------------------------------------------------------------
# Zero log mode
# ---------------------------------------------------------------------------
ZERO_LOG_MODE             = False
ZERO_LOG_IMPORT_HOURS     = 0
INTEGRITY_CHECK_INTERVAL  = 3600   # seconds
RAM_DB_URI                = "file::memory:?cache=shared"

# ---------------------------------------------------------------------------
# Intelligence layer (self-learning threat detection)
# ---------------------------------------------------------------------------
INTELLIGENCE_MODE       = True    # master switch for the learning pipeline
LEARNING_PERIOD_DAYS    = 7       # baseline learning window after first start
ANOMALY_BLOCK_THRESHOLD = 0.7     # classifier score at/above which we block
ANOMALY_FLAG_THRESHOLD  = 0.4     # classifier score at/above which we flag

# Downloaded blocklist/IP feeds are OPT-IN: default protection is the
# built-in seed blocklist (seed_blocklist.py) + learned intelligence.
# Enable per-run with --download-lists, or permanently by setting True.
USE_EXTERNAL_LISTS      = False

INTEL_FLUSH_INTERVAL    = 30      # seconds between SQLite flushes of learned state
INTEL_HISTORY_SAMPLES   = 16      # timestamps/payloads kept per (process, domain)
INTEL_HEARTBEAT_MIN_SAMPLES = 4   # gaps needed before heartbeat detection fires
INTEL_HEARTBEAT_MIN_GAP = 5.0     # seconds — faster than this is a burst, not a beacon
INTEL_HEARTBEAT_MAX_GAP = 3600.0  # seconds — slower than this is not a heartbeat
INTEL_HEARTBEAT_MAX_CV  = 0.25    # coefficient of variation below this = regular
INTEL_SMALL_PAYLOAD_BYTES = 512   # repeated payloads under this = beacon-like
INTEL_GOOD_AFTER_ALLOWS = 5       # clean allows before a domain is remembered good

SELF_HEAL_INTERVAL      = 30      # seconds between component health checks

# ---------------------------------------------------------------------------
# EDR layer (detection -> incident -> response, on top of the existing sensors)
# ---------------------------------------------------------------------------
# The EDR layer subscribes to the live DNS-decision stream, runs detection
# plugins, and correlates the results into incidents with timelines. It adds no
# new sensing — it interprets what Valkyrie already sees — and stays entirely
# local (its state lives in the same SQLite DB, so zero-log RAM mode covers it).
EDR_MODE                    = True     # master switch for the EDR/SOC layer
EDR_CORRELATION_WINDOW      = 600      # seconds: a detection folds into an open
                                       # incident sharing its category + entity/process
# Directory scanned for third-party plugins (detection/responder/enrichment).
# Empty by default — discovery is opt-in and only from a directory you control.
EDR_PLUGIN_DIR              = DATA_DIR / "plugins"
# AI-assisted investigation. OFF by default: turning it on SENDS incident
# details (including domains) to the Claude API, so it is opt-in and clearly
# disclosed, matching the roadmap's rule for anything that leaves the machine.
EDR_AI_INVESTIGATION        = False

# ---------------------------------------------------------------------------
# Bucket-B: third-party co-occurrence signal (SIGNAL_DESIGN_REPORT.md)
# ---------------------------------------------------------------------------
# Catches tracker subdomains hanging off mixed-use parents (tr.snapchat.com,
# events.reddit.com) that cannot be listed by parent SLD. Learns, per candidate
# host, the set of DISTINCT first-party "anchor" sites it is resolved behind in
# the same process/burst. A host that rides behind many unrelated first parties,
# is never navigated to directly, and is not infrastructure is behaving like a
# third-party tracker.
#
# HARD INVARIANT: this signal is FLAG-ONLY. COOC_SCORE_CAP is held strictly
# below ANOMALY_BLOCK_THRESHOLD so co-occurrence can never, on its own, cause a
# block — enforced both by this cap and by the classifier applying it only as an
# allow->flag upgrade. Do not raise the cap to/above the block threshold.
COOC_QUIET_GAP     = 8.0     # s of quiet that ends a burst (next query = new anchor)
COOC_BURST_MAX     = 30.0    # s; force a new anchor if one burst runs longer
COOC_MIN_ANCHORS   = 3       # G4: distinct anchors required before any score
COOC_SCORE_BASE    = 0.45    # flag-band score at exactly COOC_MIN_ANCHORS anchors
COOC_SCORE_STEP    = 0.03    # added per extra distinct anchor
COOC_SCORE_CAP     = 0.60    # < ANOMALY_BLOCK_THRESHOLD (0.7) — flag-only, hard cap

# G1 — shipped infrastructure / functional-third-party allowlist (eTLD+1, last
# two labels). These are legitimately co-loaded across many sites (CDNs, static
# asset and font hosts, payment/captcha/error-reporting services) and would
# otherwise look identical to a tracker under co-occurrence. They are exempt:
# the co-occurrence signal never scores a domain whose base is in this set.
INFRA_ALLOWLIST: frozenset[str] = frozenset({
    # CDNs / static asset hosts
    "cloudflare.com", "cloudfront.net", "akamai.net", "akamaihd.net",
    "akamaiedge.net", "akamaized.net", "edgekey.net", "edgesuite.net",
    "fastly.net", "fastlylb.net", "jsdelivr.net", "unpkg.com",
    "gstatic.com", "googleapis.com", "googleusercontent.com", "gvt1.com",
    "ggpht.com", "azureedge.net", "azurefd.net", "bootstrapcdn.com",
    "cdnjs.com", "cdn77.com", "keycdn.com", "stackpathcdn.com",
    "stackpathdns.com", "jquery.com", "typekit.net", "cloudinary.com",
    "imgix.net",
    # Fonts
    "fontawesome.com",
    # Functional third parties (payments / captcha / error reporting) that are
    # co-loaded but not tracking-for-profiling in the EasyPrivacy sense.
    "stripe.com", "stripe.network", "paypalobjects.com",
    "recaptcha.net", "hcaptcha.com", "gravatar.com", "sentry.io",
})

# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------
UI_REFRESH_RATE     = 4           # Rich live refresh per second
UI_MAX_TABLE_ROWS   = 30          # rows visible in each dashboard table
UI_STATS_PANEL_ROWS = 8

# ---------------------------------------------------------------------------
# Layered overrides (config file / environment) — applied LAST so they win over
# the documented defaults above. See valkyrie/settings.py for precedence and the
# list of overridable settings. This block is deliberately at the end of the
# module: Python finishes executing config.py (including these re-bindings)
# before any `from .config import X` elsewhere resolves, so every consumer
# transparently sees the resolved value with no change on their side.
#
# With no config file and no VALKYRIE_* environment variables this is a no-op
# and every constant keeps exactly the default declared above.
# ---------------------------------------------------------------------------
from . import settings as _settings   # noqa: E402  (intentional late import)

CONFIG_OVERRIDES: "list[_settings.Override]" = []
try:
    _base_settings = {s.key: globals()[s.key] for s in _settings.SPECS}
    _resolved_settings, CONFIG_OVERRIDES = _settings.load(
        _base_settings, config_dir=DATA_DIR
    )
    globals().update(_resolved_settings)
except _settings.ConfigError as _cfg_exc:
    # Fail loud on an explicitly-bad override rather than silently run a
    # security tool on a misconfiguration. A missing file / unset var never
    # reaches here — those simply leave the defaults in place.
    raise SystemExit(f"[valkyrie] invalid configuration: {_cfg_exc}")
