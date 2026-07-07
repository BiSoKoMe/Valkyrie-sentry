"""Central configuration — all constants, paths, and defaults live here."""

from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

DB_PATH        = DATA_DIR / "valkyrie.db"
BLOCKLIST_PATH = DATA_DIR / "blocklist.txt"
RULES_PATH     = BASE_DIR / "valkyrie_rules.yaml"
LOG_PATH       = DATA_DIR / "valkyrie.log"

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
DOMAIN_AGE_THRESHOLD   = 30     # days; newer domains flagged (WHOIS optional)
BEHAVIORAL_BLOCK_SCORE = 0.7    # suspicion score at/above which we block

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

# CIDRs that must never be blocked (local network, loopback, upstream DNS)
FIREWALL_NEVER_BLOCK = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",   # link-local
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
WEB_HOST = "0.0.0.0"
WEB_PORT = 8080

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
# UI
# ---------------------------------------------------------------------------
UI_REFRESH_RATE     = 4           # Rich live refresh per second
UI_MAX_TABLE_ROWS   = 30          # rows visible in each dashboard table
UI_STATS_PANEL_ROWS = 8
