"""Central configuration - all constants, paths, and defaults live here."""

import os
import shutil
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
# Frozen-build awareness (PyInstaller). When packaged as valkyrie.exe the
# module lives inside an ephemeral temp extraction dir (sys._MEIPASS), so
# read-only bundled assets are read from the bundle dir (BUNDLE_DIR), while all
# writable state is kept OUT of the install directory entirely.
#
# Like professional Windows software (Defender, etc.), a packaged install keeps
# its mutable data - database, logs, rules, keys, caches - under
# %ProgramData%\Valkyrie, generated fresh on first launch. The installer ships
# ZERO user data; two machines installing the same ValkyrieSetup.exe get
# identical software and completely independent local state. Running from source
# keeps everything in the repo's data/ folder exactly as before.
if getattr(sys, "frozen", False):
    BASE_DIR   = Path(sys.executable).resolve().parent            # install dir (read-only)
    BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", BASE_DIR))         # bundled assets
    _program_data = os.environ.get("ProgramData") or os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
    _default_data = Path(_program_data) / "Valkyrie"
else:
    BASE_DIR   = Path(__file__).resolve().parent.parent
    BUNDLE_DIR = BASE_DIR
    _default_data = BASE_DIR / "data"

# VALKYRIE_DATA_DIR lets the shell relocate all writable state - used by the
# Portable build (state beside the executable) and by deterministic tests. When
# unset, an installed build uses %ProgramData%\Valkyrie and a source checkout
# uses the repo's data/ folder.
_data_override = os.environ.get("VALKYRIE_DATA_DIR")
DATA_DIR = Path(_data_override) if _data_override else _default_data

DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH        = DATA_DIR / "valkyrie.db"
BLOCKLIST_PATH = DATA_DIR / "blocklist.txt"
LOG_PATH       = DATA_DIR / "valkyrie.log"

# ---------------------------------------------------------------------------
# Ransomware Shield (local behavioral defense - see valkyrie/ransomware_shield.py)
# ---------------------------------------------------------------------------
RANSOMWARE_SHIELD_ENABLED  = True
# monitor = alert only . suspend = pause culprit (default, reversible) . kill
RANSOMWARE_RESPONSE_MODE   = "suspend"
RANSOMWARE_POLL_INTERVAL   = 2.0          # seconds between canary checks
RANSOMWARE_MANIFEST_PATH   = DATA_DIR / "ransomware_canaries.json"

# ---------------------------------------------------------------------------
# AMSI content scanning (see valkyrie/amsi.py)
# ---------------------------------------------------------------------------
# Asks the OS antimalware provider (Defender, or a third-party AV) for a real
# verdict on script content and files. Valkyrie ships no signature engine and
# does not fake one; this is the documented local path to content conviction.
# Scanning is local to the machine - content is handed to a provider already
# installed on this host and nothing leaves the box.
AMSI_ENABLED        = True
AMSI_SCAN_SCRIPTS   = True                # scan PowerShell script blocks (4104)
AMSI_MAX_BYTES      = 8 * 1024 * 1024     # skip (never truncate) content above this
AMSI_CACHE_SIZE     = 512                 # content-hash -> verdict LRU entries

# User-editable rules live in the writable data dir. The read-only factory
# default is bundled with the app; on first launch (no rules file yet) it is
# copied out so the user always starts from a clean, generic rule set and their
# later edits are never clobbered by an update.
RULES_PATH         = DATA_DIR / "valkyrie_rules.yaml"
DEFAULT_RULES_PATH = BUNDLE_DIR / "valkyrie" / "defaults" / "rules.default.yaml"
if not RULES_PATH.exists():
    try:
        if DEFAULT_RULES_PATH.exists():
            shutil.copyfile(DEFAULT_RULES_PATH, RULES_PATH)
    except OSError:
        pass   # first-run seeding is best-effort; RulesEngine tolerates absence


def _strip_dead_manual_lists(path=None) -> None:
    """Remove the retired ``always_allow`` / ``always_block`` keys from an
    existing rules file.

    Valkyrie is list-free: every allow/block is analysis-driven, and the decision
    path no longer reads these keys. But a rules file seeded by an OLDER build
    still carries the hand-written lists on disk (a re-install over a beta),
    where they sit as a dead landmine and contaminate testing. Strip them so the
    file honestly reflects the no-manual-lists model. Best-effort; never blocks
    startup, and only rewrites when a key is actually present.
    """
    p = path or RULES_PATH
    try:
        import yaml
        if not p.exists():
            return
        with open(p, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict) or (
                "always_allow" not in data and "always_block" not in data):
            return
        data.pop("always_allow", None)
        data.pop("always_block", None)
        with open(p, "w", encoding="utf-8") as fh:
            yaml.safe_dump(data, fh, default_flow_style=False, sort_keys=False)
    except Exception:
        pass


_strip_dead_manual_lists()

# Response playbooks (SOAR) ship ENABLED so confirmed-malicious incidents are
# auto-blocked/remediated and audited out of the box (before this the engine
# started with zero playbooks and every incident was observe-only).
#
# Seeding is VERSION-AWARE so a client is fully armed with NO manual step in
# every case - fresh install *and* upgrade:
#   * Fresh install (no file): copy the bundled armed default verbatim.
#   * Upgrade (installed `version` < bundled `version`): refresh the built-in
#     playbooks to the new armed set - backing up the old file - while
#     preserving any playbooks the user added under their own ids.
#   * Current or user-ahead: left untouched, so deliberate edits persist.
# Without this, an existing install (a beta tester, a re-install over an older
# build) would silently keep an old dry-run config and never actually protect.
PLAYBOOKS_PATH         = DATA_DIR / "playbooks.yaml"
DEFAULT_PLAYBOOKS_PATH = BUNDLE_DIR / "valkyrie" / "defaults" / "playbooks.default.yaml"


def _playbook_doc_version(data: dict) -> int:
    try:
        return int((data or {}).get("version", 0))
    except (TypeError, ValueError):
        return 0


def _seed_or_migrate_playbooks(path=None, default_path=None) -> None:
    """Ensure the shipped built-in playbooks are present and current without
    clobbering user-added playbooks. Best-effort; never raises.

    Paths default to the module-level PLAYBOOKS_PATH / DEFAULT_PLAYBOOKS_PATH but
    are injectable so the migration can be unit-tested against temp files."""
    path = path or PLAYBOOKS_PATH
    default_path = default_path or DEFAULT_PLAYBOOKS_PATH
    try:
        if not default_path.exists():
            return
        if not path.exists():
            shutil.copyfile(default_path, path)
            return
        import yaml
        default = yaml.safe_load(default_path.read_text(encoding="utf-8")) or {}
        current = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if _playbook_doc_version(current) >= _playbook_doc_version(default):
            return   # user is current or ahead - never clobber deliberate edits
        builtin_ids = {str(p.get("id")) for p in (default.get("playbooks") or [])}
        user_added = [p for p in (current.get("playbooks") or [])
                      if str(p.get("id")) not in builtin_ids]
        merged = dict(default)
        merged["playbooks"] = list(default.get("playbooks") or []) + user_added
        try:      # keep the superseded file so a migration is never lossy
            shutil.copyfile(
                path, path.with_suffix(f".v{_playbook_doc_version(current)}.bak"))
        except OSError:
            pass
        path.write_text(yaml.safe_dump(merged, sort_keys=False), encoding="utf-8")
    except Exception:
        pass       # PlaybookEngine falls back to the bundled default if needed


_seed_or_migrate_playbooks()

# ---------------------------------------------------------------------------
# Fleet control plane (multi-device management)
# ---------------------------------------------------------------------------
# Turns Valkyrie from a single-machine tool into an agent that reports to a
# central control plane. Deliberately privacy-preserving: agents send status
# METADATA (health, counts, category tallies) - never raw domains or traffic -
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
DNS_UPSTREAM     = "9.9.9.9"   # Quad9 - privacy-respecting public resolver (default)
DNS_UPSTREAM_PORT = 53
DNS_TIMEOUT      = 3.0         # seconds

# Ordered list of public upstream resolvers tried in sequence on forward
# failure. All privacy-respecting anycast resolvers - no network-specific hosts.
UPSTREAM_SERVERS: list[str] = [
    "9.9.9.9",      # Quad9 - primary (privacy-focused, blocks malware)
    "1.1.1.1",      # Cloudflare - fallback
    "8.8.8.8",      # Google - fallback
]

SINKHOLE_IPV4 = "0.0.0.0"
SINKHOLE_IPV6 = "::"

# Where a DECEIVED name resolves - the loopback deception endpoint
# (valkyrie/deception.py), NOT the sinkhole.
#
# The distinction is the whole point of DECEIVE. A sinkholed beacon fails at
# connect and tells the tracker nothing false; worse, a machine whose beacons
# reliably fail while its other traffic resolves is identifiable as one that
# runs a blocker - a smaller and more distinctive population than the one the
# user was trying to disappear into. Pointing at a listening local endpoint
# means the beacon is ANSWERED, with a plausible, persona-consistent reply.
#
# Loopback only. This must never be routable off-machine: a deception endpoint
# reachable from the network is a service others can query and fingerprint.
DECEPTION_IPV4 = "127.0.0.1"
DECEPTION_IPV6 = "::1"
DECEPTION_PORT = int(os.environ.get("VALKYRIE_DECEPTION_PORT", "8181"))

# Reserved local name the protection heartbeat resolves to prove the DNS
# interceptor is still answering. The interceptor serves it INSTANTLY and
# locally (never upstream), so an offline machine still reports HEALTHY instead
# of a false "sinkhole not answering" alarm while upstream resolution times out.
# `.invalid` is the RFC 6761 reserved TLD - it can never be a real domain, so
# this can never collide with or leak a genuine query.
HEALTH_PROBE_DOMAIN = "heartbeat.valkyrie.invalid"

# No-leak DNS policy.
#   When the local recursive resolver (Unbound) is the upstream, allowed
#   queries must NOT silently fall back to public resolvers (8.8.8.8,
#   1.1.1.1, 9.9.9.9, ISP) - that would leak the very queries Unbound
#   exists to keep local.  With fallback disabled the interceptor only ever
#   contacts the configured local upstream and returns SERVFAIL on failure
#   (fail-closed), so a plaintext query can never reach a third-party
#   resolver.  This is auto-enabled whenever Unbound is active, and can be
#   forced on (even without Unbound) with --no-dns-leak.
DNS_LOCAL_ONLY = False   # default off -> preserves external-resolver behaviour
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
# Sysmon (valkyrie/sysmon_manager.py) - a first-class dependency, not a
# bundled binary. The Sysinternals EULA forbids redistribution, so Valkyrie
# never ships Sysmon64.exe; it downloads the official signed build from
# Microsoft's own Sysinternals live endpoint at install/first-run time and
# verifies the Authenticode signature before executing anything extracted
# from it. See docs/adr/0048-sysmon-dependency.md.
SYSMON_DOWNLOAD_URL = "https://download.sysinternals.com/files/Sysmon.zip"

# ---------------------------------------------------------------------------
# Threat-intelligence IOC feeds (valkyrie/threat_intel.py)
# ---------------------------------------------------------------------------
# Active threat infrastructure - botnet C2s and live malware-distribution
# hosts - from abuse.ch's public, no-account feeds. Distinct from the
# ad/tracker blocklist (different threat class, hours-scale rotation,
# incident-grade severity on hit). Downloads obey the same opt-in flag as
# every other list (USE_EXTERNAL_LISTS / --download-lists); matching is
# always local - no indicator ever leaves the machine.
# Tuples: (name, kind, category, url)
THREAT_INTEL_SOURCES = [
    ("feodo_c2", "ip", "botnet_c2",
     "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
    ("urlhaus", "domain", "malware_distribution",
     "https://urlhaus.abuse.ch/downloads/hostfile/"),
    # Full-URL (path-level) malware distribution. The hostfile feed above can
    # only ever say "this DOMAIN is bad", which is the wrong verdict for the
    # common case - malware hosted on a compromised but otherwise legitimate
    # site. This feed carries the exact URL, so the TLS inspector can block
    # the one malicious path and leave the rest of the site working. Matched
    # ONLY where a full URL exists (TLS inspection); DNS never sees a path.
    ("urlhaus_url", "url", "malware_distribution",
     "https://urlhaus.abuse.ch/downloads/text_recent/"),
    # ThreatFox recent IOC export (community-confirmed botnet C2s across
    # malware families; quoted-CSV ip:port rows). Chosen over SSLBL's IP
    # blacklist, which abuse.ch deprecated on 2025-01-03.
    ("threatfox_c2", "ip", "botnet_c2",
     "https://threatfox.abuse.ch/export/csv/ip-port/recent/"),
]
THREAT_INTEL_DIR             = DATA_DIR / "threat_intel"
THREAT_INTEL_MAX_AGE_HOURS   = 6        # C2 infrastructure rotates fast
THREAT_INTEL_REFRESH_SECONDS = 6 * 3600

# ---------------------------------------------------------------------------
# Behavioral heuristics
# ---------------------------------------------------------------------------
ENTROPY_THRESHOLD      = 3.5    # Shannon entropy above this -> suspicious
RATE_WINDOW_SECONDS    = 10     # sliding window for query-rate check
RATE_MAX_QUERIES       = 30     # queries per window per process -> suspicious
BEHAVIORAL_BLOCK_SCORE = 0.7    # suspicion score at/above which we block

# TLD reputation - offline replacement for the old WHOIS domain-age signal.
#
# The previous "new domain" signal called python-whois over the network. That
# dependency is not installed and, more importantly, network WHOIS does not work
# in the offline / intelligence-only posture this product ships in - so it
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
# (0.40) or block (0.70) threshold - it only nudges a domain already suspicious
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
# DGA (Domain Generation Algorithm) detection - valkyrie/dga.py
# ---------------------------------------------------------------------------
# A confirmed-DGA registrable label is a high-confidence C2 signal (T1568.002).
# The detector fires ONLY when all three corroborators clear their floors, which
# is what keeps it off legitimate random-looking hostnames (CDN hashes, short
# consonant-heavy brands). Tuned for precision on a hard benign control set that
# includes CDN hostnames and odd-spelled brands (see docs + tests/test_dga.py):
#   * MIN_LEN 12   - short brands (netflix=7, spotify=7) can never qualify.
#   * MIN_ENTROPY 3.6 - repetitive / dictionary labels are excluded.
#   * MIN_RARE_BIGRAM 0.55 - the linguistic discriminator: >=55% of the label's
#     character pairs must be implausible in real words/brands. Real long
#     dictionary domains (washingtonpost, bankofamerica) sit well below this.
DGA_MIN_LEN          = 12
DGA_MIN_ENTROPY      = 3.0
DGA_MIN_RARE_BIGRAM  = 0.55
DGA_BLOCK_CONFIDENCE = 0.70     # a fired DGA verdict is block-worthy on its own

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
# is at best pointless and at worst actively harmful - blocking 169.254.0.0/16
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
    "169.254.0.0/16",   # link-local (RFC 3927) - APIPA
    # Special-use / documentation / bogon ranges that must never be treated as
    # routable threat destinations (RFC 6890 and friends).
    "0.0.0.0/8",        # "this network" (RFC 1122)
    "100.64.0.0/10",    # carrier-grade NAT (RFC 6598)
    "192.0.0.0/24",     # IETF protocol assignments (RFC 6890)
    "192.0.2.0/24",     # TEST-NET-1 documentation (RFC 5737)
    "198.18.0.0/15",    # benchmarking (RFC 2544)
    "198.51.100.0/24",  # TEST-NET-2 documentation (RFC 5737)
    "203.0.113.0/24",   # TEST-NET-3 documentation (RFC 5737)
    "224.0.0.0/4",      # multicast (RFC 5771) - mDNS/SSDP live here
    "240.0.0.0/4",      # reserved / future use, incl. 255.255.255.255 broadcast
    DNS_UPSTREAM,       # upstream resolver - blocking it breaks forwarding
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

# Pure ad-tech / tracking SLDs - score +0.7, block alone.
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

# Analytics / monitoring SLDs - score +0.4, flag only.
ANALYTICS_SLDS: frozenset[str] = frozenset({
    "segment", "mixpanel", "amplitude", "heap",
    "hotjar", "mouseflow", "fullstory", "logrocket",
    "chartbeat", "parsely", "optimizely", "abtasty",
    "newrelic", "datadoghq", "rollbar", "heap-api",
})

# Subdomain prefixes that indicate tracker infrastructure - score +0.7, block alone.
# Only fires when the FIRST label of the domain exactly matches one of these
# AND the domain has 3+ parts (subdomain.domain.tld).
TRACKER_PREFIXES: frozenset[str] = frozenset({
    "tracker", "tracking", "telemetry", "analytics",
    "pixel", "beacon", "collect", "adserver", "adtrack",
    # Added 2026-08-04 from the scanner-accuracy investigation:
    # marketing.<company>.com is marketing-automation infrastructure in
    # essentially every observed case. Zero hits across the 699-domain benign
    # corpus.
    "marketing",
})

# DELIBERATELY NOT a tracker prefix: "events".
# events.reddit.com IS an event-collection (tracking) endpoint, and the
# scanner-accuracy measurement flags it as a known miss. But "events" is
# genuinely ambiguous as a first label - events.linuxfoundation.org,
# events.microsoft.com and events.google.com are conference WEBSITES, not
# telemetry. As a +0.7 block-alone signal this would break real browsing,
# which is the exact false-positive class that has burned this project before
# (see ADR 0040, the popular-domain floor). Precision over aggression: one
# documented miss beats a rule that kills conference sites. Revisit only as a
# weak COMBINING signal that needs corroboration, never block-alone.

# Distinctive tracker/analytics brand names for startswith-matching against
# an SLD (e.g. "segmentapis" -> "segment", "taboolasyndication" -> "taboola")
# - catches companies that register variant apex domains for infra/CDN use.
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
# DNS tunnelling / exfiltration detection (dns_tunnel.py + scanner S8/S9)
# ---------------------------------------------------------------------------
# Wildcard "IP-echo" DNS providers: anything.<ip>.nip.io resolves to <ip>.
# Completely legitimate dev tools - but because the registrable domain is the
# provider's (nip.io), domain-reputation and DGA analysis of the SLD are blind
# to whatever an attacker stuffs into the subdomain. For these roots the
# scanner analyses the LEFTMOST label as the effective payload label instead.
DYNDNS_WILDCARD_ROOTS: frozenset[str] = frozenset({
    "nip.io", "sslip.io", "xip.io", "traefik.me",
    "localtest.me", "lvh.me", "vcap.me",
})

# Unique-subdomain flood (the classic DNS-tunnel/exfil shape: many never-seen
# machine-generated labels under one base in a short window). Thresholds are
# deliberately conservative - a handful of unique cryptic labels is normal
# CDN/sharding behaviour, a sustained stream is not.
TUNNEL_WINDOW_SECONDS: float = 60.0
TUNNEL_FLAG_UNIQUE:    int   = 3     # unique cryptic labels -> combining signal
TUNNEL_BLOCK_UNIQUE:   int   = 5     # unique cryptic labels -> block-alone

# Media/CDN roots that legitimately fan out many machine-generated hostnames
# (video shards, blob stores). The flood detector never counts these - the
# false-positive cost of blocking one would be broken video/storage for the
# user, and their sharded hostnames are exactly the pattern the detector
# hunts. Reputation for these roots comes from the other layers.
TUNNEL_EXEMPT_ROOTS: frozenset[str] = frozenset({
    "googlevideo.com", "gvt1.com", "gvt2.com", "ytimg.com",
    "akamaized.net", "akamaiedge.net", "akamai.net",
    "edgekey.net", "edgesuite.net",
    "cloudfront.net", "fastly.net", "fastlylb.net",
    "fbcdn.net", "cdninstagram.com",
    "llnwd.net", "msedge.net", "azureedge.net",
    "amazonaws.com", "awsstatic.com", "windows.net", "azure.com",
    "aaplimg.com", "apple-dns.net", "cdn-apple.com",
    "steamcontent.com", "steamstatic.com",
    "nflxvideo.net", "nflximg.net",
    "ttvnw.net", "twitchcdn.net",
    "scdn.co", "spotifycdn.com",
    "trafficmanager.net", "cloudflarestorage.com",
})

# Subdomain labels so common on legitimate multi-service sites that they can
# never count toward a tunnel flood, whatever their shape.
COMMON_SUBDOMAIN_LABELS: frozenset[str] = frozenset({
    "www", "api", "cdn", "static", "img", "images", "mail", "smtp", "imap",
    "app", "apps", "dev", "staging", "test", "web", "m", "mobile", "shop",
    "blog", "docs", "news", "media", "assets", "files", "download", "ftp",
    "login", "auth", "sso", "id", "account", "accounts", "portal", "admin",
    "status", "help", "support", "store", "video", "play", "music", "maps",
})

# ---------------------------------------------------------------------------
# Web dashboard
# ---------------------------------------------------------------------------
# Loopback by default. The dashboard exposes live DNS/browsing history, system
# status, and control buttons; binding 0.0.0.0 would let any device on the LAN
# read that feed. Opt into LAN / router-wide exposure explicitly with
# --web-host 0.0.0.0 - which then additionally requires the per-process control
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
    # Matched segment-exact (see tls_addon._is_tracker_path), so these specific
    # beacon segments cannot collide with ordinary words. Deliberately NOT added:
    # "/tr" (Facebook pixel) - "/tr/" is the standard Turkish-locale path and
    # would false-positive whole non-English sites; it is caught by the
    # facebook.net domain rule instead. "/batch", "/ss" - too generic (ordinary
    # API endpoints), would break real apps.
    "/adsct",   # Twitter/X conversion beacon (/i/adsct)
    "/pagead",  # Google AdSense/ad beacons (/pagead/...)
]
FINGERPRINT_URL_PATTERNS = [
    # Generalised: any script whose path contains "fingerprint" is a
    # fingerprinting library (FingerprintJS v2/v3, canvas-fingerprint, etc.) -
    # one signal instead of enumerating each library name. fp.js/fpjs/clientjs
    # don't contain the word, so they stay explicit.
    "fingerprint", "evercookie", "fp.js", "fpjs", "clientjs",
]
TRACKING_QUERY_PARAMS = [
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "msclkid", "mc_eid", "_ga", "_gid", "ref",
    "source", "medium", "campaign",
]
EXFIL_BODY_SIZE_BYTES = 1024   # POST body larger than this to a tracker domain -> flagged

# Nyx data-guard response mode. False = OBSERVE (watch outbound personal-data
# leaks and report them; never alter traffic). True = ACT - rewrite the leaking
# values into consistent persona ("John") fakes so the tracker/app receives
# believable-but-false data and the request STILL COMPLETES (deception, not
# blocking, so it cannot break a page). Default off: Nyx never changes your
# traffic until you turn this on.
NYX_ACT = False

# ---------------------------------------------------------------------------
# Telemetry killer
# ---------------------------------------------------------------------------
TELEMETRY_BACKUP_PATH = DATA_DIR / "telemetry_backup.json"
TELEMETRY_SERVICES_TO_DISABLE = ["DiagTrack", "dmwappushservice"]

# ---------------------------------------------------------------------------
# EDR responder rollback snapshots (see valkyrie/edr/reversibility.py)
# ---------------------------------------------------------------------------
# isolate_host backs up the FULL pre-isolation firewall state here (a Windows
# `netsh advfirewall export` .wfw file, or a Linux `iptables-save` ruleset)
# before touching anything, so release_isolation can restore the machine to
# exactly what it was - not to a hardcoded guess at the "normal" policy. See
# IIBA Cybersecurity Analysis handbook §4.2.5 ("can it be backed out?").
ISOLATION_BACKUP_DIR = DATA_DIR / "isolation_backup"
# remove_persistence backs up the exact ASEP it is about to delete (registry
# value + type / scheduled-task XML / service config / startup-file bytes)
# here first, so a false-positive removal can be undone - the task previously
# ran as delete-only with no way back.
PERSISTENCE_BACKUP_DIR = DATA_DIR / "persistence_backup"

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
    # Well-known trackers found missing by the Nyx privacy battery.
    "mxpnl.com",              # Mixpanel CDN (mixpanel.com above is the API host)
    "analytics.tiktok.com",   # TikTok pixel
    "lfeeder.com",            # Leadfeeder
    "marketo.net",            # Marketo Munchkin tracking
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

# Per-install secret key (32 CSPRNG bytes) used to derive per-network MAC
# addresses via HMAC. Created on first use with restrictive permissions; it is
# what makes per-network addresses stable-yet-unpredictable - see mac_randomizer.
MAC_KEY_PATH: Path = DATA_DIR / "mac_key.bin"

# Per-network stable randomisation (the iOS "Private Wi-Fi Address" / Android
# persistent-randomised-MAC model): the address for a given network is derived
# deterministically from the install key + a stable network id, so it is the
# SAME every time you rejoin that network (captive portals, DHCP leases and NAC
# keep working) but UNLINKABLE across networks. Falls back to a fresh CSPRNG
# random address when the network can't be identified. Top-tier default.
MAC_PER_NETWORK: bool = True

# Address style. Default False = spec-compliant locally-administered random
# (LA bit set, matching iOS/Android - honest, standards-clean randomisation).
# True = blend in behind a real vendor OUI with the LA bit CLEAR (stealthier,
# but impersonates a vendor's universally-administered space); opt-in because a
# vendor OUI with the LA bit set - the old behaviour - is a combination real
# hardware never has, and thus itself a fingerprint.
MAC_VENDOR_BLEND: bool = False

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
LEARNING_PERIOD_DAYS    = 7       # (legacy display hint only; readiness is data-based below)
# Baseline readiness is gated on DATA, not the calendar: the novelty signals
# ("never seen this domain from this process") switch on once the machine has
# revealed enough of its OWN normal - this many distinct process->domain pairs.
# So it learns whenever the computer is on and is "trained" by observation, not
# by days elapsed. A busy machine is ready in hours; an idle one takes longer -
# which is correct. The baseline persists in SQLite, so this accumulates across
# reboots and never restarts.
BASELINE_READY_PAIRS    = 200
ANOMALY_BLOCK_THRESHOLD = 0.7     # classifier score at/above which we block
ANOMALY_FLAG_THRESHOLD  = 0.4     # classifier score at/above which we flag

# Downloaded blocklist/threat-intel feeds. DEFAULT ON (as of 2026-08):
# "detect and block like the commercial EDRs/DNS-security products" assumes
# live threat intelligence, not just the built-in seed blocklist + learned
# intelligence - Feodo/URLhaus/ThreatFox (threat_intel.py) and the tracker-
# blocklist refresh (blocklist.py) were previously silent no-ops for anyone
# who didn't know to pass --download-lists, which is not an honest default
# for a security product. Matching stays 100% local either way (nothing but
# the periodic feed fetch itself ever leaves the machine - see
# threat_intel.py's module docstring); this flag only controls whether that
# fetch happens. Opt OUT per-run with --no-download-lists, or permanently by
# setting False here.
USE_EXTERNAL_LISTS      = True

INTEL_FLUSH_INTERVAL    = 30      # seconds between SQLite flushes of learned state
INTEL_HISTORY_SAMPLES   = 16      # timestamps/payloads kept per (process, domain)
INTEL_HEARTBEAT_MIN_SAMPLES = 4   # gaps needed before heartbeat detection fires
INTEL_HEARTBEAT_MIN_GAP = 5.0     # seconds - faster than this is a burst, not a beacon
INTEL_HEARTBEAT_MAX_GAP = 3600.0  # seconds - slower than this is not a heartbeat
INTEL_HEARTBEAT_MAX_CV  = 0.25    # coefficient of variation below this = regular
INTEL_SMALL_PAYLOAD_BYTES = 512   # repeated payloads under this = beacon-like
INTEL_GOOD_AFTER_ALLOWS = 5       # clean allows before a domain is remembered good

SELF_HEAL_INTERVAL      = 30      # seconds between component health checks

# Seconds between enforcement-lease sweeps. Leases default to a 900s TTL
# (valkyrie/edr/leases.py), so 60s is fine-grained enough that an expiry is
# lifted promptly while the sweep itself stays cheap. A sweep can only ever
# REMOVE enforcement, so erring toward sweeping more often is the safe
# direction.
LEASE_SWEEP_INTERVAL    = 60

# ---------------------------------------------------------------------------
# EDR layer (detection -> incident -> response, on top of the existing sensors)
# ---------------------------------------------------------------------------
# The EDR layer subscribes to the live DNS-decision stream, runs detection
# plugins, and correlates the results into incidents with timelines. It adds no
# new sensing - it interprets what Valkyrie already sees - and stays entirely
# local (its state lives in the same SQLite DB, so zero-log RAM mode covers it).
EDR_MODE                    = True     # master switch for the EDR/SOC layer
EDR_CORRELATION_WINDOW      = 600      # seconds: a detection folds into an open
                                       # incident sharing its category + entity/process
# Directory scanned for third-party plugins (detection/responder/enrichment).
# Empty by default - discovery is opt-in and only from a directory you control.
EDR_PLUGIN_DIR              = DATA_DIR / "plugins"
# AI-assisted investigation. OFF by default: turning it on SENDS incident
# details (including domains) to the configured AI provider (a network LLM
# backend), so it is opt-in and clearly disclosed, matching the roadmap's rule
# for anything that leaves the machine. Provider is vendor-neutral and
# selectable (see valkyrie/edr/ai_provider.py); the `local` provider keeps
# everything on-box.
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
# block - enforced both by this cap and by the classifier applying it only as an
# allow->flag upgrade. Do not raise the cap to/above the block threshold.
COOC_QUIET_GAP     = 8.0     # s of quiet that ends a burst (next query = new anchor)
COOC_BURST_MAX     = 30.0    # s; force a new anchor if one burst runs longer
COOC_MIN_ANCHORS   = 3       # G4: distinct anchors required before any score
COOC_SCORE_BASE    = 0.45    # flag-band score at exactly COOC_MIN_ANCHORS anchors
COOC_SCORE_STEP    = 0.03    # added per extra distinct anchor
COOC_SCORE_CAP     = 0.60    # < ANOMALY_BLOCK_THRESHOLD (0.7) - flag-only, hard cap

# G1 - shipped infrastructure / functional-third-party allowlist (eTLD+1, last
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
# Layered overrides (config file / environment) - applied LAST so they win over
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
    # reaches here - those simply leave the defaults in place.
    raise SystemExit(f"[valkyrie] invalid configuration: {_cfg_exc}")
