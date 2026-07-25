"""Built-in detection & enrichment plugins.

These translate Valkyrie's existing sensor output — the DNS decision event
stream (blocklist, scanner, firewall answer-IP screening, behavioural
heuristics, the intelligence classifier) — into EDR Detections. They add no new
sensing; they *interpret* what Valkyrie already sees so it shows up as triable
security signal instead of a flat log line.

Each detection carries a severity and a best-effort MITRE ATT&CK technique so
the incident view reads like an EDR, not a firewall log.
"""

from __future__ import annotations

from .plugins import DetectionPlugin, EnrichmentPlugin, PluginContext
from .schema import Detection


def _ev(event: dict) -> tuple:
    """Pull the common fields out of a Store event dict."""
    return (
        str(event.get("domain", "")),
        str(event.get("decision", "")),
        str(event.get("process_name", "")),
        int(event.get("process_pid", 0) or 0),
        str(event.get("category", "") or event.get("raw_category", "")),
        float(event.get("suspicion", 0.0) or 0.0),
        str(event.get("reason", "")),
    )


# ---------------------------------------------------------------------------
# Category → MITRE ATT&CK technique (best-effort, informational)
# ---------------------------------------------------------------------------

_TECHNIQUE = {
    "firewall_ip":  "T1071 — Application Layer Protocol (C2)",
    "intelligence": "T1071.004 — DNS C2 / beaconing",
    "behavioral":   "T1568.002 — Domain Generation Algorithm",
    "dga":          "T1568.002 — Domain Generation Algorithm",
    "tunnel":       "T1048.003 — Exfiltration Over Alternative Protocol (DNS tunnelling)",
    "dyndns":       "T1568 — Dynamic Resolution (wildcard DNS)",
    "attack_chain": "Multi-stage attack (correlated ATT&CK tactics)",
    "anomaly":      "T1071.004 — Anomalous DNS",
    "doh_bypass":   "T1572 — Protocol Tunnelling (DoH bypass)",
    "tracker":      "T1041 — Exfiltration / tracking",
    "blocklist":    "T1071 — Known-bad infrastructure",
    "scanner":      "T1071 — Known-bad infrastructure",
    "user_rule":    "",
}


class MitreEnrichment(EnrichmentPlugin):
    name = "enrich.mitre"
    description = "Attach a best-effort MITRE ATT&CK technique by category"

    def enrich(self, det: Detection, ctx: PluginContext) -> None:
        if not det.technique:
            det.technique = _TECHNIQUE.get(det.category, "")


# ---------------------------------------------------------------------------
# Detection plugins
# ---------------------------------------------------------------------------

class MalwareIpDetection(DetectionPlugin):
    name = "dns.malware_ip"
    description = "Domain resolved to an IP inside a threat-intel range (likely C2/malware)"

    def analyze(self, event, ctx):
        domain, decision, pname, pid, cat, susp, reason = _ev(event)
        if cat == "firewall_ip" and decision in ("blocked", "behavioral"):
            return [Detection(
                source=self.name, severity="high", category="firewall_ip",
                title=f"{pname or 'a process'} contacted threat-intel infrastructure",
                entity=domain, process_name=pname, process_pid=pid,
                details={"reason": reason, "suspicion": susp},
            )]
        return []


class BeaconDetection(DetectionPlugin):
    name = "dns.beacon"
    description = "Regular, low-payload callbacks — beacon/heartbeat behaviour"

    _MARKERS = ("beacon", "heartbeat", "periodic", "regular interval")

    def analyze(self, event, ctx):
        domain, decision, pname, pid, cat, susp, reason = _ev(event)
        rl = reason.lower()
        if cat == "intelligence" and any(m in rl for m in self._MARKERS):
            return [Detection(
                source=self.name, severity="high", category="intelligence",
                title=f"Beacon-like callbacks from {pname or 'a process'}",
                entity=domain, process_name=pname, process_pid=pid,
                technique="T1071.004 — DNS C2 / beaconing",
                details={"reason": reason, "suspicion": susp},
            )]
        return []


class IntelBlockDetection(DetectionPlugin):
    name = "dns.intel"
    description = "The self-learning intelligence layer blocked a learned threat"

    def analyze(self, event, ctx):
        domain, decision, pname, pid, cat, susp, reason = _ev(event)
        if cat == "intelligence" and decision in ("blocked", "behavioral"):
            # Beacon detections already covered above — avoid double counting.
            if any(m in reason.lower() for m in BeaconDetection._MARKERS):
                return []
            return [Detection(
                source=self.name, severity="medium", category="intelligence",
                title=f"Learned-threat block for {pname or 'a process'}",
                entity=domain, process_name=pname, process_pid=pid,
                details={"reason": reason, "suspicion": susp},
            )]
        return []


class DohBypassDetection(DetectionPlugin):
    name = "dns.doh_bypass"
    description = "A process tried to tunnel DNS over HTTPS to bypass filtering"

    def analyze(self, event, ctx):
        domain, decision, pname, pid, cat, susp, reason = _ev(event)
        if cat == "doh_bypass":
            return [Detection(
                source=self.name, severity="medium", category="doh_bypass",
                title=f"DoH bypass attempt by {pname or 'a process'}",
                entity=domain, process_name=pname, process_pid=pid,
                technique="T1572 — Protocol Tunnelling (DoH bypass)",
                details={"reason": reason},
            )]
        return []


class DgaDetection(DetectionPlugin):
    name = "dns.dga"
    description = "Algorithmically generated (DGA) domain — likely malware C2 rendezvous"

    def analyze(self, event, ctx):
        domain, decision, pname, pid, cat, susp, reason = _ev(event)
        # Confirmed DGA from the corroborated classifier (valkyrie/dga.py, wired
        # into the scanner) — length + entropy + bigram-implausibility all agree,
        # so this is a high-confidence C2 signal.
        if cat == "dga":
            return [Detection(
                source=self.name, severity="high", category="dga",
                title=f"DGA C2 domain contacted by {pname or 'a process'}",
                entity=domain, process_name=pname, process_pid=pid,
                technique="T1568.002 — Domain Generation Algorithm",
                details={"reason": reason, "suspicion": susp},
            )]
        # Looser legacy signal: a behavioral block whose reason cites entropy.
        is_beh = decision == "behavioral" or cat == "behavioral"
        if is_beh and "entropy" in reason.lower():
            return [Detection(
                source=self.name, severity="medium", category="behavioral",
                title=f"DGA-like domain from {pname or 'a process'}",
                entity=domain, process_name=pname, process_pid=pid,
                technique="T1568.002 — Domain Generation Algorithm",
                details={"reason": reason, "suspicion": susp},
            )]
        return []


class TunnelDetection(DetectionPlugin):
    name = "dns.tunnel"
    description = "DNS tunnelling — a stream of unique generated subdomains under one base"

    def analyze(self, event, ctx):
        domain, decision, pname, pid, cat, susp, reason = _ev(event)
        # The scanner's unique-subdomain flood verdict (site_scanner S9 /
        # dns_tunnel.py): many never-seen machine-generated labels under one
        # registrable base in a short window — the shape of DNS exfil/C2,
        # invisible to any single-query signal.
        if cat == "tunnel":
            return [Detection(
                source=self.name, severity="high", category="tunnel",
                title=f"DNS tunnelling pattern from {pname or 'a process'}",
                entity=domain, process_name=pname, process_pid=pid,
                technique="T1048.003 — Exfiltration Over Alternative Protocol (DNS tunnelling)",
                details={"reason": reason, "suspicion": susp},
            )]
        # A blocked generated-looking hostname on a wildcard IP-echo provider —
        # not yet a corroborated flood, but the same technique family (hiding
        # traffic under a legitimate wildcard base). Medium: real signal,
        # single-query evidence.
        if cat == "dyndns" and decision in ("blocked", "behavioral"):
            return [Detection(
                source=self.name, severity="medium", category="dyndns",
                title=f"Suspicious wildcard-DNS hostname from {pname or 'a process'}",
                entity=domain, process_name=pname, process_pid=pid,
                technique="T1568 — Dynamic Resolution (wildcard DNS)",
                details={"reason": reason, "suspicion": susp},
            )]
        return []


class AnomalyDetection(DetectionPlugin):
    name = "dns.anomaly"
    description = "A process reached a domain outside its learned baseline"

    def analyze(self, event, ctx):
        domain, decision, pname, pid, cat, susp, reason = _ev(event)
        if decision == "flagged" and cat in ("anomaly", "intelligence"):
            return [Detection(
                source=self.name, severity="low", category="anomaly",
                title=f"Baseline anomaly for {pname or 'a process'}",
                entity=domain, process_name=pname, process_pid=pid,
                details={"reason": reason, "suspicion": susp},
            )]
        return []


class TrackerDetection(DetectionPlugin):
    name = "dns.tracker"
    description = "Known tracker/ad domain blocked (privacy signal)"

    def analyze(self, event, ctx):
        domain, decision, pname, pid, cat, susp, reason = _ev(event)
        if decision == "blocked" and cat in ("tracker", "blocklist", "scanner"):
            return [Detection(
                source=self.name, severity="low", category="tracker",
                title=f"Tracker blocked for {pname or 'a process'}",
                entity=domain, process_name=pname, process_pid=pid,
                technique="T1041 — Exfiltration / tracking",
                details={"reason": reason},
            )]
        return []


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

BUILTIN_DETECTIONS = [
    MalwareIpDetection,
    BeaconDetection,
    IntelBlockDetection,
    DohBypassDetection,
    DgaDetection,
    TunnelDetection,
    AnomalyDetection,
    TrackerDetection,
]


def register_builtin(registry) -> None:
    """Register all built-in detection & enrichment plugins on a registry."""
    registry.register(MitreEnrichment())
    for cls in BUILTIN_DETECTIONS:
        registry.register(cls())
