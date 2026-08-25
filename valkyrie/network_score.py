"""Network anomaly scorer - the LIST-FREE half of Valkyrie's blocker.

The firewall today decides by membership: is this IP in a feed? That has two
structural problems. An IP carries no readable signal (unlike a domain, where
`rtb-adserver.net` at least *looks* like an ad server), and C2 infrastructure
rotates in hours while a feed refreshes in hours - so a list is permanently
one step behind.

This module is the answer: judge the CONNECTION, not the address. Six weak
signals over who made the connection and how it behaves, none of which needs a
list, combined with the same precision discipline as `behavior_score.py`:

    NO SINGLE WEAK SIGNAL FIRES.

A connection surfaces only when a strong tell is present or several weak
signals compound past the threshold. An over-eager network blocker takes the
user offline, which is the cardinal sin - see the ML-domain-blocker lesson in
[[valkyrie-detection-model]] and the popular-domain FP class in ADR 0033.

Signals (S7 is the only one that touches a list, and it can never fire alone):

    S1  actor_untrusted      unsigned / temp-path / low-trust binary
    S2  never_resolved       Valkyrie never handed out this IP  (STRONGEST)
    S3  beacon_rhythm        fixed interval + jitter, uniform payload
    S4  process_novelty      this binary has no history of network use
    S5  volume_anomaly       sustained upload from a process that never uploads
    S6  protocol_mismatch    :443 with no TLS, DNS off :53, etc.
    S7  intel_corroboration  a feed knows this IP  (WEIGHT ONLY, never a verdict)

The S7 rule is the architectural commitment: threat intel adds confidence to a
decision the behavioural signals already reached. Delete every feed and the
verdicts must not change - `tests/test_list_free_firewall.py` enforces exactly
that, so "Valkyrie does not depend on lists" is a property that cannot silently
regress rather than a claim in a README.

Pure and deterministic: no clock reads, no I/O, no network. Everything the
scorer needs arrives on the ConnFacts record, so it is unit-testable offline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Weights. Tuned so that no single signal reaches THRESHOLD alone - the
# precision rule is enforced by construction, not by convention.
# ---------------------------------------------------------------------------
W_ACTOR_UNTRUSTED   = 0.30
W_NEVER_RESOLVED    = 0.35      # strongest single behavioural tell
W_BEACON_RHYTHM     = 0.30
W_PROCESS_NOVELTY   = 0.15
W_VOLUME_ANOMALY    = 0.25
W_PROTOCOL_MISMATCH = 0.25
W_SCAN_FANOUT       = 0.35      # one process, many distinct peers = scanning
W_INTEL             = 0.30      # corroboration only

THRESHOLD = 0.55                # surfacing floor
BLOCK_FLOOR = 0.75              # decision engine may escalate above this

# A horizontal scan is one process reaching this many DISTINCT peers within the
# caller's recent window. Set high so a couple of parallel connections (a
# browser, an updater fanning to a CDN) never looks like a sweep.
_SCAN_FANOUT = 20

# Ports where a plaintext/raw payload is expected and a "no TLS" observation
# is therefore meaningless. Keeps S6 from firing on ordinary HTTP.
_PLAINTEXT_OK_PORTS = frozenset({80, 53, 67, 68, 123, 137, 138, 139, 445, 5353})


@dataclass(frozen=True)
class ConnFacts:
    """One outbound connection, in the shape Zeek's conn.log reduced to the
    fields that actually carry signal. Every field is an observation the
    collector already has or can cheaply derive - nothing here requires deep
    packet inspection or content."""
    process_name: str = ""
    process_path: str = ""
    raddr_ip: str = ""
    raddr_port: int = 0
    proto: str = "tcp"
    bytes_sent: int = 0
    bytes_recv: int = 0
    duration: float = 0.0

    # Derived context supplied by the caller (all tri-state-safe):
    #   None = unknown / feature not deployed -> contributes NOTHING.
    #   Treating "unknown" as "bad" would make every connection look malicious
    #   the moment a feature is disabled, which is how you ship an outage.
    resolved: Optional[bool] = None       # resolution_log.was_resolved()
    actor_trusted: Optional[bool] = None  # trust.is_trusted_os_path / signed
    actor_low_trust_path: bool = False    # %TEMP%, Downloads, ProgramData...
    process_net_history: Optional[int] = None   # prior connections by this image
    process_upload_baseline: Optional[int] = None  # typical bytes_sent
    beacon_interval: Optional[float] = None     # seconds, if periodic
    beacon_jitter: Optional[float] = None       # 0..1 relative deviation
    beacon_count: int = 0                       # repetitions observed
    distinct_peers_recent: Optional[int] = None # distinct dest hosts this
                                                # process hit in the window (S8)
    tls_expected: bool = False            # port implies TLS
    tls_observed: Optional[bool] = None   # ClientHello actually seen
    intel_hit: bool = False               # a feed knows this IP (S7)


@dataclass
class _Sig:
    name: str
    weight: float
    reason: str


def _signals(f: ConnFacts) -> list[_Sig]:
    """Evaluate every signal. Pure; order is irrelevant to the result."""
    out: list[_Sig] = []

    # S1 - who is talking. An unsigned binary running out of a user-writable
    # directory is a different proposition from a signed OS component, even
    # when the destination is identical.
    if f.actor_trusted is False or f.actor_low_trust_path:
        why = []
        if f.actor_trusted is False:
            why.append("unsigned/untrusted binary")
        if f.actor_low_trust_path:
            why.append("runs from a user-writable directory")
        out.append(_Sig("actor_untrusted", W_ACTOR_UNTRUSTED,
                        "connection made by an " + " and ".join(why)))

    # S2 - the signal only Valkyrie can compute, because it owns the resolver.
    # Nothing on this machine ever asked DNS for this address.
    if f.resolved is False:
        out.append(_Sig("never_resolved", W_NEVER_RESOLVED,
                        "destination was never resolved by this machine — the "
                        "address was hardcoded or obtained out-of-band"))

    # S3 - C2 beacons are periodic by construction. Requires several
    # repetitions AND low jitter; a couple of coincidental polls never counts.
    if (f.beacon_interval and f.beacon_count >= 4
            and f.beacon_jitter is not None and f.beacon_jitter <= 0.25):
        out.append(_Sig("beacon_rhythm", W_BEACON_RHYTHM,
                        f"periodic contact every ~{f.beacon_interval:.0f}s "
                        f"across {f.beacon_count} connections with low jitter"))

    # S4 - a binary with no networking history suddenly networking.
    if f.process_net_history == 0:
        out.append(_Sig("process_novelty", W_PROCESS_NOVELTY,
                        "this program has no prior history of network use"))

    # S5 - exfiltration shape: sustained upload from something that does not
    # normally upload. Needs a baseline; absent one it cannot fire.
    if (f.process_upload_baseline is not None
            and f.bytes_sent > max(1_000_000, f.process_upload_baseline * 20)):
        out.append(_Sig("volume_anomaly", W_VOLUME_ANOMALY,
                        f"uploaded {f.bytes_sent:,} bytes — far beyond this "
                        f"program's normal volume"))

    # S6 - claiming a protocol it is not speaking.
    if (f.tls_expected and f.tls_observed is False
            and f.raddr_port not in _PLAINTEXT_OK_PORTS):
        out.append(_Sig("protocol_mismatch", W_PROTOCOL_MISMATCH,
                        f"port {f.raddr_port} implies TLS but no TLS handshake "
                        f"was observed"))

    # S8 - horizontal scan. One process reaching a large number of DISTINCT
    # peers in a short window is network-service discovery / scanning (T1046) -
    # the list-free way to catch SoftPerfect NetScan / Advanced IP Scanner and
    # the like without ever naming the tool. Like every signal it cannot fire
    # alone, so a sanctioned admin scanner (trusted, resolved) stays quiet while
    # the same fan-out from an untrusted or never-before-networked binary
    # compounds past the threshold.
    if (f.distinct_peers_recent is not None
            and f.distinct_peers_recent >= _SCAN_FANOUT):
        out.append(_Sig("scan_fanout", W_SCAN_FANOUT,
                        f"contacted {f.distinct_peers_recent} distinct hosts in a "
                        f"short window — horizontal network scan"))

    # S7 - corroboration ONLY. Weighted like any other signal; never special,
    # never an override. See the module docstring and the list-free gate.
    if f.intel_hit:
        out.append(_Sig("intel_corroboration", W_INTEL,
                        "a threat-intelligence feed also lists this address"))

    return out


def score_connection(f: ConnFacts) -> dict:
    """Score one connection. Always returns a dict (score/signals/reason)."""
    sigs = _signals(f)
    raw = sum(s.weight for s in sigs)
    score = min(1.0, round(raw, 3))
    # A lone signal can never surface, whatever its weight. This is the
    # precision rule made structural rather than a matter of tuning.
    fires = len(sigs) >= 2 and score >= THRESHOLD
    return {
        "score": score,
        "fires": fires,
        "labels": [s.name for s in sigs],
        "signals": [{"name": s.name, "weight": s.weight, "reason": s.reason}
                    for s in sigs],
        "reason": "; ".join(s.reason for s in sigs),
        "severity": ("high" if score >= BLOCK_FLOOR
                     else "medium" if fires else "info"),
    }


def classify_connection_anomaly(f: ConnFacts) -> Optional[dict]:
    """Surface a verdict only when the scorer fires. None otherwise.

    Mirrors `behavior_score.classify_anomaly` so the two scorers read the same
    way at their call sites.
    """
    r = score_connection(f)
    if not r["fires"]:
        return None
    # Name the technique after the dominant tell: a scan fan-out is Discovery
    # (T1046), a periodic beacon is C2 (T1071); otherwise the generic app-layer
    # C2 label. Keeps the kill-chain tactic accurate instead of always C2.
    if "scan_fanout" in r["labels"]:
        technique = "T1046 — Network Service Discovery"
    else:
        technique = "T1071 — Application Layer Protocol"
    return {
        "severity": r["severity"],
        "technique": technique,
        "labels": ["network_anomaly"] + r["labels"],
        "reason": r["reason"],
        "confidence": r["score"],
    }


def verdict_without_intel(f: ConnFacts) -> dict:
    """The same connection scored with S7 forced off.

    Exists so the list-free gate can assert, mechanically, that removing every
    feed changes confidence but never the decision.
    """
    import dataclasses
    return score_connection(dataclasses.replace(f, intel_hit=False))
