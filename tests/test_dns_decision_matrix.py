"""Tier 1.6 — the full decision matrix for ``DNSInterceptor._decide``.

Why this file is the highest-value test in the repo: `_decide` is where every
signal in the product converges into the one irreversible act Valkyrie performs
— returning `0.0.0.0` for a domain. Both of this project's real outages lived
here (the world-banks ML false positive, and the query-burst class that
sinkholed microsoft/paypal/bing/live/linkedin). The module was 33% covered.

The stages are *ordered*, and the order is the security policy:

    1   user always_allow      2   user always_block
    2a  threat-intel IOC       2b  intelligence memory (bad → block, good → allow)
    3   scanner                3b  blocklist
    3c  intelligence classify  4   baseline anomaly

Coverage alone would not catch a precedence regression — you can execute every
line while silently reordering two of them. So each test below pins one
*relationship*: given two stages that disagree, which one wins. Every fake
disagrees deliberately, so a reordering flips a result rather than passing.

The fakes are minimal on purpose. Using the real collaborators would test them
too and make a failure ambiguous; here a failure can only mean the precedence
changed.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks
from valkyrie.dns_interceptor import DNSInterceptor
from valkyrie.process_watcher import ProcessInfo


# ── Minimal fakes: each one is a single stage that can be told what to say ───

@dataclass
class _Rules:
    allow: set = field(default_factory=set)
    block: set = field(default_factory=set)

    def get(self):
        return self

    def is_always_allowed(self, domain, proc):
        return domain in self.allow

    def is_always_blocked(self, domain, proc):
        return domain in self.block


@dataclass
class _Hit:
    reason: str


@dataclass
class _ThreatIntel:
    hits: set = field(default_factory=set)

    def match_domain(self, domain):
        return _Hit("threat_intel:c2-feed") if domain in self.hits else None


@dataclass
class _ScanResult:
    decision: str
    reasons: tuple = ("scanner-said-so",)
    confidence: float = 0.9
    category: str = "tracker"


@dataclass
class _Scanner:
    verdicts: dict = field(default_factory=dict)

    def analyze(self, domain, proc):
        return self.verdicts.get(domain, _ScanResult("allow", (), 0.1, ""))


@dataclass
class _Intelligence:
    memory: dict = field(default_factory=dict)          # domain -> 'bad'/'good'
    classification: dict = field(default_factory=dict)  # domain -> verdict dict
    blocked_calls: list = field(default_factory=list)   # remember_block audit

    def record(self, proc, domain, now, size):
        pass

    def check_memory(self, domain):
        return self.memory.get(domain)

    def memory_reason(self, domain):
        return "learned-bad-reason"

    def remember_block(self, domain, reason):
        self.blocked_calls.append((domain, reason))

    def classify(self, proc, domain, now, size):
        return self.classification.get(
            domain, {"decision": "allow", "reason": "", "score": 0.0})


@dataclass
class _Blocklist:
    blocked: set = field(default_factory=set)

    def is_blocked(self, domain):
        return domain in self.blocked


@dataclass
class _Behavioral:
    def should_block(self, domain, proc):
        return (False, 0.0, "")


@dataclass
class _Store:
    anomalies: set = field(default_factory=set)

    def is_anomaly(self, proc, domain):
        return domain in self.anomalies


class _Watcher:
    def get_process_for_port(self, *a, **k):
        return None

    def start(self):
        pass

    def stop(self):
        pass


def _build(**kw) -> tuple[DNSInterceptor, dict]:
    """An interceptor whose every stage is a controllable fake."""
    parts = {
        "rules": kw.get("rules", _Rules()),
        "threat_intel": kw.get("threat_intel", _ThreatIntel()),
        "intelligence": kw.get("intelligence", _Intelligence()),
        "scanner": kw.get("scanner", _Scanner()),
        "blocklist": kw.get("blocklist", _Blocklist()),
        "store": kw.get("store", _Store()),
    }
    di = DNSInterceptor(
        store=parts["store"], blocklist=parts["blocklist"],
        behavioral=_Behavioral(), rules=parts["rules"],
        process_watcher=_Watcher(), scanner=parts["scanner"],
        intelligence=parts["intelligence"], threat_intel=parts["threat_intel"],
    )
    return di, parts


_PROC = ProcessInfo(name="firefox.exe", pid=1234, path="")
_QTYPE = 1   # A


def _decide(di, domain):
    """(decision, reason, score, category)"""
    return di._decide(domain, _QTYPE, _PROC, 0)


def main() -> int:
    c = Checks("dns decision matrix", expect_min=26)

    D = "example.test"

    # ── 1. NO human-authored allow/block list is ever consulted ─────────────
    # Valkyrie analyses every domain and decides for itself. Even if a rules
    # object still carries allow/block entries, the decision IGNORES them and
    # comes from analysis. There is no "user:always_*" verdict any more.
    print("\n[1] manual allow/block lists are IGNORED — analysis decides")
    di, _ = _build(
        rules=_Rules(allow={D}, block={D}),          # both set; must be ignored
        threat_intel=_ThreatIntel(hits={D}),
    )
    dec, reason, _, cat = _decide(di, D)
    c.check("a domain a list would 'allow' still blocks on a C2 feed",
            dec == "blocked")
    c.check("the verdict is analysis (threat_intel), never a user rule",
            cat == "threat_intel" and "user:" not in reason)

    # ── 2. a domain a list would 'block' is decided by analysis, not the list ─
    print("\n[2] a would-be blocked domain is decided by analysis, not a list")
    di, _ = _build(
        rules=_Rules(block={D}),                     # list says block; ignored
        scanner=_Scanner({D: _ScanResult("allow", (), 0.0, "")}),
        intelligence=_Intelligence(memory={D: "good"}),
    )
    dec, reason, score, cat = _decide(di, D)
    c.check("analysis known-good wins over a would-be block list",
            dec == "allowed")
    c.check("no user:always_block verdict exists", "user:always_block" not in reason)

    # ── 2a. threat intel beats the known-good fast path ─────────────────────
    # The compromised-infrastructure case, and it is explicitly commented in
    # _decide: a domain we learned as good but which now appears in a C2 feed
    # must block. This is the single most important precedence in the chain.
    print("\n[2a] threat-intel IOC beats the intelligence known-good fast path")
    ti_intel = _Intelligence(memory={D: "good"})
    di, _ = _build(threat_intel=_ThreatIntel(hits={D}), intelligence=ti_intel)
    dec, reason, score, cat = _decide(di, D)
    c.check("a known-good domain in a C2 feed still blocks", dec == "blocked")
    c.check("the reason names threat intel", "threat_intel" in reason)
    c.check("threat-intel block is categorised threat_intel", cat == "threat_intel")
    c.check("a threat-intel block is remembered for the next lookup",
            any(d == D for d, _ in ti_intel.blocked_calls))

    # ── 2b. intelligence memory ─────────────────────────────────────────────
    print("\n[2b] intelligence memory short-circuits the pipeline")
    di, _ = _build(intelligence=_Intelligence(memory={D: "bad"}),
                   scanner=_Scanner({D: _ScanResult("allow", (), 0.0, "")}))
    dec, reason, score, cat = _decide(di, D)
    c.check("a learned-bad domain blocks even when the scanner allows",
            dec == "blocked")
    c.check("the learned reason is surfaced, not invented",
            "learned-bad-reason" in reason)
    c.check("learned-bad carries full confidence", score == 1.0)

    di, _ = _build(intelligence=_Intelligence(memory={D: "good"}),
                   scanner=_Scanner({D: _ScanResult("block")}))
    dec, reason, score, cat = _decide(di, D)
    c.check("a known-good domain skips the scanner entirely", dec == "allowed")
    c.check("known-good carries zero suspicion", score == 0.0)

    # ── 3. scanner ──────────────────────────────────────────────────────────
    print("\n[3] scanner verdicts")
    di, parts = _build(scanner=_Scanner({D: _ScanResult("block", category="malware")}),
                       blocklist=_Blocklist())
    dec, reason, score, cat = _decide(di, D)
    c.check("a scanner block blocks", dec == "blocked")
    c.check("the scanner's own reasons are surfaced", "scanner-said-so" in reason)
    c.check("the scanner's category is preserved", cat == "malware")
    # A tracker/telemetry scanner-block is DECEIVED (decoy dead-end) in the
    # Standard profile, not hard-blocked — full matrix in tests/test_deceive.py.
    di_t, _ = _build(scanner=_Scanner({D: _ScanResult("block", category="tracker")}))
    c.check("a tracker scanner-block is deceived, not blocked (Standard)",
            _decide(di_t, D)[0] == "deceived")
    c.check("a scanner block is remembered",
            any(d == D for d, _ in parts["intelligence"].blocked_calls))

    di, parts = _build(scanner=_Scanner({D: _ScanResult("flag")}))
    dec, reason, score, cat = _decide(di, D)
    c.check("a scanner flag flags rather than blocks", dec == "flagged")
    c.check("a flag is NOT written to memory as a block",
            parts["intelligence"].blocked_calls == [])

    # ── 3b. blocklist applies on top of a scanner 'allow' ───────────────────
    print("\n[3b] blocklist enforces beneath a scanner 'allow'")
    di, _ = _build(scanner=_Scanner(), blocklist=_Blocklist(blocked={D}))
    dec, reason, score, cat = _decide(di, D)
    c.check("a blocklisted domain blocks when the scanner allows",
            dec == "blocked")
    c.check("blocklist block is categorised blocklist", cat == "blocklist")

    # ── 3c. intelligence classifier ─────────────────────────────────────────
    print("\n[3c] intelligence classifier runs after the list-based checks")
    di, parts = _build(intelligence=_Intelligence(
        classification={D: {"decision": "block", "reason": "beacon-cadence",
                            "score": 0.95}}))
    dec, reason, score, cat = _decide(di, D)
    c.check("a classifier block blocks", dec == "blocked")
    c.check("the classifier's reason is surfaced", reason == "beacon-cadence")
    c.check("a classifier block is remembered",
            any(d == D for d, _ in parts["intelligence"].blocked_calls))

    di, parts = _build(intelligence=_Intelligence(
        classification={D: {"decision": "flag", "reason": "odd-hours",
                            "score": 0.5}}))
    dec, _, _, _ = _decide(di, D)
    c.check("a classifier flag flags rather than blocks", dec == "flagged")
    c.check("a classifier flag is not remembered as a block",
            parts["intelligence"].blocked_calls == [])

    # ── OPEN POLICY GAP: hard blocks vs the known-good fast path ────────────
    # docs/TEST_PLAN.md tier 1.6 states the intent that "hard blocks must beat
    # the known-good fast path". Today only threat-intel does (stage 2a, before
    # the fast path). The blocklist (3b) and a scanner 'block' (3) both sit
    # AFTER stage 2b, so a domain once promoted to known-good is allowed even
    # once it lands on the blocklist — which matters because the blocklist grows
    # over time, so a domain promoted last week can be blocklisted today and
    # still resolve.
    #
    # These checks pin the CURRENT behaviour rather than the intended one, on
    # purpose. Changing it alters what gets blocked, and for this product a
    # false positive is the cardinal sin, so it is an owner decision and not a
    # test-suite decision. What the tests guarantee is that the behaviour cannot
    # now change silently in either direction. See TEST_PLAN tier 1.6.
    print("\n[!] OPEN GAP: hard blocks do NOT beat the known-good fast path")
    di, _ = _build(intelligence=_Intelligence(memory={D: "good"}),
                   blocklist=_Blocklist(blocked={D}))
    dec_bl, _, _, _ = _decide(di, D)
    c.check("DOCUMENTED GAP: known-good outranks the blocklist (allowed)",
            dec_bl == "allowed")
    di, _ = _build(intelligence=_Intelligence(memory={D: "good"}),
                   scanner=_Scanner({D: _ScanResult("block")}))
    dec_sc, _, _, _ = _decide(di, D)
    c.check("DOCUMENTED GAP: known-good outranks a scanner block (allowed)",
            dec_sc == "allowed")
    c.check("threat-intel remains the ONLY override of the fast path",
            dec_bl == "allowed" and dec_sc == "allowed")

    # ── 4. baseline anomaly, and the default ────────────────────────────────
    print("\n[4] baseline anomaly flags; silence allows")
    di, _ = _build(store=_Store(anomalies={D}))
    dec, reason, _, cat = _decide(di, D)
    c.check("an unbaselined pairing flags", dec == "flagged")
    c.check("anomaly flag is categorised anomaly", cat == "anomaly")

    di, parts = _build()
    dec, reason, score, cat = _decide(di, D)
    c.check("a domain no stage objects to is allowed", dec == "allowed")
    c.check("an uneventful allow carries no reason", reason == "")
    c.check("an allow is never written to memory as a block",
            parts["intelligence"].blocked_calls == [])

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
