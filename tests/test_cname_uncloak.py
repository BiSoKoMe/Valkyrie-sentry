#!/usr/bin/env python3
"""CNAME-cloak uncloaking tests (valkyrie/cname_uncloak.py + dns_interceptor).

CNAME cloaking is the #1 modern DNS-blocklist evasion: a first-party-looking
subdomain (metrics.brand.com) is a CNAME to the tracker (brand.eulerian.net).
This proves Valkyrie uncloaks it - and, just as important, that it does NOT
break legitimate CNAMEs to CDNs (Cloudflare/Akamai/Fastly), which is where a
naive uncloaker would take down half the web.

  [1] Curated tracker matching is correct + boundary-safe
  [2] same_registrable suppresses only first-party internal CNAMEs
  [3] Interceptor uncloaks a real CNAME-chain answer to a known tracker
  [4] Interceptor uncloaks via the scanner (non-curated tracker)
  [5] Interceptor does NOT block legitimate CDN CNAMEs (the FP boundary)
  [6] A plain A answer with no CNAME is untouched
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


# --- Lightweight stubs so we can exercise the real interceptor method without a
#    live socket / process watcher / store. ---
class _StubStore:
    def log(self, *a, **k):
        pass


class _StubBlocklist:
    def __init__(self, blocked=()):
        self._b = set(blocked)

    def is_blocked(self, d):
        return d in self._b


class _Res:
    def __init__(self, decision, reasons):
        self.decision = decision
        self.reasons = reasons
        self.confidence = 1.0 if decision == "block" else 0.0
        self.category = "tracker"


class _StubScanner:
    def __init__(self, block=()):
        self._b = set(block)

    def analyze(self, domain, proc):
        # Suffix-aware like the real SiteScanner (a subdomain of a tracker apex
        # scores the same as the apex).
        hit = any(domain == b or domain.endswith("." + b) for b in self._b)
        return _Res("block", ["ad-tech tracker"]) if hit else _Res("allow", [])


def _make_answer(qname: str, chain: list[tuple[str, str]], final_ip: str = "1.2.3.4") -> bytes:
    """Build a DNS answer wire with a CNAME *chain* then a final A record.
    chain = [(owner, cname_target), ...]."""
    import dns.message, dns.rrset, dns.rdatatype
    q = dns.message.make_query(qname, dns.rdatatype.A)
    r = dns.message.make_response(q)
    for owner, target in chain:
        r.answer.append(dns.rrset.from_text(owner + ".", 300, "IN", "CNAME", target + "."))
    last_owner = chain[-1][1] if chain else qname
    r.answer.append(dns.rrset.from_text(last_owner + ".", 300, "IN", "A", final_ip))
    return r.to_wire()


def main() -> int:
    from valkyrie.cname_uncloak import (
        matches_cname_tracker, suffix_match, same_registrable, CNAME_TRACKERS,
    )
    from valkyrie.dns_interceptor import DNSInterceptor
    from valkyrie.process_watcher import _UNKNOWN

    print("\n=== CNAME-cloak uncloaking ===\n")

    print("[1] Curated tracker matching + boundary safety")
    _check("eulerian.net apex matches", matches_cname_tracker("eulerian.net") == "eulerian.net")
    _check("subdomain of a tracker matches",
           matches_cname_tracker("brand.eulerian.net") == "eulerian.net")
    _check("Adobe demdex matches", matches_cname_tracker("cdn.demdex.net") == "demdex.net")
    _check("unrelated domain does not match", matches_cname_tracker("api.github.com") is None)
    _check("boundary-safe: noteulerian.net does NOT match",
           matches_cname_tracker("noteulerian.net") is None)
    _check("empty host is safe", matches_cname_tracker("") is None)

    print("\n[2] same_registrable suppresses only first-party internal CNAMEs")
    _check("a.brand.com ~ b.brand.com (internal)", same_registrable("a.brand.com", "b.brand.com"))
    _check("brand.com !~ eulerian.net (cross-site)",
           not same_registrable("metrics.brand.com", "x.eulerian.net"))

    # Build the interceptor once with stubs.
    itc = DNSInterceptor(
        store=_StubStore(),
        blocklist=_StubBlocklist({"evil-tracker.example"}),
        behavioral=None, rules=None, process_watcher=None,
        scanner=_StubScanner({"doubleclick.net"}),
        threat_intel=None,
    )

    print("\n[3] Uncloak a real CNAME-chain answer to a known tracker")
    wire = _make_answer("metrics.brand.com",
                        [("metrics.brand.com", "brand.eulerian.net")])
    targets = itc._cname_targets(wire)
    _check("CNAME target parsed from the wire", "brand.eulerian.net" in targets)
    res = itc._uncloak_block(wire, "metrics.brand.com", _UNKNOWN)
    _check("known-tracker CNAME is blocked", res is not None and res[0] == "brand.eulerian.net")
    _check("block reason names the tracker apex",
           res is not None and "eulerian.net" in res[1])

    print("\n[4] Uncloak via the scanner (non-curated tracker in the chain)")
    wire = _make_answer("stats.brand.com",
                        [("stats.brand.com", "hidden.doubleclick.net")])
    res = itc._uncloak_block(wire, "stats.brand.com", _UNKNOWN)
    _check("scanner-flagged CNAME target is blocked",
           res is not None and res[0] == "hidden.doubleclick.net")

    print("\n[5] Legitimate CDN CNAMEs are NOT blocked (the FP boundary)")
    for owner, cdn in [
        ("www.brand.com", "brand.com.edgekey.net"),      # Akamai
        ("assets.brand.com", "d111abc.cloudfront.net"),  # CloudFront
        ("cdn.brand.com", "brand.map.fastly.net"),       # Fastly
        ("img.brand.com", "brand.azureedge.net"),        # Azure CDN
    ]:
        wire = _make_answer(owner, [(owner, cdn)])
        res = itc._uncloak_block(wire, owner, _UNKNOWN)
        _check(f"CDN CNAME not blocked: {cdn}", res is None)

    print("\n[6] Multi-hop chain + a plain no-CNAME answer")
    # Legit first hop then a tracker deeper in the chain - still caught.
    wire = _make_answer("t.brand.com",
                        [("t.brand.com", "edge.brand.com"),
                         ("edge.brand.com", "collect.ati-host.net")])
    res = itc._uncloak_block(wire, "t.brand.com", _UNKNOWN)
    _check("tracker deeper in a multi-hop chain is caught",
           res is not None and res[0] == "collect.ati-host.net")
    # Plain A answer, no CNAME -> nothing to uncloak.
    import dns.message, dns.rrset, dns.rdatatype
    q = dns.message.make_query("clean.example", dns.rdatatype.A)
    r = dns.message.make_response(q)
    r.answer.append(dns.rrset.from_text("clean.example.", 300, "IN", "A", "93.184.216.34"))
    _check("no-CNAME answer yields no uncloak block",
           itc._uncloak_block(r.to_wire(), "clean.example", _UNKNOWN) is None)

    print("\n" + "=" * 54)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print(f"All checks PASSED (curated set: {len(CNAME_TRACKERS)} tracker apexes).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
