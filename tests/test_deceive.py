#!/usr/bin/env python3
"""DECEIVE mechanism — tracker/telemetry gets a decoy dead-end (Standard profile)
instead of a hard block, so the app keeps working while its telemetry goes
nowhere. Stricter profiles hard-block. Malware is NEVER deceived — only blocked.

Pins the profile-aware deceive-vs-block decision at the DNS layer.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))
sys.path.insert(0, str(_HERE))

from valkyrie.decision import should_deceive, Profile
import valkyrie.dns_interceptor as dnsi
from test_dns_decision_matrix import _build, _Scanner, _ScanResult, _PROC

_fail = 0


def _check(label, ok):
    global _fail
    if not ok:
        _fail += 1
    print(f"  [{'ok  ' if ok else 'FAIL'}] {label}")


def _set_profile(p):
    dnsi._PROFILE_CACHE["val"] = p
    dnsi._PROFILE_CACHE["ts"] = time.time()


def main() -> int:
    print("=" * 60)
    print("DECEIVE mechanism")
    print("=" * 60)

    print("[1] should_deceive: trackers only, Standard profile only")
    _check("tracker + Standard -> deceive", should_deceive("tracker", Profile.STANDARD))
    _check("telemetry + Standard -> deceive", should_deceive("telemetry", Profile.STANDARD))
    _check("tracker + High-Risk -> NO deceive (hard block)",
           not should_deceive("tracker", Profile.HIGH_RISK))
    _check("tracker + Clean-Room -> NO deceive", not should_deceive("tracker", Profile.CLEAN_ROOM))
    _check("a malware category is never deceived", not should_deceive("scanner", Profile.STANDARD))

    print("[2] _decide: a tracker is DECEIVED in Standard, BLOCKED in strict profiles")
    di, _ = _build(scanner=_Scanner(
        {"metrics.tracker.io": _ScanResult("block", ("analytics beacon",), 0.9, "tracker")}))
    _set_profile(Profile.STANDARD)
    dec, _, _, cat = di._decide("metrics.tracker.io", 1, _PROC)
    _check("tracker in Standard -> 'deceived'", dec == "deceived")
    _check("category preserved (tracker)", cat == "tracker")
    _set_profile(Profile.HIGH_RISK)
    dec2, _, _, _ = di._decide("metrics.tracker.io", 1, _PROC)
    _check("same tracker in High-Risk -> 'blocked'", dec2 == "blocked")

    print("[3] malware is NEVER deceived — blocked even in Standard")
    di2, _ = _build(scanner=_Scanner(
        {"evil-c2.io": _ScanResult("block", ("malware",), 1.0, "scanner")}))
    _set_profile(Profile.STANDARD)
    dec3, _, _, _ = di2._decide("evil-c2.io", 1, _PROC)
    _check("malware in Standard stays 'blocked' (not deceived)", dec3 == "blocked")

    print("[4] a 'deceived' verdict resolves to the DECEPTION ENDPOINT, not the sinkhole")
    # This used to assert, by reading _build_response's SOURCE TEXT, that
    # deceived "shares the decoy/sinkhole branch with blocked" -- i.e. it pinned
    # DECEIVE to returning 0.0.0.0. That was the defect, not the contract:
    # 0.0.0.0 is a relabelled block that tells the tracker nothing false and
    # marks the machine as one running a blocker. It also asserted on source
    # text, so it would have kept passing no matter what the code actually
    # returned. Now it checks the ANSWER ON THE WIRE.
    import dns.message
    import dns.rdatatype
    from valkyrie.config import SINKHOLE_IPV4, DECEPTION_IPV4, DECEPTION_IPV6
    from valkyrie.deception import DeceptionEndpoint

    def _answer(di, name, qtype=dns.rdatatype.A):
        req = dns.message.make_query(name, qtype)
        dec, _, _, _ = di._decide(name, qtype, _PROC)
        resp = dns.message.from_wire(di._build_response(req, name, qtype, dec))
        return dec, [r.address for rr in resp.answer for r in rr]

    scan = _Scanner({
        "metrics.tracker.io": _ScanResult("block", ("analytics beacon",), 0.9, "tracker"),
        "evil-c2.io": _ScanResult("block", ("malware",), 1.0, "scanner")})
    _set_profile(Profile.STANDARD)

    # (a) No endpoint configured -> must behave EXACTLY as before. The deception
    #     layer is additive; it may never make DECEIVE worse than the dead-end.
    di_a, _ = _build(scanner=scan)
    dec, ips = _answer(di_a, "metrics.tracker.io")
    _check(f"no endpoint -> deceived falls back to sinkhole ({ips})",
           dec == "deceived" and ips == [SINKHOLE_IPV4])

    # (b) Endpoint listening -> deceived resolves to loopback, so the beacon
    #     CONNECTS and gets answered instead of failing.
    ep = DeceptionEndpoint(port=0)
    _check("deception endpoint starts", ep.start() and ep.running)
    di_b, _ = _build(scanner=scan)
    di_b._deception = ep
    try:
        dec, ips = _answer(di_b, "metrics.tracker.io")
        _check(f"endpoint up -> deceived resolves to the endpoint ({ips})",
               dec == "deceived" and ips == [DECEPTION_IPV4])

        dec6, ips6 = _answer(di_b, "metrics.tracker.io", dns.rdatatype.AAAA)
        _check(f"AAAA is deceived consistently too ({ips6})",
               dec6 == "deceived" and ips6 == [DECEPTION_IPV6])

        # The safety property: malware is NEVER pointed at the endpoint. Serving
        # a plausible reply to C2 would be feeding the attacker, not the tracker.
        decm, ipsm = _answer(di_b, "evil-c2.io")
        _check(f"malware is still hard-sinkholed, never deceived ({ipsm})",
               decm == "blocked" and ipsm == [SINKHOLE_IPV4])
    finally:
        ep.stop()

    # (c) Endpoint dies at runtime -> must revert to the sinkhole. Handing out a
    #     loopback address with nothing behind it costs a connect timeout for the
    #     same failure, which is strictly worse than the sinkhole.
    dec, ips = _answer(di_b, "metrics.tracker.io")
    _check(f"endpoint stopped -> reverts to sinkhole, no dead loopback ({ips})",
           dec == "deceived" and ips == [SINKHOLE_IPV4])

    print("-" * 60)
    if _fail:
        print(f"{_fail} check(s) FAILED.")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
