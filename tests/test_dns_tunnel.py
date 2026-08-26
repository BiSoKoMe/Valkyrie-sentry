#!/usr/bin/env python3
"""DNS tunnelling / wildcard-DNS detection tests.

Pins the fix for a measured miss: an Atomic Red Team DNS burst
(atomicredteam-<rand>.127.0.0.1.nip.io) was ALLOWED by the live product
because every layer judged each query alone - DGA analysis saw only the
registrable label (nip.io -> too short), entropy capped below the flag
threshold, and the rate limiter needed >30 q/10s.

  [1] Pure helpers: registrable base, effective label, embedded IPs,
      cryptic-label gate
  [2] Flood detector: unique-label counting, thresholds, window eviction,
      common-label and exempt-root immunity
  [3] Scanner end-to-end: the real ART burst blocks from query 1; flood
      escalates to a block-alone "tunnel" verdict; benign traffic and the
      legitimate dev-tool use of nip.io stay unblocked
  [4] EDR mapping: "tunnel" category raises a high T1048.003 detection
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


def main() -> int:
    from valkyrie.dns_tunnel import (
        SubdomainFloodDetector, effective_label, embedded_ip,
        embedded_private_ip, is_cryptic_label, is_dyndns_root,
        registrable_base,
    )
    from valkyrie.site_scanner import SiteScanner
    from valkyrie.config import TUNNEL_BLOCK_UNIQUE, TUNNEL_WINDOW_SECONDS

    print("\n=== DNS tunnelling detection ===\n")

    print("[1] Pure helpers")
    _check("registrable base strips subdomains",
           registrable_base("a.b.c.nip.io") == "nip.io")
    _check("nip.io is a wildcard provider", is_dyndns_root("x.127.0.0.1.nip.io"))
    _check("github.com is not", not is_dyndns_root("api.github.com"))
    _check("effective label is leftmost",
           effective_label("payload123.127.0.0.1.nip.io") == "payload123")
    _check("embedded IPv4 found",
           embedded_ip("x.192.168.1.7.sslip.io") == "192.168.1.7")
    _check("loopback IP flagged as private",
           embedded_private_ip("x.127.0.0.1.nip.io") == "127.0.0.1")
    _check("public IP not flagged as private",
           embedded_private_ip("x.8.8.8.8.nip.io") is None)
    _check("no false IP from version-ish labels",
           embedded_ip("v1.2.update.example.com") is None)
    _check("ART label is cryptic", is_cryptic_label("atomicredteam-703907"))
    _check("hex payload label is cryptic", is_cryptic_label("68656c6c6f776f726c64"))
    _check("base64ish label is cryptic", is_cryptic_label("aGVsbG93b3JsZa"))
    _check("'avatars0' is not cryptic (short)", not is_cryptic_label("avatars0"))
    _check("'s3-us-west-2' is not cryptic (2 digits, low entropy)",
           not is_cryptic_label("s3-us-west-2"))
    _check("'www' is not cryptic (common label)", not is_cryptic_label("www"))
    _check("'downloadcenter' is not cryptic (no digits, low entropy)",
           not is_cryptic_label("downloadcenter"))

    print("\n[2] Flood detector")
    det = SubdomainFloodDetector()
    now = 1000.0
    scores = []
    for i in range(TUNNEL_BLOCK_UNIQUE + 2):
        s, _ = det.record_and_score(f"chunk-{i:06d}-data.evil-base.com", now=now + i)
        scores.append(s)
    _check("first unique label scores 0", scores[0] == 0.0)
    _check(f"block-alone at {TUNNEL_BLOCK_UNIQUE} unique labels",
           scores[TUNNEL_BLOCK_UNIQUE - 1] >= 0.75)
    _check("repeat of one label never inflates the count",
           all(det.record_and_score("chunk-000001-data.evil-base.com",
                                    now=now + 10)[0] >= 0.75 for _ in range(3)))
    det2 = SubdomainFloodDetector()
    det2.record_and_score("chunk-aaa111bbb.slow-base.com", now=0.0)
    s, _ = det2.record_and_score("chunk-ccc222ddd.slow-base.com",
                                 now=TUNNEL_WINDOW_SECONDS + 5)
    _check("window evicts stale labels", s == 0.0)
    det3 = SubdomainFloodDetector()
    burst_common = [det3.record_and_score(f"{l}.big-site.com", now=now)[0]
                    for l in ("www", "api", "cdn", "static", "mail", "login", "docs")]
    _check("common labels never count", all(s == 0.0 for s in burst_common))
    det4 = SubdomainFloodDetector()
    burst_cdn = [det4.record_and_score(f"rr{i}---sn-4g5e6nsz{i}.googlevideo.com",
                                       now=now + i)[0] for i in range(8)]
    _check("exempt CDN root immune even to cryptic fan-out",
           all(s == 0.0 for s in burst_cdn))

    print("\n[3] Scanner end-to-end (the measured real-world miss)")
    scanner = SiteScanner(store=None)
    art = [f"atomicredteam-{n}.127.0.0.1.nip.io"
           for n in (703907, 435169, 339451, 583611, 478539, 636933)]
    results = [scanner.analyze(d, "powershell.exe") for d in art]
    _check("first ART query already blocked (no flood needed)",
           results[0].decision == "block")
    _check("every ART query blocked", all(r.decision == "block" for r in results))
    _check("flood escalates to a 'tunnel' verdict",
           results[-1].category == "tunnel")
    _check("tunnel reason names the pattern",
           any("tunnel" in reason.lower() for reason in results[-1].reasons))
    dev = scanner.analyze("myapp.127.0.0.1.nip.io", "node.exe")
    _check("legit dev use of nip.io is flagged, never blocked",
           dev.decision == "flag")
    benign = ["www.github.com", "wikipedia.org", "chase.com",
              "avatars0.githubusercontent.com", "s3-us-west-2.amazonaws.com",
              "rr3---sn-4g5e6nsz.googlevideo.com"]
    _check("benign controls all still allowed",
           all(scanner.analyze(d, "brave.exe").decision == "allow" for d in benign))

    print("\n[4] EDR mapping")
    from valkyrie.edr.builtin import TunnelDetection, _TECHNIQUE
    _check("'tunnel' maps to T1048.003", "T1048.003" in _TECHNIQUE["tunnel"])
    _check("'dyndns' maps to T1568", "T1568" in _TECHNIQUE["dyndns"])
    dets = TunnelDetection().analyze(
        {"domain": art[-1], "decision": "blocked", "process_name": "powershell.exe",
         "process_pid": 4242, "raw_category": "tunnel", "suspicion": 1.0,
         "reason": "DNS tunnelling pattern: 6 unique generated subdomains"}, None)
    _check("tunnel event raises a detection", len(dets) == 1)
    _check("detection is high severity", dets and dets[0].severity == "high")
    _check("detection carries T1048.003", dets and "T1048.003" in dets[0].technique)

    print("\n" + "=" * 48)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
