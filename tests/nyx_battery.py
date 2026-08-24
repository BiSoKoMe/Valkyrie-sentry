"""Nyx privacy-efficacy battery - the differentiator's scoreboard.

The EDR side has Tier B (real Atomic Red Team on a live VM). Nyx is the privacy
core, and it needs the SAME kind of honest measurement: run real-world tracking /
fingerprinting / exfil attempts through Nyx's ACTUAL code paths and score how many
are defended - plus a hard false-positive guard, because for a privacy tool that
sits in front of all your traffic, BREAKING A SITE is a worse failure than missing
one tracker (the prime directive: "protection must never break the page").

This is Tier 2: the real code (tls_addon cleaner, path detection, cname_uncloak,
deception, nyx.inspect_outbound), driven with a real corpus, offline / CI-safe (no
browser, no mitmproxy socket). Tier 3 (a headless real browser through the live
proxy against CreepJS / browserleaks) is the next rung up.

Honesty: a MISS here is a real gap from the user's chair - an uncaught tracker is
uncaught whatever the reason (short list vs logic bug). The battery names every
miss so it becomes the fix list. It hard-FAILS only on a false positive, because
that is the unforgivable one.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from valkyrie import farble
from valkyrie import cname_uncloak as cu
from valkyrie import nyx
from valkyrie import deception
from valkyrie.tls_addon import (
    ValkyrieAddon, _is_tracker_path, _is_fingerprint_path,
)

# Tallies -------------------------------------------------------------------
_defended = 0
_attacks = 0
_fp = 0
_fp_total = 0
_misses: list[str] = []
_fps: list[str] = []


def defend(label: str, ok: bool) -> None:
    global _defended, _attacks
    _attacks += 1
    if ok:
        _defended += 1
        print(f"  [DEFENDED] {label}")
    else:
        _misses.append(label)
        print(f"  [MISSED]   {label}")


def benign(label: str, unbroken: bool) -> None:
    """A benign case that must be left ALONE. Failing this is a false positive -
    the unforgivable failure for a tool in front of all your traffic."""
    global _fp, _fp_total
    _fp_total += 1
    if unbroken:
        print(f"  [OK]     {label}")
    else:
        _fp += 1
        _fps.append(label)
        print(f"  [BROKEN] {label}   <-- FALSE POSITIVE")


# A pure cleaner instance (no store), same trick test_farble uses.
_addon = ValkyrieAddon.__new__(ValkyrieAddon)


def _clean(html: bytes, domain: str) -> tuple[bytes, int]:
    return _addon._clean_html_regex(html, domain, "https://" + domain)


def main() -> int:
    print("NYX PRIVACY BATTERY\n")

    # --- A. Tracker script removal (real cleaner) ---
    print("[A] third-party tracker scripts are stripped from the page")
    trackers = [
        "google-analytics.com", "googletagmanager.com", "connect.facebook.net",
        "doubleclick.net", "static.hotjar.com", "cdn.mxpnl.com",
        "cdn.amplitude.com", "cdn.segment.com", "snap.licdn.com",
        "analytics.tiktok.com", "quantserve.com", "b.scorecardresearch.com",
        "cdn.taboola.com", "bat.bing.com", "sc.lfeeder.com", "munchkin.marketo.net",
    ]
    for host in trackers:
        html = (b"<html><head></head><body><p>real page</p>"
                b"<script src=\"https://" + host.encode() + b"/x.js\"></script>"
                b"</body></html>")
        _body, removed = _clean(html, "example.com")
        defend(f"script: {host}", removed > 0)

    # --- B. Inline analytics calls are neutralised ---
    print("\n[B] inline analytics calls are neutralised (tag kept, call no-op'd)")
    inline = {
        "facebook fbq": b"fbq('track','PageView')",
        "google gtag":  b"gtag('event','x')",
        "google ga":    b"ga('send','pageview')",
        "mixpanel":     b"mixpanel.track('x')",
        "amplitude":    b"amplitude.getInstance().logEvent('x')",
        "heap":         b"heap.track('x')",
        "hotjar":       b"hj('event','x')",
    }
    for name, call in inline.items():
        html = b"<html><head><script>" + call + b";</script></head><body>hi</body></html>"
        _body, removed = _clean(html, "example.com")
        defend(f"inline: {name}", removed > 0)

    # --- C. Beacon / pixel request paths are recognised ---
    print("\n[C] tracking beacon/pixel request paths are recognised")
    beacon_paths = [
        "/collect", "/g/collect", "/j/collect", "/pixel", "/beacon", "/track",
        "/tr", "/i/adsct", "/pagead/1p-user-list", "/telemetry", "/analytics",
        "/v1/batch", "/b/ss",
    ]
    for p in beacon_paths:
        defend(f"path: {p}", _is_tracker_path(p))

    # --- D. Fingerprinting scripts are recognised ---
    print("\n[D] fingerprinting scripts are recognised by path")
    fp_paths = [
        "/fingerprintjs/v3.js", "/fp.js", "/fpjs/agent", "/evercookie.js",
        "/canvas-fingerprint.js", "/fingerprint2.js", "/clientjs.min.js",
    ]
    for p in fp_paths:
        defend(f"fp-script: {p}", _is_fingerprint_path(p))

    # --- E. CNAME-cloaked trackers are uncloaked ---
    print("\n[E] CNAME-cloaked trackers are uncloaked (caught on the chain target)")
    cloaked = [
        "brand.eulerian.net", "cust-1.demdex.net", "sub.omtrdc.net",
        "x.criteo.com", "a.ati-host.net", "m.everesttech.net",
        "c.adobedc.net", "t.tagcommander.com", "e.en25.com", "p.pardot.com",
    ]
    for host in cloaked:
        defend(f"uncloak: {host}", cu.matches_cname_tracker(host) is not None)

    # --- F. Beacon deception serves a plausible LIE, not silence ---
    print("\n[F] intercepted beacons get a served LIE (persona), not a failure")
    beacons = [
        ("GET",  "/collect", "v=1&tid=UA-1"),
        ("POST", "/g/collect", ""),
        ("GET",  "/pixel.gif", ""),
        ("GET",  "/cmp/consent", ""),
        ("POST", "/ads/bid", ""),
    ]
    for method, path, q in beacons:
        try:
            r = deception.build_reply(method, path, q)
            ok = r is not None and r.status < 400 and len(r.body) > 0
        except Exception:
            ok = False
        defend(f"deceive: {method} {path}", ok)

    # --- G. Personal data leaving to a third party is caught (Nyx brain) ---
    print("\n[G] personal data crossing to a third party is caught")
    FP_ORIGIN = "https://news.example/x"
    THIRD = "https://collector.tracker.example/submit"
    H = {"Referer": FP_ORIGIN, "Content-Type": "application/x-www-form-urlencoded"}
    exfil = {
        "device id": b"adid=550e8400-e29b-41d4-a716-446655440000",
        "location":  b"latitude=40.71&longitude=-74.00",
        "email":     b"e=alice%40example.com",
        "fingerprint": b"screen=1920x1080&timezone=America/New_York&lang=en-US&cores=8",
    }
    for name, body in exfil.items():
        obs = nyx.inspect_outbound("POST", THIRD, H, body)
        defend(f"exfil: {name}", len(obs) > 0)

    # --- G1b. MODERN fingerprinting surfaces (2026's #1 tracking vector) ---
    print("\n[G1b] modern high-entropy fingerprinting is caught "
          "(audio / fonts / WebRTC local-IP leak)")
    # An audio + fonts + WebRTC-private-IP bundle IS a fingerprinter - the
    # deanonymising kind that leaks your LAN IP from behind a VPN.
    modern_fp = (b"audiocontext=124.043475&fontlist=Arial,Calibri,Verdana,Tahoma"
                 b"&rtcpeerconnection=1&candidate=192.168.1.37")
    defend("fingerprint: audio+fonts+webrtc bundle is caught",
           any(o.category == nyx.CAT_FINGERPRINT
               for o in nyx.inspect_outbound("POST", THIRD, H, modern_fp)))
    defend("fingerprint: a WebRTC-leaked private IP counts as a surface",
           any(o.category == nyx.CAT_FINGERPRINT
               for o in nyx.inspect_outbound(
                   "POST", THIRD, H,
                   b"audio_hash=ab12&fonts=Arial,Calibri&ip=10.0.0.14")))

    # --- G2. ACT: the leak is not just watched, it is FED A LIE ---
    print("\n[G2] Nyx ACTS — the tracker gets consistent persona fakes, not your data")
    from valkyrie.persona import current_persona as _cp
    _p = _cp()
    act_cases = {
        "device id": (b"adid=550e8400-e29b-41d4-a716-446655440000",
                      b"550e8400-e29b-41d4-a716-446655440000"),
        "location":  (b"latitude=40.71&longitude=-74.00", b"40.71"),
        "email":     (b"e=alice%40example.com", b"alice"),
    }
    for name, (payload, real) in act_cases.items():
        _u, nb, fk = nyx.fake_outbound("POST", THIRD, H, payload, _p)
        defend(f"act: {name} replaced with a persona fake", bool(fk) and real not in nb)

    # --- G3. expanded categories: payment cards + persistent cookies ---
    print("\n[G3] expanded coverage — payment cards and third-party tracking cookies")
    defend("card: a Luhn-valid card to a tracker is caught",
           any(o.category == nyx.CAT_FINANCIAL
               for o in nyx.inspect_outbound("POST", THIRD, H, b"cc=4111111111111111")))
    _u, cnb, cfk = nyx.fake_outbound("POST", THIRD, H, b"cc=4242424242424242", _p)
    defend("card: is rewritten to a fake in act mode", b"4242424242424242" not in cnb)
    defend("cookie: a persistent third-party cookie is caught",
           any(o.category == nyx.CAT_COOKIE
               for o in nyx.inspect_outbound(
                   "GET", THIRD, {"Referer": FP_ORIGIN, "Cookie": "uid=a1b2c3d4e5f6g7h8i9j0"}, None)))

    # --- H. Fingerprint spoofing actually defeats an execution attack ---
    print("\n[H] fingerprint spoofing defeats a real execution-based attack")
    node = shutil.which("node")
    harness = Path(__file__).resolve().parent / "farble_attack.js"
    if node and harness.exists():
        tmp = tempfile.NamedTemporaryFile("wb", suffix=".html", delete=False)
        try:
            tmp.write(farble.script_for("https://battery.example"))
            tmp.close()
            proc = subprocess.run([node, str(harness), tmp.name],
                                  capture_output=True, text=True, timeout=60)
            defend("fingerprint spoof undetectable (node attack)", proc.returncode == 0)
        finally:
            try:
                import os
                os.unlink(tmp.name)
            except OSError:
                pass
    else:
        print("  [skip] node/farble_attack.js not available")

    # --- FALSE-POSITIVE GUARD (must be 0 - breaking a site is unforgivable) ---
    print("\n[FP] benign traffic is left completely alone")
    # A normal article page with no trackers must lose nothing.
    article = (b"<html><head><title>News</title></head><body>"
               b"<h1>Headline</h1><p>Body text that matters.</p>"
               b"<script src=\"https://cdn.example.com/app.js\"></script></body></html>")
    _b, removed = _clean(article, "news.example")
    benign("benign article: nothing removed", removed == 0)
    benign("benign article: body text preserved", b"Body text that matters." in _b)
    # First-party data (your own login) is not an exfil.
    fp_post = nyx.inspect_outbound(
        "POST", "https://news.example/login", H, b"e=alice%40example.com")
    benign("first-party login not flagged as exfil", fp_post == [])
    # The ACT path must respect the same first-party boundary - never rewrite
    # your own data to the site you are actually on.
    _u, afb, aff = nyx.fake_outbound(
        "POST", "https://news.example/login", H, b"e=alice%40example.com", _p)
    benign("act: first-party data is NOT faked",
           aff == [] and afb == b"e=alice%40example.com")
    # A random 16-digit id is not a card (Luhn boundary); a short cookie is not tracking.
    benign("non-Luhn 16-digit id not flagged as a card",
           not any(o.category == nyx.CAT_FINANCIAL
                   for o in nyx.inspect_outbound("POST", THIRD, H, b"order=1234567890123456")))
    benign("short functional cookie not flagged as tracking",
           not any(o.category == nyx.CAT_COOKIE
                   for o in nyx.inspect_outbound(
                       "GET", THIRD, {"Referer": FP_ORIGIN, "Cookie": "lang=en; s=1"}, None)))
    # The new fingerprint surfaces must NOT fire on ONE benign signal - the >=3
    # bundle guard is what keeps them safe. A lone private IP (an internal API
    # call), or a single font/audio mention, is not a fingerprint.
    benign("a lone private IP is not flagged as a fingerprint",
           not any(o.category == nyx.CAT_FINGERPRINT
                   for o in nyx.inspect_outbound("POST", THIRD, H,
                       b"callback_host=192.168.1.10")))
    benign("a single font value (styling) is not a fingerprint",
           not any(o.category == nyx.CAT_FINGERPRINT
                   for o in nyx.inspect_outbound("POST", THIRD, H,
                       b"font=Arial&size=14")))
    # Legit CDNs / sites are not uncloaked as trackers.
    for legit in ["www.github.com", "cdn.jsdelivr.net", "fonts.googleapis.com",
                  "api.stripe.com", "www.wikipedia.org"]:
        benign(f"legit host not uncloaked: {legit}",
               cu.matches_cname_tracker(legit) is None)
    # Ordinary content paths are not mistaken for tracker beacons.
    for path in ["/about", "/api/products", "/collections/shoes",
                 "/blog/how-we-track-shipments", "/account/settings",
                 "/tr/products",        # Turkish locale, must NOT match a beacon
                 "/pages/about",        # must NOT match "/pagead"
                 "/adventure-tours"]:   # must NOT match "/adsct"
        benign(f"benign path not a tracker beacon: {path}", not _is_tracker_path(path))

    # --- Scoreboard ---
    pct = (100.0 * _defended / _attacks) if _attacks else 0.0
    print("\n" + "=" * 68)
    # Known, deliberate non-coverage - real trackers we do NOT match by PATH
    # because a path rule would break sites, but which are still caught by the
    # DOMAIN rules (so the tracker is handled, just not via this signal).
    _ACCEPTED = {
        "path: /tr": "Facebook pixel — '/tr/' is the Turkish locale; caught by facebook.net domain",
        "path: /v1/batch": "Segment — too generic to path-match; caught by segment.com domain",
        "path: /b/ss": "Comscore — too generic to path-match; caught by scorecardresearch.com domain",
    }
    if _misses:
        real = [m for m in _misses if m not in _ACCEPTED]
        if real:
            print("MISSES (the fix list):")
            for m in real:
                print("   -", m)
        accepted = [m for m in _misses if m in _ACCEPTED]
        if accepted:
            print("ACCEPTED non-coverage (deliberate precision tradeoff):")
            for m in accepted:
                print(f"   ~ {m}  ({_ACCEPTED[m]})")
    if _fps:
        print("FALSE POSITIVES (unforgivable — fix before anything else):")
        for f in _fps:
            print("   !", f)
    print(f"\nNYX-BATTERY defended={_defended}/{_attacks} ({pct:.0f}%)  "
          f"false_positives={_fp}/{_fp_total}")
    # Breaking a site fails the build. Coverage gaps are reported, not fatal -
    # they are the honest to-do list that drives the hardening loop.
    if _fp > 0:
        print("RESULT: FAIL — false positive(s) present.")
        return 1
    print("RESULT: PASS (no false positives). Coverage above is the work queue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
