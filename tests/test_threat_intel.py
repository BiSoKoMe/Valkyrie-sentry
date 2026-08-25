#!/usr/bin/env python3
"""Threat-intel feed engine - offline unit + integration + benchmark.

Everything runs without network: feed bodies are fixture strings in the
real formats (Feodo bare-IP, URLhaus hostfile, SSLBL CSV), caches are
written to a temp dir, and the fetch path is exercised with a
monkeypatched urlopen. Covers:

  [1] parsers + validation guards (private IPs, junk domains can't enter)
  [2] cache round-trip, offline load, corrupt-cache revalidation
  [3] matching semantics (exact, subdomain, miss, provenance)
  [4] fetch fail-safety (network error / empty body keep the old cache)
  [5] DNS pipeline integration: intel hit blocks before learned known-good
  [6] resolved-answer screening + network-collector reputation
  [7] lookup benchmark on 100k indicators (hot-path budget)
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


FEODO_BODY = """\
################################################
# abuse.ch Feodo Tracker Botnet C2 IP Blocklist #
################################################
185.220.101.9
45.155.204.10
10.0.0.5
127.0.0.1
not-an-ip
"""

URLHAUS_BODY = """\
# URLhaus Host file
127.0.0.1\tmalware-drop.example
127.0.0.1\tevil-c2.test
0.0.0.0 payload.badsite.example
127.0.0.1\tlocalhost
127.0.0.1\t192.0.2.9
"""

SSLBL_BODY = """\
# SSLBL IP blacklist (CSV)
# Firstseen,DstIP,DstPort
2026-07-01 10:00:00,91.219.236.222,443
2026-07-02 11:00:00,141.98.10.60,447
2026-07-02 11:00:00,169.254.1.1,443
"""


THREATFOX_BODY = """\
# ThreatFox recent IOCs (CSV)
# first_seen_utc,ioc_id,ioc_value,ioc_type,threat_type,...
"2026-07-19 01:05:06", "1853610", "43.143.7.85:4369", "ip:port", "botnet_cc"
"2026-07-19 01:05:05", "1853607", "23.94.27.110:3478", "ip:port", "botnet_cc"
"2026-07-19 01:05:05", "1853608", "192.168.1.50:443", "ip:port", "botnet_cc"
"""

# URLhaus full-URL (path-level) feed - one URL per line.
URLHAUS_URL_BODY = """\
# URLhaus recent URLs
http://compromised-shop.example/wp-content/uploads/2026/payload.exe
https://compromised-shop.example:8443/staging/loader.dll?id=42
http://45.155.204.10/bins/mirai.arm7
http://127.0.0.1/evil.exe
http://localhost/evil.exe
"""


def main() -> int:
    from valkyrie.threat_intel import (
        IntelFeed, ThreatIntelManager, parse_feed,
    )

    print("\n=== threat-intel feed engine ===\n")

    print("[1] Parsers + validation guards")
    ips = parse_feed(FEODO_BODY, "ip")
    _check("feodo: both public IPs parsed",
           ips == {"185.220.101.9", "45.155.204.10"})
    _check("private/loopback IPs rejected",
           "10.0.0.5" not in ips and "127.0.0.1" not in ips)
    doms = parse_feed(URLHAUS_BODY, "domain")
    _check("urlhaus: hosts-format domains parsed",
           {"malware-drop.example", "evil-c2.test",
            "payload.badsite.example"} <= doms)
    _check("localhost / bare-IP lines rejected as domains",
           "localhost" not in doms and "192.0.2.9" not in doms)
    csv_ips = parse_feed(SSLBL_BODY, "ip")
    _check("sslbl: IPs extracted from CSV rows",
           csv_ips == {"91.219.236.222", "141.98.10.60"})
    _check("link-local rejected from CSV", "169.254.1.1" not in csv_ips)
    tf_ips = parse_feed(THREATFOX_BODY, "ip")
    _check("threatfox: quoted ip:port rows parsed",
           tf_ips == {"43.143.7.85", "23.94.27.110"})
    _check("threatfox: private ip:port rejected",
           "192.168.1.50" not in tf_ips)

    print("\n[1b] URL normalization + full-URL feed parsing")
    from valkyrie.threat_intel import normalize_url
    _check("scheme stripped (http and https normalize alike)",
           normalize_url("http://a.example/x") == normalize_url("https://a.example/x")
           == "a.example/x")
    _check("host lowercased", normalize_url("https://A.Example/Path") == "a.example/Path")
    _check("default ports dropped",
           normalize_url("https://a.example:443/x") == "a.example/x"
           and normalize_url("http://a.example:80/x") == "a.example/x")
    _check("non-default port kept (it is part of the identity)",
           normalize_url("https://a.example:8443/x") == "a.example:8443/x")
    _check("fragment dropped (client-side only)",
           normalize_url("https://a.example/x#frag") == "a.example/x")
    _check("trailing bare slash is the same as no path",
           normalize_url("https://a.example/") == normalize_url("https://a.example")
           == "a.example")
    _check("QUERY is kept — it often selects the payload",
           normalize_url("https://a.example/d?id=42") == "a.example/d?id=42")
    _check("private/loopback URL hosts rejected",
           normalize_url("http://127.0.0.1/e.exe") is None
           and normalize_url("http://10.0.0.5/e.exe") is None)
    _check("localhost / dotless hosts rejected",
           normalize_url("http://localhost/e.exe") is None
           and normalize_url("http://intranet/e.exe") is None)
    _check("embedded credentials rejected",
           normalize_url("http://user:pw@a.example/x") is None)
    urls = parse_feed(URLHAUS_URL_BODY, "url")
    _check("urlhaus url feed: public URLs parsed",
           {"compromised-shop.example/wp-content/uploads/2026/payload.exe",
            "compromised-shop.example:8443/staging/loader.dll?id=42",
            "45.155.204.10/bins/mirai.arm7"} == urls)
    _check("loopback/localhost URLs never enter the match set",
           not any("127.0.0.1" in u or "localhost" in u for u in urls))

    feeds = [
        IntelFeed("feodo_c2", "ip", "botnet_c2", "https://x.invalid/feodo"),
        IntelFeed("urlhaus", "domain", "malware_distribution",
                  "https://x.invalid/urlhaus"),
    ]

    print("\n[2] Cache round-trip + offline load")
    with tempfile.TemporaryDirectory() as td:
        cache = Path(td)
        (cache / "feodo_c2.txt").write_text(FEODO_BODY, encoding="utf-8")
        (cache / "urlhaus.txt").write_text(URLHAUS_BODY, encoding="utf-8")
        mgr = ThreatIntelManager(feeds=feeds, cache_dir=cache)
        n = mgr.load(allow_download=False)
        _check("offline load counts indicators", n == 5)
        st = mgr.status()
        _check("status reports per-feed counts",
               st["feeds"]["feodo_c2"]["count"] == 2
               and st["feeds"]["urlhaus"]["count"] == 3)
        # Corrupt/poisoned cache lines must be revalidated on read.
        (cache / "feodo_c2.txt").write_text(
            "185.220.101.9\n127.0.0.1\n10.1.2.3\ngarbage\n", encoding="utf-8")
        mgr.load(allow_download=False)
        _check("poisoned cache lines dropped on reload",
               mgr.match_ip("127.0.0.1") is None
               and mgr.match_ip("10.1.2.3") is None
               and mgr.match_ip("185.220.101.9") is not None)

        print("\n[3] Matching semantics")
        hit = mgr.match_domain("evil-c2.test")
        _check("exact domain match", hit is not None)
        sub = mgr.match_domain("cdn.assets.evil-c2.test")
        _check("subdomain matches parent indicator",
               sub is not None and sub.indicator == "evil-c2.test")
        _check("provenance reason string",
               sub is not None
               and sub.reason == "threat_intel:urlhaus:malware_distribution")
        _check("clean domain misses", mgr.match_domain("example.com") is None)
        _check("clean IP misses", mgr.match_ip("8.8.8.8") is None)

        print("\n[4] Fetch fail-safety")
        import valkyrie.threat_intel as ti_mod

        real_urlopen = ti_mod.urllib.request.urlopen
        class _Boom:
            def __call__(self, *a, **k):
                raise OSError("network down")
        ti_mod.urllib.request.urlopen = _Boom()
        try:
            mgr.refresh()
            _check("network failure keeps previous cache",
                   mgr.match_ip("185.220.101.9") is not None)
        finally:
            ti_mod.urllib.request.urlopen = real_urlopen

        class _EmptyResp:
            def read(self): return b"# outage page, no indicators\n"
            def __enter__(self): return self
            def __exit__(self, *a): return False
        ti_mod.urllib.request.urlopen = lambda *a, **k: _EmptyResp()
        try:
            mgr.refresh()
            _check("empty fetch body keeps previous cache",
                   mgr.match_ip("185.220.101.9") is not None)
        finally:
            ti_mod.urllib.request.urlopen = real_urlopen

    print("\n[4b] Full-URL matching (path-level, TLS-inspector-only seam)")
    with tempfile.TemporaryDirectory() as td2:
        cache2 = Path(td2)
        (cache2 / "urlhaus_url.txt").write_text(URLHAUS_URL_BODY, encoding="utf-8")
        umgr = ThreatIntelManager(
            feeds=[IntelFeed("urlhaus_url", "url", "malware_distribution",
                             "https://x.invalid/urlhaus_url")],
            cache_dir=cache2)
        umgr.load(allow_download=False)
        bad = "http://compromised-shop.example/wp-content/uploads/2026/payload.exe"
        _check("exact malicious URL matches", umgr.match_url(bad) is not None)
        _check("same URL over https also matches (scheme-insensitive)",
               umgr.match_url(bad.replace("http://", "https://")) is not None)
        _check("provenance reason string",
               umgr.match_url(bad).reason
               == "threat_intel:urlhaus_url:malware_distribution")
        # THE POINT of URL-level matching: the compromised host is otherwise
        # a legitimate site, so only the malicious PATH may be blocked.
        _check("a DIFFERENT path on the same compromised host does NOT match",
               umgr.match_url("https://compromised-shop.example/index.html") is None)
        _check("the bare compromised domain does NOT match",
               umgr.match_url("https://compromised-shop.example") is None)
        _check("a URL indicator never leaks into domain matching",
               umgr.match_domain("compromised-shop.example") is None)
        _check("clean URL misses",
               umgr.match_url("https://example.com/index.html") is None)
        _check("junk input is safely None", umgr.match_url("") is None
               and umgr.match_url("not a url") is None)
        _check("count includes URL indicators", umgr.count() == 3)
        _check("status reports a url total", umgr.status()["urls"] == 3)

        print("\n[4c] TLS addon blocks a malicious URL, allows the rest of the site")

        class _FakeReq:
            def __init__(self, url, host, path):
                self.pretty_url, self.pretty_host, self.path = url, host, path
                self.method, self.raw_content = "GET", b""

        class _FakeFlow:
            def __init__(self, url, host, path):
                self.request = _FakeReq(url, host, path)
                self.response = None
                self.client_conn = None

        from valkyrie.tls_addon import ValkyrieAddon
        logged: list = []

        class _FakeStore:
            def log(self, ev):
                logged.append(ev)

        addon = ValkyrieAddon(store=_FakeStore(), threat_intel=umgr)
        # Record _block calls instead of letting them run: the real _block
        # constructs a mitmproxy http.Response, and mitmproxy is an optional
        # dependency. What this pins is the DECISION ROUTING (does a URL
        # indicator reach a block, and does a clean path on the same host
        # avoid one) - the actual 403 construction is mitmproxy's own code.
        blocks: list = []
        addon._block = lambda flow, domain, url, proc, reason, category: blocks.append(
            {"url": url, "reason": reason, "category": category})

        bad_flow = _FakeFlow(
            "https://compromised-shop.example/wp-content/uploads/2026/payload.exe",
            "compromised-shop.example", "/wp-content/uploads/2026/payload.exe")
        addon._handle_request(bad_flow)     # not request(): that swallows errors
        _check("malicious URL routes to a block", len(blocks) == 1)
        _check("block carries the threat_intel_url category",
               blocks and blocks[0]["category"] == "threat_intel_url")
        _check("block reason names the feed provenance",
               blocks and "urlhaus_url" in blocks[0]["reason"])

        good_flow = _FakeFlow("https://compromised-shop.example/index.html",
                              "compromised-shop.example", "/index.html")
        addon._handle_request(good_flow)
        _check("a clean path on the SAME compromised host is NOT blocked",
               len(blocks) == 1)
        _check("the clean request was logged as allowed",
               any(getattr(e, "decision", "") == "allowed" for e in logged))

    print("\n[5] DNS pipeline: intel outranks learned known-good")
    try:
        import dns.rdatatype
        from valkyrie.store import Store
        from valkyrie.blocklist import BlocklistManager
        from valkyrie.behavioral import BehavioralEngine
        from valkyrie.rules import RulesLoader
        from valkyrie.process_watcher import ProcessWatcher, ProcessInfo
        from valkyrie.dns_interceptor import DNSInterceptor
        from valkyrie.intelligence import Intelligence
    except ImportError as exc:
        print(f"  [-] SKIP — DNS stack unavailable: {exc}")
    else:
        class _W(ProcessWatcher):
            def __init__(self): self._i = ProcessInfo("t.exe", 1, "/t")
            def start(self): pass
            def lookup(self, ip, port): return self._i

        with tempfile.TemporaryDirectory() as td:
            cache = Path(td) / "intel"
            cache.mkdir()
            (cache / "urlhaus.txt").write_text(
                "compromised-cdn.example\n", encoding="utf-8")
            (cache / "feodo_c2.txt").write_text("185.220.101.9\n",
                                                encoding="utf-8")
            mgr = ThreatIntelManager(feeds=feeds, cache_dir=cache)
            mgr.load(allow_download=False)

            store = Store(db_path=Path(td) / "ti.db")
            store.start()
            behavioral = BehavioralEngine()
            intel = Intelligence(store, behavioral=behavioral)
            intel.start()
            # Simulate a domain the intelligence layer had learned as GOOD
            # before it was compromised and landed in a feed.
            intel.memory.remember_good("compromised-cdn.example")
            rules = RulesLoader(); rules.start()
            blocklist = BlocklistManager(); blocklist.load(allow_download=False)

            interceptor = DNSInterceptor(
                store=store, blocklist=blocklist, behavioral=behavioral,
                rules=rules, process_watcher=_W(), intelligence=intel,
                threat_intel=mgr,
            )
            proc = ProcessInfo(name="t.exe", pid=1, path="/t")
            decision, reason, score, category = interceptor._decide(
                "compromised-cdn.example", dns.rdatatype.A, proc, 60)
            _check("intel-listed domain blocks despite known-good memory",
                   decision == "blocked" and category == "threat_intel")
            _check("reason carries feed provenance",
                   reason.startswith("threat_intel:urlhaus"))
            d2, *_ = interceptor._decide("example.org", dns.rdatatype.A,
                                         proc, 60)
            # Behavioral layers may observe/flag; the claim under test is
            # only that threat intel never blocks a clean domain.
            _check("clean domain not blocked", d2 != "blocked")

            print("\n[6] Resolved-answer screening + collector reputation")
            import dns.message, dns.rrset, dns.rdataclass
            resp = dns.message.make_response(
                dns.message.make_query("innocent-front.example", "A"))
            rr = dns.rrset.from_text("innocent-front.example.", 60,
                                     dns.rdataclass.IN, dns.rdatatype.A,
                                     "185.220.101.9")
            resp.answer.append(rr)
            _check("answer pointing at C2 IP is sinkholed",
                   interceptor._answer_blocked_ip(resp.to_wire())
                   == "185.220.101.9")

            from valkyrie.network_telemetry import ConnInfo
            rep = lambda ip: mgr.match_ip(ip) is not None
            ev = ConnInfo(pid=9, name="x.exe", raddr_ip="185.220.101.9",
                          raddr_port=443).to_event(blocked=rep("185.220.101.9"))
            _check("collector flags live connection to intel IP",
                   ev.action == "flagged" and "threat_intel_ip" in ev.labels)

            intel.stop()
            store.stop()

    print("\n[7] Lookup benchmark (hot-path budget)")
    big = ThreatIntelManager(feeds=[], cache_dir=Path(tempfile.mkdtemp()))
    big._ips = frozenset(f"198.18.{i >> 8 & 255}.{i & 255}" for i in range(50_000))
    big._domains = frozenset(f"host{i}.bad.example" for i in range(50_000))
    n_lookups = 100_000
    t0 = time.perf_counter()
    for i in range(n_lookups // 2):
        big.match_ip(f"198.18.{i >> 8 & 255}.{i & 255}")
        big.match_domain("www.clean-site.example")
    dt = time.perf_counter() - t0
    per_us = dt / n_lookups * 1e6
    rate = n_lookups / dt
    print(f"      100k indicators loaded; {n_lookups:,} lookups "
          f"in {dt*1000:.1f} ms — {per_us:.2f} µs/lookup ({rate:,.0f}/s)")
    _check("lookup under 50 µs (DNS hot-path budget)", per_us < 50)

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
