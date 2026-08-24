#!/usr/bin/env python3
"""Popular-legitimate-domain guard tests (valkyrie/popular_domains.py + memory).

Regression test for a real, live-found false positive: Valkyrie sinkholing
microsoft.com / paypal.com / bing.com / live.com / linkedin.com because weak
behavioural heuristics (query burst, never-seen-from-process) learned them
'bad' and persisted it. The guard must:

  [1] Match popular domains + their subdomains, boundary-safe; NOT protect
      trackers (doubleclick.net) or look-alikes (notmicrosoft.com)
  [2] Memory: never LEARN a popular domain bad; never SERVE it bad
  [3] Memory: SELF-HEAL — purge pre-existing popular 'bad' verdicts on start()
  [4] Classifier: a behavioural block on a popular domain downgrades to flag,
      while a non-popular domain still blocks

Sections [5]-[7] are the mirror-image bug: a live VM run had Valkyrie learn
"malware-c2-test.example.com" — a stock red-team test lookup — as known-good
after enough clean-looking queries, then permanently allow it. RFC 2606
reserved test/documentation domains (example.com/.net/.org/.edu, .test,
.invalid, .example) must never be eligible for that "N clean queries ->
known-good" promotion, since "queried repeatedly without another signal
firing" is not evidence of legitimacy — it is exactly what a red-team script
(or a patient real C2 domain) also looks like.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def main() -> int:
    from valkyrie.popular_domains import is_popular
    from valkyrie.intelligence.memory import IntelligenceMemory
    from valkyrie.store import Store

    print("\n=== popular-domain guard ===\n")

    print("[1] Matching + boundary safety")
    _check("microsoft.com is popular", is_popular("microsoft.com"))
    _check("subdomain www.bing.com is popular", is_popular("www.bing.com"))
    _check("paypal.com is popular", is_popular("paypal.com"))
    _check("deep sub a.b.live.com is popular", is_popular("a.b.live.com"))
    _check("tracker doubleclick.net is NOT protected", not is_popular("doubleclick.net"))
    _check("google-analytics.com is NOT protected", not is_popular("google-analytics.com"))
    _check("look-alike notmicrosoft.com does NOT match", not is_popular("notmicrosoft.com"))
    _check("random domain not popular", not is_popular("some-random-blog-42.dev"))
    _check("empty is safe", not is_popular(""))

    print("\n[2] Memory never learns / serves a popular domain bad")
    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "m.db"); store.start()
        mem = IntelligenceMemory(store); mem.start()
        mem.remember_bad("paypal.com", reason="query burst (131 queries in 10s)")
        _check("remember_bad('paypal.com') did not store bad", mem.check("paypal.com") != "bad")
        mem.remember_bad("login.microsoftonline.com", reason="never seen")
        _check("popular subdomain also not stored bad",
               mem.check("login.microsoftonline.com") != "bad")
        # A genuine non-popular bad domain still works.
        mem.remember_bad("evil-c2-xyz.example", reason="c2")
        _check("non-popular domain IS remembered bad",
               mem.check("evil-c2-xyz.example") == "bad")
        store.stop()

    print("\n[3] Self-heal: purge pre-existing popular 'bad' verdicts on start()")
    with tempfile.TemporaryDirectory() as td:
        dbp = Path(td) / "h.db"
        store = Store(db_path=dbp); store.start()
        # Seed the DB the way an OLDER build left it: popular domains marked bad.
        mem0 = IntelligenceMemory(store); mem0.start()
        conn = store.connection()
        try:
            for d in ("microsoft.com", "bing.com", "paypal.com"):
                conn.execute(
                    "INSERT OR REPLACE INTO intel_memory"
                    "(domain,verdict,ip,process,reason,first_seen,last_seen,hits)"
                    " VALUES (?,?,?,?,?,?,?,1)",
                    (d, "bad", "", "", "query burst", "2026-07-22", "2026-07-22"))
            # a real threat that must SURVIVE the purge
            conn.execute(
                "INSERT OR REPLACE INTO intel_memory"
                "(domain,verdict,ip,process,reason,first_seen,last_seen,hits)"
                " VALUES (?,?,?,?,?,?,?,1)",
                ("bad-c2.example", "bad", "", "", "c2", "2026-07-22", "2026-07-22"))
            conn.commit()
        finally:
            conn.close()
        # Fresh memory instance simulates the next launch → start() self-heals.
        mem = IntelligenceMemory(store); mem.start()
        _check("microsoft.com no longer bad after start()", mem.check("microsoft.com") != "bad")
        _check("bing.com no longer bad after start()", mem.check("bing.com") != "bad")
        _check("paypal.com no longer bad after start()", mem.check("paypal.com") != "bad")
        _check("real threat bad-c2.example SURVIVED the purge",
               mem.check("bad-c2.example") == "bad")
        # And it was actually deleted from the DB, not just the cache.
        conn = store.connection()
        try:
            left = [r[0] for r in conn.execute(
                "SELECT domain FROM intel_memory WHERE verdict='bad'").fetchall()]
        finally:
            conn.close()
        _check("popular rows physically purged from DB",
               "microsoft.com" not in left and "paypal.com" not in left)
        _check("threat row kept in DB", "bad-c2.example" in left)
        store.stop()

    print("\n[4] Classifier floor: popular domain downgrades block -> flag")
    from valkyrie.intelligence.classifier import ThreatClassifier

    class _Baseline:
        def is_learning(self): return False
    class _Anom:
        def score(self, *a, **k): return 0.0
        def explain(self, *a, **k): return ""
    class _Graph:
        def is_related(self, *a, **k): return 0.0
        def explain(self, *a, **k): return ""
    class _Beh:
        def score(self, domain, process): return 0.9, "query burst (99 queries in 10s)"

    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "c.db"); store.start()
        mem = IntelligenceMemory(store); mem.start()
        clf = ThreatClassifier(_Baseline(), _Anom(), _Graph(), mem, behavioral=_Beh())
        pop = clf.classify("chrome.exe", "microsoft.com", 1000.0)
        _check("popular domain with high behavioural score is NOT blocked",
               pop["decision"] != "block")
        _check("popular domain is instead flagged (still visible)",
               pop["decision"] == "flag")
        eco = clf.classify("chrome.exe", "evil-random-c2.example", 1000.0)
        _check("non-popular domain with same score STILL blocks",
               eco["decision"] == "block")
        store.stop()

    print("\n[5] is_reserved_test_domain — matching + boundary safety")
    from valkyrie.popular_domains import is_reserved_test_domain
    _check("malware-c2-test.example.com is reserved",
           is_reserved_test_domain("malware-c2-test.example.com"))
    _check("example.com itself is reserved", is_reserved_test_domain("example.com"))
    _check("sub.example.net is reserved", is_reserved_test_domain("sub.example.net"))
    _check("foo.test is reserved", is_reserved_test_domain("foo.test"))
    _check("foo.invalid is reserved", is_reserved_test_domain("foo.invalid"))
    _check("look-alike example.com.evil.com is NOT reserved (suffix, not prefix)",
           not is_reserved_test_domain("example.com.evil.com"))
    _check("google.com is NOT reserved", not is_reserved_test_domain("google.com"))
    _check("empty is safe", not is_reserved_test_domain(""))

    print("\n[6] Memory never promotes a reserved test domain to known-good")
    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "r.db"); store.start()
        mem = IntelligenceMemory(store); mem.start()
        for _ in range(10):
            mem.remember_good("malware-c2-test.example.com", process="nslookup.exe")
        _check("STILL NEVER 'good' after repeated remember_good calls",
               mem.check("malware-c2-test.example.com") != "good")
        # A genuine site must still be promotable — this must not become a
        # blanket "nothing ever gets promoted" regression.
        mem.remember_good("some-real-clean-site.dev")
        _check("STILL FIRES: an ordinary domain IS promoted to good",
               mem.check("some-real-clean-site.dev") == "good")
        store.stop()

    print("\n[7] Self-heal: purge a pre-existing reserved-domain 'good' verdict on start()")
    with tempfile.TemporaryDirectory() as td:
        dbp = Path(td) / "s.db"
        store = Store(db_path=dbp); store.start()
        # Seed the DB the way the live VM run left it: the test domain
        # already promoted to good by an older build.
        mem0 = IntelligenceMemory(store); mem0.start()
        conn = store.connection()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO intel_memory"
                "(domain,verdict,ip,process,reason,first_seen,last_seen,hits)"
                " VALUES (?,?,?,?,?,?,?,1)",
                ("malware-c2-test.example.com", "good", "", "nslookup.exe",
                 "consistently clean behaviour", "2026-07-31", "2026-07-31"))
            # a real known-good domain that must SURVIVE the purge
            conn.execute(
                "INSERT OR REPLACE INTO intel_memory"
                "(domain,verdict,ip,process,reason,first_seen,last_seen,hits)"
                " VALUES (?,?,?,?,?,?,?,1)",
                ("some-real-clean-site.dev", "good", "", "chrome.exe",
                 "consistently clean behaviour", "2026-07-31", "2026-07-31"))
            conn.commit()
        finally:
            conn.close()
        # Fresh memory instance simulates the next launch → start() self-heals.
        mem = IntelligenceMemory(store); mem.start()
        _check("malware-c2-test.example.com no longer good after start()",
               mem.check("malware-c2-test.example.com") != "good")
        _check("real known-good domain SURVIVED the purge",
               mem.check("some-real-clean-site.dev") == "good")
        conn = store.connection()
        try:
            left = [r[0] for r in conn.execute(
                "SELECT domain FROM intel_memory WHERE verdict='good'").fetchall()]
        finally:
            conn.close()
        _check("reserved test domain physically purged from DB",
               "malware-c2-test.example.com" not in left)
        _check("real good domain kept in DB", "some-real-clean-site.dev" in left)
        store.stop()

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
