"""Bucket-B co-occurrence signal - behavioural test with built-in FP protection.

Drives the REAL DNSInterceptor._decide pipeline (intelligence-only) across
several simulated page-load bursts from one browser process, then asserts:

  RECALL   a tracker subdomain on a mixed-use parent (tr.snapchat.com,
           events.reddit.com) that rides behind >= COOC_MIN_ANCHORS distinct
           first-party sites gets FLAGGED.

  FP GUARD benign infra co-loaded across the SAME sites is NOT flagged:
             - a CDN            (d1.cloudfront.net)
             - a fonts host     (fonts.gstatic.com)
             - a payment SDK    (js.stripe.com)
             - an error-reporting/analytics-adjacent service (o1.ingest.sentry.io)
           and a non-allowlisted benign service seen behind only 2 sites stays
           allowed (ubiquity gate G4).

  INVARIANT the co-occurrence signal is FLAG-ONLY: the tracker is never
           BLOCKED by it on any appearance, and its deciding reason is the
           co-occurrence signal (attribution), with the anomaly engine
           contributing nothing.

Burst timing is driven by a controlled clock injected into the interceptor's
time source, so the real pipeline runs with realistic burst boundaries without
real sleeps.

Run:  python3 test_cooccurrence.py
"""
from __future__ import annotations

import sys
import tempfile
import time as _time
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import valkyrie.config as config
config.USE_EXTERNAL_LISTS = False

import valkyrie.dns_interceptor as di
from valkyrie.behavioral import BehavioralEngine
from valkyrie.blocklist import BlocklistManager
from valkyrie.intelligence import Intelligence
from valkyrie.process_watcher import ProcessInfo, ProcessWatcher
from valkyrie.rules import RulesLoader
from valkyrie.site_scanner import SiteScanner
from valkyrie.store import Store

_PASS = 0
_FAIL = 0

def check(label, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1; print(f"  PASS  {label}")
    else:
        _FAIL += 1; print(f"  FAIL  {label}  {detail}")


class _FixedWatcher(ProcessWatcher):
    def __init__(self, name): self._info = ProcessInfo(name=name, pid=42, path=f"/usr/bin/{name}")
    def start(self): pass
    def lookup(self, ip, port): return self._info


def main() -> int:
    print("Valkyrie Bucket-B co-occurrence test\n")

    # Controlled clock injected into the interceptor's time source. The
    # RateLimiters (behavioral/site_scanner) use time.monotonic in their own
    # modules and are unaffected.
    CLOCK = [1_000_000.0]
    di.time = types.SimpleNamespace(
        time=lambda: CLOCK[0], monotonic=_time.monotonic, sleep=_time.sleep)

    tmp = Path(tempfile.mkdtemp(prefix="valkyrie_cooc_"))
    store = Store(db_path=tmp / "t.db"); store.start()
    blocklist = BlocklistManager(); blocklist.load(allow_download=False)
    scanner = SiteScanner(store=store)
    behavioral = BehavioralEngine()
    intel = Intelligence(store, behavioral=behavioral); intel.start()
    rules = RulesLoader(); rules.start()

    import psutil, dns.rdatatype
    A = dns.rdatatype.A
    live = psutil.Process().name()           # live name -> no false "app closed"
    proc = ProcessInfo(name=live, pid=psutil.Process().pid, path="")
    itc = di.DNSInterceptor(store=store, blocklist=blocklist, behavioral=behavioral,
                            rules=rules, process_watcher=_FixedWatcher(live),
                            scanner=scanner, intelligence=intel)

    anchors = ["news-alpha.test", "shop-bravo.test", "forum-charlie.test", "blog-delta.test"]
    # These MUST NOT be in the shipped blocklist seed - the whole point of this
    # test is the softer co-occurrence FLAG path, which only runs for domains
    # that aren't already hard-blocked. `tr.snapchat.com` used to live here but
    # was later added to the seed (Bucket-A widening), which hard-blocked it
    # before it ever reached the co-occurrence logic and silently broke this
    # test. The setup guard below now fails loudly if that drift recurs.
    trackers = ["tr.pinterest.com", "events.reddit.com"]
    for _t in trackers:
        if blocklist.is_blocked(_t):
            print(f"  FAIL  fixture '{_t}' is in the blocklist seed — pick a "
                  f"tracker subdomain that is NOT hard-blocked, or this test "
                  f"silently stops exercising the co-occurrence path")
            store.stop()
            return 1
    infra = ["d1.cloudfront.net", "fonts.gstatic.com", "js.stripe.com", "o1.ingest.sentry.io"]
    partial = "widget.benign-svc.test"       # only in first 2 bursts -> ubiquity 2
    payloads = [50, 320, 70, 480]            # wide spread -> no beacon/heartbeat signals

    # results[(burst_index, domain)] = (decision, score, reason)
    results = {}
    tracker_ever_blocked = False
    for i, anchor in enumerate(anchors):
        CLOCK[0] += 12.0 + i           # jittered quiet gap (> COOC_QUIET_GAP) -> new burst
        load = [anchor] + trackers + infra + ([partial] if i < 2 else [])
        for dom in load:
            CLOCK[0] += 0.1            # intra-burst
            dec, reason, score, cat = itc._decide(dom, A, proc, payloads[i])
            results[(i, dom)] = (dec, round(score, 3), reason)
            if dom in trackers and dec == "blocked":
                tracker_ever_blocked = True

    acount = {t: intel.cooc.anchor_count(t) for t in trackers}
    infra_anchor = {d: intel.cooc.anchor_count(d) for d in infra}
    intel.stop(); store.stop()

    # --- RECALL: tracker flagged once ubiquity reached (>=3 distinct anchors) ---
    print("[recall] tracker flagged after riding behind 3+ first parties")
    for t in trackers:
        d0 = results[(0, t)]; d2 = results[(2, t)]; d3 = results[(3, t)]
        check(f"{t}: allowed at 1 anchor (n<3)", d0[0] == "allowed", f"got {d0}")
        check(f"{t}: FLAGGED at 3rd distinct anchor", d2[0] == "flagged", f"got {d2}")
        check(f"{t}: deciding reason is co-occurrence",
              "co-occurrence" in (d2[2] or ""), f"reason={d2[2]}")
        check(f"{t}: learned {acount[t]} distinct anchors (>= {config.COOC_MIN_ANCHORS})",
              acount[t] >= config.COOC_MIN_ANCHORS, f"count={acount[t]}")

    # --- HARD INVARIANT: flag-only, never blocked by co-occurrence ---
    print("\n[invariant] co-occurrence is FLAG-ONLY — tracker never blocked")
    check("tracker never blocked on any appearance", not tracker_ever_blocked)
    for t in trackers:
        check(f"{t}: score stays below block threshold ({config.ANOMALY_BLOCK_THRESHOLD})",
              all(results[(i, t)][1] < config.ANOMALY_BLOCK_THRESHOLD for i in range(4)),
              f"scores={[results[(i,t)][1] for i in range(4)]}")

    # --- FP GUARD: benign infra co-loaded across all sites is NOT flagged ---
    print("\n[fp-guard] benign co-loaded infra never flagged (G1 allowlist)")
    for d in infra:
        decs = [results[(i, d)][0] for i in range(4)]
        check(f"{d}: allowed in every burst", all(x == "allowed" for x in decs),
              f"got {decs}")
        # G1 also prevents accrual: infra is never credited an anchor, so even
        # its ubiquity count stays 0 despite being co-loaded across every site.
        check(f"{d}: accrued 0 anchors (never credited as a candidate)",
              infra_anchor[d] == 0, f"count={infra_anchor[d]}")

    print("\n[fp-guard] non-allowlisted benign service behind <3 anchors (G4)")
    decs_p = [results[(i, partial)][0] for i in range(2)]
    check(f"{partial}: allowed (ubiquity 2 < {config.COOC_MIN_ANCHORS})",
          all(x == "allowed" for x in decs_p), f"got {decs_p}")

    print("\n[fp-guard] first-party anchors themselves never flagged")
    for i, a in enumerate(anchors):
        check(f"{a}: allowed", results[(i, a)][0] == "allowed", f"got {results[(i,a)]}")

    print(f"\n{'='*52}\n  {_PASS} passed, {_FAIL} failed\n{'='*52}")
    return 1 if _FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
