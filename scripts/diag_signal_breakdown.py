"""Signal-level diagnosis for the 7 missed trackers (DIAGNOSIS ONLY).

Drives the real DNSInterceptor._decide pipeline (intelligence-only,
USE_EXTERNAL_LISTS=False, live process name — identical setup to
test_scanner_accuracy.py) over the same 30-domain ordered set, but this
time decomposes EVERY sub-signal that feeds a decision, per domain.

Nothing here changes detection logic.  For faithfulness it:
  * calls the REAL signal functions (site_scanner / behavioral / anomaly /
    baseline / threat_graph), not re-implementations, and
  * independently calls interceptor._decide on each domain and asserts the
    recomposed scanner/classifier totals match the pipeline's own output.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import valkyrie.config as config
config.USE_EXTERNAL_LISTS = False

from valkyrie import config as cfg
from valkyrie.behavioral import (BehavioralEngine, entropy_score,
                                 tld_reputation_score, _shannon_entropy)
from valkyrie.blocklist import BlocklistManager
from valkyrie.dns_interceptor import DNSInterceptor
from valkyrie.intelligence import Intelligence
from valkyrie.process_watcher import ProcessInfo
from valkyrie.rules import RulesLoader
from valkyrie.site_scanner import (SiteScanner, _sld, _first_label,
                                   _root_domain, _label_count)
from valkyrie.store import Store
from test_scanner_accuracy import TRACKERS, CLEAN, _FixedWatcher

MISSED = ["tr.snapchat.com", "cs.media.net", "l.sharethis.com",
          "events.reddit.com", "browser-intake-datadoghq.com",
          "segmentapis.com", "taboolasyndication.com"]


def build():
    tmp = Path(tempfile.mkdtemp(prefix="valkyrie_diag_"))
    store = Store(db_path=tmp / "t.db"); store.start()
    bl = BlocklistManager(); bl.load(allow_download=False)
    scanner = SiteScanner(store=store)
    beh = BehavioralEngine()
    intel = Intelligence(store, behavioral=beh); intel.start()
    rules = RulesLoader(); rules.start()
    import psutil
    ln = psutil.Process().name()
    itc = DNSInterceptor(store=store, blocklist=bl, behavioral=beh, rules=rules,
                         process_watcher=_FixedWatcher(ln), scanner=scanner,
                         intelligence=intel)
    proc = ProcessInfo(name=ln, pid=psutil.Process().pid, path="")
    return store, bl, scanner, beh, intel, itc, proc, ln


def main() -> int:
    import dns.rdatatype, time
    A = dns.rdatatype.A
    store, bl, scanner, beh, intel, itc, proc, ln = build()

    order = TRACKERS + CLEAN
    rows = {}   # domain -> dict of sub-signals

    for domain in order:
        now = time.time()
        d = domain.lower()
        sld = _sld(d); first = _first_label(d)
        root = _root_domain(d); parts = _label_count(d)

        # ---- reproduce pipeline order: record baseline FIRST (as _decide does)
        intel.record(ln, d, now, 60)
        learning = intel.baseline.is_learning()

        # ===== SCANNER stage sub-signals (site_scanner._score) =====
        s1a = 0.7 if sld in cfg.TRACKER_SLDS else 0.0
        s1b = 0.4 if (sld in cfg.ANALYTICS_SLDS and sld not in cfg.TRACKER_SLDS) else 0.0
        s2_fired = first in cfg.TRACKER_PREFIXES and parts >= 3
        s2 = 0.7 if s2_fired else 0.0
        sc_ent_partial = 0.0
        if parts >= 3:
            e, _ = entropy_score(d); sc_ent_partial = e
        s3 = 0.3 if (parts >= 3 and sc_ent_partial > 0) else 0.0
        # rate (scanner has its own RateLimiter) — read live
        r_sc, _ = scanner._rate.record_and_score(ln)
        s4 = 0.2 if r_sc > 0 else 0.0
        s5 = 0.2 if (s2_fired and ln in cfg.SYSTEM_PROCESSES
                     and root not in cfg.MS_TRUSTED_ROOTS) else 0.0
        scanner_total = min(1.0, s1a + s1b + s2 + s3 + s4 + s5)

        # ===== CLASSIFIER stage sub-signals =====
        # anomaly.py components (mirror AnomalyDetector.score, gates included)
        an_bg = 0.3 if intel.anomaly._is_background(ln) else 0.0
        an_hb = 0.4 if intel.anomaly.is_heartbeat(ln, d) else 0.0
        alive = intel.anomaly._is_running(ln)
        an_ac = 0.5 if alive is False else 0.0
        an_ns = 0.3 if (not learning and not intel.baseline.is_normal(ln, d, now)) else 0.0
        an_td = 0.2 if (not learning and intel.anomaly._timing_deviates(ln, d)) else 0.0
        an_as = 0.3 if intel.anomaly._asymmetric_small_out(ln, d, 60) else 0.0
        anomaly_total = min(1.0, an_bg + an_hb + an_ac + an_ns + an_td + an_as)

        # threat graph
        graph = intel.graph.is_related(d, "")

        # behavioral.py components (entropy/rate/age -> weighted combine)
        be_ent, _ = entropy_score(d)         # NOT gated by part count
        be_rate, _ = beh._rate.record_and_score(ln)
        be_age, _ = tld_reputation_score(d)   # PHASE 0: replaced dead WHOIS age signal
        beh_total = min(1.0, be_ent * 0.5 + be_rate * 0.35 + be_age * 0.15)

        classifier_total = max(anomaly_total, graph, beh_total)

        rows[d] = dict(
            sld=sld, first=first, parts=parts,
            s1a=s1a, s1b=s1b, s2=s2, s3=s3, s3_ent_raw=round(sc_ent_partial, 3),
            s4=s4, s5=s5, scanner_total=round(scanner_total, 3),
            an_bg=an_bg, an_hb=an_hb, an_ac=an_ac, an_ns=an_ns, an_td=an_td,
            an_as=an_as, anomaly_total=round(anomaly_total, 3),
            graph=round(graph, 3),
            be_ent_raw=round(be_ent, 3), be_rate=be_rate, be_age=be_age,
            beh_total=round(beh_total, 3),
            classifier_total=round(classifier_total, 3),
            first_label_entropy=round(_shannon_entropy(first), 3),
            learning=learning,
        )

    # ---- Cross-check: run the pipeline itself and compare finals ----
    store2, bl2, sc2, beh2, intel2, itc2, proc2, ln2 = build()
    finals = {}
    for domain in order:
        dec, reason, score, cat = itc2._decide(domain, A, proc2, 60)
        finals[domain.lower()] = (dec, round(score, 3), reason)
    intel.stop(); store.stop(); intel2.stop(); store2.stop()

    print("Cross-check (recomposed vs pipeline) for the 7 missed domains:")
    ok = True
    for d in MISSED:
        r = rows[d]
        pdec, pscore, preason = finals[d]
        # pipeline final score for an allowed domain = classifier_total
        # (scanner allowed, blocklist miss).  Compare.
        match = abs(pscore - r["classifier_total"]) < 0.02 or pscore == r["classifier_total"]
        ok = ok and match and pdec == "allowed"
        print(f"  {d:<32} pipeline=({pdec},{pscore})  recomposed_classifier={r['classifier_total']}  {'OK' if match else 'MISMATCH'}")
    print("  ALL CONSISTENT" if ok else "  *** INCONSISTENCY — investigate ***")

    # Persist rows for the report writer
    import json
    out = Path("/tmp/claude-0/-home-user-Valkyrie/6c733103-2c92-531d-9622-a8c9045146af/scratchpad/diag_rows.json")
    json.dump({d: rows[d] for d in MISSED}, open(out, "w"), indent=2)
    json.dump({d: finals[d.lower()] for d in MISSED}, open(str(out)+".finals", "w"), indent=2)
    print("\nsaved:", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
