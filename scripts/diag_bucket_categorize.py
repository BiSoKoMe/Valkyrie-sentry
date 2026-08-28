"""PHASE 1 - categorize held-out EasyPrivacy trackers into Bucket A / Bucket B.

Bucket A: the registrable parent (eTLD+1) is a DEDICATED tracker/ad/analytics
          domain - safe to ship in seed_blocklist.py. Fixable by widening the
          shipped list; no new architecture.
Bucket B: the tracker is a subdomain of a MIXED-USE legitimate parent
          (snapchat.com, reddit.com, ...). Listing the parent would break the
          real site - genuinely needs a context signal.

Ground truth: every domain is confirmed by EasyPrivacy and absent from seed
(verified here). Each is then run through the REAL pipeline in isolation
(fresh intelligence state per domain, so a blocked sibling can't inflate the
result via the threat-graph) to record its intrinsic caught/missed status
AFTER the Phase-0 change.
"""
from __future__ import annotations
import re, glob, tempfile, json
from pathlib import Path
import valkyrie.config as config
config.USE_EXTERNAL_LISTS = False
from valkyrie.behavioral import BehavioralEngine
from valkyrie.blocklist import BlocklistManager
from valkyrie.dns_interceptor import DNSInterceptor
from valkyrie.intelligence import Intelligence
from valkyrie.process_watcher import ProcessInfo
from valkyrie.rules import RulesLoader
from valkyrie.site_scanner import SiteScanner
from valkyrie.store import Store
from test_scanner_accuracy import _FixedWatcher

# where the easyprivacy_*.txt inputs are read from and the rows are written
OUT_DIR = Path(__file__).resolve().parent / "diag_out"

# (domain, rationale) - Bucket A: dedicated tracker parent
BUCKET_A = [
    ("taboolasyndication.com", "Taboola dedicated ad-syndication domain"),
    ("segmentapis.com", "Segment/Twilio CDP API ingest domain"),
    ("sharethis.com", "ShareThis — dedicated share-widget/tracker company"),
    ("l.sharethis.com", "ShareThis logging host (parent is a pure tracker)"),
    ("seg.sharethis.com", "ShareThis segment host (pure tracker parent)"),
    ("cs.media.net", "Media.net — dedicated contextual-ad network"),
    ("browser-intake-datadoghq.com", "Datadog RUM ingest — dedicated telemetry domain"),
    ("posthog.com", "PostHog product-analytics vendor (cf. seeded mixpanel/segment)"),
    ("plausible.io", "Plausible analytics ingest domain"),
    ("fingerprint.com", "FingerprintJS device-fingerprinting vendor"),
    ("brandmetrics.com", "Brandmetrics ad-measurement vendor"),
    ("adalytics.io", "Adalytics ad-analytics vendor"),
    ("ceros.com", "Ceros interactive-content tracker"),
    ("count-server.sharethis.com", "ShareThis counter host (pure tracker parent)"),
    ("datasphere-sbsvc.sharethis.com", "ShareThis data-broker host"),
]
# Bucket B: tracker subdomain on a mixed-use legitimate parent
BUCKET_B = [
    ("tr.snapchat.com", "snapchat.com is the Snapchat app/site"),
    ("intg.snapchat.com", "snapchat.com mixed-use"),
    ("events.reddit.com", "reddit.com is a content site people visit"),
    ("alb.reddit.com", "reddit.com mixed-use"),
    ("ct.pinterest.com", "pinterest.com is a real user site"),
    ("log.pinterest.com", "pinterest.com mixed-use"),
    ("trk.pinterest.com", "pinterest.com mixed-use"),
    ("beacon.dropbox.com", "dropbox.com is a file-storage product"),
    ("marketing.dropbox.com", "dropbox.com mixed-use"),
    ("analytics.yahoo.com", "yahoo.com is a portal/mail site"),
    ("3p-udc.yahoo.com", "yahoo.com mixed-use"),
    ("pulsar.ebay.com", "ebay.com is a marketplace"),
    ("c.paypal.com", "paypal.com is a payments product"),
    ("t.paypal.com", "paypal.com mixed-use"),
    ("platform.twitter.com", "twitter.com is a social site"),
    ("stats.shopify.com", "shopify.com is a commerce platform"),
    ("v.shopify.com", "shopify.com mixed-use"),
    ("frog.wix.com", "wix.com is a site builder"),
    ("px.srvcs.tumblr.com", "tumblr.com is a blogging site"),
    ("log-gateway.zoom.us", "zoom.us is a video product"),
    ("events.squarespace.com", "squarespace.com is a site builder"),
    ("web-perf.booking.com", "booking.com is a travel site"),
    ("analytics.pointdrive.linkedin.com", "linkedin.com is a social site"),
    ("analytics.m7g.twitch.tv", "twitch.tv is a streaming site"),
    ("api.x.com", "x.com is a social site"),
]


def load_ep():
    ep = set(); rx = re.compile(r'^\|\|([a-z0-9][a-z0-9.-]*\.[a-z]{2,})[\^/]')
    for fn in glob.glob(str(OUT_DIR / 'easyprivacy_*.txt')):
        for line in open(fn, encoding='utf-8', errors='ignore'):
            line = line.strip()
            if line.startswith('||'):
                m = rx.match(line)
                if m: ep.add(m.group(1).lower())
    return ep


def decide_isolated(domain):
    """Fresh pipeline per domain - no cross-domain threat-graph contamination."""
    import psutil, dns.rdatatype
    tmp = Path(tempfile.mkdtemp())
    store = Store(db_path=tmp / "t.db"); store.start()
    bl = BlocklistManager(); bl.load(allow_download=False)
    sc = SiteScanner(store=store); beh = BehavioralEngine()
    intel = Intelligence(store, behavioral=beh)
    intel.baseline.start(); intel.graph.start(); intel.memory.start()  # skip health print
    rules = RulesLoader(); rules.start()
    ln = psutil.Process().name()
    itc = DNSInterceptor(store=store, blocklist=bl, behavioral=beh, rules=rules,
                         process_watcher=_FixedWatcher(ln), scanner=sc, intelligence=intel)
    proc = ProcessInfo(name=ln, pid=psutil.Process().pid, path="")
    dec, reason, score, cat = itc._decide(domain, dns.rdatatype.A, proc, 60)
    intel.stop(); store.stop()
    return dec, round(score, 3), reason


def main():
    ep = load_ep()
    from valkyrie.seed_blocklist import SEED_DOMAINS
    def seed_covers(d):
        p = d.split('.'); return any('.'.join(p[i:]) in SEED_DOMAINS for i in range(len(p)))

    rows = []
    for bucket, items in (("A", BUCKET_A), ("B", BUCKET_B)):
        for domain, why in items:
            in_ep = domain in ep
            in_seed = seed_covers(domain)
            dec, score, reason = decide_isolated(domain)
            caught = dec in ("blocked", "flagged")
            rows.append(dict(domain=domain, bucket=bucket, rationale=why,
                             in_ep=in_ep, in_seed=in_seed, decision=dec,
                             score=score, caught=caught, reason=reason))

    # Validate ground truth
    bad = [r for r in rows if not r["in_ep"] or r["in_seed"]]
    print(f"total={len(rows)}  A={sum(r['bucket']=='A' for r in rows)}  "
          f"B={sum(r['bucket']=='B' for r in rows)}  ground-truth-violations={len(bad)}")
    for r in bad:
        print("  BAD:", r["domain"], "in_ep", r["in_ep"], "in_seed", r["in_seed"])

    misses = [r for r in rows if not r["caught"]]
    mA = sum(r["bucket"] == "A" for r in misses)
    mB = sum(r["bucket"] == "B" for r in misses)
    caught = [r for r in rows if r["caught"]]
    print(f"\nCAUGHT (current pipeline): {len(caught)}/{len(rows)}")
    print(f"MISSED: {len(misses)}/{len(rows)}  ->  Bucket A misses={mA}  Bucket B misses={mB}")

    print("\n%-36s %-2s %-8s %-6s %s" % ("domain", "Bk", "decision", "score", "caught"))
    for r in rows:
        print("%-36s %-2s %-8s %-6s %s" % (r["domain"], r["bucket"], r["decision"],
                                            r["score"], "Y" if r["caught"] else "MISS"))

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / 'bucket_rows.json'
    json.dump(rows, open(out, "w"), indent=2)
    print("\nsaved:", out)


if __name__ == "__main__":
    main()
