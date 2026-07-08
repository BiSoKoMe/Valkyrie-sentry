"""Real-world accuracy measurement of Valkyrie's behavioural scanner.

This is a MEASUREMENT, not a pass/fail test.  It drives the REAL DNS
decision pipeline (DNSInterceptor._decide) in intelligence-only mode
(USE_EXTERNAL_LISTS = False — seed blocklist + behavioural scanner +
intelligence, no downloaded lists) against two labelled sets:

  * 15 confirmed tracker/telemetry endpoints, each independently confirmed
    by EasyPrivacy (github.com/easylist/easylist) AND deliberately absent
    from Valkyrie's own seed_blocklist.py — so every one is genuinely novel
    to Valkyrie.
  * 15 confirmed-benign domains (OS projects, CDNs, reference sites) absent
    from both EasyPrivacy and the seed list — a false-positive control.

Ground truth comes from an INDEPENDENT source (EasyPrivacy), never from
Valkyrie's own lists.  For each domain we record Valkyrie's decision
(block / flag / allow) and the suspicion score, then report a confusion
matrix with precision and recall.

Methodology notes (why the numbers are trustworthy, not gamed):
  * Each domain is queried ONCE through interceptor._decide, exactly as a
    real DNS query would be, so nothing is decided by code inspection.
  * A single LIVE process name is used for every query.  A fake name would
    make the anomaly detector's liveness check fire "process not running
    but still connecting" (+0.5) on every domain — a pure test artifact.
  * 30 queries in one process never trips the >30/10s rate-burst signal,
    heartbeat/beacon signals need 4+ repeats of the same pair, and the
    baseline is in its learning window, so the "never-seen"/timing signals
    are gated off.  The decision therefore reflects the domain itself.

Run:  python3 test_scanner_accuracy.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import valkyrie.config as config

config.USE_EXTERNAL_LISTS = False   # intelligence-only posture

from valkyrie.behavioral import BehavioralEngine
from valkyrie.blocklist import BlocklistManager
from valkyrie.dns_interceptor import DNSInterceptor
from valkyrie.intelligence import Intelligence
from valkyrie.process_watcher import ProcessInfo, ProcessWatcher
from valkyrie.rules import RulesLoader
from valkyrie.site_scanner import SiteScanner
from valkyrie.store import Store


# (domain, ground-truth label) — label is the INDEPENDENT verdict.
#   "tracker" → confirmed by EasyPrivacy, absent from Valkyrie's seed list
#   "clean"   → absent from EasyPrivacy and from Valkyrie's seed list
TRACKERS = [
    "analytics.tiktok.com",
    "analytics.pinterest.com",
    "analytics.yahoo.com",
    "analytics.adobe.io",
    "beacon.dropbox.com",
    "pixel.byspotify.com",
    "tr.snapchat.com",
    "ct.pinterest.com",
    "cs.media.net",
    "l.sharethis.com",
    "events.reddit.com",
    "marketing.dropbox.com",
    "browser-intake-datadoghq.com",
    "segmentapis.com",
    "taboolasyndication.com",
]
CLEAN = [
    "kernel.org",
    "python.org",
    "gitlab.com",
    "wordpress.org",
    "apache.org",
    "debian.org",
    "ubuntu.com",
    "archive.org",
    "mit.edu",
    "gnu.org",
    "postgresql.org",
    "nginx.org",
    "videolan.org",
    "sqlite.org",
    "torproject.org",
]


class _FixedWatcher(ProcessWatcher):
    def __init__(self, name: str) -> None:
        self._info = ProcessInfo(name=name, pid=4242, path=f"/usr/bin/{name}")
    def start(self) -> None:
        pass
    def lookup(self, src_ip: str, src_port: int) -> ProcessInfo:
        return self._info


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="valkyrie_accuracy_"))
    store = Store(db_path=tmp / "t.db")
    store.start()

    blocklist = BlocklistManager()
    n = blocklist.load(allow_download=False)   # seed only, offline

    scanner = SiteScanner(store=store)
    behavioral = BehavioralEngine()
    intel = Intelligence(store, behavioral=behavioral)
    intel.start()
    rules = RulesLoader(); rules.start()

    import psutil
    live_name = psutil.Process().name()

    interceptor = DNSInterceptor(
        store=store, blocklist=blocklist, behavioral=behavioral,
        rules=rules, process_watcher=_FixedWatcher(live_name),
        scanner=scanner, intelligence=intel,
    )

    import dns.rdatatype
    A = dns.rdatatype.A
    proc = ProcessInfo(name=live_name, pid=psutil.Process().pid, path="")

    print(f"USE_EXTERNAL_LISTS = {config.USE_EXTERNAL_LISTS}")
    print(f"seed blocklist loaded offline: {n} domains")
    print(f"query process (live): {live_name}\n")

    rows = []   # (domain, truth, decision, score, reason)
    for domain, truth in ([(d, "tracker") for d in TRACKERS]
                          + [(d, "clean") for d in CLEAN]):
        decision, reason, score, category = interceptor._decide(domain, A, proc, 60)
        rows.append((domain, truth, decision, round(score, 3), reason))

    intel.stop()
    store.stop()

    # ── Per-domain table ──────────────────────────────────────────────
    print(f"{'domain':<32} {'truth':<8} {'decision':<9} {'score':<6} reason")
    print("-" * 100)
    for domain, truth, decision, score, reason in rows:
        print(f"{domain:<32} {truth:<8} {decision:<9} {score:<6} {reason[:44]}")

    # ── Confusion matrix (positive = blocked OR flagged) ──────────────
    def positive(dec: str) -> bool:
        return dec in ("blocked", "flagged")

    TP = sum(1 for d, t, dec, s, r in rows if t == "tracker" and positive(dec))
    FN = sum(1 for d, t, dec, s, r in rows if t == "tracker" and not positive(dec))
    FP = sum(1 for d, t, dec, s, r in rows if t == "clean" and positive(dec))
    TN = sum(1 for d, t, dec, s, r in rows if t == "clean" and not positive(dec))

    blocked_tp = sum(1 for d, t, dec, s, r in rows if t == "tracker" and dec == "blocked")
    flagged_tp = sum(1 for d, t, dec, s, r in rows if t == "tracker" and dec == "flagged")

    precision = TP / (TP + FP) if (TP + FP) else float("nan")
    recall    = TP / (TP + FN) if (TP + FN) else float("nan")
    f1 = (2 * precision * recall / (precision + recall)
          if precision and recall and (precision + recall) else float("nan"))

    print("\n" + "=" * 60)
    print("CONFUSION MATRIX  (positive = block or flag)")
    print("=" * 60)
    print(f"                    predicted TRACKER   predicted CLEAN")
    print(f"  actual TRACKER          TP={TP:<2}              FN={FN:<2}")
    print(f"  actual CLEAN            FP={FP:<2}              TN={TN:<2}")
    print(f"\n  of the {TP} caught trackers: {blocked_tp} blocked, {flagged_tp} flagged")
    print(f"\n  Precision = {precision:.3f}")
    print(f"  Recall    = {recall:.3f}")
    print(f"  F1        = {f1:.3f}")
    print(f"  Trackers missed (false negatives): {FN}/{len(TRACKERS)}")
    print(f"  Clean wrongly flagged (false positives): {FP}/{len(CLEAN)}")

    if FN:
        print("\n  MISSED trackers (Valkyrie allowed these EasyPrivacy-confirmed trackers):")
        for d, t, dec, s, r in rows:
            if t == "tracker" and not positive(dec):
                print(f"    - {d}")
    if FP:
        print("\n  FALSE POSITIVES (Valkyrie blocked/flagged these benign sites):")
        for d, t, dec, s, r in rows:
            if t == "clean" and positive(dec):
                print(f"    - {d}  ({dec}: {r})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
