"""Tier 1.7 - the standing benign corpus gate.

docs/TEST_PLAN.md calls this the single most valuable test in the repo, and the
reason is history rather than theory: this project has shipped a false positive
twice. The world-banks ML classifier blocked real banks, and the query-burst
behavioural class sinkholed microsoft, paypal, bing, live and linkedin. Both
would have been caught here.

The asymmetry that justifies a dedicated gate: a **missed threat** leaves one
machine at ambient risk, which is bad. A **false positive** returns `0.0.0.0`
for a domain, so the user's bank, tax portal, or hospital simply stops working
and they have no idea Valkyrie did it. For this product the FP is the worse
failure, so it gets the harder gate - **zero blocks tolerated**.

BLOCKED is a hard failure - not one benign domain may be sinkholed. FLAGGED is
bounded rather than ignored: a flag does not break the site, but a rising flag
rate is the leading indicator of the next outage.

Three sweeps, each on a FRESH pipeline. The freshness is not incidental: an
earlier draft shared one pipeline and sweep A's learned verdicts leaked into
sweep B, producing a spectacular and completely false "653 of 699 benign
domains blocked". State bleed between sweeps makes every number here
unattributable, so each sweep builds its own store, engine and intelligence.

  A  each domain judged on its own merits (rate window cleared per lookup)
  B  60 lookups in one burst - one ordinary page load
  C  all 699 as one sustained burst - the shape of the real query-burst
     incident that sinkholed microsoft/paypal/bing/live/linkedin

This runs the REAL pipeline - real `SiteScanner`, real `BlocklistManager` seed,
real `BehavioralEngine`, real `Intelligence`, real `_decide` ordering. Fakes
would defeat the entire point: the bug classes this exists to catch live in the
interaction between those stages, not in any one of them.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks
from valkyrie.behavioral import BehavioralEngine
from valkyrie.blocklist import BlocklistManager
from valkyrie.dns_interceptor import DNSInterceptor
from valkyrie.intelligence import Intelligence
from valkyrie.popular_domains import is_popular
from valkyrie.process_watcher import ProcessInfo, ProcessWatcher
from valkyrie.rules import RulesLoader
from valkyrie.site_scanner import SiteScanner
from valkyrie.store import Store

_CORPUS = Path(__file__).resolve().parent / "corpus" / "benign_domains.txt"

# A flag does not break a site, but a rising flag rate is the leading indicator
# of the next false-positive outage, so it is bounded rather than merely printed.
_MAX_FLAG_RATE = 0.05


class _FixedWatcher(ProcessWatcher):
    def __init__(self, name: str) -> None:
        self._info = ProcessInfo(name=name, pid=4242, path=f"/usr/bin/{name}")

    def start(self) -> None:
        pass

    def lookup(self, src_ip: str, src_port: int) -> ProcessInfo:
        return self._info


def _load_corpus() -> list[str]:
    out: list[str] = []
    for line in _CORPUS.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out


def main() -> int:
    c = Checks("benign corpus", expect_min=6)

    domains = _load_corpus()

    # A fresh pipeline per sweep. Sharing one would let an earlier sweep's
    # learned verdicts and rate windows leak into the next, which would make
    # every number here unattributable - the exact confound this file exists to
    # rule out.
    # Must be a process that is genuinely running: the `app_closed` anomaly does
    # a live psutil liveness check, so an invented process name flags every
    # single lookup and drowns out the signal this file exists to measure.
    import psutil
    proc_name = psutil.Process().name()

    blocklist = BlocklistManager()
    seed_n = blocklist.load(allow_download=False)      # offline seed only
    counter = {"n": 0}

    def _pipeline():
        counter["n"] += 1
        tmp = Path(tempfile.mkdtemp(prefix=f"valkyrie_benign_{counter['n']}_"))
        store = Store(db_path=tmp / "t.db")
        store.start()
        behavioral = BehavioralEngine()
        intel = Intelligence(store, behavioral=behavioral)
        intel.start()
        rules = RulesLoader()
        rules.start()
        di = DNSInterceptor(
            store=store, blocklist=blocklist, behavioral=behavioral,
            rules=rules, process_watcher=_FixedWatcher(proc_name),
            scanner=SiteScanner(store=store), intelligence=intel,
        )
        return di, store, behavioral

    proc = ProcessInfo(name=proc_name, pid=psutil.Process().pid, path="")

    print(f"corpus:        {len(domains)} benign domains")
    print(f"seed blocklist:{seed_n} entries (offline)")

    def _sweep(label: str, subset: list[str], isolate_rate: bool):
        """Run *subset* through a FRESH pipeline. Returns (blocked, flagged).

        ``isolate_rate=True`` clears the sliding rate window before each lookup,
        so each domain is judged on its OWN merits rather than on how many
        lookups happened to precede it. With False the window accumulates, which
        is the shape of the query-burst incident that sinkholed microsoft/
        paypal/bing/live/linkedin - worth asserting directly, not just avoiding.
        """
        di, store, behavioral = _pipeline()
        blocked_, flagged_ = [], []
        for d in subset:
            if isolate_rate:
                behavioral._rate._windows.clear()
            decision, reason, _s, _cat = di._decide(d, 1, proc, 0)
            if decision in ("blocked", "behavioral"):
                blocked_.append((d, reason))
            elif decision == "flagged":
                flagged_.append((d, reason))
        print(f"\n[{label}]")
        print(f"  of {len(subset)}:  blocked {len(blocked_)}   "
              f"flagged {len(flagged_)}   "
              f"allowed {len(subset) - len(blocked_) - len(flagged_)}")
        if blocked_:
            print("  FALSE POSITIVES — Valkyrie would sinkhole these real sites:")
            for d, r in blocked_[:15]:
                print(f"    - {d}  ({r})")
            if len(blocked_) > 15:
                print(f"    ... and {len(blocked_) - 15} more")
        elif flagged_:
            for d, r in flagged_[:6]:
                print(f"    ~ flagged {d}  ({r})")
            if len(flagged_) > 6:
                print(f"    ... and {len(flagged_) - 6} more flagged")
        store.stop()
        return blocked_, flagged_

    n = len(domains)
    tail = [d for d in domains if not is_popular(d)]

    # A - each domain on its own merits.
    solo_blocked, solo_flagged = _sweep(
        "A: each domain judged independently (rate window isolated)",
        domains, isolate_rate=True)
    # B - a realistic page load: ~60 lookups from one process in one burst.
    page_blocked, _page_flagged = _sweep(
        "B: 60 lookups in one burst (one ordinary page load)",
        domains[:60], isolate_rate=False)
    # C - the full corpus as one sustained burst: the outage shape.
    burst_blocked, burst_flagged = _sweep(
        f"C: all {n} lookups as one sustained burst (the outage shape)",
        domains, isolate_rate=False)

    solo_rate = len(solo_flagged) / n if n else 0.0
    tail_blocked = [d for d, _ in solo_blocked if not is_popular(d)]
    burst_tail = [d for d, _ in burst_blocked if not is_popular(d)]

    print("\n" + "=" * 60)
    c.check(f"corpus is substantial (>= 500 domains, have {n})", n >= 500)
    c.check(f"corpus is mostly long-tail, not floor-protected "
            f"({len(tail)}/{n} unprotected)", len(tail) >= int(0.8 * n))
    c.check(f"A: ZERO benign domains blocked on their own merits "
            f"(found {len(solo_blocked)})", len(solo_blocked) == 0)
    c.check(f"A: no long-tail domain blocked on merit "
            f"(found {len(tail_blocked)})", len(tail_blocked) == 0)
    c.check(f"A: flag rate within {_MAX_FLAG_RATE:.0%} "
            f"(measured {solo_rate:.1%})", solo_rate <= _MAX_FLAG_RATE)
    # B is the realistic gate: an ordinary page load must not sinkhole anything.
    c.check(f"B: ZERO benign domains blocked by one ordinary page load "
            f"(found {len(page_blocked)})", len(page_blocked) == 0)
    # C is the regression gate for the real incident. It is recorded as a
    # measured number rather than asserted at zero, because the finding it
    # produced is a live product question (see TEST_PLAN tier 1.7) and encoding
    # today's behaviour as "expected" would be pretending the gap is a feature.
    print(f"\n  MEASURED under sustained burst: {len(burst_blocked)}/{n} benign "
          f"domains blocked, {len(burst_tail)} of them long-tail")
    c.check("C: the popular-domain floor holds under sustained burst "
            f"({len(burst_blocked) - len(burst_tail)} floor-protected domains "
            "blocked)", (len(burst_blocked) - len(burst_tail)) == 0)

    return c.finish()   # each sweep closes its own store


if __name__ == "__main__":
    raise SystemExit(main())
