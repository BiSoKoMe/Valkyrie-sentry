"""Intelligence-only coverage test - no external lists, no network.

Confirms that with USE_EXTERNAL_LISTS = False the seed list + behavioural
scanner + intelligence memory alone still catch all three surveillance
classes, driving the REAL DNS decision pipeline (DNSInterceptor._decide):

  1. a seed-list tracker                              -> sinkholed (DECEIVED in
     Standard profile - a decoy dead-end, not a hard block)
  2. a tracker-name-pattern domain in NO list        -> deceived/flagged (scanner)
  3. a repeat of a real (non-tracker) THREAT          -> block via memory
     (fast path - category "intelligence", set before any scanner re-run;
     trackers are handled by DECEIVE and deliberately NOT learned as threats)

Run:  python3 test_intel_only.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import valkyrie.config as config

# Enforce the intelligence-only posture for this test explicitly.
config.USE_EXTERNAL_LISTS = False

from valkyrie.behavioral import BehavioralEngine
from valkyrie.blocklist import BlocklistManager
from valkyrie.dns_interceptor import DNSInterceptor
from valkyrie.intelligence import Intelligence
from valkyrie.process_watcher import ProcessInfo, ProcessWatcher
from valkyrie.rules import RulesLoader
from valkyrie.site_scanner import SiteScanner
from valkyrie.store import Store

_PASS = 0
_FAIL = 0


def check(label: str, cond: bool, detail: str = "") -> None:
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  PASS  {label}")
    else:
        _FAIL += 1
        print(f"  FAIL  {label}  {detail}")


class _FixedWatcher(ProcessWatcher):
    """ProcessWatcher stub returning a constant process (no OS lookup)."""
    def __init__(self, name: str) -> None:
        self._info = ProcessInfo(name=name, pid=4242, path=f"/usr/bin/{name}")
    def start(self) -> None:  # noqa: D401 - no background thread in the test
        pass
    def lookup(self, src_ip: str, src_port: int) -> ProcessInfo:
        return self._info


def main() -> int:
    print("Valkyrie intelligence-only coverage test")
    check("USE_EXTERNAL_LISTS is False", config.USE_EXTERNAL_LISTS is False)

    tmp = Path(tempfile.mkdtemp(prefix="valkyrie_intel_only_"))
    store = Store(db_path=tmp / "t.db")
    store.start()

    blocklist = BlocklistManager()
    n = blocklist.load(allow_download=False)          # seed only, offline
    check("blocklist loaded offline (seed only)", n > 0, f"count={n}")

    scanner = SiteScanner(store=store)
    behavioral = BehavioralEngine()
    intel = Intelligence(store, behavioral=behavioral)
    intel.start()
    rules = RulesLoader(); rules.start()

    # Use the *actually running* process name so the anomaly detector's
    # liveness check reflects reality (the process that makes a DNS query is
    # alive at that moment - on the real system this is always true). Using a
    # fake dead name would wrongly trip the "app closed but connecting" signal.
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

    # --- Case 1: seed-list tracker ---
    print("\n[1] Seed-list tracker (no external list, no network)")
    # A tracker is SINKHOLED, but in the Standard profile as a DECEIVE (decoy
    # dead-end) rather than a hard block - the app keeps working, telemetry dies.
    d1, r1, s1, c1 = interceptor._decide("scorecardresearch.com", A, proc, 80)
    check("seed tracker scorecardresearch.com is sinkholed (deceived in Standard)",
          d1 in ("deceived", "blocked"), f"got {d1} ({r1})")

    # --- Case 2: tracker-name pattern in NO list ---
    print("\n[2] Tracker-pattern domain absent from every list")
    novel = "telemetry.totally-unknown-vendor-4821.example"
    check("novel domain is NOT in the blocklist",
          not blocklist.is_blocked(novel))
    d2, r2, s2, c2 = interceptor._decide(novel, A, proc, 60)
    check("novel tracker-pattern domain is acted on by the scanner",
          d2 in ("deceived", "blocked", "flagged"), f"got {d2} ({r2})")
    print(f"       -> decision={d2}  score={s2}  reason={r2}")

    # --- Case 3: repeat hit served from intelligence memory ---
    print("\n[3] Repeat query served instantly from intelligence memory")
    # A REAL (non-tracker) threat is remembered and served from memory before the
    # scanner re-runs (category 'intelligence'). Trackers are NOT used here: they
    # go through the DECEIVE policy and are deliberately never learned as threats,
    # so the intelligence memory fast path is demonstrated with actual malware.
    threat = "malware-c2-7f3a9k2p.example"
    intel.remember_block(threat, "known malware C2 infrastructure")   # learn it
    d3, r3, s3, c3 = interceptor._decide(threat, A, proc, 80)         # repeat
    check("repeat decision comes from intelligence memory",
          c3 == "intelligence" and d3 == "blocked",
          f"got decision={d3} category={c3} reason={r3}")
    check("memory reason is tagged 'intelligence:'",
          r3.startswith("intelligence:"), f"reason={r3}")

    # A legitimate site must still resolve (no over-blocking)
    print("\n[4] Legitimate site not over-blocked")
    d4, r4, s4, c4 = interceptor._decide("wikipedia.org", A, proc, 300)
    check("wikipedia.org allowed", d4 == "allowed", f"got {d4} ({r4})")

    intel.stop()
    store.stop()

    print(f"\n{'='*52}")
    print(f"  {_PASS} passed, {_FAIL} failed")
    print(f"{'='*52}")
    return 1 if _FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
