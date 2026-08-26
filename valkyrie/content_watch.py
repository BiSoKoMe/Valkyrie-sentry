"""Background page-content analysis - the analyst's eye, running continuously.

WHAT THIS FIXES
---------------
``site_analyzer.py`` already scores a page by what it actually *does* -
cryptominers, fingerprinting scripts, packed/obfuscated JS, phishing forms,
hidden iframes, tracker density. That is genuine analysis, and unlike a
blocklist it works on a domain nobody has ever seen before, because it
judges the page rather than the name.

Its only caller was ``python -m valkyrie --analyze <url>``: a command you
type by hand, which fetches one page, prints a verdict and exits. Nothing
in the running product ever called it. The engine existed and was never
switched on.

This module is the missing connection: it watches domains as they are
resolved and analyses their content in the background.

WHY IT IS ASYNCHRONOUS (this is not an optimisation, it is a requirement)
------------------------------------------------------------------------
``DNSInterceptor._decide`` is synchronous - a real DNS query is blocked
waiting on it. Content analysis needs an HTTP fetch, which takes up to
``timeout`` seconds. Calling it inline would add seconds of latency to
every first lookup of every new domain, which would make browsing unusable
and would be a far worse product than the one it was trying to improve.

So: ``observe()`` is O(1) and returns immediately. A worker thread does the
fetching. The verdict lands in the cache and informs *subsequent* lookups.
That is the same trade every real content-inspection product makes, and it
is effective because a single page load triggers many lookups and users
revisit the same sites constantly.

FALSE-POSITIVE POLICY (the part that matters most)
--------------------------------------------------
This project has shipped a false positive twice, and content analysis is
exactly the kind of signal that could do it a third time. A page is *not*
auto-blocked just because it scored badly. Only categories where a false
positive is close to impossible can auto-block:

  * ``miner`` - an in-page cryptominer is essentially never legitimate.

Everything else is recorded as EVIDENCE and surfaced, but never sinkholes
a site on its own:

  * ``fingerprinting`` - **banks and payment processors fingerprint
    deliberately, for fraud detection.** Auto-blocking this would recreate
    the world-banks incident precisely.
  * ``malware`` (obfuscation) - minifiers and packers are everywhere on
    legitimate sites.
  * ``phishing`` - good signal, but wrongly blocking a real site is worse
    than missing one, per this product's stated asymmetry.
  * tracker density - informational only; a site's own CDN counts as
    third-party, so it is far too noisy to act on.

Popular domains are never analysed at all: they carry the highest FP cost
and the least benefit.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from typing import Optional

from .popular_domains import is_popular

# Categories permitted to auto-block. Deliberately minimal - see the
# false-positive policy in the module docstring before adding to this.
AUTO_BLOCK_CATEGORIES = frozenset({"miner"})

_MAX_QUEUE = 256          # bounded: a lookup storm must not grow memory
_MAX_CACHE = 2048         # bounded LRU of completed verdicts
_MIN_INTERVAL = 1.0       # seconds between fetches - never hammer a host


class ContentWatcher:
    """Analyses page content off the DNS path. Never blocks a decision."""

    def __init__(self, store=None, analyzer=None, intelligence=None, *,
                 max_queue: int = _MAX_QUEUE, min_interval: float = _MIN_INTERVAL,
                 auto_block: bool = True) -> None:
        self._store = store
        self._intel = intelligence
        self._analyzer = analyzer
        self._auto_block = auto_block
        self._min_interval = min_interval
        self._queue: deque = deque(maxlen=max_queue)   # drops oldest when full
        self._seen: set = set()          # domains already queued/analysed
        self._verdicts: OrderedDict = OrderedDict()    # domain -> ContentVerdict
        self._lock = threading.RLock()
        self._wake = threading.Event()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._analyzed = 0
        self._blocked = 0
        self._flagged = 0
        self._dropped = 0
        self._errors = 0

    # ------------------------------------------------------------------
    # Lifecycle (matches the Component contract: start/stop/is_running)
    # ------------------------------------------------------------------

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(
                target=self._loop, daemon=True, name="content-watch")
            self._thread.start()

    def stop(self) -> None:
        self._running = False
        self._wake.set()

    def is_running(self) -> bool:
        t = self._thread
        return bool(self._running and t is not None and t.is_alive())

    # ------------------------------------------------------------------
    # Hot path - called from _decide. MUST be O(1) and MUST NOT raise.
    # ------------------------------------------------------------------

    def observe(self, domain: str) -> None:
        """Queue a domain for background analysis. Returns immediately."""
        try:
            d = (domain or "").strip().lower().rstrip(".")
            if not d or is_popular(d):
                return          # popular = highest FP cost, least benefit
            with self._lock:
                if d in self._seen:
                    return
                self._seen.add(d)
                if len(self._queue) >= self._queue.maxlen:
                    self._dropped += 1      # deque drops the oldest itself
                self._queue.append(d)
            self._wake.set()
        except Exception:
            pass    # the DNS path must never break because of this

    def verdict(self, domain: str):
        """Completed content verdict for *domain*, or None if not analysed."""
        try:
            d = (domain or "").strip().lower().rstrip(".")
            with self._lock:
                v = self._verdicts.get(d)
                if v is not None:
                    self._verdicts.move_to_end(d)   # LRU touch
                return v
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Worker
    # ------------------------------------------------------------------

    def _loop(self) -> None:
        while self._running:
            try:
                with self._lock:
                    domain = self._queue.popleft() if self._queue else None
                if domain is None:
                    self._wake.wait(timeout=2.0)
                    self._wake.clear()
                    continue
                self._analyze_one(domain)
                time.sleep(self._min_interval)     # be a good citizen
            except BaseException:
                # A worker that dies silently would leave the feature looking
                # enabled while analysing nothing - the exact failure mode this
                # codebase keeps finding. Never let the loop exit on an error.
                self._errors += 1
                time.sleep(1.0)

    def _analyze_one(self, domain: str) -> None:
        analyzer = self._analyzer
        if analyzer is None:
            from .site_analyzer import SiteAnalyzer
            analyzer = self._analyzer = SiteAnalyzer(store=self._store)
        try:
            v = analyzer.analyze_url(f"http://{domain}")
        except Exception:
            self._errors += 1
            return
        if v is None or not getattr(v, "fetched", False):
            return      # unreachable: no evidence either way, stay silent

        with self._lock:
            self._verdicts[domain] = v
            self._verdicts.move_to_end(domain)
            while len(self._verdicts) > _MAX_CACHE:
                self._verdicts.popitem(last=False)
            self._analyzed += 1

        category = getattr(v, "category", "") or ""
        decision = getattr(v, "decision", "") or ""
        reasons = "; ".join(getattr(v, "reasons", []) or [])

        # Auto-block is deliberately narrow - see the module docstring.
        if (self._auto_block and decision == "block"
                and category in AUTO_BLOCK_CATEGORIES and not is_popular(domain)):
            self._blocked += 1
            if self._intel is not None:
                try:
                    self._intel.remember_bad(
                        domain, reason=f"page content: {reasons}"[:300])
                except Exception:
                    pass
            self._log(domain, "blocked", category, reasons)
        elif decision in ("block", "flag"):
            # Real evidence, but NOT acted on automatically. Recorded so it is
            # visible in the UI and to threat hunting, without risking an FP.
            self._flagged += 1
            self._log(domain, "flagged", category, reasons)

    def _log(self, domain: str, decision: str, category: str, reasons: str) -> None:
        if self._store is None:
            return
        try:
            from .store import DnsEvent
            self._store.log(DnsEvent.now(
                domain=domain, decision=decision, process_name="valkyrie",
                process_pid=0, process_path="",
                reason=f"content analysis: {reasons}"[:500],
                suspicion=0.0, raw_category=f"content_{category}",
            ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        with self._lock:
            return {
                "running": self.is_running(),
                "analyzed": self._analyzed,
                "auto_blocked": self._blocked,
                "flagged_evidence": self._flagged,
                "queued": len(self._queue),
                "dropped": self._dropped,
                "errors": self._errors,
                "cached_verdicts": len(self._verdicts),
                "auto_block_categories": sorted(AUTO_BLOCK_CATEGORIES),
            }
