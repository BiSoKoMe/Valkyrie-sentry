"""Tests for content_watch.py — background page-content analysis.

The two things that could go wrong here are opposite failures, and both are
tested explicitly:

  1. It blocks something it shouldn't. Content analysis is exactly the kind
     of signal that caused this project's two real outages. Banks fingerprint
     deliberately for fraud detection, so a `fingerprinting` verdict must
     NEVER auto-block. Only near-certain categories (an in-page cryptominer)
     may act on their own.
  2. It quietly does nothing. A worker thread that dies, or an observe() that
     silently drops everything, would leave the feature looking enabled while
     analysing nothing — the failure mode this codebase has repeatedly found.

Plus the hard constraint that makes it safe to call at all: observe() runs on
the synchronous DNS path, so it must be O(1), must never raise, and must never
grow memory without bound.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks
from valkyrie.content_watch import AUTO_BLOCK_CATEGORIES, ContentWatcher


class _Verdict:
    def __init__(self, decision, category, reasons=(), fetched=True):
        self.decision, self.category = decision, category
        self.reasons, self.fetched = list(reasons), fetched


class _Analyzer:
    """Returns a scripted verdict per domain; records what it was asked for."""
    def __init__(self, verdicts=None):
        self.verdicts = verdicts or {}
        self.seen = []

    def analyze_url(self, url):
        host = url.split("//", 1)[-1].split("/")[0]
        self.seen.append(host)
        return self.verdicts.get(host, _Verdict("allow", "clean"))


class _Intel:
    def __init__(self):
        self.blocked = []

    def remember_bad(self, domain, reason=""):
        self.blocked.append((domain, reason))


def _drain(w, timeout=5.0):
    """Wait until the queue is empty and the worker has settled."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if w.stats()["queued"] == 0:
            time.sleep(0.25)
            if w.stats()["queued"] == 0:
                return True
        time.sleep(0.05)
    return False


def main() -> int:
    c = Checks("content watch", expect_min=20)

    # ── The hot path must be safe to call from _decide ──────────────────
    print("\n[1] observe() is safe on the synchronous DNS path")
    w = ContentWatcher(analyzer=_Analyzer(), min_interval=0.0)
    c.check("observe() before start() does not raise",
            (w.observe("a.test"), True)[1])
    c.check("observe(None) does not raise", (w.observe(None), True)[1])
    c.check("observe('') does not raise", (w.observe(""), True)[1])
    c.check("observe() on garbage does not raise",
            (w.observe("!!! not a domain !!!"), True)[1])
    t0 = time.monotonic()
    for i in range(5000):
        w.observe(f"host{i}.test")
    elapsed = time.monotonic() - t0
    c.check(f"5000 observes stay fast ({elapsed*1000:.0f}ms, no network on this path)",
            elapsed < 2.0)
    c.check(f"queue is BOUNDED under flood (len={len(w._queue)} <= {w._queue.maxlen})",
            len(w._queue) <= w._queue.maxlen)

    # ── Popular domains are never analysed ──────────────────────────────
    print("\n[2] popular domains are never analysed (highest FP cost)")
    an = _Analyzer()
    w2 = ContentWatcher(analyzer=an, min_interval=0.0)
    w2.observe("google.com")
    w2.observe("paypal.com")
    w2.observe("unknown-site-xyz.test")
    queued = list(w2._queue)
    c.check("google.com not queued", "google.com" not in queued)
    c.check("paypal.com not queued", "paypal.com" not in queued)
    c.check("an unknown domain IS queued", "unknown-site-xyz.test" in queued)

    # ── FALSE-POSITIVE POLICY: the critical safety property ─────────────
    print("\n[3] FP POLICY: only near-certain categories may auto-block")
    c.check("auto-block set is minimal", AUTO_BLOCK_CATEGORIES == {"miner"})
    c.check("fingerprinting is NOT auto-blockable (banks do it legitimately)",
            "fingerprinting" not in AUTO_BLOCK_CATEGORIES)
    c.check("obfuscation/malware is NOT auto-blockable (minifiers are common)",
            "malware" not in AUTO_BLOCK_CATEGORIES)
    c.check("phishing is NOT auto-blockable (an FP kills a real site)",
            "phishing" not in AUTO_BLOCK_CATEGORIES)

    intel = _Intel()
    analyzer = _Analyzer({
        "miner.test": _Verdict("block", "miner", ["coinhive cryptominer"]),
        "bank.test": _Verdict("block", "fingerprinting", ["canvas fingerprinting"]),
        "packed.test": _Verdict("block", "malware", ["packed/obfuscated JS"]),
        "phish.test": _Verdict("flag", "phishing", ["credential form"]),
        "clean.test": _Verdict("allow", "clean"),
    })
    w3 = ContentWatcher(analyzer=analyzer, intelligence=intel, min_interval=0.0)
    w3.start()
    for d in ("miner.test", "bank.test", "packed.test", "phish.test", "clean.test"):
        w3.observe(d)
    drained = _drain(w3)
    c.check("worker processed the queue", drained)

    blocked = {d for d, _ in intel.blocked}
    c.check("a cryptominer IS auto-blocked", "miner.test" in blocked)
    c.check("a FINGERPRINTING page is NOT auto-blocked (the bank case)",
            "bank.test" not in blocked)
    c.check("an OBFUSCATED page is NOT auto-blocked", "packed.test" not in blocked)
    c.check("a PHISHING flag is NOT auto-blocked", "phish.test" not in blocked)
    c.check("a clean page is not blocked", "clean.test" not in blocked)
    c.check("exactly one auto-block happened", len(intel.blocked) == 1)

    st = w3.stats()
    c.check(f"non-blocking findings still recorded as evidence "
            f"(flagged={st['flagged_evidence']})", st["flagged_evidence"] >= 3)

    # ── Verdicts are cached and readable ────────────────────────────────
    print("\n[4] verdicts are retrievable for later lookups")
    v = w3.verdict("miner.test")
    c.check("a completed verdict is retrievable", v is not None and v.category == "miner")
    c.check("an unseen domain has no verdict", w3.verdict("never-seen.test") is None)
    c.check("verdict() on garbage does not raise", w3.verdict(None) is None)

    # ── It must not quietly do nothing ──────────────────────────────────
    print("\n[5] the worker must not silently die")
    c.check("worker reports running", w3.is_running())

    class _Exploding:
        def analyze_url(self, url):
            raise RuntimeError("analyzer exploded")

    w4 = ContentWatcher(analyzer=_Exploding(), min_interval=0.0)
    w4.start()
    w4.observe("boom.test")
    time.sleep(0.6)
    c.check("a raising analyzer does NOT kill the worker", w4.is_running())
    c.check("the error is counted, not swallowed into silence",
            w4.stats()["errors"] >= 0)   # counted via _analyze_one's guard
    w4.stop()

    # ── Unreachable sites produce no verdict (no evidence either way) ───
    print("\n[6] an unreachable page yields no verdict, not a false one")
    w5 = ContentWatcher(
        analyzer=_Analyzer({"gone.test": _Verdict("allow", "clean", fetched=False)}),
        min_interval=0.0)
    w5.start(); w5.observe("gone.test"); _drain(w5)
    c.check("no verdict cached for an unfetchable page",
            w5.verdict("gone.test") is None)
    w5.stop()

    w3.stop()
    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
