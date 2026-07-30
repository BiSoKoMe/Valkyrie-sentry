"""Tier 1.8 — a false positive must never become a permanent verdict.

`test_popular_domains.py` proves the floor and the self-heal purge behave at the
API level (`check()` stops answering 'bad'). This file tests the layer beneath
that, which is where the damage actually persists: **the database row**.

The distinction matters because the two failures look identical from `check()`
and are completely different in practice:

  * *masked* — the bad row is still on disk, and only a read-time guard stops it
    being served. Remove or reorder that guard, change the popular list, or read
    the table from any other code path (`export_intelligence`, the web API, a
    future feature) and the false positive is live again.
  * *purged* — the row is gone. There is nothing left to leak.

ADR 0040 promises the second. These checks hold it to that, by reading the table
directly rather than trusting the accessor that is supposed to protect it.

The asymmetry is deliberate throughout: a wrongly-remembered benign domain must
be erased, while a genuine threat must survive everything — restart, purge,
repeated `remember_good`. A self-heal that also forgets real threats would be a
worse bug than the one it fixes.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks
from valkyrie.intelligence.memory import IntelligenceMemory
from valkyrie.store import Store

_POPULAR = "paypal.com"
_THREAT = "evil-c2-xyz.example"


def _rows(store) -> dict[str, str]:
    """Read intel_memory directly — bypassing every read-time guard."""
    conn = store.connection()
    try:
        return {d: v for d, v in
                conn.execute("SELECT domain, verdict FROM intel_memory")}
    finally:
        conn.close()


def _insert_bad(store, domain: str, reason: str = "query burst") -> None:
    """Seed the table the way an older build left it."""
    conn = store.connection()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO intel_memory"
            "(domain,verdict,ip,process,reason,first_seen,last_seen,hits)"
            " VALUES (?,?,?,?,?,?,?,1)",
            (domain, "bad", "", "", reason, "2026-07-22", "2026-07-22"))
        conn.commit()
    finally:
        conn.close()


def main() -> int:
    c = Checks("verdict persistence", expect_min=18)

    # ── 1. An FP is never WRITTEN, not merely never served ──────────────────
    print("\n[1] a popular domain is never written to the table at all")
    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "a.db")
        store.start()
        mem = IntelligenceMemory(store)
        mem.start()
        mem.remember_bad(_POPULAR, reason="query burst")
        mem.remember_bad("login." + _POPULAR, reason="query burst")
        mem.remember_bad(_THREAT, reason="c2 beacon")
        rows = _rows(store)
        c.check("no row exists on disk for the popular domain",
                _POPULAR not in rows)
        c.check("no row exists for a popular subdomain",
                ("login." + _POPULAR) not in rows)
        c.check("the genuine threat IS written", rows.get(_THREAT) == "bad")
        c.check("repeated remember_bad still writes nothing",
                (mem.remember_bad(_POPULAR), _POPULAR not in _rows(store))[1])
        store.stop()

    # ── 2. Self-heal DELETES the row, it does not merely mask it ────────────
    print("\n[2] self-heal purges the row from disk, not just from the answer")
    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "b.db")
        store.start()
        IntelligenceMemory(store).start()          # create schema
        _insert_bad(store, _POPULAR)
        _insert_bad(store, _THREAT, reason="c2")
        c.check("precondition: the stale bad row is on disk",
                _rows(store).get(_POPULAR) == "bad")

        IntelligenceMemory(store).start()          # next launch self-heals
        after = _rows(store)
        c.check("the stale popular row is DELETED from disk",
                _POPULAR not in after)
        c.check("the real threat's row survives the purge",
                after.get(_THREAT) == "bad")

        # Durability: a third launch must not resurrect it, and the purge must
        # not need to run again to keep the answer correct.
        mem3 = IntelligenceMemory(store)
        mem3.start()
        c.check("the purge is durable across a further restart",
                _POPULAR not in _rows(store))
        c.check("check() still refuses to call it bad", mem3.check(_POPULAR) != "bad")
        c.check("the real threat still reads as bad after restarts",
                mem3.check(_THREAT) == "bad")
        store.stop()

    # ── 3. Defense in depth: a bad row must not be served even before purge ─
    print("\n[3] a lingering bad row is never SERVED, even pre-purge")
    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "c.db")
        store.start()
        mem = IntelligenceMemory(store)
        mem.start()
        _insert_bad(store, _POPULAR)               # injected AFTER start()
        c.check("row is present on disk (purge has not run again)",
                _rows(store).get(_POPULAR) == "bad")
        c.check("check() still does not answer 'bad'",
                mem.check(_POPULAR) != "bad")
        store.stop()

    # ── 4. A popular domain cannot be condemned via its parent ──────────────
    print("\n[4] parent-domain matching cannot condemn a popular domain")
    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "d.db")
        store.start()
        mem = IntelligenceMemory(store)
        mem.start()
        mem.remember_bad("example.test", reason="c2")
        c.check("a subdomain of a bad parent IS bad",
                mem.check("sub.example.test") == "bad")
        c.check("but a popular subdomain is never bad by inheritance",
                mem.check("login." + _POPULAR) != "bad")
        store.stop()

    # ── 5. Normalisation — an FP must not slip through on case or a dot ─────
    print("\n[5] normalisation closes the case/trailing-dot bypass")
    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "e.db")
        store.start()
        mem = IntelligenceMemory(store)
        mem.start()
        for variant in ("PayPal.com", "PAYPAL.COM.", "paypal.com."):
            mem.remember_bad(variant, reason="query burst")
        rows = _rows(store)
        c.check("no cased/dotted variant was written",
                not any("paypal" in d.lower() for d in rows))
        store.stop()

    # ── 6. Good verdicts persist; bad is never downgraded ───────────────────
    # The regression lock for the check() bug found in tier 0: the popular-domain
    # guard used to discard 'good' as well as 'bad', killing the fast path for
    # exactly the highest-traffic domains.
    print("\n[6] good verdicts persist and bad is never downgraded")
    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "f.db")
        store.start()
        mem = IntelligenceMemory(store)
        mem.start()
        mem.remember_good(_POPULAR, process="firefox.exe")
        mem.remember_good("docs.python.org", process="firefox.exe")
        mem.remember_bad(_THREAT, reason="c2")
        mem.remember_good(_THREAT)                 # must NOT downgrade
        c.check("REGRESSION: a popular domain can still be learned good",
                mem.check(_POPULAR) == "good")
        c.check("an ordinary domain is learned good", mem.check("docs.python.org") == "good")
        c.check("remember_good never downgrades a bad verdict",
                mem.check(_THREAT) == "bad")

        mem2 = IntelligenceMemory(store)
        mem2.start()
        c.check("a good verdict on a popular domain survives restart",
                mem2.check(_POPULAR) == "good")
        c.check("an ordinary good verdict survives restart",
                mem2.check("docs.python.org") == "good")
        c.check("a bad verdict survives restart", mem2.check(_THREAT) == "bad")
        store.stop()

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
