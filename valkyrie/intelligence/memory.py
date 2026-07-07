"""IntelligenceMemory — Valkyrie's self-built threat intelligence.

Every confirmed decision is remembered so it never has to be re-derived:
``check()`` is an O(1) in-memory lookup that answers "we already decided
about this domain" before any scoring runs.  The memory grows over time,
survives restarts (SQLite via the existing Store), and can be exported
for backup or transfer to another machine.

Verdict rules:
  - ``remember_bad`` always wins: it evicts an earlier "good" verdict.
  - ``remember_good`` never overwrites a "bad" verdict.
  - a domain is also considered bad when a parent domain was remembered
    bad (bad "example.com" covers "cdn.example.com").
"""

from __future__ import annotations

import threading
from datetime import datetime
from typing import Optional


class IntelligenceMemory:
    """Persistent, fast-lookup memory of past threat decisions."""

    def __init__(self, store) -> None:
        self._store = store
        self._lock = threading.RLock()
        self._bad:  dict[str, str] = {}     # domain -> reason
        self._good: set[str] = set()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        conn = self._store.connection()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS intel_memory (
                    domain     TEXT PRIMARY KEY,
                    verdict    TEXT NOT NULL,          -- 'bad' | 'good'
                    ip         TEXT NOT NULL DEFAULT '',
                    process    TEXT NOT NULL DEFAULT '',
                    reason     TEXT NOT NULL DEFAULT '',
                    first_seen TEXT NOT NULL DEFAULT '',
                    last_seen  TEXT NOT NULL DEFAULT '',
                    hits       INTEGER NOT NULL DEFAULT 1
                );
            """)
            conn.commit()
            rows = conn.execute(
                "SELECT domain, verdict, reason FROM intel_memory"
            ).fetchall()
        finally:
            conn.close()
        with self._lock:
            for domain, verdict, reason in rows:
                if verdict == "bad":
                    self._bad[domain] = reason
                else:
                    self._good.add(domain)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def remember_bad(self, domain: str, ip: str = "", reason: str = "") -> None:
        domain = domain.lower().rstrip(".")
        if not domain:
            return
        with self._lock:
            self._good.discard(domain)
            self._bad[domain] = reason
        self._persist(domain, "bad", ip=ip, reason=reason)

    def remember_good(self, domain: str, process: str = "") -> None:
        domain = domain.lower().rstrip(".")
        if not domain:
            return
        with self._lock:
            if domain in self._bad:
                return              # bad verdicts are never downgraded here
            if domain in self._good:
                return
            self._good.add(domain)
        self._persist(domain, "good", process=process,
                      reason="consistently clean behaviour")

    def check(self, domain: str, ip: str = "") -> Optional[str]:
        """Fast path: 'bad' / 'good' if already decided, else None."""
        domain = domain.lower().rstrip(".")
        with self._lock:
            if domain in self._bad:
                return "bad"
            # Parent-domain match: bad example.com covers sub.example.com
            parts = domain.split(".")
            for i in range(1, len(parts) - 1):
                if ".".join(parts[i:]) in self._bad:
                    return "bad"
            if domain in self._good:
                return "good"
        return None

    def reason_for(self, domain: str) -> str:
        domain = domain.lower().rstrip(".")
        with self._lock:
            if domain in self._bad:
                return self._bad[domain]
            parts = domain.split(".")
            for i in range(1, len(parts) - 1):
                parent = ".".join(parts[i:])
                if parent in self._bad:
                    return f"parent domain {parent}: {self._bad[parent]}"
        return ""

    def export_intelligence(self) -> dict:
        """Full learned intelligence as a plain dict (backup / transfer)."""
        with self._lock:
            threats = dict(self._bad)
            safe    = sorted(self._good)
        return {
            "format":      "valkyrie-intelligence",
            "version":     1,
            "exported_at": datetime.utcnow().isoformat(timespec="seconds"),
            "threats":     threats,
            "safe":        safe,
        }

    def stats(self) -> dict:
        with self._lock:
            bad, good = len(self._bad), len(self._good)
        return {
            "threats_learned": bad,
            "safe_patterns":   good,
            "db_size_bytes":   self._store.db_size_bytes(),
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _persist(self, domain: str, verdict: str, ip: str = "",
                 process: str = "", reason: str = "") -> None:
        now = datetime.utcnow().isoformat(timespec="seconds")
        try:
            conn = self._store.connection()
            try:
                conn.execute(
                    "INSERT INTO intel_memory"
                    "(domain, verdict, ip, process, reason, first_seen, last_seen, hits) "
                    "VALUES (?,?,?,?,?,?,?,1) "
                    "ON CONFLICT(domain) DO UPDATE SET "
                    "verdict=excluded.verdict, ip=excluded.ip, "
                    "reason=excluded.reason, last_seen=excluded.last_seen, "
                    "hits=hits+1",
                    (domain, verdict, ip, process, reason, now, now),
                )
                conn.commit()
            finally:
                conn.close()
        except Exception:
            pass    # persistence failure must never break the DNS path
