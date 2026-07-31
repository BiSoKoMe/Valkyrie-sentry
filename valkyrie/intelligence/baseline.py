"""BaselineLearner — learns what normal network behaviour looks like
for THIS machine.

Every DNS query is recorded per (process, domain) pair: hit counts,
first/last seen, inter-query timing, and payload sizes.  After the
learning period (LEARNING_PERIOD_DAYS) the baseline is the reference
for "have we ever seen this process talk to this domain, and at what
rhythm?".

Persistence: SQLite via the existing Store (works in zero-log RAM mode
too).  Writes are batched by a background flush thread so the DNS hot
path never blocks on disk.  The baseline never resets on its own — it
keeps learning across restarts.
"""

from __future__ import annotations

import collections
import threading
import time
from datetime import datetime
from typing import Optional

from ..config import (
    INTEL_FLUSH_INTERVAL,
    INTEL_HISTORY_SAMPLES,
    LEARNING_PERIOD_DAYS,
)


class _PairProfile:
    """In-memory learning state for one (process, domain) pair."""

    __slots__ = ("hits", "first_seen", "last_seen", "last_ts",
                 "avg_gap", "timestamps", "payloads", "dirty")

    def __init__(self) -> None:
        self.hits:       int = 0
        self.first_seen: str = ""
        self.last_seen:  str = ""
        self.last_ts:    float = 0.0
        self.avg_gap:    float = 0.0     # EWMA of gaps between queries (seconds)
        self.timestamps: collections.deque = collections.deque(maxlen=INTEL_HISTORY_SAMPLES)
        self.payloads:   collections.deque = collections.deque(maxlen=INTEL_HISTORY_SAMPLES)
        self.dirty:      bool = False

    def gaps(self) -> list[float]:
        ts = list(self.timestamps)
        return [b - a for a, b in zip(ts, ts[1:]) if b >= a]


class BaselineLearner:
    """Per-machine behavioural baseline, persisted in the Store's SQLite DB."""

    def __init__(self, store, learning_days: float = LEARNING_PERIOD_DAYS) -> None:
        self._store = store
        self._learning_days = learning_days
        self._profiles: dict[tuple[str, str], _PairProfile] = {}
        self._lock = threading.RLock()
        self._learning_started: float = 0.0
        self._running = False
        self._flush_thread = threading.Thread(
            target=self._flush_loop, daemon=True, name="intel-baseline-flush"
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        self._init_schema()
        self._load()
        self._running = True
        self._flush_thread.start()

    def stop(self) -> None:
        self._running = False
        self.flush()

    def _init_schema(self) -> None:
        conn = self._store.connection()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS intel_meta (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS intel_baseline (
                    process    TEXT NOT NULL,
                    domain     TEXT NOT NULL,
                    hits       INTEGER NOT NULL DEFAULT 0,
                    first_seen TEXT NOT NULL DEFAULT '',
                    last_seen  TEXT NOT NULL DEFAULT '',
                    last_ts    REAL NOT NULL DEFAULT 0,
                    avg_gap    REAL NOT NULL DEFAULT 0,
                    PRIMARY KEY (process, domain)
                );
                CREATE INDEX IF NOT EXISTS idx_intel_baseline_proc
                    ON intel_baseline(process);
            """)
            conn.commit()
        finally:
            conn.close()

    def _load(self) -> None:
        conn = self._store.connection()
        try:
            row = conn.execute(
                "SELECT value FROM intel_meta WHERE key='learning_started'"
            ).fetchone()
            if row:
                self._learning_started = float(row[0])
            else:
                self._learning_started = time.time()
                conn.execute(
                    "INSERT OR REPLACE INTO intel_meta(key, value) VALUES(?, ?)",
                    ("learning_started", str(self._learning_started)),
                )
                conn.commit()

            profiles: dict[tuple[str, str], _PairProfile] = {}
            for r in conn.execute(
                "SELECT process, domain, hits, first_seen, last_seen, last_ts, avg_gap "
                "FROM intel_baseline"
            ):
                p = _PairProfile()
                p.hits       = r[2]
                p.first_seen = r[3]
                p.last_seen  = r[4]
                p.last_ts    = r[5]
                p.avg_gap    = r[6]
                profiles[(r[0], r[1])] = p
        finally:
            conn.close()
        with self._lock:
            self._profiles = profiles

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(self, process: str, domain: str, timestamp: float,
               payload_size: int = 0) -> None:
        """Record one observation.  Cheap (in-memory); safe from DNS threads."""
        process = (process or "unknown").lower()
        domain  = domain.lower().rstrip(".")
        now_iso = datetime.utcfromtimestamp(timestamp).isoformat(timespec="seconds")
        with self._lock:
            p = self._profiles.get((process, domain))
            if p is None:
                p = _PairProfile()
                p.first_seen = now_iso
                self._profiles[(process, domain)] = p
            if p.last_ts > 0:
                gap = max(0.0, timestamp - p.last_ts)
                # EWMA — recent behaviour weighted, but history not forgotten
                p.avg_gap = gap if p.avg_gap == 0 else (0.7 * p.avg_gap + 0.3 * gap)
            p.hits     += 1
            p.last_seen = now_iso
            p.last_ts   = timestamp
            p.timestamps.append(timestamp)
            if payload_size > 0:
                p.payloads.append(payload_size)
            p.dirty = True

    def is_learning(self) -> bool:
        """True during the initial learning window after first ever start."""
        if self._learning_started == 0.0:
            return True
        return (time.time() - self._learning_started) < self._learning_days * 86_400

    def learning_day(self) -> int:
        """1-based day of the learning period (clamped to the period length)."""
        if self._learning_started == 0.0:
            return 1
        day = int((time.time() - self._learning_started) // 86_400) + 1
        return min(day, int(self._learning_days))

    def get_baseline(self, process: str) -> dict:
        """Normal domains, frequencies, and timing for one process."""
        process = (process or "unknown").lower()
        domains:     dict[str, int]   = {}
        frequencies: dict[str, float] = {}
        timing:      dict[str, float] = {}
        with self._lock:
            for (proc, domain), p in self._profiles.items():
                if proc != process:
                    continue
                domains[domain] = p.hits
                timing[domain]  = round(p.avg_gap, 2)
                span = max(1.0, p.last_ts - self._learning_started)
                frequencies[domain] = round(p.hits / (span / 3600.0), 4)  # per hour
        return {
            "process":     process,
            "domains":     domains,
            "frequencies": frequencies,
            "timing":      timing,
        }

    def is_normal(self, process: str, domain: str,
                  timestamp: Optional[float] = None) -> bool:
        """True when this process has been seen talking to this domain before."""
        process = (process or "unknown").lower()
        domain  = domain.lower().rstrip(".")
        with self._lock:
            p = self._profiles.get((process, domain))
            if p is None:
                return False
            # A pair observed once a few seconds ago is not yet "normal";
            # require repeat observations, or observations spread over time.
            if p.hits >= 3:
                return True
            return (p.last_ts - self._first_ts(p)) > 600

    def _first_ts(self, p: _PairProfile) -> float:
        try:
            return datetime.fromisoformat(p.first_seen).timestamp()
        except ValueError:
            return p.last_ts

    def history(self, process: str, domain: str) -> Optional[_PairProfile]:
        """Raw in-memory profile (timestamps/payloads) for the anomaly engine."""
        process = (process or "unknown").lower()
        domain  = domain.lower().rstrip(".")
        with self._lock:
            return self._profiles.get((process, domain))

    def learned_avg_gap(self, process: str, domain: str) -> float:
        p = self.history(process, domain)
        return p.avg_gap if p else 0.0

    def coverage(self) -> int:
        """Number of distinct processes with at least one profiled domain."""
        with self._lock:
            return len({proc for proc, _ in self._profiles})

    def pair_count(self) -> int:
        with self._lock:
            return len(self._profiles)

    def reset(self) -> None:
        """Wipe all learned baselines and restart the learning clock."""
        conn = self._store.connection()
        try:
            conn.execute("DELETE FROM intel_baseline")
            self._learning_started = time.time()
            conn.execute(
                "INSERT OR REPLACE INTO intel_meta(key, value) VALUES(?, ?)",
                ("learning_started", str(self._learning_started)),
            )
            conn.commit()
        finally:
            conn.close()
        with self._lock:
            self._profiles.clear()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def flush(self) -> int:
        """Write dirty profiles to SQLite.  Returns rows written."""
        with self._lock:
            dirty = [
                (proc, domain, p.hits, p.first_seen, p.last_seen, p.last_ts, p.avg_gap)
                for (proc, domain), p in self._profiles.items() if p.dirty
            ]
            for (proc, domain), p in self._profiles.items():
                p.dirty = False
        if not dirty:
            return 0
        try:
            conn = self._store.connection()
            try:
                conn.executemany(
                    "INSERT INTO intel_baseline"
                    "(process, domain, hits, first_seen, last_seen, last_ts, avg_gap) "
                    "VALUES (?,?,?,?,?,?,?) "
                    "ON CONFLICT(process, domain) DO UPDATE SET "
                    "hits=excluded.hits, last_seen=excluded.last_seen, "
                    "last_ts=excluded.last_ts, avg_gap=excluded.avg_gap",
                    dirty,
                )
                conn.commit()
            finally:
                conn.close()
        except Exception:
            return 0    # flush failures must never take down the DNS path
        return len(dirty)

    def _flush_loop(self) -> None:
        # flush() guards its own DB work, but the snapshot it takes before that
        # (iterating _profiles under the lock) is outside that guard, so this
        # loop is not provably safe on its own. Guarded defensively: if this
        # thread dies, learned per-process baselines stop being persisted and
        # every restart silently begins from an empty baseline — the anomaly
        # layer would appear to work while never accumulating any history.
        while self._running:
            time.sleep(INTEL_FLUSH_INTERVAL)
            try:
                self.flush()
            except BaseException:             # noqa: BLE001
                pass    # a flush failure must never take down the DNS path
