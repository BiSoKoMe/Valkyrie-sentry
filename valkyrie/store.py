"""SQLite persistence layer.

Two tables:
  events    — every DNS decision, DoH alert, behavioral flag
  baselines — per-process domain/rate profiles built after BASELINE_WINDOW_HOURS

Writes are non-blocking: callers push to an in-process queue; a background
thread drains that queue and commits in batches.
"""

from __future__ import annotations

import json
import queue
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Optional

from .config import (
    BASELINE_ANOMALY_LABEL,
    BASELINE_WINDOW_HOURS,
    DB_PATH,
    STORE_FLUSH_EVERY,
    STORE_QUEUE_SIZE,
)
from .eventbus import EventBus


# ---------------------------------------------------------------------------
# Event dataclass
# ---------------------------------------------------------------------------

@dataclass
class DnsEvent:
    """One DNS resolution decision."""
    timestamp:    str
    domain:       str
    decision:     str           # "blocked" | "allowed" | "flagged" | "behavioral"
    process_name: str
    process_pid:  int
    process_path: str
    reason:       str
    suspicion:    float = 0.0
    raw_category: str  = ""     # e.g. "doh_bypass", "anomaly", "behavioral"
    url:          str  = ""     # full URL — populated for HTTPS/TLS-inspected events

    @classmethod
    def now(cls, **kwargs) -> "DnsEvent":
        return cls(timestamp=datetime.utcnow().isoformat(timespec="milliseconds"), **kwargs)


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------
# Internal message types for scan-cache operations on the writer queue
# ---------------------------------------------------------------------------

@dataclass
class _ScanCacheTouch:
    domain: str

@dataclass
class _ScanCacheSet:
    domain:     str
    decision:   str
    confidence: float
    reasons:    list
    category:   str


# ---------------------------------------------------------------------------

class Store:
    """Thread-safe SQLite event log with async write queue."""

    def __init__(self, db_path: Path = DB_PATH, ram_uri: str = "") -> None:
        """Args:
            db_path: on-disk SQLite path (ignored when ram_uri is set).
            ram_uri: if non-empty, use this URI for an in-memory database
                     (e.g. "file::memory:?cache=shared").  All writes and
                     reads target the RAM database — nothing touches disk.
        """
        self._db_path = db_path
        self._ram_uri = ram_uri          # non-empty → RAM mode
        # RAM mode: a shared-cache in-memory database only lives while at
        # least one connection is open. Short-lived sessions now close their
        # handles, so anchor the database with one connection held for the
        # Store's whole lifetime.
        self._ram_anchor: Optional[sqlite3.Connection] = (
            sqlite3.connect(ram_uri, uri=True, check_same_thread=False)
            if ram_uri else None
        )
        self._queue: queue.Queue = queue.Queue(maxsize=STORE_QUEUE_SIZE)
        # Rows the writer could not persist. A gap in the audit trail must be
        # countable, not invisible.
        self._write_errors = 0
        self._writer_thread = threading.Thread(
            target=self._writer_loop, daemon=True, name="store-writer"
        )
        self._lock = threading.Lock()   # for read queries from main thread
        # Live-event fan-out (EDR engine, web dashboard) runs over the shared
        # EventBus primitive instead of a hand-rolled subscriber list.
        self._bus = EventBus("store")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Initialise schema and start background writer."""
        self._init_schema()
        self._writer_thread.start()

    def stop(self) -> None:
        """Drain the queue and shut down cleanly."""
        self._queue.put(None)           # sentinel
        self._writer_thread.join(timeout=5)
        if self._ram_anchor is not None:
            try:
                self._ram_anchor.close()
            except Exception:
                pass
            self._ram_anchor = None

    # ------------------------------------------------------------------
    # Public write API (non-blocking)
    # ------------------------------------------------------------------

    def log(self, event: DnsEvent) -> None:
        """Enqueue an event for async write.  Never blocks the caller."""
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            pass    # drop under extreme load rather than block

    def subscribe(self, callback: Callable[[dict], None]) -> None:
        """Register callback(event_dict) called after each committed event."""
        self._bus.subscribe(callback)

    def unsubscribe(self, callback: Callable[[dict], None]) -> None:
        self._bus.unsubscribe(callback)

    # ------------------------------------------------------------------
    # Public read API (called from UI thread — uses its own connection)
    # ------------------------------------------------------------------

    def recent_events(self, limit: int = 200) -> list[dict]:
        with self._session() as conn:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict:
        """Return aggregate counters for the last 24 hours."""
        since = (datetime.utcnow() - timedelta(hours=24)).isoformat()
        with self._session() as conn:
            total   = conn.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ?", (since,)).fetchone()[0]
            blocked = conn.execute(
                "SELECT COUNT(*) FROM events WHERE timestamp >= ? AND decision IN ('blocked','behavioral')", (since,)
            ).fetchone()[0]
            flagged = conn.execute(
                "SELECT COUNT(*) FROM events WHERE timestamp >= ? AND decision = 'flagged'", (since,)
            ).fetchone()[0]
            top_domain = conn.execute(
                "SELECT domain, COUNT(*) c FROM events WHERE timestamp >= ? "
                "GROUP BY domain ORDER BY c DESC LIMIT 1", (since,)
            ).fetchone()
            top_proc = conn.execute(
                "SELECT process_name, COUNT(*) c FROM events WHERE timestamp >= ? "
                "GROUP BY process_name ORDER BY c DESC LIMIT 1", (since,)
            ).fetchone()
        return {
            "total_24h":   total,
            "blocked_24h": blocked,
            "flagged_24h": flagged,
            "allowed_24h": total - blocked - flagged,
            "top_domain":  top_domain[0] if top_domain else "—",
            "top_process": top_proc[0]   if top_proc   else "—",
        }

    def top_blocked_domains(self, limit: int = 5) -> list[dict]:
        """Return top blocked domains in the last 24 hours."""
        since = (datetime.utcnow() - timedelta(hours=24)).isoformat()
        with self._session() as conn:
            rows = conn.execute(
                "SELECT domain, COUNT(*) c FROM events "
                "WHERE timestamp >= ? AND decision IN ('blocked','behavioral') "
                "GROUP BY domain ORDER BY c DESC LIMIT ?",
                (since, limit),
            ).fetchall()
        return [{"domain": r[0], "count": r[1]} for r in rows]

    def scanner_decision_count(self) -> int:
        """Total number of scanner decisions made (sum of query_count in cache)."""
        with self._session() as conn:
            row = conn.execute("SELECT SUM(query_count) FROM scan_cache").fetchone()
        return row[0] or 0

    def cleaned_count(self) -> int:
        """Total number of page-clean events (HTML elements removed by tls_addon)."""
        with self._session() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM events WHERE raw_category = 'page_clean'"
            ).fetchone()
        return row[0] or 0

    # ------------------------------------------------------------------
    # Scan cache (site_scanner.py results)
    # ------------------------------------------------------------------

    def get_cached_scan(self, domain: str) -> Optional[dict]:
        """Return a cached ScanResult dict if one exists and is within TTL.

        Returns None on miss or when the entry is stale (> SCAN_CACHE_TTL_HOURS old).
        """
        from .config import SCAN_CACHE_TTL_HOURS
        cutoff = (datetime.utcnow() - timedelta(hours=SCAN_CACHE_TTL_HOURS)).isoformat()
        with self._session() as conn:
            row = conn.execute(
                "SELECT decision, confidence, reasons, category FROM scan_cache "
                "WHERE domain = ? AND last_seen >= ?",
                (domain, cutoff),
            ).fetchone()
        if row is None:
            return None
        # Touch last_seen + increment query_count in the writer thread — lightweight fire-and-forget
        try:
            self._queue.put_nowait(_ScanCacheTouch(domain))
        except Exception:
            pass
        return {
            "decision":   row[0],
            "confidence": row[1],
            "reasons":    json.loads(row[2]),
            "category":   row[3],
        }

    def set_cached_scan(self, domain: str, decision: str, confidence: float,
                         reasons: list, category: str) -> None:
        """Upsert a scan result into the cache (fire-and-forget via write queue)."""
        try:
            self._queue.put_nowait(_ScanCacheSet(domain, decision, confidence, reasons, category))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Baseline helpers
    # ------------------------------------------------------------------

    def should_build_baseline(self) -> bool:
        """True once we have >= BASELINE_WINDOW_HOURS of data."""
        with self._session() as conn:
            earliest = conn.execute("SELECT MIN(timestamp) FROM events").fetchone()[0]
        if not earliest:
            return False
        age = datetime.utcnow() - datetime.fromisoformat(earliest)
        return age >= timedelta(hours=BASELINE_WINDOW_HOURS)

    def build_baselines(self) -> None:
        """Compute per-process domain sets and avg hourly rates; store in DB."""
        cutoff = (datetime.utcnow() - timedelta(hours=BASELINE_WINDOW_HOURS)).isoformat()
        with self._session() as conn:
            rows = conn.execute(
                "SELECT process_name, domain FROM events WHERE timestamp >= ?", (cutoff,)
            ).fetchall()
            # Build domain set per process
            proc_domains: dict[str, set] = {}
            for r in rows:
                proc_domains.setdefault(r["process_name"], set()).add(r["domain"])

            # Hourly rates
            rate_rows = conn.execute(
                "SELECT process_name, COUNT(*) c FROM events "
                "WHERE timestamp >= ? GROUP BY process_name", (cutoff,)
            ).fetchall()

            conn.execute("DELETE FROM baselines")
            for r in rate_rows:
                pname = r["process_name"]
                domains_json = json.dumps(sorted(proc_domains.get(pname, [])))
                avg_rate = r["c"] / BASELINE_WINDOW_HOURS
                conn.execute(
                    "INSERT INTO baselines(process_name, domains_json, avg_hourly_rate, built_at) "
                    "VALUES (?,?,?,?)",
                    (pname, domains_json, avg_rate, datetime.utcnow().isoformat()),
                )
            conn.commit()

    def get_baseline(self, process_name: str) -> Optional[dict]:
        with self._session() as conn:
            row = conn.execute(
                "SELECT * FROM baselines WHERE process_name = ?", (process_name,)
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["domains"] = set(json.loads(d["domains_json"]))
        return d

    def is_anomaly(self, process_name: str, domain: str) -> bool:
        """Return True if domain is not in process baseline."""
        # Reverse-DNS / local-resolution names are not domains a process
        # "reached" — they are PTR lookups the OS does constantly, and treating
        # an unseen one as anomalous produced a wall of false positives on real
        # hardware. They can never be a baseline anomaly.
        from .popular_domains import is_infrastructure_domain
        if is_infrastructure_domain(domain):
            return False
        baseline = self.get_baseline(process_name)
        if baseline is None:
            return False    # no baseline yet — can't flag
        return domain not in baseline["domains"]

    # ------------------------------------------------------------------
    # Intelligence layer support
    # ------------------------------------------------------------------

    def connection(self) -> sqlite3.Connection:
        """Open a new connection to this Store's database (disk or RAM).

        Used by the intelligence layer so learned state lives in the same
        SQLite database as events — including zero-log RAM mode, where
        learned intelligence correctly stays in RAM only.  Callers own the
        returned connection and must close it themselves.
        """
        return self._connect()

    def is_writing(self) -> bool:
        """True while the background event writer thread is alive."""
        return self._writer_thread.is_alive()

    def write_errors(self) -> int:
        """Rows the writer could not persist (malformed data, SQLite errors).

        Non-zero means the audit trail has gaps. Surfaced rather than hidden:
        silently dropping events is exactly what this counter exists to make
        impossible to do unnoticed.
        """
        return self._write_errors

    def restart_writer(self) -> bool:
        """Bring the writer thread back after it has died.

        The self-healing watchdog registered `store_writer` with a health check
        and NO recovery action, so it could detect a dead writer and do nothing
        about it. This is that missing action. A Thread cannot be restarted, so
        a fresh one is created; the queue is untouched, so anything still
        pending is written by the new thread.
        """
        if self._writer_thread.is_alive():
            return False
        self._writer_thread = threading.Thread(
            target=self._writer_loop, daemon=True, name="store-writer")
        self._writer_thread.start()
        return True

    def db_size_bytes(self) -> int:
        """Size of the on-disk database in bytes (0 in RAM mode)."""
        if self._ram_uri:
            return 0
        try:
            return self._db_path.stat().st_size
        except OSError:
            return 0

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def is_ram_mode(self) -> bool:
        """True when this Store is operating entirely in RAM (zero-log mode)."""
        return bool(self._ram_uri)

    @contextmanager
    def _session(self):
        """A short-lived connection: transaction-scoped AND closed on exit.

        ``with sqlite3.connect(...)`` alone only commits/rolls back — it never
        closes, and each leaked handle keeps the DB file locked on Windows
        until GC. RAM-mode state is safe: the writer thread's long-lived
        connection keeps the shared in-memory database alive.
        """
        conn = self._connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        if self._ram_uri:
            conn = sqlite3.connect(self._ram_uri, uri=True, check_same_thread=False)
        else:
            conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._session() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp    TEXT    NOT NULL,
                    domain       TEXT    NOT NULL,
                    decision     TEXT    NOT NULL,
                    process_name TEXT    NOT NULL DEFAULT '',
                    process_pid  INTEGER NOT NULL DEFAULT 0,
                    process_path TEXT    NOT NULL DEFAULT '',
                    reason       TEXT    NOT NULL DEFAULT '',
                    suspicion    REAL    NOT NULL DEFAULT 0.0,
                    raw_category TEXT    NOT NULL DEFAULT '',
                    url          TEXT    NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_proc ON events(process_name);
                CREATE INDEX IF NOT EXISTS idx_events_dom  ON events(domain);

                CREATE TABLE IF NOT EXISTS baselines (
                    process_name    TEXT PRIMARY KEY,
                    domains_json    TEXT NOT NULL,
                    avg_hourly_rate REAL NOT NULL DEFAULT 0,
                    built_at        TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_cache (
                    domain       TEXT PRIMARY KEY,
                    decision     TEXT NOT NULL,
                    confidence   REAL NOT NULL,
                    reasons      TEXT NOT NULL,
                    category     TEXT NOT NULL,
                    first_seen   TEXT NOT NULL,
                    last_seen    TEXT NOT NULL,
                    query_count  INTEGER NOT NULL DEFAULT 1
                );
            """)
            conn.commit()
            # Migrations for pre-existing DBs
            cols = {row[1] for row in conn.execute("PRAGMA table_info(events)").fetchall()}
            if "url" not in cols:
                conn.execute("ALTER TABLE events ADD COLUMN url TEXT NOT NULL DEFAULT ''")
                conn.commit()

    def _writer_loop(self) -> None:
        """Background thread: drain queue, batch-commit to SQLite."""
        INSERT = (
            "INSERT INTO events"
            "(timestamp,domain,decision,process_name,process_pid,process_path,reason,suspicion,raw_category,url)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)"
        )
        if self._ram_uri:
            conn = sqlite3.connect(self._ram_uri, uri=True, check_same_thread=False)
        else:
            conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        pending: list[DnsEvent] = []

        def flush():
            if not pending:
                return
            rows = [
                (e.timestamp, e.domain, e.decision, e.process_name,
                 e.process_pid, e.process_path, e.reason, e.suspicion, e.raw_category, e.url)
                for e in pending
            ]
            evts = list(pending)
            try:
                conn.executemany(INSERT, rows)
                conn.commit()
            except Exception:
                # ONE malformed row must not cost the whole batch, and must not
                # kill this thread. executemany is all-or-nothing, so fall back
                # to row-at-a-time and drop only what genuinely cannot be
                # written. Verified failure mode: a single event carrying an
                # unbindable value (sqlite3.ProgrammingError) previously killed
                # the writer outright, and EVERY subsequent event — every DNS
                # decision, detection and response — was silently never
                # recorded for the rest of the run, while the product carried
                # on looking healthy.
                written = []
                for row, evt in zip(rows, evts):
                    try:
                        conn.execute(INSERT, row)
                        written.append(evt)
                    except Exception:
                        self._write_errors += 1
                try:
                    conn.commit()
                except Exception:
                    self._write_errors += 1
                    written = []
                evts = written
            pending.clear()

            # Fan out committed events to live subscribers over the bus. Skip the
            # per-event dict construction entirely when nobody is listening.
            if self._bus.has_subscribers():
                for e in evts:
                    # Ship the full UTC timestamp (explicitly zone-marked) so the
                    # dashboard renders it in the viewer's local timezone. Stored
                    # timestamps are naive UTC; a bare ISO string would be parsed
                    # as local time by the browser (the "times are N hours off"
                    # bug). The 'Z' suffix marks it UTC.
                    ts = e.timestamp
                    if ts and not (ts.endswith("Z") or "+" in ts[10:]):
                        ts = ts + "Z"
                    self._bus.publish({
                        "type": "event",
                        "event": {
                            "timestamp":    ts,
                            "domain":       e.domain,
                            "decision":     e.decision,
                            "process_name": e.process_name,
                            "reason":       e.reason,
                            "suspicion":    e.suspicion,
                            "category":     e.raw_category,
                            "url":          e.url,
                        },
                    })

        _now = datetime.utcnow

        while True:
            try:
                evt = self._queue.get(timeout=0.25)
                if evt is None:           # sentinel → shut down
                    flush()
                    break
                if isinstance(evt, _ScanCacheTouch):
                    now_s = _now().isoformat()
                    conn.execute(
                        "UPDATE scan_cache SET last_seen=?, query_count=query_count+1 WHERE domain=?",
                        (now_s, evt.domain),
                    )
                    conn.commit()
                elif isinstance(evt, _ScanCacheSet):
                    now_s = _now().isoformat()
                    reasons_json = json.dumps(evt.reasons)
                    conn.execute(
                        "INSERT INTO scan_cache(domain,decision,confidence,reasons,category,"
                        "first_seen,last_seen,query_count) VALUES(?,?,?,?,?,?,?,1) "
                        "ON CONFLICT(domain) DO UPDATE SET "
                        "decision=excluded.decision, confidence=excluded.confidence, "
                        "reasons=excluded.reasons, category=excluded.category, "
                        "last_seen=excluded.last_seen, query_count=query_count+1",
                        (evt.domain, evt.decision, evt.confidence, reasons_json,
                         evt.category, now_s, now_s),
                    )
                    conn.commit()
                else:
                    pending.append(evt)
                    if len(pending) >= STORE_FLUSH_EVERY:
                        flush()
            except queue.Empty:
                flush()
            except BaseException:
                # The writer must never die. Only queue.Empty was caught here,
                # so any SQLite error (locked database, disk full, a scan-cache
                # write that fails) escaped the loop, killed this thread AND
                # skipped conn.close() below. Every event after that point --
                # every DNS decision, detection and response -- was silently
                # never recorded, while the rest of the product carried on
                # looking perfectly healthy. For a security product, losing the
                # audit trail without saying so is close to the worst quiet
                # failure available.
                self._write_errors += 1

        conn.close()
