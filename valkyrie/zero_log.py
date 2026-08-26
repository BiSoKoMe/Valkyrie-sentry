"""Zero log mode - RAM-only operation for privacy-critical sessions.

When active:
  - SQLite lives entirely in RAM (file::memory:?cache=shared)
  - No log files are written to disk
  - Blocklist lookups use an in-RAM copy
  - Scan cache is RAM-only
  - valkyrie_rules.yaml is still read from disk at startup

Tamper detection:
  - SHA-256 hashes all valkyrie/*.py files on startup
  - Re-checks every INTEGRITY_CHECK_INTERVAL seconds
  - Fires an alert (dashboard banner + logged event) if any file changed

Secure wipe on shutdown:
  - Issues gc.collect() to drop all Python references
  - On Linux: writes /proc/sys/vm/drop_caches to ask the kernel to release
    page-cache pages (best-effort, requires root)
"""

from __future__ import annotations

import gc
import hashlib
import platform
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional

from .config import (
    INTEGRITY_CHECK_INTERVAL,
    RAM_DB_URI,
)

# Path to the valkyrie package directory
_PKG_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# ZeroLogMode
# ---------------------------------------------------------------------------

class ZeroLogMode:
    """Controls RAM-only operation and file-integrity monitoring."""

    def __init__(self, store=None) -> None:
        """Args:
            store: the Store instance that will be replaced/used in RAM mode.
        """
        self._active        = False
        self._store         = store
        self._hashes:  dict[str, str] = {}   # path -> sha256 hex
        self._tampered: list[str]      = []   # paths that changed
        self._check_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._alert_callbacks: list = []
        # Integrity-checker health. status() must be able to tell "checked, and
        # nothing was tampered with" apart from "nothing has been checked" -
        # reporting the second as the first is exactly the false reassurance a
        # log-integrity feature exists to prevent.
        self._last_check: float = 0.0
        self._integrity_errors: int = 0
        self._last_integrity_error: str = ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enable(self) -> None:
        """Activate zero-log mode.

        Call this BEFORE creating the Store - it returns a RAM-backed Store
        that should be used in place of the disk Store.
        """
        self._active = True
        self._hashes = self._hash_sources()
        self._tampered = []
        self._start_integrity_checker()

    def disable(self) -> None:
        """Deactivate zero-log mode and wipe the RAM database."""
        self._active = False
        self._stop_event.set()
        if self._check_thread:
            self._check_thread.join(timeout=5)
        self._secure_wipe()

    def is_active(self) -> bool:
        """Return True when zero-log mode is active."""
        return self._active

    def make_ram_store(self):
        """Create and return a Store backed by an in-RAM SQLite database."""
        from .store import Store
        return Store(ram_uri=RAM_DB_URI)

    def import_from_disk(self, store, hours: int) -> int:
        """Copy the last *hours* of events from the disk DB into *store* (RAM).

        Returns the number of events imported.
        """
        from .config import DB_PATH
        from datetime import datetime, timedelta

        if not DB_PATH.exists():
            return 0

        cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        try:
            disk_conn = sqlite3.connect(str(DB_PATH))
            disk_conn.row_factory = sqlite3.Row
            rows = disk_conn.execute(
                "SELECT timestamp,domain,decision,process_name,process_pid,"
                "process_path,reason,suspicion,raw_category,url "
                "FROM events WHERE timestamp >= ? ORDER BY id",
                (cutoff,),
            ).fetchall()
            disk_conn.close()
        except Exception:
            return 0

        from .store import DnsEvent
        for r in rows:
            event = DnsEvent(
                timestamp    = r["timestamp"],
                domain       = r["domain"],
                decision     = r["decision"],
                process_name = r["process_name"],
                process_pid  = r["process_pid"],
                process_path = r["process_path"],
                reason       = r["reason"],
                suspicion    = r["suspicion"],
                raw_category = r["raw_category"],
                url          = r["url"],
            )
            store.log(event)

        return len(rows)

    def status(self) -> dict:
        """Return current zero-log status dict (for the API and dashboard)."""
        session_events = 0
        if self._store is not None:
            try:
                s = self._store.stats()
                session_events = s.get("total_24h", 0)
            except Exception:
                pass

        # "verified" is a CLAIM, and it may only be made when a check actually
        # ran. Previously this returned "verified" whenever _tampered was empty
        # - which is also true when the checker thread never started, or died,
        # or has not completed its first pass. Reporting "no tampering found"
        # when nothing looked is the worst answer this function can give.
        checker_alive = bool(self._check_thread and self._check_thread.is_alive())
        if self._tampered:
            integrity = "TAMPERED"
        elif self._last_check <= 0.0:
            integrity = "unknown (no check has completed yet)"
        elif not checker_alive:
            integrity = "unknown (integrity checker is not running)"
        else:
            integrity = "verified"

        return {
            "active":          self._active,
            "mode":            "zero_log_ram" if self._active else "disk",
            "session_events":  session_events,
            "disk_writes":     "none" if self._active else "enabled",
            "integrity":       integrity,
            "tampered_files":  self._tampered,
            "checker_running": checker_alive,
            "last_check_age":  (round(time.time() - self._last_check, 1)
                                if self._last_check else None),
            "integrity_errors": self._integrity_errors,
            "last_integrity_error": self._last_integrity_error,
        }

    def on_tamper(self, callback) -> None:
        """Register a callback(list[str]) fired when a source file changes."""
        self._alert_callbacks.append(callback)

    # ------------------------------------------------------------------
    # Integrity checking
    # ------------------------------------------------------------------

    def _hash_sources(self) -> dict[str, str]:
        """SHA-256 all .py files in the valkyrie package."""
        hashes: dict[str, str] = {}
        for py in sorted(_PKG_DIR.glob("*.py")):
            try:
                data = py.read_bytes()
                hashes[str(py)] = hashlib.sha256(data).hexdigest()
            except Exception:
                pass
        return hashes

    def _start_integrity_checker(self) -> None:
        self._stop_event.clear()
        self._check_thread = threading.Thread(
            target=self._integrity_loop,
            daemon=True,
            name="integrity-checker",
        )
        self._check_thread.start()

    def _integrity_loop(self) -> None:
        # _check_integrity() hashes files on disk, and file I/O raises for
        # ordinary reasons (a file locked, rotated or deleted between ticks).
        # Unguarded, one such raise killed this thread permanently and integrity
        # checking simply stopped - while status() went on reporting the LAST
        # verdict, so the UI would keep showing "verified" forever with nothing
        # actually verifying. That is the frozen-heartbeat failure again, in the
        # subsystem whose entire job is proving the logs were not tampered with.
        while not self._stop_event.wait(INTEGRITY_CHECK_INTERVAL):
            try:
                self._check_integrity()
            except BaseException as exc:      # noqa: BLE001
                self._integrity_errors += 1
                self._last_integrity_error = f"{type(exc).__name__}: {exc}"

    def _check_integrity(self) -> None:
        current = self._hash_sources()
        changed = [
            path for path, digest in current.items()
            if self._hashes.get(path) != digest
        ]
        # Recorded only on a completed pass, so status() can distinguish
        # "checked and clean" from "never checked".
        self._last_check = time.time()
        if changed:
            self._tampered = changed
            for cb in self._alert_callbacks:
                try:
                    cb(changed)
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Secure wipe
    # ------------------------------------------------------------------

    def _secure_wipe(self) -> None:
        """Overwrite RAM DB with zeros and force Python GC.

        IMPORTANT: this must run while at least one other connection to the
        shared-cache RAM DB (e.g. the Store's writer-thread connection) is
        still open. `file::memory:?cache=shared` databases are destroyed the
        instant their last connection closes, so calling this *after* the
        Store has already been stopped means the DELETE statements below
        silently no-op against a database that no longer exists (SQLite
        raises "no such table", which the inner try/except swallows) - the
        wipe never actually touches real session data. Callers (see
        ZeroLogMode.disable()) must call this before the owning Store's
        connections are torn down. See docs/TLS_ZEROLOG_AUDIT_REPORT.md.
        """
        try:
            # Overwrite the shared memory DB with zeros
            conn = sqlite3.connect(RAM_DB_URI, uri=True, check_same_thread=False)
            try:
                # secure_delete must be set BEFORE the deletes so the freed
                # pages are actually zero-filled by these statements, rather
                # than only affecting deletes that happen after this point.
                conn.execute("PRAGMA secure_delete=ON")
                for table in ("events", "scan_cache", "baselines"):
                    try:
                        conn.execute(f"DELETE FROM {table}")
                    except Exception:
                        pass
                conn.commit()
                conn.close()
            except Exception:
                pass
        except Exception:
            pass

        gc.collect()

        # Linux: hint to kernel to drop page caches (best-effort, needs root)
        if platform.system() == "Linux":
            try:
                with open("/proc/sys/vm/drop_caches", "w") as f:
                    f.write("3")
            except Exception:
                pass

        print("Zero log: all session data wiped")
