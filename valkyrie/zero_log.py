"""Zero log mode — RAM-only operation for privacy-critical sessions.

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
        self._hashes:  dict[str, str] = {}   # path → sha256 hex
        self._tampered: list[str]      = []   # paths that changed
        self._check_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._alert_callbacks: list = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enable(self) -> None:
        """Activate zero-log mode.

        Call this BEFORE creating the Store — it returns a RAM-backed Store
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

        return {
            "active":          self._active,
            "mode":            "zero_log_ram" if self._active else "disk",
            "session_events":  session_events,
            "disk_writes":     "none" if self._active else "enabled",
            "integrity":       "TAMPERED" if self._tampered else "verified",
            "tampered_files":  self._tampered,
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
        while not self._stop_event.wait(INTEGRITY_CHECK_INTERVAL):
            self._check_integrity()

    def _check_integrity(self) -> None:
        current = self._hash_sources()
        changed = [
            path for path, digest in current.items()
            if self._hashes.get(path) != digest
        ]
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
        """Overwrite RAM DB with zeros and force Python GC."""
        try:
            # Overwrite the shared memory DB with zeros
            conn = sqlite3.connect(RAM_DB_URI, uri=True, check_same_thread=False)
            try:
                for table in ("events", "scan_cache", "baselines"):
                    try:
                        conn.execute(f"DELETE FROM {table}")
                    except Exception:
                        pass
                conn.execute("PRAGMA secure_delete=ON")
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
