"""Server-side device registry for the fleet control plane.

A small SQLite table of enrolled devices and their last reported status.
Security-relevant invariant: this store NEVER holds a usable device token —
only sha256(token). A dump of fleet.db does not let an attacker impersonate a
device.

Thread-safe: a single connection guarded by a lock (write volume is tiny —
one row-update per device per heartbeat interval).
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional


_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    device_id     TEXT PRIMARY KEY,
    token_hash    TEXT NOT NULL,
    label         TEXT NOT NULL,
    org           TEXT NOT NULL DEFAULT '',
    platform      TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    enrolled_at   REAL NOT NULL,
    last_seen     REAL NOT NULL DEFAULT 0,
    last_status   TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS policies (
    org           TEXT PRIMARY KEY,
    bundle        TEXT NOT NULL,
    updated_at    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS commands (
    command_id    TEXT PRIMARY KEY,
    org           TEXT NOT NULL DEFAULT '',
    device_id     TEXT NOT NULL DEFAULT '',   -- '' = all devices in the org
    bundle        TEXT NOT NULL,              -- signed-command JSON
    created_at    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS command_acks (
    command_id    TEXT NOT NULL,
    device_id     TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT '',
    result        TEXT NOT NULL DEFAULT '',
    acked_at      REAL NOT NULL,
    PRIMARY KEY (command_id, device_id)
);
"""


class FleetStore:
    def __init__(self, db_path: Path) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        """Add columns introduced after the first release to pre-existing DBs.
        `CREATE TABLE IF NOT EXISTS` won't add a column to an older table, so
        an `org`-less registry from an earlier version is upgraded here."""
        cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(devices)")}
        if "org" not in cols:
            self._conn.execute("ALTER TABLE devices ADD COLUMN org TEXT NOT NULL DEFAULT ''")

    # ------------------------------------------------------------------

    def add_device(self, device_id: str, token_hash: str, label: str,
                   platform: str, agent_version: str, org: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO devices "
                "(device_id, token_hash, label, org, platform, agent_version, "
                " enrolled_at, last_seen, last_status) "
                "VALUES (?,?,?,?,?,?,?,0,'{}')",
                (device_id, token_hash, label, org, platform, agent_version, time.time()),
            )
            self._conn.commit()

    def org_for(self, device_id: str) -> Optional[str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT org FROM devices WHERE device_id=?", (device_id,)
            ).fetchone()
        return row["org"] if row else None

    def token_hash_for(self, device_id: str) -> Optional[str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT token_hash FROM devices WHERE device_id=?", (device_id,)
            ).fetchone()
        return row["token_hash"] if row else None

    def record_status(self, device_id: str, status: dict, agent_version: str = "") -> bool:
        """Update a device's last_seen + last_status. Returns False if unknown."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE devices SET last_seen=?, last_status=?, agent_version=? "
                "WHERE device_id=?",
                (time.time(), json.dumps(status)[:20000],
                 agent_version or "", device_id),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def get_device(self, device_id: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM devices WHERE device_id=?", (device_id,)
            ).fetchone()
        return self._row_to_public(row) if row else None

    def list_devices(self, org: Optional[str] = None) -> list[dict]:
        with self._lock:
            if org is None:
                rows = self._conn.execute(
                    "SELECT * FROM devices ORDER BY label").fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM devices WHERE org=? ORDER BY label", (org,)).fetchall()
        return [self._row_to_public(r) for r in rows]

    # ------------------------------------------------------------------
    # Policy persistence (per org)
    # ------------------------------------------------------------------

    def set_policy(self, org: str, bundle_json: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO policies (org, bundle, updated_at) VALUES (?,?,?)",
                (org, bundle_json, time.time()),
            )
            self._conn.commit()

    def get_policy(self, org: str) -> Optional[str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT bundle FROM policies WHERE org=?", (org,)).fetchone()
        return row["bundle"] if row else None

    # ------------------------------------------------------------------
    # Remote-response commands (per org, optionally per device)
    # ------------------------------------------------------------------

    def queue_command(self, command_id: str, org: str, device_id: str,
                      bundle_json: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO commands "
                "(command_id, org, device_id, bundle, created_at) VALUES (?,?,?,?,?)",
                (command_id, org or "", device_id or "", bundle_json, time.time()),
            )
            self._conn.commit()

    def commands_for_device(self, org: str, device_id: str) -> list[str]:
        """Return pending signed-command bundles this device hasn't acked yet.

        A command applies if it targets this device explicitly OR the whole org
        (device_id ''), and this device has no ack row for it — that's the
        at-most-once + anti-replay guarantee.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT bundle FROM commands WHERE org=? "
                "AND (device_id='' OR device_id=?) "
                "AND command_id NOT IN "
                "  (SELECT command_id FROM command_acks WHERE device_id=?) "
                "ORDER BY created_at",
                (org or "", device_id, device_id),
            ).fetchall()
        return [r["bundle"] for r in rows]

    def ack_command(self, command_id: str, device_id: str,
                    status: str, result: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO command_acks "
                "(command_id, device_id, status, result, acked_at) VALUES (?,?,?,?,?)",
                (command_id, device_id, status[:32], result[:2000], time.time()),
            )
            self._conn.commit()

    def command_acks(self, command_id: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT device_id, status, result, acked_at FROM command_acks "
                "WHERE command_id=? ORDER BY acked_at", (command_id,)).fetchall()
        return [dict(r) for r in rows]

    def remove_device(self, device_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM devices WHERE device_id=?", (device_id,)
            )
            self._conn.commit()
            return cur.rowcount > 0

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_public(row: sqlite3.Row) -> dict:
        """Row -> API dict. token_hash is intentionally NEVER exposed."""
        try:
            status = json.loads(row["last_status"])
        except (ValueError, TypeError):
            status = {}
        return {
            "device_id":     row["device_id"],
            "label":         row["label"],
            "org":           row["org"],
            "platform":      row["platform"],
            "agent_version": row["agent_version"],
            "enrolled_at":   row["enrolled_at"],
            "last_seen":     row["last_seen"],
            "status":        status,
        }
