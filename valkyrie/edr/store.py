"""EDR persistence — detections, incidents, and a response audit log.

Deliberately reuses the main :class:`valkyrie.store.Store`'s connection factory
so EDR state lives in the *same* SQLite database as DNS events. That gives two
things for free:

  * threat-hunting can JOIN detections against the raw ``events`` table, and
  * zero-log RAM mode keeps EDR data in RAM too (nothing new touches disk),
    because the connection URI is whatever the Store is using.

Writes here are low-volume (a detection per notable event, not per query) so a
simple lock + short-lived connection is plenty — no async writer needed.
"""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

from .schema import Detection, Incident, ResponseAction, severity_rank


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class EdrStore:
    """SQLite-backed store for detections, incidents and response audit rows."""

    def __init__(self, store) -> None:
        """Args:
            store: a :class:`valkyrie.store.Store` (or anything exposing
                   ``connection() -> sqlite3.Connection``). EDR tables are
                   created in that same database.
        """
        self._store = store
        self._lock = threading.RLock()

    @contextmanager
    def _connect(self):
        # Transaction-scoped AND closed: a bare sqlite3 connection context
        # manager never closes, and leaked handles hold the DB file lock on
        # Windows past Store.stop().
        conn = self._store.connection()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS edr_detections (
                    id           TEXT PRIMARY KEY,
                    timestamp    TEXT NOT NULL,
                    source       TEXT NOT NULL DEFAULT '',
                    severity     TEXT NOT NULL DEFAULT 'low',
                    category     TEXT NOT NULL DEFAULT '',
                    title        TEXT NOT NULL DEFAULT '',
                    entity       TEXT NOT NULL DEFAULT '',
                    process_name TEXT NOT NULL DEFAULT '',
                    process_pid  INTEGER NOT NULL DEFAULT 0,
                    technique    TEXT NOT NULL DEFAULT '',
                    details      TEXT NOT NULL DEFAULT '{}',
                    incident_id  TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_det_incident ON edr_detections(incident_id);
                CREATE INDEX IF NOT EXISTS idx_det_ts       ON edr_detections(timestamp);
                CREATE INDEX IF NOT EXISTS idx_det_cat      ON edr_detections(category);

                CREATE TABLE IF NOT EXISTS edr_incidents (
                    id              TEXT PRIMARY KEY,
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL,
                    title           TEXT NOT NULL DEFAULT '',
                    severity        TEXT NOT NULL DEFAULT 'low',
                    category        TEXT NOT NULL DEFAULT '',
                    entity          TEXT NOT NULL DEFAULT '',
                    process_name    TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'open',
                    technique       TEXT NOT NULL DEFAULT '',
                    assignee        TEXT NOT NULL DEFAULT '',
                    notes           TEXT NOT NULL DEFAULT '',
                    detection_count INTEGER NOT NULL DEFAULT 0,
                    timeline        TEXT NOT NULL DEFAULT '[]',
                    actions         TEXT NOT NULL DEFAULT '[]'
                );
                CREATE INDEX IF NOT EXISTS idx_inc_status ON edr_incidents(status);
                CREATE INDEX IF NOT EXISTS idx_inc_sev    ON edr_incidents(severity);
                CREATE INDEX IF NOT EXISTS idx_inc_upd    ON edr_incidents(updated_at);

                CREATE TABLE IF NOT EXISTS edr_responses (
                    id           TEXT PRIMARY KEY,
                    timestamp    TEXT NOT NULL,
                    action       TEXT NOT NULL DEFAULT '',
                    target       TEXT NOT NULL DEFAULT '',
                    status       TEXT NOT NULL DEFAULT '',
                    result       TEXT NOT NULL DEFAULT '',
                    operator     TEXT NOT NULL DEFAULT 'local',
                    dry_run      INTEGER NOT NULL DEFAULT 1,
                    incident_id  TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_resp_incident ON edr_responses(incident_id);
            """)
            conn.commit()
            # Migration for pre-existing DBs: `technique` was captured per-
            # Detection from day one (see edr_detections above) but never
            # copied onto the Incident it correlated into, so a real MITRE id
            # like T1562.001 was computed and then discarded before it ever
            # reached the incident list/API. Same add-column-if-missing
            # pattern as valkyrie/store.py's `events.url` migration.
            cols = {row[1] for row in
                    conn.execute("PRAGMA table_info(edr_incidents)").fetchall()}
            if "technique" not in cols:
                conn.execute(
                    "ALTER TABLE edr_incidents ADD COLUMN technique "
                    "TEXT NOT NULL DEFAULT ''")
                conn.commit()

    # ------------------------------------------------------------------
    # Detections
    # ------------------------------------------------------------------

    def add_detection(self, det: Detection) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO edr_detections"
                "(id,timestamp,source,severity,category,title,entity,"
                " process_name,process_pid,technique,details,incident_id)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (det.id, det.timestamp, det.source, det.severity, det.category,
                 det.title, det.entity, det.process_name, det.process_pid,
                 det.technique, json.dumps(det.details), det.incident_id),
            )
            conn.commit()

    def get_detection(self, det_id: str) -> Optional[Detection]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM edr_detections WHERE id=?", (det_id,)
            ).fetchone()
        return Detection.from_row(dict(row)) if row else None

    def list_detections(self, incident_id: Optional[str] = None,
                        since: Optional[str] = None,
                        limit: int = 200) -> list[Detection]:
        sql = "SELECT * FROM edr_detections"
        where, params = [], []
        if incident_id is not None:
            where.append("incident_id=?"); params.append(incident_id)
        if since is not None:
            where.append("timestamp>=?"); params.append(since)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(int(limit))
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [Detection.from_row(dict(r)) for r in rows]

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------

    def save_incident(self, inc: Incident) -> None:
        """Insert or fully overwrite an incident (timeline + actions inline)."""
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO edr_incidents"
                "(id,created_at,updated_at,title,severity,category,entity,"
                " process_name,status,technique,assignee,notes,detection_count,"
                " timeline,actions)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (inc.id, inc.created_at, inc.updated_at, inc.title, inc.severity,
                 inc.category, inc.entity, inc.process_name, inc.status,
                 inc.technique, inc.assignee, inc.notes, inc.detection_count,
                 json.dumps([t if isinstance(t, dict) else t.to_dict() for t in inc.timeline]),
                 json.dumps([a if isinstance(a, dict) else a.to_dict() for a in inc.actions])),
            )
            conn.commit()

    def get_incident(self, inc_id: str) -> Optional[Incident]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM edr_incidents WHERE id=?", (inc_id,)
            ).fetchone()
        return Incident.from_row(dict(row)) if row else None

    def list_incidents(self, status: Optional[str] = None,
                       severity: Optional[str] = None,
                       since: Optional[str] = None,
                       limit: int = 100) -> list[Incident]:
        sql = "SELECT * FROM edr_incidents"
        where, params = [], []
        if status:
            where.append("status=?"); params.append(status)
        if severity:
            where.append("severity=?"); params.append(severity)
        if since:
            where.append("updated_at>=?"); params.append(since)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(int(limit))
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [Incident.from_row(dict(r)) for r in rows]

    def find_open_incident(self, entity: str, category: str,
                           process_name: str, within_seconds: float) -> Optional[Incident]:
        """Return the most-recent still-open incident matching this
        (entity, category) or (process, category) within the correlation
        window, or None. Used by the engine to fold repeat detections into a
        single incident instead of spamming one per event."""
        cutoff = (datetime.now(timezone.utc)
                  - timedelta(seconds=within_seconds)).isoformat()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM edr_incidents "
                "WHERE status IN ('open','investigating') AND category=? "
                "AND updated_at>=? ORDER BY updated_at DESC LIMIT 20",
                (category, cutoff),
            ).fetchall()
        for r in rows:
            d = dict(r)
            if entity and d.get("entity") == entity:
                return Incident.from_row(d)
            if process_name and d.get("process_name") == process_name:
                return Incident.from_row(d)
        return None

    # ------------------------------------------------------------------
    # Response audit
    # ------------------------------------------------------------------

    def record_response(self, action: ResponseAction) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO edr_responses"
                "(id,timestamp,action,target,status,result,operator,dry_run,incident_id)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (action.id, action.timestamp, action.action, action.target,
                 action.status, action.result, action.operator,
                 1 if action.dry_run else 0, action.incident_id),
            )
            conn.commit()

    def list_responses(self, incident_id: Optional[str] = None,
                       limit: int = 100) -> list[dict]:
        sql = "SELECT * FROM edr_responses"
        params: list = []
        if incident_id is not None:
            sql += " WHERE incident_id=?"; params.append(incident_id)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(int(limit))
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["dry_run"] = bool(d.get("dry_run"))
            out.append(d)
        return out

    # ------------------------------------------------------------------
    # Aggregates
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        with self._connect() as conn:
            by_status = {s: 0 for s in ("open", "investigating", "contained",
                                        "resolved", "dismissed")}
            for row in conn.execute(
                "SELECT status, COUNT(*) c FROM edr_incidents GROUP BY status"):
                by_status[row["status"]] = row["c"]
            by_sev = {}
            for row in conn.execute(
                "SELECT severity, COUNT(*) c FROM edr_incidents "
                "WHERE status IN ('open','investigating') GROUP BY severity"):
                by_sev[row["severity"]] = row["c"]
            total_inc = conn.execute("SELECT COUNT(*) FROM edr_incidents").fetchone()[0]
            total_det = conn.execute("SELECT COUNT(*) FROM edr_detections").fetchone()[0]
            total_resp = conn.execute("SELECT COUNT(*) FROM edr_responses").fetchone()[0]
        open_active = by_status["open"] + by_status["investigating"]
        return {
            "incidents_total":  total_inc,
            "incidents_open":   open_active,
            "detections_total": total_det,
            "responses_total":  total_resp,
            "by_status":        by_status,
            "open_by_severity": by_sev,
        }
