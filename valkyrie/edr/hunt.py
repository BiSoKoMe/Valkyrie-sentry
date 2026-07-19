"""Threat hunting — structured queries over Valkyrie's event history.

A hunter never runs arbitrary SQL. Callers describe *what* they want with a
small, validated filter spec and the hunter compiles it to a parameterised
query. That keeps the feature safe to expose on the (localhost) web API while
still being expressive enough for real hunting: pivot by process, category,
decision, entropy/suspicion, and time window.

It also ships a set of **saved hunts** — canned queries for the questions a
defender actually asks ("what looks like a beacon?", "which process is the
noisiest talker?", "what did we block in the last hour?").
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional


_VALID_DECISIONS = {"allowed", "blocked", "flagged", "behavioral"}
_ORDER_COLUMNS = {"timestamp", "domain", "process_name", "decision", "suspicion"}


def _since_iso(hours: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


class ThreatHunter:
    """Read-only query surface over the events table + EDR detections."""

    def __init__(self, store, edr_store=None) -> None:
        self._store = store
        self._edr = edr_store

    @contextmanager
    def _connect(self):
        # Read-only queries, but the handle must still be closed: leaked
        # connections keep the DB file locked on Windows.
        conn = self._store.connection()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Ad-hoc structured query
    # ------------------------------------------------------------------

    def run(self, filters: Optional[dict] = None, limit: int = 200) -> dict:
        """Run a structured hunt.

        Recognised filter keys (all optional):
          domain_contains : substring match on domain (LIKE %x%)
          process         : exact process_name match
          decision        : one decision or a list of decisions
          category        : exact raw_category match
          since_hours     : only events newer than N hours
          min_suspicion   : suspicion >= this float
          order_by        : one of timestamp|domain|process_name|decision|suspicion
        """
        filters = filters or {}
        where, params = [], []

        dc = str(filters.get("domain_contains", "")).strip()
        if dc:
            where.append("domain LIKE ?"); params.append(f"%{dc}%")

        proc = str(filters.get("process", "")).strip()
        if proc:
            where.append("process_name = ?"); params.append(proc)

        decision = filters.get("decision")
        if isinstance(decision, str):
            decision = [decision]
        if isinstance(decision, (list, tuple)):
            valid = [d for d in decision if d in _VALID_DECISIONS]
            if valid:
                where.append("decision IN (%s)" % ",".join("?" * len(valid)))
                params.extend(valid)

        cat = str(filters.get("category", "")).strip()
        if cat:
            where.append("raw_category = ?"); params.append(cat)

        try:
            since_hours = float(filters.get("since_hours", 0) or 0)
        except (TypeError, ValueError):
            since_hours = 0.0
        if since_hours > 0:
            where.append("timestamp >= ?"); params.append(_since_iso(since_hours))

        try:
            min_susp = float(filters.get("min_suspicion", 0) or 0)
        except (TypeError, ValueError):
            min_susp = 0.0
        if min_susp > 0:
            where.append("suspicion >= ?"); params.append(min_susp)

        order = str(filters.get("order_by", "timestamp"))
        if order not in _ORDER_COLUMNS:
            order = "timestamp"

        limit = max(1, min(int(limit), 2000))
        sql = "SELECT timestamp,domain,decision,process_name,process_pid," \
              "reason,suspicion,raw_category FROM events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += f" ORDER BY {order} DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
        return {"count": len(rows), "rows": rows, "filters": filters}

    # ------------------------------------------------------------------
    # Facets — quick pivots for the console's summary strip
    # ------------------------------------------------------------------

    def facets(self, since_hours: float = 24.0) -> dict:
        since = _since_iso(since_hours)
        with self._connect() as conn:
            top_proc = [dict(r) for r in conn.execute(
                "SELECT process_name, COUNT(*) c FROM events WHERE timestamp>=? "
                "GROUP BY process_name ORDER BY c DESC LIMIT 8", (since,))]
            top_cat = [dict(r) for r in conn.execute(
                "SELECT raw_category, COUNT(*) c FROM events "
                "WHERE timestamp>=? AND raw_category<>'' "
                "GROUP BY raw_category ORDER BY c DESC LIMIT 8", (since,))]
            decisions = {r["decision"]: r["c"] for r in conn.execute(
                "SELECT decision, COUNT(*) c FROM events WHERE timestamp>=? "
                "GROUP BY decision", (since,))}
        return {
            "since_hours": since_hours,
            "top_processes": top_proc,
            "top_categories": top_cat,
            "decisions": decisions,
        }

    # ------------------------------------------------------------------
    # Saved hunts
    # ------------------------------------------------------------------

    SAVED = [
        {"id": "blocked_recent", "name": "Blocked in last hour",
         "description": "Everything blocked or sinkholed in the past 60 minutes."},
        {"id": "beacon_candidates", "name": "Beacon candidates",
         "description": "Domains a single process hits repeatedly — possible C2 heartbeat."},
        {"id": "high_suspicion", "name": "High-suspicion events",
         "description": "Events scored >= 0.7 by the behavioural/intelligence engines."},
        {"id": "noisy_processes", "name": "Noisiest talkers",
         "description": "Processes generating the most DNS traffic (data-exfil pivot)."},
        {"id": "rare_domains", "name": "Rare domains",
         "description": "Domains seen only once or twice — new/unusual infrastructure."},
        {"id": "flagged_anomalies", "name": "Baseline anomalies",
         "description": "Domains a process reached outside its learned baseline."},
    ]

    def saved_hunts(self) -> list[dict]:
        return list(self.SAVED)

    def run_saved(self, hunt_id: str, limit: int = 200) -> dict:
        limit = max(1, min(int(limit), 2000))
        fn = getattr(self, f"_hunt_{hunt_id}", None)
        if fn is None:
            return {"error": f"unknown hunt '{hunt_id}'", "rows": [], "count": 0}
        result = fn(limit)
        result.setdefault("hunt", hunt_id)
        result["count"] = len(result.get("rows", []))
        return result

    # -- individual saved hunts (all read-only, parameterised) ---------

    def _hunt_blocked_recent(self, limit):
        return self.run({"decision": ["blocked", "behavioral"], "since_hours": 1,
                         "order_by": "timestamp"}, limit)

    def _hunt_high_suspicion(self, limit):
        return self.run({"min_suspicion": 0.7, "order_by": "suspicion"}, limit)

    def _hunt_flagged_anomalies(self, limit):
        return self.run({"decision": ["flagged"], "category": "anomaly"}, limit)

    def _hunt_beacon_candidates(self, limit):
        # A domain a single process resolves many times is a beacon pivot.
        sql = ("SELECT domain, process_name, COUNT(*) hits, "
               "COUNT(DISTINCT substr(timestamp,1,16)) distinct_minutes "
               "FROM events WHERE timestamp>=? "
               "GROUP BY domain, process_name "
               "HAVING hits >= 6 AND distinct_minutes >= 3 "
               "ORDER BY hits DESC LIMIT ?")
        with self._connect() as conn:
            rows = [dict(r) for r in conn.execute(
                sql, (_since_iso(24), limit)).fetchall()]
        return {"rows": rows}

    def _hunt_noisy_processes(self, limit):
        sql = ("SELECT process_name, COUNT(*) queries, "
               "COUNT(DISTINCT domain) distinct_domains, "
               "SUM(CASE WHEN decision IN ('blocked','behavioral') THEN 1 ELSE 0 END) blocked "
               "FROM events WHERE timestamp>=? "
               "GROUP BY process_name ORDER BY queries DESC LIMIT ?")
        with self._connect() as conn:
            rows = [dict(r) for r in conn.execute(
                sql, (_since_iso(24), limit)).fetchall()]
        return {"rows": rows}

    def _hunt_rare_domains(self, limit):
        sql = ("SELECT domain, COUNT(*) hits, MIN(timestamp) first_seen, "
               "MAX(process_name) process_name FROM events "
               "WHERE timestamp>=? GROUP BY domain "
               "HAVING hits <= 2 ORDER BY first_seen DESC LIMIT ?")
        with self._connect() as conn:
            rows = [dict(r) for r in conn.execute(
                sql, (_since_iso(24), limit)).fetchall()]
        return {"rows": rows}
