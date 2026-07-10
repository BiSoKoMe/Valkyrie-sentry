"""EdrEngine — the correlation core and the single facade the web API / CLI use.

The engine subscribes to Valkyrie's live DNS-decision stream (the same
``Store.subscribe`` feed the dashboard uses), runs the registered detection
plugins over every event, and **correlates** the resulting detections into a
much smaller set of incidents — each with a running timeline and a severity
that escalates as related detections arrive.

Correlation rule (deliberately simple and explainable): a detection joins the
most-recent still-open incident that shares its category AND either its entity
(domain/IP) or its process, within a time window. Otherwise it opens a new
incident. This collapses "the same beacon blocked 400 times" into one incident
instead of 400, while keeping unrelated activity separate.

Everything the engine produces (incidents, detections) is also pushed to its
own subscribers so the web layer can stream them live over the existing
WebSocket.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Callable, Optional

from .builtin import register_builtin
from .investigate import Investigator
from .hunt import ThreatHunter
from .plugins import PluginContext, PluginRegistry
from .response import ResponseManager, register_responders
from .schema import Detection, Incident, TimelineEntry, max_severity
from .store import EdrStore


class EdrEngine:
    """Detection → correlation → incident pipeline + response/hunt/investigate facade."""

    def __init__(self, store, *, intelligence=None, firewall=None, rules=None,
                 blocklist=None, plugin_dir=None,
                 correlation_window_seconds: float = 600.0) -> None:
        self._store = store
        self._edr = EdrStore(store)
        self._ctx = PluginContext(store=store, intelligence=intelligence,
                                  firewall=firewall, rules=rules, blocklist=blocklist)
        self._registry = PluginRegistry()
        self._window = correlation_window_seconds

        # Wire built-in plugins, then discover external ones (opt-in).
        register_builtin(self._registry)
        register_responders(self._registry)
        self._discovered: list[str] = []
        if plugin_dir:
            self._discovered = self._registry.discover(plugin_dir)

        self._responder = ResponseManager(self._registry, self._ctx, self._edr)
        self._hunter = ThreatHunter(store, self._edr)
        self._investigator = Investigator(self._edr)

        self._subscribers: list[Callable[[dict], None]] = []
        self._sub_lock = threading.Lock()
        self._corr_lock = threading.Lock()   # serialise correlation writes
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        self._edr.init_schema()
        self._store.subscribe(self._on_store_event)
        self._running = True

    def stop(self) -> None:
        self._running = False
        try:
            self._store.unsubscribe(self._on_store_event)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Live-event ingest (runs on the Store writer thread)
    # ------------------------------------------------------------------

    def _on_store_event(self, msg: dict) -> None:
        if not self._running or not isinstance(msg, dict) or msg.get("type") != "event":
            return
        event = msg.get("event") or {}
        try:
            detections = self._registry.run_detections(event, self._ctx)
        except Exception:
            return
        for det in detections:
            try:
                self._ingest_detection(det)
            except Exception:
                pass

    def _ingest_detection(self, det: Detection) -> None:
        with self._corr_lock:
            existing = self._edr.find_open_incident(
                entity=det.entity, category=det.category,
                process_name=det.process_name, within_seconds=self._window)
            if existing is None:
                inc = Incident(
                    title=det.title, severity=det.severity, category=det.category,
                    entity=det.entity, process_name=det.process_name,
                    detection_count=1,
                )
                inc.timeline.append(TimelineEntry(
                    kind="detection", summary=det.title,
                    data={"severity": det.severity, "entity": det.entity,
                          "source": det.source}).to_dict())
                det.incident_id = inc.id
                self._edr.add_detection(det)
                self._edr.save_incident(inc)
                self._notify({"type": "incident", "incident": _inc_wire(inc), "new": True})
            else:
                det.incident_id = existing.id
                self._edr.add_detection(det)
                existing.severity = max_severity(existing.severity, det.severity)
                existing.detection_count += 1
                existing.touch()
                existing.timeline.append(TimelineEntry(
                    kind="detection", summary=det.title,
                    data={"severity": det.severity, "entity": det.entity,
                          "source": det.source}).to_dict())
                # Keep timelines bounded.
                if len(existing.timeline) > 200:
                    existing.timeline = existing.timeline[-200:]
                self._edr.save_incident(existing)
                self._notify({"type": "incident", "incident": _inc_wire(existing),
                              "new": False})

    # ------------------------------------------------------------------
    # Subscriptions (for the web WebSocket)
    # ------------------------------------------------------------------

    def subscribe(self, cb: Callable[[dict], None]) -> None:
        with self._sub_lock:
            self._subscribers.append(cb)

    def unsubscribe(self, cb: Callable[[dict], None]) -> None:
        with self._sub_lock:
            try:
                self._subscribers.remove(cb)
            except ValueError:
                pass

    def _notify(self, payload: dict) -> None:
        with self._sub_lock:
            subs = list(self._subscribers)
        for cb in subs:
            try:
                cb(payload)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Facade — incidents
    # ------------------------------------------------------------------

    def list_incidents(self, status=None, severity=None, limit=100) -> list[dict]:
        return [_inc_wire(i) for i in
                self._edr.list_incidents(status=status, severity=severity, limit=limit)]

    def get_incident(self, inc_id: str) -> Optional[dict]:
        inc = self._edr.get_incident(inc_id)
        if inc is None:
            return None
        d = inc.to_dict()
        d["detections"] = [x.to_dict() for x in
                           self._edr.list_detections(incident_id=inc_id, limit=200)]
        d["responses"] = self._edr.list_responses(incident_id=inc_id, limit=100)
        return d

    def update_incident(self, inc_id: str, *, status=None, notes=None,
                        assignee=None, operator="local") -> Optional[dict]:
        inc = self._edr.get_incident(inc_id)
        if inc is None:
            return None
        changed = []
        if status and status in ("open", "investigating", "contained",
                                 "resolved", "dismissed"):
            inc.status = status; changed.append(f"status→{status}")
        if notes is not None:
            inc.notes = str(notes)[:4000]; changed.append("notes updated")
        if assignee is not None:
            inc.assignee = str(assignee)[:120]; changed.append(f"assignee→{assignee}")
        if changed:
            inc.touch()
            inc.timeline.append(TimelineEntry(
                kind="status", summary="; ".join(changed),
                data={"operator": operator}).to_dict())
            self._edr.save_incident(inc)
        return self.get_incident(inc_id)

    # ------------------------------------------------------------------
    # Facade — response / hunt / investigate / plugins / stats
    # ------------------------------------------------------------------

    def respond(self, action: str, target: str = "", *, dry_run: bool = True,
                operator: str = "local", incident_id: str = "") -> dict:
        act = self._responder.respond(action, target, dry_run=dry_run,
                                      operator=operator, incident_id=incident_id)
        # Attach the action to its incident's timeline for a full audit trail.
        if incident_id:
            inc = self._edr.get_incident(incident_id)
            if inc is not None:
                inc.actions.append(act.to_dict())
                inc.timeline.append(TimelineEntry(
                    kind="response",
                    summary=f"{action} → {act.status}"
                            + (" (dry-run)" if dry_run else ""),
                    data={"target": target, "result": act.result,
                          "operator": operator}).to_dict())
                inc.touch()
                self._edr.save_incident(inc)
        return act.to_dict()

    def available_actions(self) -> list[str]:
        return self._responder.available_actions()

    def hunt(self, filters=None, limit=200) -> dict:
        return self._hunter.run(filters, limit)

    def run_saved_hunt(self, hunt_id: str, limit=200) -> dict:
        return self._hunter.run_saved(hunt_id, limit)

    def saved_hunts(self) -> list[dict]:
        return self._hunter.saved_hunts()

    def hunt_facets(self, since_hours: float = 24.0) -> dict:
        return self._hunter.facets(since_hours)

    def investigate(self, inc_id: str, *, use_ai: bool = False,
                    operator: str = "local") -> Optional[dict]:
        inc = self._edr.get_incident(inc_id)
        if inc is None:
            return None
        report = self._investigator.investigate(inc, use_ai=use_ai, operator=operator)
        # Record that an investigation ran (auditable).
        inc.timeline.append(TimelineEntry(
            kind="note",
            summary=f"Investigation run ({report.get('analyst', 'offline')} analyst)",
            data={"operator": operator}).to_dict())
        inc.touch()
        self._edr.save_incident(inc)
        return report

    def plugins(self) -> dict:
        return {
            "plugins": self._registry.list_info(),
            "discovered": self._discovered,
            "errors": self._registry.errors(),
            "actions": self._responder.available_actions(),
        }

    def stats(self) -> dict:
        s = self._edr.stats()
        s["plugins"] = len(self._registry.all())
        s["discovered_plugins"] = len(self._discovered)
        return s


# ---------------------------------------------------------------------------
# Wire helpers
# ---------------------------------------------------------------------------

def _inc_wire(inc: Incident) -> dict:
    """A compact incident view for lists and live pushes (no full timeline)."""
    return {
        "id": inc.id,
        "title": inc.title,
        "severity": inc.severity,
        "category": inc.category,
        "entity": inc.entity,
        "process_name": inc.process_name,
        "status": inc.status,
        "detection_count": inc.detection_count,
        "created_at": inc.created_at,
        "updated_at": inc.updated_at,
    }
