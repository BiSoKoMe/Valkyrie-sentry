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
import time
from datetime import datetime, timezone
from typing import Callable, Optional

from ..eventbus import EventBus
from .builtin import register_builtin
from .investigate import Investigator
from .hunt import ThreatHunter
from .killchain import KillChainCorrelator
from ..behavioral_sequences import SequenceEngine
from .plugins import PluginContext, PluginRegistry
from .response import ResponseManager, register_responders
from .schema import Detection, Incident, TimelineEntry, max_severity, severity_rank

# Map process-telemetry labels onto rough MITRE ATT&CK techniques for display.
_TELEMETRY_TECHNIQUE = {
    "lolbin":             "T1059 — Command & Scripting Interpreter",
    "office_child_shell": "T1566 — Phishing (macro) → shell",
    "suspicious_path":    "T1204 — User Execution",
    # Command-line heuristics (process collector)
    "encoded_powershell": "T1027 — Obfuscated/Encoded Command",
    "download_cradle":    "T1105 — Ingress Tool Transfer",
    "hidden_window":      "T1564 — Hide Artifacts",
    # Persistence / ASEP (persistence collector)
    "persistence_run_key":        "T1547.001 — Registry Run Keys / Startup Folder",
    "persistence_service":        "T1543.003 — Create or Modify System Process: Windows Service",
    "persistence_scheduled_task": "T1053.005 — Scheduled Task",
    "persistence_startup_folder": "T1547.001 — Registry Run Keys / Startup Folder",
    # PowerShell script-block sensor (ETW-backed, etw.powershell)
    "encoded_command":     "T1027 — Obfuscated/Encoded Command",
    "base64_decode":       "T1140 — Deobfuscate/Decode Files or Information",
    "download":            "T1105 — Ingress Tool Transfer",
    "dynamic_exec":        "T1059.001 — PowerShell (IEX)",
    "amsi_bypass":         "T1562.001 — Impair Defenses: Disable/Modify Tools",
    "defender_tamper":     "T1562.001 — Impair Defenses: Disable/Modify Tools",
    "credential_access":   "T1003 — OS Credential Dumping",
    "persistence_task":    "T1053.005 — Scheduled Task",
    "injection_primitive": "T1055 — Process Injection",
    "stealth_flags":       "T1059.001 — PowerShell",
    "obfuscation":         "T1027 — Obfuscated/Encoded Command",
    # AMSI conviction (valkyrie/amsi.py) — an external engine's verdict, not a
    # Valkyrie heuristic. The sensor sets an exact technique when it knows one;
    # this is the fallback for content convicted with no other tell.
    "amsi_detected":       "T1059 — Command & Scripting Interpreter (malicious content)",
    # WMI-Activity sensor (etw.wmi)
    "persistence_wmi":      "T1546.003 — WMI Event Subscription",
    "wmi_script_consumer":  "T1546.003 — WMI Event Subscription",
    "wmi_command_consumer": "T1546.003 — WMI Event Subscription",
    "wmi_timer_trigger":    "T1546.003 — WMI Event Subscription",
    "wmi_remote":           "T1047 — Windows Management Instrumentation",
    # Sysmon sensor (etw.sysmon)
    "unsigned_module":         "T1574 — Hijack Execution Flow",
    "remote_thread_injection": "T1055 — Process Injection",
    "lsass_access":            "T1003.001 — LSASS Memory",
    "process_tampering":       "T1055.012 — Process Hollowing",
}
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

        # Incident fan-out to the web dashboard runs over the shared EventBus.
        self._bus = EventBus("edr")
        self._corr_lock = threading.Lock()   # serialise correlation writes
        # Multi-stage kill-chain correlator (same window as base correlation).
        self._killchain = KillChainCorrelator(window_seconds=correlation_window_seconds)
        # ESP-style named behavioural-sequence IOAs (specific attack patterns).
        self._sequences = SequenceEngine()
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

    def ingest_telemetry(self, event) -> Optional[str]:
        """Ingest a normalized TelemetryEvent (dict or object) from a non-DNS
        collector — e.g. the process collector.

        Flagged / medium-and-above observations become Detections and flow
        through the same correlation → incident pipeline as DNS detections; plain
        low/info observations are visibility only and are not escalated (avoids
        turning every process start into an incident). Returns the incident id
        when a detection was created, else None.
        """
        if not self._running:
            return None
        d = event.to_dict() if hasattr(event, "to_dict") else dict(event)
        severity = str(d.get("severity", "info"))
        action = str(d.get("action", ""))
        if severity_rank(severity) < severity_rank("medium") and action != "flagged":
            return None

        labels = list(d.get("labels") or [])
        # A behavioral rule (behavioral_rules.py) carries its exact ATT&CK id on
        # the event; prefer it over inferring one from a label. Falls back to the
        # label→technique map for events from other collectors.
        technique = str((d.get("fields") or {}).get("technique") or "")
        if not technique:
            for lab in labels:
                if lab in _TELEMETRY_TECHNIQUE:
                    technique = _TELEMETRY_TECHNIQUE[lab]
                    break
        entity = str(d.get("actor_path") or d.get("actor_name") or "")
        title = str(d.get("reason") or
                    f"{d.get('activity','')} {d.get('actor_name','')}".strip())
        # Process lineage, when the collector captured it (process_telemetry
        # fields ppid/parent_name/parent_chain; sysmon parent_pid/parent_image).
        # Carried in details so kill-chain correlation can link a child process
        # to its parent's chain — no DB-schema change (details is JSON).
        fields = d.get("fields") or {}
        ppid = int(fields.get("ppid") or fields.get("parent_pid") or 0)
        parent_name = str(fields.get("parent_name") or fields.get("parent_image") or "")
        det = Detection(
            source=str(d.get("source", "collector")),
            severity=severity,
            category=str(d.get("category", "") or "process"),
            title=title,
            entity=entity,
            process_name=str(d.get("actor_name", "")),
            process_pid=int(d.get("actor_pid", 0) or 0),
            technique=technique,
            details={"labels": labels, "target": d.get("target", {}),
                     "activity": d.get("activity", ""),
                     "ppid": ppid, "parent_name": parent_name,
                     "parent_chain": list(fields.get("parent_chain") or [])},
        )
        # _ingest_detection takes the correlation lock itself — do not wrap.
        self._ingest_detection(det)
        return det.incident_id

    def report_detection(self, det: Detection) -> Optional[str]:
        """Public entry for sensors that produce a fully-formed Detection (e.g.
        the ransomware shield) rather than raw telemetry. Flows through the same
        correlation → incident → timeline → WebSocket pipeline. Returns the
        incident id, or None if the engine isn't running."""
        if not self._running:
            return None
        self._ingest_detection(det)
        return det.incident_id

    def _ingest_detection(self, det: Detection) -> None:
        with self._corr_lock:
            existing = self._edr.find_open_incident(
                entity=det.entity, category=det.category,
                process_name=det.process_name, within_seconds=self._window)
            if existing is None:
                inc = Incident(
                    title=det.title, severity=det.severity, category=det.category,
                    entity=det.entity, process_name=det.process_name,
                    process_pid=det.process_pid, detection_count=1,
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

        # Correlation runs AFTER the correlation lock is released — it may
        # re-enter _ingest_detection to raise a derived incident, and _corr_lock
        # is a plain Lock (re-acquiring would deadlock). Derived detections carry
        # category "attack_chain"/"attack_sequence" and are never fed back into a
        # correlator, so there is no unbounded recursion.
        if det.category not in ("attack_chain", "attack_sequence"):
            self._correlate_chain(det)
            self._correlate_sequence(det)

    def _correlate_chain(self, det: Detection) -> None:
        """Feed a real detection to the kill-chain correlator; if the same
        actor now spans multiple ATT&CK tactics, raise ONE escalating
        'attack_chain' incident that grows as new stages appear."""
        try:
            chain = self._killchain.observe(
                actor=det.process_name, technique=det.technique,
                title=det.title, ts=time.monotonic(),
                pid=det.process_pid,
                ppid=int((det.details or {}).get("ppid") or 0))
        except Exception:
            return
        if not chain:
            return
        actor = chain["actor"]
        n = chain["distinct_tactics"]
        procs = chain.get("processes", 1)
        # Correlate the chain incident on the ORIGIN process so a growing
        # multi-process chain folds into one incident rather than reopening
        # per child process.
        origin = (chain.get("actors") or [actor])[0]
        span = f" across {procs} linked processes" if procs > 1 else ""
        chain_det = Detection(
            source="edr.killchain",
            severity=chain["severity"],
            category="attack_chain",
            title=f"Multi-stage attack on {origin}: {n} ATT&CK tactics{span}",
            entity=origin,
            process_name=origin,
            process_pid=det.process_pid,
            technique="; ".join(chain["techniques"]),
            details={"chain": chain, "reason": chain["explanation"],
                     "confidence": chain["score"]},
        )
        self._ingest_detection(chain_det)

    def _correlate_sequence(self, det: Detection) -> None:
        """Feed a detection to the ESP sequence engine; if it completes a named
        behavioural sequence (e.g. injection→credential-access) on one lineage,
        raise ONE high-confidence 'attack_sequence' incident naming the pattern.
        This is the specific-pattern complement to the generic kill-chain."""
        try:
            details = det.details or {}
            seq = self._sequences.observe(
                actor=det.process_name, technique=det.technique,
                labels=details.get("labels") or [],
                activity=details.get("activity") or "",
                ts=time.monotonic(),
                pid=det.process_pid,
                ppid=int(details.get("ppid") or 0))
        except Exception:
            return
        if not seq:
            return
        origin = seq.get("actor") or det.process_name
        seq_det = Detection(
            source="edr.sequence",
            severity=seq["severity"],
            category="attack_sequence",
            title=f"{seq['name']} on {origin}",
            entity=origin,
            process_name=origin,
            process_pid=det.process_pid,
            technique=seq["technique"],
            details={"sequence": seq, "reason": seq["explanation"],
                     "confidence": seq["score"], "labels": ["attack_sequence"]},
        )
        self._ingest_detection(seq_det)

    # ------------------------------------------------------------------
    # Subscriptions (for the web WebSocket)
    # ------------------------------------------------------------------

    def subscribe(self, cb: Callable[[dict], None]) -> None:
        self._bus.subscribe(cb)

    def unsubscribe(self, cb: Callable[[dict], None]) -> None:
        self._bus.unsubscribe(cb)

    def _notify(self, payload: dict) -> None:
        self._bus.publish(payload)

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
            "loaded": self._registry.loaded_plugins(),
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
        "process_pid": inc.process_pid,
        "status": inc.status,
        "detection_count": inc.detection_count,
        "created_at": inc.created_at,
        "updated_at": inc.updated_at,
    }
