"""Normalized telemetry events — one envelope for every signal source.

Today Valkyrie's detection layer consumes a DNS-decision dict shaped by the
Store. Phase 3 adds more signal sources (process starts, network connections,
and — later — kernel/ETW/eBPF telemetry). Rather than teach the correlator a new
dict shape per source, every source normalizes into one small, explicit
``TelemetryEvent`` (an OCSF-inspired lingua franca kept deliberately minimal).

Design goals:
  * **Source-agnostic.** DNS, process, and network events share one structure so
    the EDR correlator and dashboard reason over them uniformly.
  * **Lossless-enough.** Common fields are first-class (actor process, target,
    action, severity); anything source-specific rides in ``fields``.
  * **Stable + serializable.** ``to_dict``/``from_dict`` round-trip cleanly for
    the event bus, the WebSocket, and on-disk storage.

Stdlib-only. No behavior change to existing code — this is the schema new
collectors emit and that adapters map the current DNS stream into.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Controlled vocabularies (small, explicit)
# ---------------------------------------------------------------------------

# category — what kind of activity
CAT_DNS     = "dns"
CAT_PROCESS = "process"
CAT_NETWORK = "network"
CATEGORIES  = frozenset({CAT_DNS, CAT_PROCESS, CAT_NETWORK})

# action — the disposition Valkyrie applied / observed
ACT_ALLOWED  = "allowed"
ACT_BLOCKED  = "blocked"
ACT_FLAGGED  = "flagged"
ACT_OBSERVED = "observed"
ACTIONS      = frozenset({ACT_ALLOWED, ACT_BLOCKED, ACT_FLAGGED, ACT_OBSERVED})

# severity — ordered low→high
SEV_INFO     = "info"
SEV_LOW      = "low"
SEV_MEDIUM   = "medium"
SEV_HIGH     = "high"
SEV_CRITICAL = "critical"
_SEV_RANK = {SEV_INFO: 0, SEV_LOW: 1, SEV_MEDIUM: 2, SEV_HIGH: 3, SEV_CRITICAL: 4}


def severity_rank(sev: str) -> int:
    """Numeric rank for ordering/compare; unknown → info."""
    return _SEV_RANK.get(sev, 0)


# ---------------------------------------------------------------------------
# The event
# ---------------------------------------------------------------------------

@dataclass
class TelemetryEvent:
    """One normalized observation from any collector."""

    category: str                       # CAT_*
    activity: str                       # verb: "query" | "exec" | "connect" | ...
    action:   str = ACT_OBSERVED        # ACT_*
    ts:       float = field(default_factory=time.time)   # epoch seconds (UTC)

    # Actor — the process responsible, when known.
    actor_pid:  int = 0
    actor_name: str = ""
    actor_path: str = ""

    # Target — what was acted on (domain / ip / port / path…). Free-form but
    # conventional keys: "domain", "ip", "port", "proto", "path".
    target: dict = field(default_factory=dict)

    severity: str = SEV_INFO
    reason:   str = ""
    source:   str = ""                  # collector name, e.g. "dns_interceptor"
    labels:   list = field(default_factory=list)
    fields:   dict = field(default_factory=dict)   # source-specific extras

    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "category":   self.category,
            "activity":   self.activity,
            "action":     self.action,
            "ts":         self.ts,
            "actor_pid":  self.actor_pid,
            "actor_name": self.actor_name,
            "actor_path": self.actor_path,
            "target":     dict(self.target),
            "severity":   self.severity,
            "reason":     self.reason,
            "source":     self.source,
            "labels":     list(self.labels),
            "fields":     dict(self.fields),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "TelemetryEvent":
        return cls(
            category   = str(d.get("category", "")),
            activity   = str(d.get("activity", "")),
            action     = str(d.get("action", ACT_OBSERVED)),
            ts         = float(d.get("ts", 0.0) or 0.0),
            actor_pid  = int(d.get("actor_pid", 0) or 0),
            actor_name = str(d.get("actor_name", "")),
            actor_path = str(d.get("actor_path", "")),
            target     = dict(d.get("target") or {}),
            severity   = str(d.get("severity", SEV_INFO)),
            reason     = str(d.get("reason", "")),
            source     = str(d.get("source", "")),
            labels     = list(d.get("labels") or []),
            fields     = dict(d.get("fields") or {}),
        )

    def bus_message(self) -> dict:
        """Wrap as an event-bus message: {"type": "telemetry", "event": {...}}."""
        return {"type": "telemetry", "event": self.to_dict()}


# ---------------------------------------------------------------------------
# Adapters — map existing signal shapes into TelemetryEvent
# ---------------------------------------------------------------------------

# The Store publishes DNS decisions as {"decision": "...", ...}. Map that
# disposition onto the normalized action + a severity floor.
_DNS_ACTION = {
    "allowed":    ACT_ALLOWED,
    "blocked":    ACT_BLOCKED,
    "behavioral": ACT_BLOCKED,   # behavioral block is still a block
    "flagged":    ACT_FLAGGED,
}


def from_dns_event(event: dict) -> TelemetryEvent:
    """Normalize one Store DNS-decision dict into a TelemetryEvent.

    Accepts either the inner ``event`` dict or the full bus message
    ``{"type": "event", "event": {...}}``.
    """
    if event.get("type") == "event" and isinstance(event.get("event"), dict):
        event = event["event"]

    decision = str(event.get("decision", "")).lower()
    action = _DNS_ACTION.get(decision, ACT_OBSERVED)

    suspicion = float(event.get("suspicion", 0.0) or 0.0)
    if action == ACT_BLOCKED:
        severity = SEV_HIGH if suspicion >= 0.9 else SEV_MEDIUM
    elif action == ACT_FLAGGED:
        severity = SEV_LOW
    else:
        severity = SEV_INFO

    ts = event.get("_ts")
    return TelemetryEvent(
        category   = CAT_DNS,
        activity   = "query",
        action     = action,
        ts         = float(ts) if ts else time.time(),
        actor_name = str(event.get("process_name", "")),
        actor_pid  = int(event.get("process_pid", 0) or 0),
        target     = {"domain": str(event.get("domain", ""))},
        severity   = severity,
        reason     = str(event.get("reason", "")),
        source     = "dns_interceptor",
        fields     = {
            "suspicion": suspicion,
            "raw_category": str(event.get("category", event.get("raw_category", ""))),
            "url": str(event.get("url", "")),
        },
    )
