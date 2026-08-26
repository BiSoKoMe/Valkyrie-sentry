"""MTTD / MTTR - first-class product metrics for REAL incidents.

Clinton's *Cybersecurity for Business* (ch. 10) and IIBA/IEEE's
*Cybersecurity Analysis* handbook (§9.1.2) both name the same two numbers as
THE headline security metrics: Mean Time To Detect and Mean Time To
Respond. ``redteam/evaluation/live_safe.py`` already computes a latency
number, but only for the eval harness, where the red-team script knows
``exec_ts`` (the exact moment it ran a technique) - ground truth a real
production incident never has. This module is the analogous measurement
for the live product, built honestly around what Valkyrie can actually
know rather than borrowing the eval harness's privileged viewpoint.

**MTTD - time from first observable event to incident raised.**
"First observable event" is the EARLIEST Detection's own ``timestamp``
among the detections that make up the incident. Until this module,
``Detection.timestamp`` on the ``ingest_telemetry()`` path always defaulted
to "now" (when the engine got around to processing the event), discarding
the collector's own ``TelemetryEvent.ts`` (when the collector itself first
observed it) - see ``EdrEngine.ingest_telemetry``'s ``iso_from_epoch(ts)``
fix. That fix is what makes this metric non-trivial: a polling collector
(process/persistence/network telemetry, 2-second interval) can now show a
real, non-zero gap between "the process actually started" and "Valkyrie's
poll noticed it," which is genuine detect-latency, not pipeline noise.
MTTD is honestly scoped: it measures Valkyrie's OWN observe-to-record
latency, not "time since the attacker's action," which no production
system can know without the ground truth only a red-team harness has.

**MTTR - time from incident raised to responder completed.**
The FIRST non-dry-run ResponseAction on the incident to reach a terminal
status (succeeded/failed/skipped - dry_run and pending are not
"completed"). This is standard SOC usage: the metric that matters is how
fast the FIRST real remediation attempt finished, not the average of every
audit-trail row.

Both are reported as median + p95 (not a single average, which one slow
outlier - or the 0ms happy path dominating a mostly-instant pipeline -
would distort) via :func:`summarize`.
"""

from __future__ import annotations

from dataclasses import dataclass
from statistics import median
from typing import Optional

from .schema import parse_iso

_TERMINAL_RESPONSE_STATES = {"succeeded", "failed", "skipped"}


def mttd_seconds(incident: dict) -> Optional[float]:
    """Seconds from the incident's earliest detection to its creation.

    ``incident`` is the shape ``EdrEngine.get_incident()`` returns: a dict
    with ``created_at`` and a ``detections`` list of Detection dicts (each
    carrying its own ``timestamp``). Returns None when there's nothing to
    measure (no detections, or unparseable timestamps) rather than a
    fabricated 0 - an absent measurement must not look like a perfect one.
    """
    dets = incident.get("detections") or []
    ts_values = [parse_iso(d.get("timestamp")) for d in dets]
    ts_values = [t for t in ts_values if t is not None]
    if not ts_values:
        return None
    created = parse_iso(incident.get("created_at"))
    if created is None:
        return None
    return max(0.0, created - min(ts_values))


def mttr_seconds(incident: dict) -> Optional[float]:
    """Seconds from incident creation to the first real responder action
    reaching a terminal status. None if no such action exists yet (an open
    incident with no completed response is not a 0-second response)."""
    created = parse_iso(incident.get("created_at"))
    if created is None:
        return None
    responses = incident.get("responses") or []
    candidates = []
    for r in responses:
        if r.get("dry_run"):
            continue
        if r.get("status") not in _TERMINAL_RESPONSE_STATES:
            continue
        ts = parse_iso(r.get("timestamp"))
        if ts is not None:
            candidates.append(ts)
    if not candidates:
        return None
    return max(0.0, min(candidates) - created)


@dataclass(frozen=True)
class MetricStats:
    n: int                              # how many incidents had a measurable value
    total: int                          # how many incidents were considered at all
    median_seconds: Optional[float]
    p95_seconds: Optional[float]

    def to_dict(self) -> dict:
        return {"n": self.n, "total": self.total,
                "median_seconds": self.median_seconds,
                "p95_seconds": self.p95_seconds}


def _pctl(sorted_vals: list, p: float) -> Optional[float]:
    if not sorted_vals:
        return None
    idx = min(len(sorted_vals) - 1, int(round(p * (len(sorted_vals) - 1))))
    return sorted_vals[idx]


def summarize(values: list, total: Optional[int] = None) -> MetricStats:
    """values: a list possibly containing None (unmeasurable incidents).
    total defaults to len(values) when not given."""
    vals = sorted(v for v in values if v is not None)
    return MetricStats(n=len(vals), total=total if total is not None else len(values),
                       median_seconds=median(vals) if vals else None,
                       p95_seconds=_pctl(vals, 0.95))


def compute(incidents: list) -> dict:
    """``incidents``: a list of EdrEngine.get_incident()-shaped dicts.
    Returns {"mttd": MetricStats, "mttr": MetricStats}."""
    mttds = [mttd_seconds(i) for i in incidents]
    mttrs = [mttr_seconds(i) for i in incidents]
    return {"mttd": summarize(mttds, total=len(incidents)),
            "mttr": summarize(mttrs, total=len(incidents))}
