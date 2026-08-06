"""EDR core data model — the shapes every other EDR module speaks in.

The EDR layer sits on top of Valkyrie's existing sensors (DNS decisions,
firewall answer-IP screening, the behavioural/intelligence engines). Those
sensors already produce a rich event stream; the EDR layer's job is to turn
that stream into things a defender actually works with:

    Detection  — one security-relevant observation from a sensor/plugin
    Incident   — a correlated group of detections with a timeline + status
    ResponseAction — an audited action taken against a threat (block/kill/isolate)

Everything here is plain, serialisable dataclasses (stdlib only) so the same
shape flows through the SQLite store, the web API, the live WebSocket stream,
and — for remote response — the signed fleet command channel.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Severity — a small ordered vocabulary shared across the whole layer
# ---------------------------------------------------------------------------

SEVERITIES = ("info", "low", "medium", "high", "critical")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def severity_rank(sev: str) -> int:
    """Numeric rank of a severity string (unknown -> 0). Higher = worse."""
    return _SEV_RANK.get(str(sev).lower(), 0)


def max_severity(a: str, b: str) -> str:
    """Return whichever severity is worse."""
    return a if severity_rank(a) >= severity_rank(b) else b


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


# Incident lifecycle states.
INCIDENT_STATES = ("open", "investigating", "contained", "resolved", "dismissed")

# Response action lifecycle.
RESPONSE_STATES = ("dry_run", "pending", "succeeded", "failed", "skipped")


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

@dataclass
class Detection:
    """One security-relevant observation.

    A detection is cheap and plentiful — every blocked tracker can be a
    detection. Correlation (in engine.py) is what turns a stream of detections
    into a much smaller set of incidents a human can triage.
    """
    source:       str                       # plugin/sensor name, e.g. "dns.tracker"
    severity:     str                       # one of SEVERITIES
    category:     str                       # tracker|malware|beacon|exfil|anomaly|...
    title:        str                       # short human summary
    entity:       str = ""                  # primary IOC (domain / ip)
    process_name: str = ""
    process_pid:  int = 0
    technique:    str = ""                  # optional MITRE-ish label
    details:      dict = field(default_factory=dict)
    id:           str = field(default_factory=lambda: _new_id("det"))
    timestamp:    str = field(default_factory=_now_iso)
    incident_id:  str = ""                  # set once correlated

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_row(cls, row: dict) -> "Detection":
        import json
        d = dict(row)
        det = d.get("details")
        if isinstance(det, str):
            try:
                d["details"] = json.loads(det) if det else {}
            except ValueError:
                d["details"] = {}
        # Drop any columns not on the dataclass.
        allowed = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in allowed})


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------

@dataclass
class TimelineEntry:
    """One dated line in an incident's story."""
    kind:      str                          # detection|note|response|status
    summary:   str
    timestamp: str = field(default_factory=_now_iso)
    data:      dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Response action
# ---------------------------------------------------------------------------

@dataclass
class ResponseAction:
    """A response taken (or simulated) against a threat, always audited."""
    action:      str                        # block_domain|kill_process|isolate_host|...
    target:      str                        # domain / pid / "" (host)
    status:      str = "pending"            # one of RESPONSE_STATES
    result:      str = ""                   # human-readable outcome
    operator:    str = "local"              # who requested it
    dry_run:     bool = True
    incident_id: str = ""
    id:          str = field(default_factory=lambda: _new_id("act"))
    timestamp:   str = field(default_factory=_now_iso)

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Incident
# ---------------------------------------------------------------------------

@dataclass
class Incident:
    """A correlated group of detections — the unit a defender triages."""
    title:        str
    severity:     str = "low"
    category:     str = ""
    entity:       str = ""                  # primary subject (process or domain)
    status:       str = "open"
    technique:    str = ""                  # MITRE id(s), e.g. "T1562.001"
    process_name: str = ""
    process_pid:  int = 0                    # live only; not persisted (see store)
    assignee:     str = ""
    notes:        str = ""
    detection_count: int = 0
    id:           str = field(default_factory=lambda: _new_id("inc"))
    created_at:   str = field(default_factory=_now_iso)
    updated_at:   str = field(default_factory=_now_iso)
    timeline:     list = field(default_factory=list)   # list[TimelineEntry]
    actions:      list = field(default_factory=list)   # list[ResponseAction]

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    def touch(self) -> None:
        self.updated_at = _now_iso()

    @classmethod
    def from_row(cls, row: dict) -> "Incident":
        import json
        d = dict(row)
        for key in ("timeline", "actions"):
            v = d.get(key)
            if isinstance(v, str):
                try:
                    d[key] = json.loads(v) if v else []
                except ValueError:
                    d[key] = []
        allowed = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in allowed})
