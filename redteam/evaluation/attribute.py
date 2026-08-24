"""Attribute live incidents to the techniques that caused them — offline.

WHY THIS IS A SEPARATE, PURE MODULE
-----------------------------------
`run_live_evaluation.ps1` used to decide "did technique X get detected?" *while
the battery was still running*, by polling `GET /api/edr/incidents` every
`$PollIntervalSeconds` for up to `$DetectWindowSeconds` per technique, plus a
detail GET per touched incident. Two problems, one fatal:

  * **Cost grows with the incident store.** By the end of a 40-technique battery
    each poll is listing a store that the battery itself filled. That is the
    API-degradation symptom `RUN_PLAN_LIVE.md` flags as "fix first".
  * **It perturbs the thing being measured.** This is not theoretical. Run
    32441713709 (settle=3 plus two per-technique API reads) recorded **4**
    distinct techniques in the incident store; run 32440735442 (settle=0)
    recorded **27** — on a BYTE-IDENTICAL engine, with only the harness
    changed. A harness that changes the result is not measuring the product.

So attribution moves here: the harness fires everything back to back touching
the API as little as possible, sleeps **once** past the slowest collector, takes
**one** snapshot of the incident store, and this module decides what detected
what — offline, afterwards, deterministically.

The side benefit is the one that lasts. Attribution logic embedded in a
PowerShell script that has never been executed end to end is unverifiable by
construction. Here it is a pure function over two lists, so it has a real test
suite (`test_attribute.py`) and stays correct.

THE ATTRIBUTION RULES (unchanged in meaning from the PowerShell they replace)
----------------------------------------------------------------------------
1. **Technique ID first, time window second.** A detection belongs to a
   technique when its technique set contains that technique's ID *and* its own
   timestamp is at/after that technique's execution start. Techniques run
   sequentially so their windows are disjoint; the window is a staleness filter
   and a tiebreaker, never the primary key. This is what keeps a late-arriving
   artifact-at-rest detection attributed correctly instead of being dropped for
   landing outside a fixed poll window.

2. **A detection folded into a pre-existing incident still counts.** Matching is
   on detections, not on incident creation, so correlation into an older
   incident does not hide a hit.

3. **User-defined rules do not count as detections.** A hit whose category is
   `user_rule`, or whose text carries `user:always_block`, is recorded and
   excluded — scoring the operator's own allow/block list as product detection
   would be self-congratulation.

4. **False positives are new incidents that matched nothing.** An incident that
   did not exist before the battery, and whose technique set matches no
   technique, is a false positive — attributed to whichever technique's
   execution window contains its first detection, since the windows are
   disjoint. A detection folded into a pre-existing incident is not a new
   incident and is therefore never miscounted as an FP.

5. **Latency comes from the detection's own timestamp.** `detection.timestamp -
   exec_start`. This is strictly better than what the poll loop could measure:
   the old stopwatch could not resolve below `$PollIntervalSeconds` (2s) and
   charged its own sleep to the product.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Optional

# Text markers that mean "this hit came from the operator's own list, not from
# Valkyrie's detection content".
_USER_RULE_CATEGORY = "user_rule"
_USER_RULE_MARKER = "user:always_block"


def parse_utc(value) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp to an aware UTC datetime, or None.

    Tolerant on purpose: this consumes timestamps from an API, a PowerShell
    harness and hand-written fixtures, and a single unparseable stamp must
    degrade one comparison rather than abort a whole run's scoring.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@dataclass
class Fired:
    """One technique as the harness actually executed it."""
    id:              str
    technique_id:    str
    exec_start_utc:  str
    exec_end_utc:    str = ""
    executed:        bool = True

    @property
    def start(self) -> Optional[datetime]:
        return parse_utc(self.exec_start_utc)

    @property
    def end(self) -> Optional[datetime]:
        return parse_utc(self.exec_end_utc) or self.start


@dataclass
class Attribution:
    """What the incident store says happened to one technique."""
    id:                 str
    technique_id:       str
    detected:           bool = False
    detection_category: str = "none"
    severity:           str = ""
    reason:             str = ""
    source:             str = ""
    labels:             tuple = ()
    latency_seconds:    Optional[float] = None
    incident_id:        str = ""
    user_rule_only:     bool = False       # matched, but only via a user rule
    false_positive_ids: tuple = ()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "technique_id": self.technique_id,
            "detected": self.detected,
            "detection_category": self.detection_category,
            "severity": self.severity,
            "reason": self.reason,
            "source": self.source,
            "labels": list(self.labels),
            "latency_seconds": self.latency_seconds,
            "incident_id": self.incident_id,
            "user_rule_only": self.user_rule_only,
            "false_positive_ids": list(self.false_positive_ids),
            "false_positives": len(self.false_positive_ids),
        }


def _techniques_of(detection: dict, incident: dict) -> list:
    """Every technique ID a detection claims, including correlated ones."""
    out: list = []
    t = detection.get("technique")
    if t:
        out.append(str(t))
    details = detection.get("details") or {}
    for at in (details.get("all_techniques") or []):
        if at:
            out.append(str(at))
    return out


def _incident_techniques(incident: dict) -> list:
    """Every technique ID anywhere on an incident - used for the FP test."""
    out: list = []
    if incident.get("technique"):
        out.append(str(incident["technique"]))
    for d in (incident.get("detections") or []):
        out.extend(_techniques_of(d, incident))
    return out


def _is_user_rule(detection: dict, incident: dict) -> bool:
    category = str(incident.get("category") or "").lower()
    if category == _USER_RULE_CATEGORY:
        return True
    blob = (str(detection.get("title") or "") +
            str(incident.get("reason") or "")).lower()
    return _USER_RULE_MARKER in blob


def _matches(technique_id: str, claimed: Iterable[str]) -> bool:
    """Substring match, mirroring the harness's `-like "*$tid*"`.

    Substring rather than equality because a detection may report
    `T1059.001` where the catalog entry is `T1059`, and the harness this
    replaces treated that as a hit. Changing the comparison here would
    silently change historical comparability of every run.
    """
    tid = (technique_id or "").strip()
    if not tid:
        return False
    return any(tid in str(c) for c in claimed)


def attribute(fired: list, incidents: list, *,
              before_incident_ids: Iterable = ()) -> list:
    """Attribute a single post-battery incident snapshot to the techniques.

    ``fired``      the techniques as executed, in order, each with its
                   execution window (``Fired``, or dicts of the same shape).
    ``incidents``  ONE snapshot of incident *detail* records taken after the
                   battery settled.
    ``before_incident_ids``  incident ids that already existed before the
                   battery started; anything else is "new" for FP purposes.

    Returns one ``Attribution`` per fired technique, in the same order.
    """
    shots = [f if isinstance(f, Fired) else Fired(**{
        k: v for k, v in f.items()
        if k in ("id", "technique_id", "exec_start_utc", "exec_end_utc",
                 "executed")}) for f in fired]

    results = {s.id: Attribution(id=s.id, technique_id=s.technique_id)
               for s in shots}
    before = {str(i) for i in before_incident_ids}

    # --- pass 1: match detections to techniques ---------------------------
    matched_incidents: set = set()
    for inc in incidents:
        inc_id = str(inc.get("id") or "")
        for det in (inc.get("detections") or []):
            dts = parse_utc(det.get("timestamp"))
            claimed = _techniques_of(det, inc)
            if not claimed:
                continue

            # Every technique this detection could belong to: ID match, and
            # not stale relative to that technique's execution.
            candidates = []
            for s in shots:
                if not _matches(s.technique_id, claimed):
                    continue
                start = s.start
                if start is not None and dts is not None and dts < start:
                    continue                       # stale: fired before this
                candidates.append(s)
            if not candidates:
                continue

            # Tiebreak: prefer the technique whose execution window actually
            # contains the detection; otherwise the nearest preceding start.
            chosen = None
            for s in candidates:
                start, end = s.start, s.end
                if start and end and dts is not None and start <= dts <= end:
                    chosen = s
                    break
            if chosen is None:
                dated = [s for s in candidates if s.start is not None]
                chosen = (max(dated, key=lambda s: s.start)
                          if dated and dts is not None else candidates[0])

            att = results[chosen.id]
            matched_incidents.add(inc_id)

            if _is_user_rule(det, inc):
                # Recorded, not counted. An operator's own block list scoring
                # as product detection would flatter every run.
                att.user_rule_only = att.user_rule_only or not att.detected
                if not att.detected:
                    att.detection_category = _USER_RULE_CATEGORY
                continue

            if att.detected:
                continue                            # first real hit wins

            att.detected = True
            att.user_rule_only = False
            att.incident_id = inc_id
            att.severity = str(det.get("severity") or "")
            att.reason = str(det.get("title") or "")
            att.source = str(det.get("source") or "")
            att.detection_category = (str(det.get("source") or "")
                                      or str(inc.get("category") or "")
                                      or "behavioral")
            details = det.get("details") or {}
            labels = details.get("labels") or []
            att.labels = tuple(dict.fromkeys(str(x) for x in labels))
            start = chosen.start
            if start is not None and dts is not None:
                att.latency_seconds = round((dts - start).total_seconds(), 2)

    # --- pass 2: false positives ------------------------------------------
    # A NEW incident that matched no technique. Attributed to whichever
    # technique was executing when its first detection landed - the windows
    # are disjoint, so this reproduces the per-technique FP count the polling
    # harness produced, without polling.
    for inc in incidents:
        inc_id = str(inc.get("id") or "")
        if not inc_id or inc_id in before or inc_id in matched_incidents:
            continue
        claimed = _incident_techniques(inc)
        if any(_matches(s.technique_id, claimed) for s in shots):
            continue                                # matched something, not FP

        stamps = [parse_utc(d.get("timestamp"))
                  for d in (inc.get("detections") or [])]
        stamps = [s for s in stamps if s is not None]
        first = min(stamps) if stamps else None

        owner = None
        if first is not None:
            for s in shots:
                start, end = s.start, s.end
                if start and end and start <= first <= end:
                    owner = s
                    break
            if owner is None:
                dated = [s for s in shots
                         if s.start is not None and s.start <= first]
                owner = max(dated, key=lambda s: s.start) if dated else None
        if owner is None and shots:
            owner = shots[-1]
        if owner is not None:
            att = results[owner.id]
            att.false_positive_ids = att.false_positive_ids + (inc_id,)

    return [results[s.id] for s in shots]


def merge_into_records(records: list, attributions: list) -> list:
    """Fold attributions into harness result records, matched on ``id``.

    Kept separate from ``attribute()`` so the attribution logic never has to
    know the result schema, and so a schema change cannot silently alter what
    counts as a detection.
    """
    by_id = {a.id: a for a in attributions}
    out = []
    for rec in records:
        merged = dict(rec)
        att = by_id.get(str(rec.get("id") or ""))
        if att is not None:
            d = att.to_dict()
            d.pop("id", None)
            d.pop("technique_id", None)
            merged.update(d)
        out.append(merged)
    return out
