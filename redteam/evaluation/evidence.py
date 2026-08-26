"""The evidence librarian - Valkyrie's testing results as a forensic chain, not a story.

WHY THIS EXISTS
---------------
On 2026-08-23 a live-EDR report said "5 techniques detected end-to-end," then
"that was wrong," then "the battery never ran." The engine had gone deaf 15s into
startup; incident-store rows left by the engine's own activity were misread as
attack detections; a run that measured NOTHING nearly became a "0% detection
rate." Every one of those is the same failure: interpretation was allowed to run
ahead of evidence, and infrastructure failure was allowed to masquerade as a
security result.

This module makes that class of mistake structurally impossible. It is a
forensic evidence librarian: it preserves *what happened -> what was observed ->
what was proven -> what was inferred -> what remains unknown*, and it refuses to
collapse those into a clean number when the evidence does not support one.

The design is four separated layers (never blended):

  L1  RAW EVIDENCE     - what literally happened (Evidence records).
  L2  TEST STATE       - what the harness did (attack executed? engine up?
                         telemetry present?).
  L3  DETECTION RESULT - DETECTED / NOT_DETECTED / INCONCLUSIVE / NOT_TESTED ...
                         DERIVED from L1+L2, never asserted directly.
  L4  VALIDITY         - VALID / INCONCLUSIVE / INFRASTRUCTURE_FAILURE ...
                         whether the measurement is even allowed to count.

The one rule that prevents last week's lie: **a DETECTED verdict requires the
whole evidence chain intact** - attack executed, engine responsive, telemetry
present, AND a detection event actually linked to the attack. Miss any link and
the verdict is INCONCLUSIVE / NOT_TESTED with the missing link named - never
DETECTED, and never a NOT_DETECTED that would score as a failure.

Pure. `adjudicate`, `audit`, `score`, `why`, `dashboard` are functions over
records; only `TestLibrary.save/load` touch disk. That is what lets the anti-lie
logic be exhaustively tested offline (test_evidence.py), which matters because
this is the component whose entire job is to not be foolable.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

SCHEMA = "valkyrie-evidence/1"


# ---------------------------------------------------------------------------
# Tri-state - the honest alternative to a bool that cannot say "unknown"
# ---------------------------------------------------------------------------
class Tri(str, Enum):
    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Layer 2 - what the harness did
# ---------------------------------------------------------------------------
class TestState(str, Enum):
    TEST_STARTED = "test_started"
    ATTACK_EXECUTED = "attack_executed"
    ATTACK_NOT_EXECUTED = "attack_not_executed"
    ENGINE_HEALTHY = "engine_healthy"
    ENGINE_UNRESPONSIVE = "engine_unresponsive"
    TELEMETRY_MISSING = "telemetry_missing"
    HARNESS_ERROR = "harness_error"
    TEST_TIMEOUT = "test_timeout"


# ---------------------------------------------------------------------------
# Layer 3 - the detection result (DERIVED, never asserted)
# ---------------------------------------------------------------------------
class Detection(str, Enum):
    DETECTED = "detected"
    PARTIALLY_DETECTED = "partially_detected"
    NOT_DETECTED = "not_detected"
    INCONCLUSIVE = "inconclusive"
    NOT_TESTED = "not_tested"


class Response(str, Enum):
    BLOCKED = "blocked"
    NOT_BLOCKED = "not_blocked"
    TERMINATED = "terminated"
    ALLOWED = "allowed"
    NONE = "none"


# ---------------------------------------------------------------------------
# Layer 4 - measurement validity (whether the number is allowed to count)
# ---------------------------------------------------------------------------
class Validity(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    INCONCLUSIVE = "inconclusive"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"
    SCORING_ERROR = "scoring_error"


class FailureClass(str, Enum):
    NONE = "none"
    ENGINE = "engine"
    HARNESS = "harness"
    TELEMETRY = "telemetry"
    SCORING = "scoring"
    ENVIRONMENT = "environment"
    OTHER = "other"


# The single set of detection states a VALID measurement may hold. Anything else
# means the measurement did not actually happen and must not enter a score.
_SCORABLE_DETECTIONS = {Detection.DETECTED, Detection.PARTIALLY_DETECTED,
                        Detection.NOT_DETECTED}


# ---------------------------------------------------------------------------
# Layer 1 - raw evidence
# ---------------------------------------------------------------------------
@dataclass
class Evidence:
    """One literal observation. `linked_attack` ties a detection event to the
    attack it belongs to - the link whose ABSENCE is what made stray DB rows
    look like detections last week."""
    kind: str            # process | etw | rule_ioa | atomic | health | telemetry ...
    detail: str
    ts: float = 0.0
    linked_attack: str = ""      # attack id this evidence is attributed to, if any
    is_detection: bool = False   # does this evidence represent a detection firing?

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Correction:
    """An auditable amendment. The original is NEVER deleted - it is superseded
    with a reason and its supporting evidence, so the history stays inspectable."""
    original: str
    corrected_to: str
    reason: str
    evidence: tuple = ()
    ts: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["evidence"] = list(self.evidence)
        return d


@dataclass
class Verdict:
    """The DERIVED conclusion for one test - the output of `adjudicate`."""
    detection: Detection
    validity: Validity
    failure_class: FailureClass
    response: Response
    why: tuple = ()             # human-readable evidence chain, in order
    missing_link: str = ""      # the first broken link in the chain, if any

    @property
    def scorable(self) -> bool:
        """True only when this measurement may enter a detection-rate numerator
        or denominator - VALID and holding a real detect/not-detect state."""
        return (self.validity == Validity.VALID
                and self.detection in _SCORABLE_DETECTIONS)

    def to_dict(self) -> dict:
        return {"detection": self.detection.value, "validity": self.validity.value,
                "failure_class": self.failure_class.value,
                "response": self.response.value, "why": list(self.why),
                "missing_link": self.missing_link, "scorable": self.scorable}


# ---------------------------------------------------------------------------
# Layer 3 record - one test, all layers, permanent id
# ---------------------------------------------------------------------------
@dataclass
class TestRecord:
    test_id: str
    campaign: str
    attack: str = ""
    attck_id: str = ""
    environment: str = ""
    configuration: str = ""
    engine_version: str = ""
    ruleset_version: str = ""
    started: str = ""
    run_id: str = ""

    # Layer 2 - test-state facts (tri-state: absence is UNKNOWN, never assumed)
    attack_executed: Tri = Tri.UNKNOWN
    engine_responsive: Tri = Tri.UNKNOWN
    telemetry_available: Tri = Tri.UNKNOWN

    # Layer 1 - raw evidence
    evidence: list = field(default_factory=list)     # list[Evidence]

    # response observed (if any)
    response: Response = Response.NONE

    # amendments (never overwrite a conclusion; supersede it)
    corrections: list = field(default_factory=list)  # list[Correction]

    def linked_detections(self) -> list:
        """Evidence rows that are detections AND linked to THIS attack. The
        link is mandatory: a detection with no linked_attack is exactly the
        stray DB row that must never be counted as a hit."""
        return [e for e in self.evidence
                if e.is_detection and e.linked_attack == self.test_id]

    def unlinked_detections(self) -> list:
        """Detection-looking evidence NOT tied to this attack - surfaced, never
        counted. Their existence is itself an audited signal (section 6)."""
        return [e for e in self.evidence
                if e.is_detection and e.linked_attack != self.test_id]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["attack_executed"] = self.attack_executed.value
        d["engine_responsive"] = self.engine_responsive.value
        d["telemetry_available"] = self.telemetry_available.value
        d["response"] = self.response.value
        d["evidence"] = [e.to_dict() if isinstance(e, Evidence) else e
                         for e in self.evidence]
        d["corrections"] = [c.to_dict() if isinstance(c, Correction) else c
                            for c in self.corrections]
        d["verdict"] = adjudicate(self).to_dict()
        return d


# ---------------------------------------------------------------------------
# THE ADJUDICATOR - the anti-lie core
# ---------------------------------------------------------------------------
def adjudicate(rec: TestRecord) -> Verdict:
    """Derive (detection, validity, failure, response) from evidence + state.

    The evidence chain, gated in order. Infrastructure gates come FIRST, so an
    infrastructure failure can never be rendered as a security result:

        attack executed? -> engine responsive? -> telemetry present?
        -> detection event linked to the attack? -> conclusion

    A DETECTED verdict requires EVERY link. The first broken link is named and
    the verdict becomes NOT_TESTED or INCONCLUSIVE - never a detection, never a
    NOT_DETECTED that would score as a miss.
    """
    why: list[str] = []
    resp = rec.response

    # --- link 1: did the attack actually execute? -------------------------
    if rec.attack_executed == Tri.YES:
        why.append("attack executed: YES")
    elif rec.attack_executed == Tri.NO:
        why.append("attack executed: NO - the attack was never run")
        # Why did it not run? Attribute the failure honestly.
        if rec.engine_responsive == Tri.NO:
            fc = FailureClass.ENGINE
            why.append("engine was unresponsive - the attack could not proceed")
        elif _has_state(rec, TestState.HARNESS_ERROR):
            fc = FailureClass.HARNESS
            why.append("harness error before execution")
        elif _has_state(rec, TestState.TEST_TIMEOUT):
            fc = FailureClass.HARNESS
            why.append("test timed out before execution")
        else:
            fc = FailureClass.HARNESS
            why.append("no execution evidence; cause not classified")
        why.append("CONCLUSION: not a detection measurement at all")
        return Verdict(Detection.NOT_TESTED, Validity.INFRASTRUCTURE_FAILURE,
                       fc, resp, tuple(why),
                       missing_link="attack_execution")
    else:  # UNKNOWN
        why.append("attack executed: UNKNOWN - no execution evidence recorded")
        why.append("CONCLUSION: cannot measure detection without proof the "
                   "attack ran")
        return Verdict(Detection.NOT_TESTED, Validity.INCONCLUSIVE,
                       FailureClass.HARNESS, resp, tuple(why),
                       missing_link="attack_execution")

    # --- link 2: was the engine responsive to observe it? -----------------
    if rec.engine_responsive == Tri.NO:
        why.append("engine responsive: NO - it could not have observed the "
                   "attack, so a non-detection here is BLINDNESS, not a miss")
        why.append("CONCLUSION: infrastructure failure; detection unmeasurable")
        return Verdict(Detection.INCONCLUSIVE, Validity.INFRASTRUCTURE_FAILURE,
                       FailureClass.ENGINE, resp, tuple(why),
                       missing_link="engine_responsive")
    if rec.engine_responsive == Tri.UNKNOWN:
        why.append("engine responsive: UNKNOWN - cannot certify the engine "
                   "was watching")
        why.append("CONCLUSION: measurement inconclusive")
        return Verdict(Detection.INCONCLUSIVE, Validity.INCONCLUSIVE,
                       FailureClass.ENGINE, resp, tuple(why),
                       missing_link="engine_responsive")
    why.append("engine responsive: YES")

    # --- link 3: was telemetry present for the relevant sensor? -----------
    if rec.telemetry_available == Tri.NO:
        why.append("telemetry available: NO - the sensor feeding this "
                   "technique was dark; a miss here is a coverage gap, not a "
                   "detection gap")
        why.append("CONCLUSION: measurement inconclusive (blind sensor)")
        return Verdict(Detection.INCONCLUSIVE, Validity.INCONCLUSIVE,
                       FailureClass.TELEMETRY, resp, tuple(why),
                       missing_link="telemetry")
    if rec.telemetry_available == Tri.UNKNOWN:
        why.append("telemetry available: UNKNOWN")
        why.append("CONCLUSION: measurement inconclusive")
        return Verdict(Detection.INCONCLUSIVE, Validity.INCONCLUSIVE,
                       FailureClass.TELEMETRY, resp, tuple(why),
                       missing_link="telemetry")
    why.append("telemetry available: YES")

    # --- link 4: is there a detection event LINKED to this attack? --------
    # This is the load-bearing link. Detection evidence that is NOT linked to
    # this attack (stray incident-store rows, engine self-activity) is
    # explicitly excluded here - that exclusion is what stops last week's
    # "5 detected" from ever recurring.
    linked = rec.linked_detections()
    stray = rec.unlinked_detections()
    if stray:
        why.append(f"note: {len(stray)} detection-like event(s) present but NOT "
                   f"linked to this attack - excluded from the verdict")

    if linked:
        why.append(f"detection linked to attack: YES ({len(linked)} event(s): "
                   f"{', '.join(sorted(e.detail for e in linked))})")
        why.append("CONCLUSION: detection is proven for this attack")
        return Verdict(Detection.DETECTED, Validity.VALID, FailureClass.NONE,
                       resp, tuple(why))

    # Full chain intact, engine watching, telemetry present, and no linked
    # detection: this is a REAL, VALID miss - the only path to NOT_DETECTED.
    why.append("detection linked to attack: NONE, with engine up and telemetry "
               "present - this is a genuine miss")
    why.append("CONCLUSION: not detected (valid measurement)")
    return Verdict(Detection.NOT_DETECTED, Validity.VALID, FailureClass.NONE,
                   resp, tuple(why))


def _has_state(rec: TestRecord, state: TestState) -> bool:
    return any(e.kind == "state" and e.detail == state.value for e in rec.evidence)


# ---------------------------------------------------------------------------
# THE "WHY?" CHAIN - human-readable, per section 4
# ---------------------------------------------------------------------------
def why(rec: TestRecord) -> str:
    v = adjudicate(rec)
    lines = [
        f"RESULT",
        f"  {rec.campaign} / {rec.attck_id or rec.attack or rec.test_id}: "
        f"{v.detection.value.upper()}  (validity: {v.validity.value.upper()})",
        "",
        "WHY?",
    ]
    for step in v.why:
        lines.append(f"  - {step}")
    # Stray detection evidence is surfaced HERE, unconditionally - even when the
    # chain exited early (e.g. the attack never ran). This is the 2026-08-23
    # guard made explicit: incident rows that look like detections but are not
    # linked to this attack are named and excluded, so they can never be quietly
    # read as hits.
    stray = rec.unlinked_detections()
    if stray:
        lines += ["", "EXCLUDED (detection-like evidence NOT linked to this attack)"]
        for e in stray:
            lines.append(f"  - [{e.kind}] {e.detail} - excluded; not linked to "
                         f"an executed attack, so NOT counted as a detection")
    lines += ["", "EVIDENCE"]
    if rec.evidence:
        for e in rec.evidence:
            tag = " [DETECTION]" if e.is_detection else ""
            link = f" ->{e.linked_attack}" if e.linked_attack else ""
            lines.append(f"  - [{e.kind}] {e.detail}{link}{tag}")
    else:
        lines.append("  - (none recorded)")
    lines += ["", "DO NOT COUNT AS"]
    if v.validity != Validity.VALID:
        lines += ["  - a detection success",
                  "  - a detection failure / false negative",
                  "  - any entry in a detection-rate numerator or denominator"]
    elif v.detection == Detection.NOT_DETECTED:
        lines += ["  - an infrastructure failure (it is a genuine, valid miss)"]
    else:
        lines += ["  - (this is a valid, scorable result)"]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# THE CONSISTENCY AUDIT - section 6
# ---------------------------------------------------------------------------
@dataclass
class Contradiction:
    test_id: str
    kind: str
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


def audit(records: list) -> list:
    """Scan for contradictions that must block a final score. Returns the list
    of contradictions found; empty means the library is internally consistent.

    These check the DERIVED verdict against the raw facts, so a verdict that was
    hand-set or ingested wrong cannot slip through - the adjudicator's own output
    is re-validated against the evidence it claims to rest on.
    """
    out: list = []
    seen: dict = {}

    for rec in records:
        # duplicate test id
        if rec.test_id in seen:
            out.append(Contradiction(rec.test_id, "duplicate_test_id",
                       "the same test_id appears more than once"))
        seen[rec.test_id] = True

        v = adjudicate(rec)

        # detected but the attack never executed
        if v.detection == Detection.DETECTED and rec.attack_executed != Tri.YES:
            out.append(Contradiction(rec.test_id, "detected_without_execution",
                       "verdict DETECTED but attack_executed is not YES"))

        # detected but no linked detection evidence
        if v.detection == Detection.DETECTED and not rec.linked_detections():
            out.append(Contradiction(rec.test_id, "detected_without_evidence",
                       "verdict DETECTED but no detection evidence is linked to "
                       "the attack"))

        # not-detected while a linked detection exists
        if v.detection == Detection.NOT_DETECTED and rec.linked_detections():
            out.append(Contradiction(rec.test_id, "missed_with_evidence",
                       "verdict NOT_DETECTED but a linked detection event exists"))

        # RAW-FACT contradiction: a detection linked to an attack that never
        # executed. adjudicate() safely collapses this to NOT_TESTED, so it
        # never shows up as a bad verdict - but the INPUT is self-contradictory
        # (how can a detection be attributed to an attack that did not run?), and
        # that smell must be surfaced, not silently absorbed. This is the exact
        # shape of the 2026-08-23 "5 detected while the battery never ran" data.
        if rec.linked_detections() and rec.attack_executed != Tri.YES:
            out.append(Contradiction(rec.test_id, "detection_without_execution",
                       "detection evidence is linked to an attack that did not "
                       "execute (attack_executed != YES)"))

        # VALID measurement resting on a dead engine / unrun attack
        if v.validity == Validity.VALID and rec.engine_responsive != Tri.YES:
            out.append(Contradiction(rec.test_id, "valid_on_dead_engine",
                       "measurement marked VALID but engine was not responsive"))
        if v.validity == Validity.VALID and rec.attack_executed != Tri.YES:
            out.append(Contradiction(rec.test_id, "valid_without_execution",
                       "measurement marked VALID but the attack did not execute"))

        # stray detection-looking evidence (the "5 detected" trap): not a hard
        # contradiction on its own, but flagged so it can never be silently
        # rolled into a count.
        if rec.unlinked_detections():
            out.append(Contradiction(rec.test_id, "unlinked_detection_evidence",
                       f"{len(rec.unlinked_detections())} detection-like event(s) "
                       f"not linked to any attack - must not be counted"))

    return out


# ---------------------------------------------------------------------------
# HONEST SCORING - section 9. Categorize the denominator; never divide by
# invalid or unexecuted tests.
# ---------------------------------------------------------------------------
@dataclass
class Scorecard:
    campaign: str
    scheduled: int = 0
    executed: int = 0
    valid: int = 0
    inconclusive: int = 0
    infrastructure_failures: int = 0
    detected: int = 0
    not_detected: int = 0
    blocked: int = 0
    # None means N/A - there were no valid measurements to form a rate.
    detection_rate_pct: Optional[float] = None
    rate_basis: str = ""
    report_valid: bool = True
    contradictions: tuple = ()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["contradictions"] = [c.to_dict() if isinstance(c, Contradiction) else c
                               for c in self.contradictions]
        return d


def score(records: list, campaign: str = "") -> Scorecard:
    """Score a set of records HONESTLY.

    Two hard rules from the spec:
      1. If the consistency audit finds any contradiction, DO NOT produce a
         score. Return report_valid=False with the contradictions attached.
      2. The detection rate is detected / VALID measurements - never over
         scheduled or executed. Zero valid measurements yields N/A (None), not
         a misleading 0%.
    """
    contradictions = audit(records)
    if contradictions:
        return Scorecard(campaign=campaign, scheduled=len(records),
                         report_valid=False,
                         contradictions=tuple(contradictions))

    sc = Scorecard(campaign=campaign, scheduled=len(records))
    for rec in records:
        v = adjudicate(rec)
        if rec.attack_executed == Tri.YES:
            sc.executed += 1
        if v.validity == Validity.INFRASTRUCTURE_FAILURE:
            sc.infrastructure_failures += 1
        if v.validity == Validity.INCONCLUSIVE:
            sc.inconclusive += 1
        if v.scorable:
            sc.valid += 1
            if v.detection in (Detection.DETECTED, Detection.PARTIALLY_DETECTED):
                sc.detected += 1
            elif v.detection == Detection.NOT_DETECTED:
                sc.not_detected += 1
        if v.response in (Response.BLOCKED, Response.TERMINATED):
            sc.blocked += 1

    if sc.valid > 0:
        sc.detection_rate_pct = round(100.0 * sc.detected / sc.valid, 1)
        sc.rate_basis = f"{sc.detected}/{sc.valid} valid measurements"
    else:
        sc.detection_rate_pct = None
        sc.rate_basis = "N/A - no valid measurements"
    return sc


# ---------------------------------------------------------------------------
# THE DASHBOARD - section 10. 10-second read, then the reasons.
# ---------------------------------------------------------------------------
def dashboard(scorecards: list) -> str:
    """Render the top-of-report dashboard from a list of Scorecards."""
    rows = ["| Campaign | Status | Valid | Result |",
            "| --- | --- | ---: | --- |"]
    reasons: list[str] = []
    for sc in scorecards:
        if not sc.report_valid:
            status, result = "⚠ VALIDATION FAILED", "SEE BELOW"
            reasons.append(f"- **{sc.campaign}**: REPORT VALIDATION FAILED - "
                           f"{len(sc.contradictions)} contradiction(s); no score "
                           f"produced. First: {sc.contradictions[0].detail}"
                           if sc.contradictions else
                           f"- **{sc.campaign}**: validation failed.")
        elif sc.valid == 0:
            status = "UNMEASURED"
            result = "N/A"
            reason = "infrastructure failure" if sc.infrastructure_failures else \
                     "inconclusive" if sc.inconclusive else "not executed"
            reasons.append(f"- **{sc.campaign}**: N/A - {sc.valid} valid of "
                           f"{sc.scheduled} scheduled "
                           f"({sc.infrastructure_failures} infra failure, "
                           f"{sc.inconclusive} inconclusive). Reason: {reason}.")
        else:
            status = "VALID"
            result = f"{sc.detected}/{sc.valid}"
            if sc.infrastructure_failures or sc.inconclusive:
                reasons.append(f"- **{sc.campaign}**: {result} valid "
                               f"({sc.detection_rate_pct}%); "
                               f"{sc.infrastructure_failures} infra failure, "
                               f"{sc.inconclusive} inconclusive excluded from "
                               f"the rate.")
        rows.append(f"| {sc.campaign} | {status} | {sc.valid} | {result} |")

    out = ["## Valkyrie test dashboard", "", *rows]
    if reasons:
        out += ["", "### Why anything is N/A / UNMEASURED / VALIDATION FAILED", *reasons]
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Reconstruction + ingestion
# ---------------------------------------------------------------------------
def _tri(v) -> Tri:
    if isinstance(v, Tri):
        return v
    s = str(v).strip().lower()
    if s in ("yes", "true", "1"):
        return Tri.YES
    if s in ("no", "false", "0"):
        return Tri.NO
    return Tri.UNKNOWN


def record_from_dict(d: dict) -> TestRecord:
    """Rebuild a TestRecord from its serialized form (round-trips to_dict)."""
    ev = [Evidence(**e) if isinstance(e, dict) else e for e in d.get("evidence", [])]
    corr = [Correction(**{k: (tuple(v) if k == "evidence" else v)
                          for k, v in c.items()}) if isinstance(c, dict) else c
            for c in d.get("corrections", [])]
    return TestRecord(
        test_id=d["test_id"], campaign=d.get("campaign", ""),
        attack=d.get("attack", ""), attck_id=d.get("attck_id", ""),
        environment=d.get("environment", ""), configuration=d.get("configuration", ""),
        engine_version=d.get("engine_version", ""),
        ruleset_version=d.get("ruleset_version", ""),
        started=d.get("started", ""), run_id=d.get("run_id", ""),
        attack_executed=_tri(d.get("attack_executed")),
        engine_responsive=_tri(d.get("engine_responsive")),
        telemetry_available=_tri(d.get("telemetry_available")),
        evidence=ev,
        response=Response(d["response"]) if d.get("response") else Response.NONE,
        corrections=corr,
    )


def from_tierb_record(rec: dict, *, run_id: str = "", campaign: str = "EDR",
                      environment: str = "", engine_version: str = "",
                      ruleset_version: str = "") -> TestRecord:
    """Ingest one record from the existing run_live_evaluation harness JSON.

    The mapping is deliberately CONSERVATIVE - it never upgrades a fact it
    cannot see. `attack_executed` becomes YES only when the harness recorded it;
    absent, it is UNKNOWN (which the adjudicator treats as not-measurable), so an
    old result file can never be inflated into a detection it did not prove.
    """
    tid = str(rec.get("id") or rec.get("technique_id") or "unknown")
    evidence: list = []

    executed = _tri(rec.get("attack_executed"))
    # A harness "counted_as_detected" only becomes linked detection evidence if
    # the attack actually executed - a detection with no execution is exactly the
    # stray signal we refuse to credit.
    if rec.get("counted_as_detected") and executed == Tri.YES:
        evidence.append(Evidence(
            kind="rule_ioa",
            detail=str(rec.get("matched_reason") or rec.get("detection_category")
                       or "detection"),
            linked_attack=tid, is_detection=True,
            ts=float(rec.get("latency_seconds") or 0.0)))

    # Engine / telemetry state: only YES when positively evidenced.
    engine = _tri(rec.get("engine_responsive"))
    if engine == Tri.UNKNOWN and executed == Tri.YES:
        # If the attack executed the engine was at least up enough to run it;
        # still not proof it stayed responsive, so leave as recorded.
        pass
    telemetry = _tri(rec.get("telemetry_available"))

    resp = Response.NONE
    if rec.get("blocked_before_execution"):
        resp = Response.BLOCKED

    return TestRecord(
        test_id=tid, campaign=campaign,
        attack=str(rec.get("technique_name") or ""),
        attck_id=str(rec.get("technique_id") or ""),
        environment=environment, configuration=str(rec.get("tier") or "Tier B"),
        engine_version=engine_version, ruleset_version=ruleset_version,
        started=str(rec.get("started") or ""), run_id=run_id,
        attack_executed=executed, engine_responsive=engine,
        telemetry_available=telemetry, evidence=evidence, response=resp)


# ---------------------------------------------------------------------------
# THE LIBRARY - section 7. Append-only; nothing disappears or is overwritten.
# ---------------------------------------------------------------------------
class TestLibrary:
    """An append-only store of runs. A run is a frozen set of records under a
    (campaign, run_id) key. New runs never overwrite old ones; a conclusion is
    amended only by appending a Correction (section 8), never by mutation."""

    def __init__(self) -> None:
        self.runs: dict = {}         # (campaign, run_id) -> list[TestRecord]

    def add_run(self, campaign: str, run_id: str, records: list) -> None:
        key = (campaign, run_id)
        if key in self.runs:
            raise ValueError(f"run {key} already exists; runs are append-only - "
                             f"use a new run_id rather than overwriting")
        self.runs[key] = list(records)

    def correct(self, campaign: str, run_id: str, test_id: str,
                correction: Correction) -> None:
        """Amend a record by APPENDING a correction - the original stays."""
        for rec in self.runs.get((campaign, run_id), []):
            if rec.test_id == test_id:
                rec.corrections.append(correction)
                return
        raise KeyError(f"no record {test_id} in run {(campaign, run_id)}")

    def campaign_scorecard(self, campaign: str, run_id: str) -> Scorecard:
        return score(self.runs.get((campaign, run_id), []), campaign=campaign)

    def to_dict(self) -> dict:
        return {"schema": SCHEMA,
                "runs": [{"campaign": c, "run_id": r,
                          "records": [rec.to_dict() for rec in recs]}
                         for (c, r), recs in self.runs.items()]}

    @classmethod
    def from_dict(cls, d: dict) -> "TestLibrary":
        lib = cls()
        for run in d.get("runs", []):
            lib.runs[(run["campaign"], run["run_id"])] = [
                record_from_dict(x) for x in run["records"]]
        return lib

    def save(self, path) -> None:
        import io
        import json
        io.open(path, "w", encoding="utf-8").write(
            json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path) -> "TestLibrary":
        import io
        import json
        return cls.from_dict(json.load(io.open(path, encoding="utf-8")))
