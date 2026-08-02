"""Incident decision policy — confidence → graded action, profile-aware.

This is the layer that turns "many strong detectors" into "the engine decides
well." It is **deterministic**: no LLM in the hot path (an always-on agent
cannot afford per-event model latency and must work fully offline). It maps an
incident's facts onto exactly one action, with a plain-language reason and user
message, so every automated response is explainable and testable.

Design (the "Big V" model, done as pure code):

  Threat class   ─┐
  Confidence     ─┼──▶  ACTION ∈ {ALLOW, ALERT, DECEIVE, BLOCK, CONTAIN}
  User profile   ─┘

  * THREAT CLASS   surveillance | compromise | metadata_leakage |
                   decoy_trigger | other  — derived from category + labels.
  * CONFIDENCE     low | medium | high — from severity, named sequences, and
                   any explicit confidence the detector supplied.
  * PROFILE        standard | high_risk | travel | clean_room — shifts the
                   block-vs-deceive trade-off (minimal disruption ↔ lock down).

Principles enforced here (from the high-risk-user threat model):
  * Safety first: when unsure on a *targeted* signal, prefer CONTAIN+ALERT over
    silent ALLOW — the stricter the profile, the more this dominates.
  * Minimal disruption: common telemetry/trackers prefer DECEIVE (feed fake
    data) over hard BLOCK in Standard, so essential apps keep working — but
    High-Risk/Travel/Clean-Room block by default.
  * High-confidence compromise / any decoy access → immediate CONTAIN.

The policy is pure and unit-tested (tests/test_decision.py). It returns a
recommendation; the caller (EDR engine / playbooks) is what actually enforces
it, so this module has no side effects and cannot break the machine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Optional

from .telemetry import severity_rank


class Profile(str, Enum):
    STANDARD = "standard"
    HIGH_RISK = "high_risk"
    TRAVEL = "travel"
    CLEAN_ROOM = "clean_room"


class Action(str, Enum):
    ALLOW = "allow"        # no action (log only)
    ALERT = "alert"        # notify the user, no enforcement
    DECEIVE = "deceive"    # allow the flow but feed fake / low-value data
    BLOCK = "block"        # stop this activity (domain/process network/kill)
    CONTAIN = "contain"    # isolate the device from the network except Big V


class ThreatClass(str, Enum):
    SURVEILLANCE = "surveillance"
    COMPROMISE = "compromise"
    METADATA_LEAKAGE = "metadata_leakage"
    DECOY_TRIGGER = "decoy_trigger"
    OTHER = "other"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# Action severity order so profile escalation can "step up" one notch.
_ACTION_ORDER = [Action.ALLOW, Action.ALERT, Action.DECEIVE, Action.BLOCK, Action.CONTAIN]


def _step_up(action: Action, notches: int = 1) -> Action:
    i = min(len(_ACTION_ORDER) - 1, _ACTION_ORDER.index(action) + notches)
    return _ACTION_ORDER[i]


# ── Label vocabularies (substring match, lower-cased) ───────────────────────
_DECOY_LABELS = ("decoy", "canary", "honeytoken", "honey_credential", "honeyfile")
_COMPROMISE_LABELS = (
    "lsass", "credential_access", "credential", "injection", "remote_thread",
    "lolbin", "persistence", "shadow_delete", "ransomware", "process_tampering",
    "web_shell", "amsi_bypass", "defender_tamper", "sam_dump",
)
_METADATA_LABELS = (
    "tracker", "telemetry", "analytics", "advertising", "beacon_telemetry",
    "fingerprint", "cloud_backup", "sync_upload",
)
_SURVEILLANCE_LABELS = (
    "c2", "beacon", "threat_intel_ip", "dga", "tunnel", "spyware",
    "surveillance", "known_campaign", "rare_ip",
)
_COMPROMISE_CATEGORIES = ("process", "persistence", "attack_chain", "attack_sequence")
_SURVEILLANCE_CATEGORIES = ("network", "firewall_ip", "intelligence", "dns", "anomaly")


@dataclass(frozen=True)
class Signal:
    """The facts a detector hands the policy. Mirrors a Detection/Incident but
    is a small, stable contract so the policy never depends on engine internals."""
    category: str = ""
    severity: str = "info"            # info | low | medium | high | critical
    labels: tuple = ()
    technique: str = ""
    process_name: str = ""
    entity: str = ""
    source: str = ""
    confidence: Optional[float] = None   # 0..1 if a detector measured one
    distinct_tactics: int = 0            # from the kill-chain correlator
    sensitive_path: bool = False         # e.g. case files / draft stories upload

    def _has(self, vocab: Iterable[str]) -> bool:
        blob = (" ".join(self.labels) + " " + self.technique + " " +
                self.source).lower()
        return any(tok in blob for tok in vocab)


@dataclass(frozen=True)
class Decision:
    action: Action
    threat_class: ThreatClass
    confidence: Confidence
    reason: str                       # internal, plain-language rationale
    user_message: str = ""            # shown only when we ALERT the user
    recommended_step: str = ""        # what the user should do next
    forensics: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "action": self.action.value,
            "threat_class": self.threat_class.value,
            "confidence": self.confidence.value,
            "reason": self.reason,
            "user_message": self.user_message,
            "recommended_step": self.recommended_step,
            "forensics": self.forensics,
        }


# ── Classification ──────────────────────────────────────────────────────────

def classify_threat(sig: Signal) -> ThreatClass:
    if sig._has(_DECOY_LABELS):
        return ThreatClass.DECOY_TRIGGER
    if sig._has(_COMPROMISE_LABELS) or sig.category in _COMPROMISE_CATEGORIES:
        return ThreatClass.COMPROMISE
    if sig._has(_METADATA_LABELS):
        return ThreatClass.METADATA_LEAKAGE
    if sig._has(_SURVEILLANCE_LABELS) or sig.category in _SURVEILLANCE_CATEGORIES:
        return ThreatClass.SURVEILLANCE
    return ThreatClass.OTHER


def assess_confidence(sig: Signal) -> Confidence:
    # A detector that measured a probability wins — it is the most direct signal.
    if sig.confidence is not None:
        if sig.confidence >= 0.80:
            return Confidence.HIGH
        if sig.confidence >= 0.45:
            return Confidence.MEDIUM
        return Confidence.LOW
    # Decoy access is unambiguous by construction.
    if sig._has(_DECOY_LABELS):
        return Confidence.HIGH
    # A completed named sequence / multi-tactic chain is high-confidence.
    if sig.category == "attack_sequence" or sig.distinct_tactics >= 3:
        return Confidence.HIGH
    rank = severity_rank(sig.severity)
    if rank >= severity_rank("critical"):
        return Confidence.HIGH
    if rank >= severity_rank("high"):
        return Confidence.HIGH if sig.distinct_tactics >= 2 else Confidence.MEDIUM
    if rank >= severity_rank("medium"):
        return Confidence.MEDIUM
    return Confidence.LOW


# ── The policy ──────────────────────────────────────────────────────────────

def decide(sig: Signal, profile: Profile = Profile.STANDARD) -> Decision:
    """Return the single recommended action + reasoning for a signal. Pure."""
    tc = classify_threat(sig)
    conf = assess_confidence(sig)
    base = _base_decision(sig, tc, conf, profile)
    return _apply_profile(base, sig, tc, conf, profile)


def _base_decision(sig: Signal, tc: ThreatClass, conf: Confidence,
                   profile: Profile) -> Decision:
    who = sig.process_name or sig.entity or "a process"
    forensics = {
        "artifacts": [x for x in (sig.process_name, sig.entity, sig.technique,
                                  sig.source) if x],
        "tamper_evident": conf == Confidence.HIGH or tc == ThreatClass.DECOY_TRIGGER,
    }

    if tc == ThreatClass.DECOY_TRIGGER:
        return Decision(
            Action.CONTAIN, tc, Confidence.HIGH,
            reason=f"{who} accessed a Big V decoy (fake confidential file / "
                   f"credential). Decoy access is a near-certain intrusion signal.",
            user_message="Big V detected something accessing fake confidential "
                         "files planted as a trap. This device may be compromised.",
            recommended_step="Stop sensitive work now, keep the device on for "
                             "evidence, and contact your security lead.",
            forensics=forensics)

    if tc == ThreatClass.COMPROMISE:
        if conf == Confidence.HIGH:
            return Decision(
                Action.CONTAIN, tc, conf,
                reason=f"High-confidence compromise on {who} "
                       f"({sig.technique or 'IOA match'}). Isolate + kill + "
                       f"quarantine to stop tailored malware before it spreads.",
                user_message=f"Big V detected a likely targeted attack "
                             f"involving {who}. The activity has been stopped and "
                             f"the device isolated.",
                recommended_step="Do not continue sensitive work on this device "
                                 "until it is reviewed; preserve evidence.",
                forensics=forensics)
        if conf == Confidence.MEDIUM:
            return Decision(
                Action.BLOCK, tc, conf,
                reason=f"Medium-confidence compromise on {who}. Block its network "
                       f"and deceive any C2-like traffic while alerting.",
                user_message=f"Big V blocked suspicious activity from {who}.",
                recommended_step="Consider locking down this device now.",
                forensics=forensics)
        return Decision(
            Action.ALERT if profile != Profile.STANDARD else Action.ALLOW,
            tc, conf,
            reason=f"Low-confidence unusual behavior on {who}. Log + raise "
                   f"monitoring; no enforcement yet.",
            forensics=forensics)

    if tc == ThreatClass.SURVEILLANCE:
        if conf == Confidence.HIGH:
            return Decision(
                Action.CONTAIN, tc, conf,
                reason=f"High-confidence surveillance pattern via {who} "
                       f"({sig.entity or sig.technique}). Contain non-essential "
                       f"network and alert.",
                user_message="Big V detected possible targeted surveillance and "
                             "restricted this device's network.",
                recommended_step="Switch to High-Risk profile and contact your "
                                 "security lead.",
                forensics=forensics)
        if conf == Confidence.MEDIUM:
            return Decision(
                Action.BLOCK, tc, conf,
                reason=f"Medium-confidence surveillance flow ({sig.entity}). Block "
                       f"and deceive telemetry-like traffic; recommend High-Risk.",
                user_message="Big V blocked a suspicious connection and is "
                             "watching more closely.",
                recommended_step="Consider switching to High-Risk profile.",
                forensics=forensics)
        return Decision(
            Action.ALERT, tc, conf,
            reason="Unusual-but-low network pattern. Subtle notice + raise "
                   "monitoring sensitivity.",
            user_message="Big V noticed unusual network activity and switched to "
                         "a higher monitoring mode.",
            forensics=forensics)

    if tc == ThreatClass.METADATA_LEAKAGE:
        if sig.sensitive_path:
            return Decision(
                Action.BLOCK, tc, conf,
                reason=f"{who} attempted to upload a sensitive working directory "
                       f"to {sig.entity or 'a cloud service'}. Block + alert: this "
                       f"could expose sources / case confidentiality.",
                user_message=f"Big V prevented {who} from uploading your working "
                             f"files to {sig.entity or 'a cloud service'}. This "
                             f"could expose confidential information.",
                recommended_step="Choose Block (keep it private) or Allow once.",
                forensics=forensics)
        # Ordinary telemetry/trackers — minimal disruption in Standard.
        return Decision(
            Action.DECEIVE, tc, conf,
            reason=f"Telemetry/tracker flow from {who} to {sig.entity}. Feed fake "
                   f"low-value data instead of breaking the app.",
            forensics=forensics)

    # OTHER
    if conf == Confidence.HIGH:
        return Decision(Action.BLOCK, tc, conf,
                        reason=f"High-severity unclassified signal on {who}; block "
                               f"and alert.",
                        user_message=f"Big V blocked risky activity from {who}.",
                        forensics=forensics)
    return Decision(Action.ALLOW, tc, conf,
                    reason="No threat-class match at low confidence; log only.",
                    forensics=forensics)


def _apply_profile(base: Decision, sig: Signal, tc: ThreatClass,
                   conf: Confidence, profile: Profile) -> Decision:
    """Shift the block-vs-deceive trade-off by profile. Standard = minimal
    disruption; stricter profiles lock down harder. Never DOWNGRADES a
    high-confidence compromise / decoy containment."""
    if profile == Profile.STANDARD:
        return base

    act = base.action

    # High-Risk / Travel / Clean-Room: prefer blocking over deceiving for
    # metadata leakage, and turn low-confidence surveillance ALERTs into blocks.
    if tc == ThreatClass.METADATA_LEAKAGE and act == Action.DECEIVE:
        act = Action.BLOCK
    if tc == ThreatClass.SURVEILLANCE and act == Action.ALERT and profile in (
            Profile.TRAVEL, Profile.CLEAN_ROOM):
        act = Action.BLOCK

    # Clean Room is the most aggressive posture: step medium-confidence
    # compromise/surveillance up one notch (block → contain), because in a
    # clean-room session any targeted signal is treated as hostile.
    if profile == Profile.CLEAN_ROOM and tc in (
            ThreatClass.COMPROMISE, ThreatClass.SURVEILLANCE) and conf != Confidence.LOW:
        act = _step_up(act, 1)

    if act == base.action:
        return base
    return Decision(act, base.threat_class, base.confidence,
                    reason=base.reason + f"  [profile={profile.value}: "
                           f"{base.action.value}→{act.value}]",
                    user_message=base.user_message,
                    recommended_step=base.recommended_step,
                    forensics=base.forensics)


# Categories the analysis engine tags on tracker / telemetry / analytics flows —
# the class where DECEPTION (feed a dead/decoy answer so the app keeps working)
# beats a hard block that could break it.
_DECEIVE_CATEGORIES = frozenset({
    "tracker", "telemetry", "analytics", "advertising", "beacon_telemetry",
})


def should_deceive(category: str, profile: Profile) -> bool:
    """True when a would-be-blocked tracker/telemetry flow should instead be
    DECEIVED — resolved to a decoy dead-end rather than hard-failed.

    Only in Standard (minimal-disruption) profile: a journalist/lawyer on
    High-Risk, Travel, or Clean-Room wants telemetry HARD-blocked, no decoy.
    Pure and profile-aware, matching the decision policy above."""
    return (profile == Profile.STANDARD
            and str(category).strip().lower() in _DECEIVE_CATEGORIES)


def signal_from_incident(inc: dict) -> Signal:
    """Adapt an EDR incident/detection dict onto a Signal."""
    details = inc.get("details") or {}
    labels = tuple(details.get("labels") or inc.get("labels") or ())
    tactics = 0
    chain = details.get("chain") or {}
    if isinstance(chain, dict):
        tactics = int(chain.get("distinct_tactics") or 0)
    return Signal(
        category=str(inc.get("category", "")),
        severity=str(inc.get("severity", "info")),
        labels=labels,
        technique=str(inc.get("technique", "")),
        process_name=str(inc.get("process_name", "")),
        entity=str(inc.get("entity", "")),
        source=str(inc.get("source", "")),
        confidence=details.get("confidence"),
        distinct_tactics=tactics,
        sensitive_path=bool(details.get("sensitive_path")),
    )
