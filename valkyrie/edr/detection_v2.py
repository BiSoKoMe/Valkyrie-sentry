"""Deterministic Detection Architecture v2 shadow pipeline.

The production detector still owns enforcement.  This module runs beside it
and answers a narrower research question: can one canonical event language,
generic behavioral evidence, and competing explanations generalize beyond a
single rule without retaining Nyx content or silently gaining authority?

The fast path is bounded and synchronous.  Longer analysis is queued in a
bounded deque and must be drained explicitly.  Nothing here performs I/O,
opens an incident, or executes a response.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import OrderedDict, deque
from dataclasses import asdict, dataclass, field
from typing import Any

from .hypothesis import EvidenceFact, HypothesisDecision, HypothesisSpec, evaluate_hypotheses

MAX_ENTITIES = 4096
MAX_LEDGER_ENTRIES = 2048
MAX_ANALYTICS_QUEUE = 4096
MAX_FACTS_PER_ENTITY = 64

_PRIVACY_ALLOWED = frozenset({
    "artifact_kind", "event_id", "privacy_category", "destination_host",
    "first_party_origin", "attribution_confidence", "authority",
    "authorized", "trusted_gesture", "consent_state",
})
_CONTENT_KEYS = frozenset({
    "body", "content", "cookie", "cookies", "dom", "form_value",
    "keystroke", "masked_sample", "query", "raw", "sample", "url",
    "value", "values",
})


def _text(value: Any) -> str:
    return str(value or "").strip()


def _stable_id(payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         default=str).encode("utf-8", "replace")
    return hashlib.blake2s(encoded, digest_size=12).hexdigest()


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    create_time: float
    image: str
    instance_id: str
    confidence: float
    inferred: bool = False


@dataclass(frozen=True)
class CanonicalObject:
    kind: str
    identity: str
    properties: dict = field(default_factory=dict)


@dataclass(frozen=True)
class CanonicalEvent:
    event_id: str
    timestamp: float
    event_type: str
    subject: ProcessIdentity
    object: CanonicalObject
    operation: str
    properties: dict
    provenance: tuple[str, ...]
    confidence: float

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ArchitectureResult:
    event: CanonicalEvent
    facts: tuple[EvidenceFact, ...]
    hypothesis: HypothesisDecision
    recommended_action: str
    enforcement_authorized: bool
    fast_path_ms: float
    analytics_queued: bool

    def to_dict(self) -> dict:
        return {
            "event": self.event.to_dict(),
            "facts": [asdict(fact) for fact in self.facts],
            "hypothesis": self.hypothesis.to_dict(),
            "recommended_action": self.recommended_action,
            "enforcement_authorized": self.enforcement_authorized,
            "fast_path_ms": self.fast_path_ms,
            "analytics_queued": self.analytics_queued,
        }


class EntityStore:
    """Bounded process-instance identity and local-neighborhood index."""

    def __init__(self, max_entities: int = MAX_ENTITIES) -> None:
        self.max_entities = max(16, int(max_entities))
        self._entities: OrderedDict[str, ProcessIdentity] = OrderedDict()
        self._latest_pid: dict[int, str] = {}

    def resolve(self, event: dict) -> ProcessIdentity:
        pid = int(event.get("actor_pid", 0) or 0)
        image = _text(event.get("actor_path") or event.get("actor_name")).lower()
        fields = event.get("fields") if isinstance(event.get("fields"), dict) else {}
        create_time = float(fields.get("create_time") or 0.0)
        is_start = (_text(event.get("category")).lower() == "process"
                    and _text(event.get("activity")).lower() == "exec")
        if not create_time and is_start and _text(event.get("source")) == "process_collector":
            create_time = float(event.get("ts") or 0.0)

        inferred = not bool(pid and create_time and image)
        if create_time:
            instance_id = f"process:{pid}/{create_time:.6f}"
        elif pid in self._latest_pid:
            instance_id = self._latest_pid[pid]
            existing = self._entities.get(instance_id)
            if existing is not None:
                self._entities.move_to_end(instance_id)
                return existing
        else:
            instance_id = f"process:{pid}/unknown"

        confidence = 1.0 if not inferred else (0.60 if pid and image else 0.25)
        identity = ProcessIdentity(pid, create_time, image, instance_id,
                                   confidence, inferred)
        self._entities[instance_id] = identity
        self._entities.move_to_end(instance_id)
        if pid:
            self._latest_pid[pid] = instance_id
        while len(self._entities) > self.max_entities:
            old_key, old = self._entities.popitem(last=False)
            if self._latest_pid.get(old.pid) == old_key:
                self._latest_pid.pop(old.pid, None)
        return identity

    def status(self) -> dict:
        return {"entities": len(self._entities), "max_entities": self.max_entities}


class EventNormalizer:
    """Convert TelemetryEvent-shaped input into one stable internal language."""

    def __init__(self, entities: EntityStore) -> None:
        self.entities = entities

    def normalize(self, raw: Any) -> CanonicalEvent:
        event = raw.to_dict() if hasattr(raw, "to_dict") else dict(raw)
        category = _text(event.get("category")).lower() or "unknown"
        operation = _text(event.get("activity")).lower() or "observe"
        target = event.get("target") if isinstance(event.get("target"), dict) else {}
        fields = event.get("fields") if isinstance(event.get("fields"), dict) else {}
        subject = self.entities.resolve(event)

        object_kind, object_identity = self._object(category, target, fields)
        if category == "privacy":
            safe_fields = {key: fields[key] for key in _PRIVACY_ALLOWED
                           if key in fields and fields[key] not in (None, "")}
            safe_target = {key: value for key, value in target.items()
                           if key in ("domain", "host", "origin")}
        else:
            safe_fields = {key: value for key, value in fields.items()
                           if str(key).lower() not in _CONTENT_KEYS}
            safe_target = {key: value for key, value in target.items()
                           if str(key).lower() not in _CONTENT_KEYS}
        properties = {
            "action": _text(event.get("action")).lower(),
            "severity": _text(event.get("severity")).lower(),
            "labels": tuple(sorted({_text(v).lower() for v in event.get("labels") or [] if _text(v)})),
            "target": safe_target,
            "fields": safe_fields,
        }
        identity_payload = {
            "ts": float(event.get("ts") or 0.0), "type": category,
            "subject": subject.instance_id, "object": object_identity,
            "operation": operation, "source": _text(event.get("source")),
            "source_event_id": _text(fields.get("event_id")),
        }
        event_id = _text(fields.get("event_id")) or f"evt:{_stable_id(identity_payload)}"
        confidence = subject.confidence
        attribution = fields.get("attribution_confidence")
        if attribution not in (None, ""):
            try:
                confidence = min(confidence, max(0.0, min(1.0, float(attribution))))
            except (TypeError, ValueError):
                confidence = min(confidence, 0.50)
        return CanonicalEvent(
            event_id=event_id,
            timestamp=float(event.get("ts") or 0.0),
            event_type=category.upper(),
            subject=subject,
            object=CanonicalObject(object_kind, object_identity, safe_target),
            operation=operation,
            properties=properties,
            provenance=tuple(v for v in (_text(event.get("source")), category) if v),
            confidence=round(confidence, 4),
        )

    @staticmethod
    def _object(category: str, target: dict, fields: dict) -> tuple[str, str]:
        candidates = (
            ("domain", target.get("domain") or fields.get("destination_host")),
            ("network", target.get("ip")),
            ("file", target.get("path")),
            ("registry", target.get("location") or fields.get("identity")),
        )
        for kind, value in candidates:
            if value not in (None, ""):
                return kind, _text(value).lower()
        return category, ""


_HYPOTHESES = (
    HypothesisSpec("ordinary_activity", "Normal application or user activity", 0.60, 1),
    HypothesisSpec("administrative_activity", "Expected administrative or maintenance work", 0.62, 1),
    HypothesisSpec("suspicious_execution_chain", "A suspicious execution chain is developing", 0.68, 2),
    HypothesisSpec("persistence_attempt", "A process is attempting durable persistence", 0.72, 2),
    HypothesisSpec("possible_data_theft", "Sensitive data may be leaving without authority", 0.72, 2),
)
_ALERT_HYPOTHESES = frozenset({
    "suspicious_execution_chain", "persistence_attempt", "possible_data_theft",
})


class BehaviorEngine:
    """Translate normalized context into reusable facts, not verdicts."""

    _EXECUTION_LABELS = frozenset({
        "lolbin", "office_child_shell", "encoded_powershell", "download_cradle",
        "dynamic_exec", "obfuscation", "remote_thread_injection", "process_tampering",
    })
    _TRUST_LABELS = frozenset({
        "trusted", "trusted_os_path", "signed", "known_admin", "expected_maintenance",
    })

    def extract(self, event: CanonicalEvent, causal_subgraph: dict | None = None) -> tuple[EvidenceFact, ...]:
        facts: list[EvidenceFact] = []
        labels = set(event.properties.get("labels") or ())
        prefix = event.event_id

        def add(behavior: str, weight: float, *, supports=(), contradicts=(),
                explanation: str, blocks: bool = False) -> None:
            facts.append(EvidenceFact(
                f"{prefix}:{behavior}", behavior, weight,
                supports=tuple(supports), contradicts=tuple(contradicts),
                provenance=(event.event_id,) + event.provenance,
                explanation=explanation, blocks_decision=blocks,
            ))

        if event.subject.inferred or event.confidence < 0.50:
            add("incomplete_process_identity", 1.0,
                explanation="Process identity lacks authoritative creation metadata",
                blocks=True)
        if labels & self._EXECUTION_LABELS:
            add("unexpected_process_relationship", 0.74,
                supports=("suspicious_execution_chain",),
                contradicts=("ordinary_activity",),
                explanation="Execution context contains a reusable suspicious relationship primitive")
        if event.event_type == "PERSISTENCE":
            add("sensitive_configuration_modified", 0.78,
                supports=("persistence_attempt", "suspicious_execution_chain"),
                contradicts=("ordinary_activity",),
                explanation="An autostart or durable configuration object changed")
        if event.event_type in ("DNS", "NETWORK"):
            add("external_communication", 0.50,
                supports=("suspicious_execution_chain", "possible_data_theft"),
                explanation="A process communicated with an external destination")
        if event.event_type == "PRIVACY":
            add("sensitive_data_disclosure", 0.82,
                supports=("possible_data_theft",),
                contradicts=("ordinary_activity",),
                explanation="Nyx observed a metadata-only sensitive category crossing a boundary")
            fields = event.properties.get("fields") or {}
            authorized = fields.get("authorized") is True or _text(fields.get("authority")).lower() in {
                "authorized", "allow", "present",
            }
            if authorized:
                add("explicit_user_authority", 0.90,
                    supports=("ordinary_activity",),
                    contradicts=("possible_data_theft",),
                    explanation="A trusted local authority signal permits this disclosure")
            else:
                add("disclosure_authority_absent", 0.76,
                    supports=("possible_data_theft",),
                    explanation="No trusted local authority signal accompanied the disclosure")
        if labels & self._TRUST_LABELS:
            add("trusted_maintenance_context", 0.84,
                supports=("administrative_activity",),
                contradicts=("suspicious_execution_chain", "persistence_attempt"),
                explanation="Signed or expected maintenance context explains the behavior")
        if "trusted_gesture" in labels or "user_initiated" in labels:
            add("active_user_context", 0.72,
                supports=("ordinary_activity",),
                contradicts=("possible_data_theft", "suspicious_execution_chain"),
                explanation="A trusted user interaction is causally nearby")

        if causal_subgraph:
            if (causal_subgraph.get("truncated") or causal_subgraph.get("evicted")
                    or causal_subgraph.get("inferred_nodes")):
                add("incomplete_causal_context", 1.0,
                    explanation="Causal state is truncated, inferred, or evicted",
                    blocks=True)
            elif causal_subgraph.get("found") and len(causal_subgraph.get("tree") or ()):
                add("observed_causal_chain", 0.58,
                    supports=("suspicious_execution_chain",),
                    explanation="Observed parent-child state connects this event to a process chain")
        return tuple(facts)


class DetectionArchitectureV2:
    """Bounded shared evidence fabric for Valkyrie and Nyx."""

    def __init__(self) -> None:
        self.entities = EntityStore()
        self.normalizer = EventNormalizer(self.entities)
        self.behaviors = BehaviorEngine()
        self._facts: OrderedDict[str, deque[EvidenceFact]] = OrderedDict()
        self._ledger: deque[ArchitectureResult] = deque(maxlen=MAX_LEDGER_ENTRIES)
        self._analytics: deque[CanonicalEvent] = deque(maxlen=MAX_ANALYTICS_QUEUE)
        self._shapes: OrderedDict[str, int] = OrderedDict()
        self._analytics_processed = 0
        self._events = 0
        self._deduplicated = 0
        self._seen: OrderedDict[str, None] = OrderedDict()

    def observe(self, raw: Any, *, causal_subgraph: dict | None = None) -> ArchitectureResult:
        started = time.perf_counter_ns()
        event = self.normalizer.normalize(raw)
        subject = event.subject.instance_id
        facts = self.behaviors.extract(event, causal_subgraph)
        duplicate = event.event_id in self._seen
        if duplicate:
            self._deduplicated += 1
        else:
            self._seen[event.event_id] = None
            self._seen.move_to_end(event.event_id)
            while len(self._seen) > MAX_LEDGER_ENTRIES * 2:
                self._seen.popitem(last=False)
            bucket = self._facts.setdefault(subject, deque(maxlen=MAX_FACTS_PER_ENTITY))
            known = {fact.fact_id for fact in bucket}
            bucket.extend(fact for fact in facts if fact.fact_id not in known)
            self._facts.move_to_end(subject)
            while len(self._facts) > MAX_ENTITIES:
                self._facts.popitem(last=False)
            self._analytics.append(event)
            self._events += 1

        current = tuple(self._facts.get(subject, ()))
        hypothesis = evaluate_hypotheses(
            _HYPOTHESES, current, alert_hypotheses=_ALERT_HYPOTHESES,
            minimum_margin=0.08,
        )
        recommended = "alert" if hypothesis.alerts else "observe"
        if hypothesis.alerts and hypothesis.confidence >= 0.92:
            recommended = "prevent"
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0
        result = ArchitectureResult(
            event=event, facts=facts, hypothesis=hypothesis,
            recommended_action=recommended,
            # Shadow mode is structural. Only the existing policy, authority,
            # invariants, and playbook layers can authorize enforcement.
            enforcement_authorized=False,
            fast_path_ms=round(elapsed_ms, 4),
            analytics_queued=not duplicate,
        )
        self._ledger.append(result)
        return result

    def drain_analytics(self, budget: int = 128) -> tuple[CanonicalEvent, ...]:
        count = max(0, min(int(budget), len(self._analytics)))
        return tuple(self._analytics.popleft() for _ in range(count))

    def run_analytics(self, budget: int = 128) -> int:
        """Update bounded local shape counts outside the event fast path."""
        events = self.drain_analytics(budget)
        for event in events:
            shape = "|".join((
                event.event_type,
                event.operation,
                event.subject.image,
                event.object.kind,
            ))
            self._shapes[shape] = self._shapes.get(shape, 0) + 1
            self._shapes.move_to_end(shape)
            while len(self._shapes) > MAX_ENTITIES:
                self._shapes.popitem(last=False)
        self._analytics_processed += len(events)
        return len(events)

    def ledger(self, limit: int = 100) -> list[dict]:
        return [item.to_dict() for item in list(self._ledger)[-max(0, int(limit)):]]

    def status(self) -> dict:
        return {
            "mode": "shadow",
            "events": self._events,
            "deduplicated": self._deduplicated,
            "subjects": len(self._facts),
            "ledger_entries": len(self._ledger),
            "analytics_queued": len(self._analytics),
            "analytics_processed": self._analytics_processed,
            "behavior_shapes": len(self._shapes),
            **self.entities.status(),
        }
