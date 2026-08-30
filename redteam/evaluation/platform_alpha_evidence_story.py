"""Platform Alpha: one shared evidence story from one real in-process event
chain.

    real event creation
        -> canonical normalization (valkyrie.edr.detection_v2)
        -> Valkyrie/NYX hypothesis evaluation (the same DetectionArchitectureV2
           instance, already fusing both -- see detection_v2.py's own
           "Valkyrie and Nyx share one subject and hypothesis" test)
        -> Aegis observation translation (valkyrie.aegis_bridge)
        -> exposure graph / inference hypotheses (valkyrie.aegis_exposure)

This is not a new reasoning layer. It is a demonstration that the pieces
built across this whole research program (behavior_ontology's translation
boundary, detection_v2's hypothesis engine, NYX's privacy facts sharing that
same engine, and now Aegis's exposure graph consuming the same canonical
events) already form one coherent platform, without merging any of their
verdicts into a single global answer.

## Shared evidence story != shared verdict

The report below deliberately keeps Valkyrie's execution-hypothesis state,
NYX's disclosure-hypothesis state, and Aegis's inference-hypothesis state as
three separate fields. They may agree, partially agree, or point in
different directions for the same causal chain -- that divergence is the
actual value of reasoning over shared context with three different
questions, not a bug to reconcile into one boolean.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))

from valkyrie.aegis_bridge import translate_session  # noqa: E402
from valkyrie.aegis_exposure import evaluate_pair  # noqa: E402
from valkyrie.edr.detection_v2 import (  # noqa: E402
    _ALERT_HYPOTHESES,
    _HYPOTHESES,
    ArchitectureResult,
    DetectionArchitectureV2,
)
from valkyrie.edr.hypothesis import evaluate_hypotheses  # noqa: E402
from valkyrie.telemetry import TelemetryEvent  # noqa: E402

# Facts whose behavior name originates from NYX's own privacy-disclosure
# reasoning inside detection_v2.BehaviorEngine (the PRIVACY event_type
# branch) -- everything else extracted for the same subject is Valkyrie's.
# This is a reporting-only partition; both sets already feed the SAME
# hypothesis engine, they are just labeled here for the evidence story.
_NYX_BEHAVIORS = frozenset({
    "sensitive_data_disclosure", "explicit_user_authority", "disclosure_authority_absent",
})


def build_shared_chain() -> tuple[TelemetryEvent, ...]:
    """One realistic causal chain: a browser process with a suspicious
    ancestry label, followed by a network connection, followed by an
    unauthorized NYX privacy observation -- all attributed to the same
    process instance. This is not a new scenario invented for this demo; it
    mirrors test_detection_architecture_v2.py's own
    test_valkyrie_and_nyx_evidence_share_one_subject_and_hypothesis case.
    """
    return (
        TelemetryEvent(
            category="process", activity="exec", ts=1.0, actor_pid=4242,
            actor_name="browser.exe", source="process_collector",
            labels=["office_child_shell"],
            fields={"create_time": 1.0, "event_id": "evt-proc-1"}),
        TelemetryEvent(
            category="network", activity="connect", ts=2.0, actor_pid=4242,
            actor_name="browser.exe", source="network_collector",
            target={"ip": "203.0.113.9", "domain": "collector.example"},
            fields={"event_id": "evt-net-1"}),
        TelemetryEvent(
            category="privacy", activity="outbound_observation", ts=3.0,
            actor_pid=4242, actor_name="browser.exe", source="nyx.tls",
            target={"domain": "collector.example"}, labels=["nyx_leak"],
            fields={"event_id": "evt-priv-1", "privacy_category": "identifier",
                    "destination_host": "collector.example", "authorized": False}),
    )


def run(events: tuple[TelemetryEvent, ...] | None = None) -> dict:
    events = events if events is not None else build_shared_chain()
    arch = DetectionArchitectureV2()
    results: list[ArchitectureResult] = [arch.observe(e) for e in events]

    all_facts = []
    seen_fact_ids: set[str] = set()
    for r in results:
        for fact in r.facts:
            if fact.fact_id not in seen_fact_ids:
                seen_fact_ids.add(fact.fact_id)
                all_facts.append(fact)

    valkyrie_facts = [f for f in all_facts if f.behavior not in _NYX_BEHAVIORS]
    nyx_facts = [f for f in all_facts if f.behavior in _NYX_BEHAVIORS]
    fused_hypothesis = results[-1].hypothesis   # what the real system actually acts on

    # Isolated views for the evidence story: what would EACH subsystem's own
    # evidence alone conclude, using the identical generic hypothesis
    # machinery. These are reporting-only recomputations -- the real
    # DetectionArchitectureV2 never evaluates them separately; it fuses both
    # sets into `fused_hypothesis` above, exactly as designed.
    valkyrie_only_hypothesis = evaluate_hypotheses(
        _HYPOTHESES, tuple(valkyrie_facts), alert_hypotheses=_ALERT_HYPOTHESES)
    nyx_only_hypothesis = evaluate_hypotheses(
        _HYPOTHESES, tuple(nyx_facts), alert_hypotheses=_ALERT_HYPOTHESES)

    canonical_events = [r.event for r in results]
    exposure_observations = translate_session(canonical_events)
    subject_instance = canonical_events[0].subject.instance_id
    aegis = evaluate_pair(exposure_observations, subject_instance) if exposure_observations else None

    return {
        "what_happened": [e.to_dict() for e in events],
        "causal_process_identity": {
            "instance_id": subject_instance,
            "image": canonical_events[0].subject.image,
            "inferred": canonical_events[0].subject.inferred,
            "confidence": canonical_events[0].subject.confidence,
        },
        "valkyrie": {
            "evidence": [_fact_dict(f) for f in valkyrie_facts],
            "hypothesis_isolated": valkyrie_only_hypothesis.to_dict(),
        },
        "nyx": {
            "evidence": [_fact_dict(f) for f in nyx_facts],
            "hypothesis_isolated": nyx_only_hypothesis.to_dict(),
        },
        "fused_decision": {
            "description": "what the real DetectionArchitectureV2 instance actually "
                           "concluded, fusing Valkyrie's and NYX's evidence together "
                           "-- this, not either isolated view above, is what a real "
                           "deployment would act on.",
            "hypothesis": fused_hypothesis.to_dict(),
        },
        "aegis": {
            "exposure_observations": [o.to_dict() for o in exposure_observations],
            "inference_hypotheses": (
                {hyp: dec for hyp, dec in aegis["decisions"].items()} if aegis else {}
            ),
        },
        "provenance": {
            "canonical_event_ids": [e.event_id for e in canonical_events],
            "valkyrie_fact_provenance": {f.fact_id: f.provenance for f in valkyrie_facts},
            "nyx_fact_provenance": {f.fact_id: f.provenance for f in nyx_facts},
            # A list, not a dict keyed by "category@point" -- this scenario
            # alone has two DESTINATION observations at the same point (one
            # from the network event, one from NYX's privacy event), and a
            # dict key would silently drop one. Every observation keeps its
            # own provenance here, full stop.
            "aegis_observation_provenance": [
                {"category": o.category, "observation_point": o.observation_point,
                 "provenance": o.provenance}
                for o in exposure_observations
            ],
        },
        "note": "valkyrie.hypothesis_isolated, nyx.hypothesis_isolated, "
               "fused_decision.hypothesis, and aegis.inference_hypotheses are "
               "reported SEPARATELY and are never merged into one global verdict -- "
               "see docs/AEGIS_PLATFORM_BRIDGE.md for why that separation is "
               "deliberate.",
    }


def _fact_dict(fact) -> dict:
    return {
        "fact_id": fact.fact_id, "behavior": fact.behavior, "weight": fact.weight,
        "supports": fact.supports, "contradicts": fact.contradicts,
        "provenance": fact.provenance, "explanation": fact.explanation,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2, default=str))
