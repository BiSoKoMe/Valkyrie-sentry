"""CanonicalEvent -> ExposureObservation translation boundary.

Valkyrie and NYX already consume the real canonical-event/hypothesis path
(`valkyrie.edr.detection_v2.CanonicalEvent`, evaluated by
`valkyrie.edr.detection_v2.BehaviorEngine` and `valkyrie.edr.hypothesis`).
This module makes Aegis a consumer of that SAME real event stream instead
of existing only over hand-built synthetic scenario objects -- exactly the
role `valkyrie.edr.behavior_ontology` plays for Valkyrie's own detectors:
a translation boundary, not a merge.

Two things this module will never do:

  1. Change `CanonicalEvent`. If Aegis needs something the schema doesn't
     carry, that gap is named here and in docs/AEGIS_PLATFORM_BRIDGE.md, not
     patched into the shared event model to make this file's job easier.
  2. Let Valkyrie or NYX import anything from here, or from any
     `valkyrie.aegis_*` module. The dependency is one-directional: Aegis
     depends on the canonical event, the canonical event does not know
     Aegis exists.

## The honesty rule

If a canonical exposure fact cannot be derived from what a CanonicalEvent
actually carries today, it is not derived -- never approximated, defaulted,
or invented so an inference has something to fire on. Every observation
this module emits carries `provenance` pointing back to the source event
id(s) and, where available, the process/causal identity that produced it.

## What is honestly derivable today, and what is not

**DESTINATION** -- from `CanonicalEvent.object` when its `kind` is
`"domain"` or `"network"` and `identity` is non-empty. Restricted to event
types that actually leave the host (`DNS`, `NETWORK`, `PRIVACY` -- NYX's own
outbound-disclosure observations). A `PROCESS`/`PERSISTENCE`/`REGISTRY`-only
event never reaches the wire, so it produces NO exposure observation at
all -- not even a weak one. That is a deliberate, tested invariant
(`test_bridge_negative.py`), not an oversight.

**TIMING, FREQUENCY, SEQUENCE** -- only from `translate_session`, given TWO
OR MORE network-visible events sharing one subject. A single event's
absolute timestamp is not itself an "exposure category" in Aegis's pairwise
sense; inter-event intervals, event rate, and event-type ordering are real,
wire-visible properties once more than one connection exists to compare.

**VOLUME, DIRECTION -- not derived.** No field anywhere in the real
telemetry schema carries a byte count or an inbound/outbound flag today
(checked directly against `network_telemetry.py`, `dns_interceptor.py`,
`nyx.py`, and `telemetry.TelemetryEvent`). This is a genuine schema gap, not
an Aegis-specific one -- see docs/AEGIS_PLATFORM_BRIDGE.md for why it was
left alone rather than added to `CanonicalEvent` in this stage.

**IDENTITY, SESSION -- not derived.** `CanonicalEvent.subject.instance_id`
is a real, stable identifier, but it describes Valkyrie's LOCAL, host-side
process attribution -- not something a network-vantage-point observer can
see at all, and it is explicitly bounded to one process's lifetime rather
than a stable cross-session identity. Mapping it directly to Aegis's
IDENTITY (a cross-session, observer-visible identity) or SESSION (an
observer's own ability to segment traffic) would conflate two different
vantage points under one name. Left unavailable rather than approximated --
`instance_id` is used only internally, as this module's own flow-grouping
key, never surfaced as an ExposureObservation's category value.
"""

from __future__ import annotations

from collections.abc import Sequence

from .aegis_exposure import ExposureObservation
from .edr.detection_v2 import CanonicalEvent

# Event types that actually leave the host -- everything else is invisible
# to any network-adjacent observer by construction, regardless of what
# Valkyrie itself knows about it locally.
_NETWORK_VISIBLE_EVENT_TYPES = frozenset({"DNS", "NETWORK", "PRIVACY"})

_DESTINATION_OBJECT_KINDS = frozenset({"domain", "network"})

# Categories this bridge does not derive today, and why -- surfaced
# programmatically (not just in the docstring) so a caller or test can ask
# "what is this bridge honestly NOT claiming" without re-reading prose.
UNAVAILABLE_CATEGORIES: dict[str, str] = {
    "VOLUME": "no byte-count field exists anywhere in the real telemetry "
             "schema today (network_telemetry.py, dns_interceptor.py, nyx.py, "
             "telemetry.TelemetryEvent all checked directly)",
    "DIRECTION": "no inbound/outbound field exists anywhere in the real "
                "telemetry schema today",
    "IDENTITY": "CanonicalEvent.subject.instance_id is local host-side "
               "process attribution, not a cross-session identity a network "
               "observer could see -- mapping it to IDENTITY would conflate "
               "two different vantage points",
    "SESSION": "the same vantage-point conflation as IDENTITY -- an "
              "observer's own ability to segment WIRE traffic into sessions "
              "isn't represented by Valkyrie's internal process-instance "
              "boundary",
}


def _destination_observation(event: CanonicalEvent) -> ExposureObservation | None:
    if event.object.kind not in _DESTINATION_OBJECT_KINDS or not event.object.identity:
        return None
    return ExposureObservation(
        observation_point="HOST_NETWORK_VANTAGE",
        category="DESTINATION",
        flow_id=event.subject.instance_id,
        precision=round(float(event.confidence), 4),
        provenance=(event.event_id,) + event.provenance + (
            f"process:{event.subject.instance_id}",),
    )


def translate_event(event: CanonicalEvent) -> tuple[ExposureObservation, ...]:
    """Translate ONE real CanonicalEvent into zero or more ExposureObservations.

    Returns an empty tuple for any event type outside
    `_NETWORK_VISIBLE_EVENT_TYPES` -- a purely local event (a process launch,
    a registry write, a persistence change) never reaches the wire, so it
    can never honestly become Aegis exposure evidence, regardless of how
    suspicious Valkyrie considers it.
    """
    if event.event_type not in _NETWORK_VISIBLE_EVENT_TYPES:
        return ()
    observations: list[ExposureObservation] = []
    destination = _destination_observation(event)
    if destination is not None:
        observations.append(destination)
    return tuple(observations)


def translate_session(events: Sequence[CanonicalEvent]) -> tuple[ExposureObservation, ...]:
    """Translate a SEQUENCE of real CanonicalEvents sharing one subject into
    exposure observations, adding TIMING/FREQUENCY/SEQUENCE on top of what
    `translate_event` derives per event -- these three categories are only
    honestly meaningful across more than one observed connection.

    Events for more than one subject are grouped by `subject.instance_id`
    and each group is translated independently; the grouping key itself is
    never exposed as an observation (see module docstring).
    """
    by_subject: dict[str, list[CanonicalEvent]] = {}
    for event in events:
        by_subject.setdefault(event.subject.instance_id, []).append(event)

    all_observations: list[ExposureObservation] = []
    for instance_id, group in by_subject.items():
        network_visible = [e for e in group if e.event_type in _NETWORK_VISIBLE_EVENT_TYPES]
        for event in network_visible:
            all_observations.extend(translate_event(event))
        if len(network_visible) < 2:
            continue

        ordered = sorted(network_visible, key=lambda e: e.timestamp)
        times = [e.timestamp for e in ordered]
        duration = times[-1] - times[0]
        provenance = tuple(e.event_id for e in ordered) + (f"process:{instance_id}",)
        # Confidence in these three categories is bounded by the WEAKEST
        # subject-attribution confidence in the group -- an observer cannot
        # be more certain about a timing/frequency/sequence pattern than it
        # is about which events actually belong together in the first place.
        group_confidence = min((e.confidence for e in ordered), default=0.0)

        if duration > 0:
            all_observations.append(ExposureObservation(
                "HOST_NETWORK_VANTAGE", "TIMING", instance_id,
                precision=round(group_confidence, 4), provenance=provenance))
            all_observations.append(ExposureObservation(
                "HOST_NETWORK_VANTAGE", "FREQUENCY", instance_id,
                precision=round(group_confidence, 4), provenance=provenance))
        # `network_visible` was already required to have >=2 entries to reach
        # this point, so an ordering always exists to observe.
        all_observations.append(ExposureObservation(
            "HOST_NETWORK_VANTAGE", "SEQUENCE", instance_id,
            precision=round(group_confidence, 4), provenance=provenance))

    return tuple(all_observations)
