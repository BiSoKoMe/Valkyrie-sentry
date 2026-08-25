"""Which sensors each detector depends on - and what its confidence means
when they are dark.

THE BUG THIS FIXES
------------------
``decision.assess_confidence()`` scores a signal without any knowledge of
whether the sensors that produced or could refute it are actually running.
Right now, on this machine, Sysmon is *stopped* and 45 of 57 controls cannot
be confirmed live - and the engine keeps returning HIGH confidence, because
nothing in the scoring path knows the difference between "I looked and found
nothing contradicting this" and "I could not look".

Those are opposite epistemic states and the second one is currently the more
dangerous, because absence of refutation reads as confirmation. A detector
whose disconfirming evidence is unavailable gets MORE aggressive as the
machine goes blind. That is backwards, and it is live today.

THREE RELATIONSHIPS, NOT ONE
----------------------------
Global coverage (19.3%) is the wrong input - the state of the process sensor
is irrelevant to a pure-DNS detection. What matters is per-detector, and the
relationships behave differently:

``requires``
    Without this sensor the detection cannot be trusted at all. Its input is
    simply missing. Floor the confidence.

``corroborates_with``
    The detection stands on its own but cannot be *strengthened* without this.
    Cap it: never escalate to the top rung on uncorroborated evidence.

``refuted_by``
    The sensor that could prove the detection WRONG. This is the subtle one.
    "the destination was never resolved by this machine" is only meaningful if
    resolution history is actually being recorded; with that sensor dark, a
    hardcoded C2 and a domain Valkyrie merely failed to log are
    indistinguishable. An unfalsifiable claim must count for LESS, not more.

Nothing here executes anything, and :func:`adjust` is pure - sensor state is
passed in, never queried globally, so ``decision.decide()`` stays pure and
every rule below is testable without a running engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

# Sensor liveness, as reported by valkyrie/coverage.py.
STATE_EFFECTIVE = "effective"
STATE_DEGRADED = "degraded"
STATE_ABSENT = "absent"
# A sensor nobody probed at all. Treated exactly as `degraded`: "I do not know"
# is never allowed to read as "fine".
STATE_UNKNOWN = "unknown"

_LIVE = {STATE_EFFECTIVE}


@dataclass(frozen=True)
class SensorDependency:
    """What one detector needs in order for its confidence to mean anything.

    ``detector`` is matched against :attr:`decision.Signal.source` first and
    :attr:`decision.Signal.category` second, so a detector can be registered
    by either its module name or the category it emits.
    """

    detector: str
    requires: tuple[str, ...] = ()
    corroborates_with: tuple[str, ...] = ()
    refuted_by: tuple[str, ...] = ()
    note: str = ""

    def all_sensors(self) -> tuple[str, ...]:
        return tuple({*self.requires, *self.corroborates_with, *self.refuted_by})


_REGISTRY: dict[str, SensorDependency] = {}


def register(dep: SensorDependency) -> SensorDependency:
    _REGISTRY[dep.detector] = dep
    return dep


def get(detector: str) -> Optional[SensorDependency]:
    return _REGISTRY.get(detector)


def all_registered() -> dict[str, SensorDependency]:
    return dict(_REGISTRY)


# ---------------------------------------------------------------------------
#  The registry.
#
#  Kept here rather than as a field on each rule, for the same reason
#  reversibility.py is a registry: a single enumerable table that a test can
#  walk and fail the build over. tests/test_sensor_deps.py asserts every
#  sensor named below is a REAL control id in coverage.py, so a typo or a
#  renamed sensor breaks the build instead of silently disabling a downgrade.
# ---------------------------------------------------------------------------

register(SensorDependency(
    detector="attack_sequence",
    requires=("process_telemetry",),
    corroborates_with=("persistence_telemetry", "network_telemetry",
                       "killchain_correlator"),
    note="A named multi-step sequence is assembled from process events. With "
         "process telemetry dark there is nothing to sequence, so a completed "
         "sequence cannot be produced honestly at all -- and note that "
         "behavioral_sequences currently scores HIGH by construction, which "
         "is exactly the rung that must not be reachable on missing input.",
))

register(SensorDependency(
    detector="behavioral_rules",
    requires=("process_telemetry",),
    corroborates_with=("etw_sysmon", "persistence_telemetry"),
    note="IOA rules read process creation + command lines. On the 4688 "
         "fallback path (Sysmon stopped) parent lineage is weaker, so the "
         "same rule is genuinely less trustworthy than under Sysmon EID 1.",
))

register(SensorDependency(
    detector="network_score",
    requires=("network_telemetry",),
    corroborates_with=("threat_intel", "dga_detector"),
    refuted_by=("dns_tunnel_detector", "cname_uncloak"),
    note="The list-free scorer's strongest signal is 'this destination was "
         "never resolved by this machine'. That is an argument from ABSENCE: "
         "it only holds while resolution history is actually being recorded. "
         "With the DNS-side sensors dark, a hardcoded C2 and a lookup Valkyrie "
         "simply missed look identical, so the signal must weaken.",
))

register(SensorDependency(
    detector="persistence",
    requires=("persistence_telemetry",),
    corroborates_with=("process_telemetry", "asset_inventory"),
    note="A new autostart entry is only anomalous relative to a known "
         "baseline; asset_inventory supplies that baseline.",
))

register(SensorDependency(
    detector="ransomware",
    requires=("ransomware_canaries",),
    corroborates_with=("process_telemetry",),
    note="Canary files are self-contained evidence -- if the canary sensor is "
         "down there is no observation at all, not a weaker one.",
))

register(SensorDependency(
    detector="decoy_trigger",
    requires=(),
    corroborates_with=(),
    note="Deliberately self-contained. Touching a decoy is unambiguous by "
         "construction: nothing legitimate has any reason to read it, so the "
         "signal needs no corroboration and admits no refutation. This entry "
         "exists to say that ON PURPOSE rather than by omission.",
))

register(SensorDependency(
    detector="amsi",
    requires=("amsi_scan",),
    corroborates_with=("process_telemetry",),
    note="Script content comes from the AMSI provider; without it there is no "
         "script body to judge.",
))


# ---------------------------------------------------------------------------
#  Degradation
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Adjustment:
    """Result of applying sensor state to a detector's confidence."""

    notches_down: int          # how far to drop (0 = untouched)
    cap: Optional[str] = None  # hard ceiling, e.g. "medium"
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def clean(self) -> bool:
        return self.notches_down == 0 and self.cap is None


def _dark(state: str) -> bool:
    """True when a sensor cannot be relied on.

    `degraded` counts as dark. coverage.py's own wording for degraded is
    "module present and importable, but no independent liveness probe is
    wired -- cannot confirm it is actually running", and an unconfirmed sensor
    is precisely the case this module refuses to treat as fine.
    """
    return state not in _LIVE


def assess(detector: str,
           sensor_state: Callable[[str], str],
           *, extra_detectors: Iterable[str] = ()) -> Adjustment:
    """Compute the confidence penalty for *detector* given live sensor state.

    ``sensor_state`` maps a control id to one of the STATE_* values. Pure: it
    is injected, never looked up here, so this is testable with a dict and
    ``decision.decide()`` remains a pure function.

    An UNREGISTERED detector returns a clean adjustment. That is deliberate:
    this module must never silently suppress a detection just because nobody
    has written its dependency entry yet. The enumerating test is what applies
    pressure to add entries -- not a runtime penalty that would quietly blunt
    detection.
    """
    names = [detector, *extra_detectors]
    deps = [d for d in (get(n) for n in names if n) if d is not None]
    if not deps:
        return Adjustment(0)

    notches, cap, reasons = 0, None, []
    for dep in deps:
        for s in dep.requires:
            st = sensor_state(s)
            if _dark(st):
                # Missing INPUT, not weaker input. Floor it.
                notches = max(notches, 2)
                cap = "low"
                reasons.append(
                    f"{detector}: required sensor {s!r} is {st} — the input "
                    f"this detection is built from is not confirmed running")
        for s in dep.refuted_by:
            st = sensor_state(s)
            if _dark(st):
                notches = max(notches, 1)
                reasons.append(
                    f"{detector}: {s!r} is {st}, so this detection cannot be "
                    f"refuted — an unfalsifiable claim counts for less, not more")
        for s in dep.corroborates_with:
            st = sensor_state(s)
            if _dark(st):
                if cap != "low":
                    cap = "medium"
                reasons.append(
                    f"{detector}: corroborating sensor {s!r} is {st} — "
                    f"evidence cannot be strengthened, capping confidence")
    return Adjustment(notches, cap, tuple(reasons))
