"""Composition: how much authority does Valkyrie actually have, right now,
for this one action?

THE MODEL
---------
``decision.decide()`` answers "what does the evidence justify?" on a single
axis. That is necessary and not sufficient. Authority to act WITHOUT A HUMAN
is a function of four independent variables, and the action taken is the
MINIMUM any of them permits::

    permitted = min(
        evidence,       # decision.decide() -- how strong, how corroborated
        coverage,       # sensor_deps -- can I confirm the relevant sensors live?
        consequence,    # reversibility/leases -- reversible? leasable?
        budget,         # cascade guard -- have I already acted a lot?
    )
    action = veto(permitted, invariants)   # categorical, overrules everything

Independence is the point. Each gate degrades on its own, none can be talked
out of its objection by another being confident, and each is testable alone.
A high-confidence detection on dark sensors is not authorised. A perfectly
corroborated one that would disable the network adapter is not authorised. The
gates do not average -- they take the floor.

WHY THE FLOOR AND NOT A SCORE
-----------------------------
Blending these into one number is the obvious design and it is wrong. A single
score lets a very strong signal on one axis buy authority it has not earned on
another -- which is exactly how an agent ends up very confidently doing
something catastrophic. Taking the minimum means every gate holds a veto over
escalation, and only the invariant layer holds a veto over acting at all.

Pure. Sensor state, budget and clock are injected; nothing is queried
globally, and this module executes no responder.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from ..decision import (Action, Confidence, Decision, Signal,
                        _ACTION_ORDER, apply_sensor_state, assess_confidence)
from . import invariants, leases, reversibility

# Actions at or above this rung actually change host state; below it Valkyrie
# only observes and tells the user. The gates only ever push DOWN toward this
# line -- authority is never manufactured here, only removed.
_ENFORCING = {Action.BLOCK, Action.CONTAIN}


def _down(action: Action, notches: int) -> Action:
    if notches <= 0:
        return action
    return _ACTION_ORDER[max(0, _ACTION_ORDER.index(action) - notches)]


def _cap(action: Action, ceiling: Action) -> Action:
    if _ACTION_ORDER.index(action) > _ACTION_ORDER.index(ceiling):
        return ceiling
    return action


@dataclass(frozen=True)
class Authority:
    """What Valkyrie is actually permitted to do, and why it is not more."""

    action: Action                  # permitted -- may be below `requested`
    requested: Action               # what the evidence alone justified
    lease_ttl_s: Optional[float]    # set when the action must be time-boxed
    vetoed: bool
    limited_by: tuple[str, ...] = field(default_factory=tuple)
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def downgraded(self) -> bool:
        return self.action != self.requested

    @property
    def enforces(self) -> bool:
        return self.action in _ENFORCING

    def to_dict(self) -> dict:
        return {
            "action": self.action.value,
            "requested": self.requested.value,
            "downgraded": self.downgraded,
            "vetoed": self.vetoed,
            "lease_ttl_s": self.lease_ttl_s,
            "limited_by": list(self.limited_by),
            "reasons": list(self.reasons),
        }


def authorize(sig: Signal, decision: Decision, *,
              target: str = "",
              responder: str = "",
              sensor_state: Optional[Callable[[str], str]] = None,
              budget_permits: Optional[Callable[[], tuple]] = None,
              observed_interval_s: Optional[float] = None) -> Authority:
    """Reduce *decision* to what may actually be done autonomously.

    ``sensor_state``   coverage control id -> sensor_deps.STATE_*  (None = skip)
    ``budget_permits`` () -> (allowed: bool, reason: str)          (None = skip)
    ``target``         what the action would be applied to; required for the
                       invariant check to mean anything.
    ``responder``      the concrete responder this authorisation is for. The
                       ``Action -> responder`` map below is only a DEFAULT: it
                       assumes one action means one responder, which stops
                       being true the moment a caller plans several distinct
                       remediations (kill / block / de-persist) that all
                       descend from a single BLOCK decision. Passing the
                       responder explicitly makes the consequence and
                       invariant gates judge THAT responder's cost, which is
                       the only way per-action authority can differ - e.g. an
                       invariant vetoing one domain while permitting another.
                       Empty (the default) preserves the map behaviour exactly.

    Every gate is optional and skipping one is a NO-OP rather than an implicit
    pass, so this can be adopted incrementally without any gate silently
    granting authority it was never asked about.
    """
    requested = decision.action
    action = requested
    limited: list[str] = []
    reasons: list[str] = []

    # ---- gate 2: coverage ------------------------------------------------
    # Evidence (gate 1) is already baked into `decision`. Re-derive the raw
    # confidence so the degradation can be measured as a delta and applied to
    # the action ladder, rather than re-entering decide() and risking a
    # different answer for a different reason.
    if sensor_state is not None:
        raw = assess_confidence(sig)
        adjusted, why = apply_sensor_state(raw, sig, sensor_state)
        drop = _conf_index(raw) - _conf_index(adjusted)
        if drop > 0:
            action = _down(action, drop)
            limited.append("coverage")
            reasons.extend(why)

    # ---- gate 3: consequence --------------------------------------------
    # An enforcing action must either be leasable (so it self-reverts) or
    # clear its own severity floor. An irreversible action with no lease is
    # the one shape that must never be reached by degradation alone.
    lease_ttl: Optional[float] = None
    if action in _ENFORCING:
        act_name = responder or _ACTION_TO_RESPONDER.get(action, "")
        rev = reversibility.get(act_name) if act_name else None
        if rev is not None and rev.leasable:
            lease_ttl = leases.ttl_for(sig.source or "",
                                       observed_interval_s=observed_interval_s)
        elif rev is not None and not rev.reversible:
            # Irreversible: authority requires the evidence to stand on its
            # own, not to have arrived here after being degraded.
            if "coverage" in limited:
                action = _cap(action, Action.ALERT)
                limited.append("consequence")
                reasons.append(
                    f"{act_name!r} is irreversible and cannot be time-boxed; "
                    f"it may not be reached by an already-degraded signal")

    # ---- gate 4: budget --------------------------------------------------
    if budget_permits is not None and action in _ENFORCING:
        allowed, why = budget_permits()
        if not allowed:
            action = _cap(action, Action.ALERT)
            lease_ttl = None
            limited.append("budget")
            reasons.append(why or "enforcement budget exhausted")

    # ---- veto: invariants ------------------------------------------------
    # Last, and categorical. Nothing above may overrule it.
    vetoed = False
    if action in _ENFORCING:
        act_name = responder or _ACTION_TO_RESPONDER.get(action, "")
        inv = invariants.check(act_name, target) if act_name else None
        if inv is None and target:
            inv = invariants.check(invariants.ANY, target)
        if inv is not None:
            action = _cap(action, Action.ALERT)
            lease_ttl = None
            vetoed = True
            limited.append("invariant")
            reasons.append(f"invariant {inv.invariant_id!r}: {inv.reason}")

    return Authority(action=action, requested=requested, lease_ttl_s=lease_ttl,
                     vetoed=vetoed, limited_by=tuple(limited),
                     reasons=tuple(reasons))


_CONF_ORDER = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]


def _conf_index(c: Confidence) -> int:
    return _CONF_ORDER.index(c)


# Which responder each policy Action would dispatch. Kept here rather than on
# Action itself so decision.py stays free of any responder knowledge -- the
# policy decides WHAT should happen, this layer knows what that costs.
_ACTION_TO_RESPONDER = {
    Action.BLOCK: "block_domain",
    Action.CONTAIN: "isolate_host",
}
