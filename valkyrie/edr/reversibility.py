"""Reversibility registry for every Valkyrie enforcement action.

IIBA/IEEE's *Cybersecurity Analysis* handbook (§4.2.5) states the questions
every control must answer before it is trusted to fire automatically:

    Can it be backed out in event of an issue?
    Does it create no additional issues during operation?
    Does it leave no residual data?

Valkyrie has failed this twice for real, on this machine, not hypothetically:

  * ``mac_randomizer`` wrote the Windows ``NetworkAddress`` registry value and
    cycled the adapter; when the enable half of that cycle failed for a reason
    other than a timeout, nothing re-enabled the adapter (see
    ``docs/MAC_DIAGNOSIS_REPORT.md`` and the fix in ``mac_randomizer.py``'s
    ``_apply_windows``).
  * A live-firewall isolate/release cycle left this host's WiFi cut, because
    ``release_isolation`` reset the firewall to a *hardcoded* policy
    (``blockinbound,allowoutbound``) instead of whatever policy actually
    existed before isolation - restoring the wrong state is not a rollback.

This module is the single place that answers, for every enforcement action
Valkyrie can take: is it reversible, by what *exact* call, what does it leave
behind if the process dies mid-action, and what happens if it fires on a
false positive. ``tests/test_responder_reversibility.py`` enumerates every
registered responder action and fails the build if one is missing an entry
here - an audited responder cannot go undocumented by accident.

Nothing in this module executes anything. It is a data registry.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Reversibility:
    """The reversibility contract for one enforcement action.

    ``min_severity`` is the hard floor :class:`~valkyrie.edr.response.ResponseManager`
    enforces before it will run this action for real (``dry_run=False``) - see
    ``ResponseManager._floor_check``. Irreversible actions get a stricter floor
    than reversible ones by construction (see ``register()``).
    """

    action: str
    reversible: bool
    #  Exact call/action that undoes this one. Required when reversible=True;
    #  for reversible=False this documents the *closest* mitigation available
    #  (e.g. "none - see backup/restore snapshot" or "" when truly nothing
    #  can be done), so it is allowed to be non-empty either way but the
    #  invariant below only requires it when reversible.
    rollback: str
    # What state survives if the process dies mid-action (before it can
    # confirm success/failure or write the audit row).
    residual_on_crash: str
    # What happens to a benign target if this fires on a false positive.
    false_positive_impact: str
    # Hard floor: ResponseManager refuses dry_run=False below this severity.
    min_severity: str = "high"
    #  MACHINE-READABLE inverse: the registered action name that undoes this
    #  one, e.g. "unblock_domain" for "block_domain". ``rollback`` above is
    #  prose for a human reading an audit; this is what code can dispatch.
    #  Required for an action to be LEASABLE (see valkyrie/edr/leases.py):
    #  a time-boxed lease must know what to fire when the clock runs out, and
    #  a prose sentence is not something a sweeper can execute. Optional so
    #  that documenting an action stays cheap -- an action without it is
    #  simply never granted a lease, which is the safe default.
    reverse_action: Optional[str] = None

    def __post_init__(self) -> None:
        if self.reversible and not self.rollback.strip():
            raise ValueError(
                f"{self.action}: reversible=True requires a non-empty rollback description")
        if self.reverse_action and not self.reversible:
            # An irreversible action cannot have an inverse by definition; if
            # one is named, one of the two fields is wrong and silently
            # trusting either would let a lease "undo" a kill.
            raise ValueError(
                f"{self.action}: reversible=False cannot declare "
                f"reverse_action={self.reverse_action!r}")

    @property
    def leasable(self) -> bool:
        """True when this action can be granted a time-boxed lease.

        Reversible AND with a dispatchable inverse. Anything else must be a
        permanent decision made at its full severity floor.
        """
        return self.reversible and bool(self.reverse_action)


_REGISTRY: dict[str, Reversibility] = {}

# Actions marked reversible=False must clear a strictly higher bar than the
# responder's own advertised floor - an author cannot quietly ship an
# irreversible action at "medium" by only setting min_severity on the entry.
_IRREVERSIBLE_MIN_FLOOR = "critical"
_REVERSIBLE_MIN_FLOOR = "low"


def register(r: Reversibility) -> Reversibility:
    """Add *r* to the registry. Raises if the floor doesn't match its class.

    Called at import time by every module that defines a responder - see
    ``valkyrie/edr/response.py`` bottom and ``valkyrie/mac_randomizer.py``'s
    entries registered from ``valkyrie/edr/reversibility_audit.py``.
    """
    from .schema import severity_rank
    floor = _IRREVERSIBLE_MIN_FLOOR if not r.reversible else _REVERSIBLE_MIN_FLOOR
    if severity_rank(r.min_severity) < severity_rank(floor):
        raise ValueError(
            f"{r.action}: reversible={r.reversible} requires min_severity >= "
            f"{floor!r}, got {r.min_severity!r}")
    _REGISTRY[r.action] = r
    return r


def get(action: str) -> Optional[Reversibility]:
    return _REGISTRY.get(action)


def all_registered() -> dict[str, Reversibility]:
    return dict(_REGISTRY)


def is_documented(action: str) -> bool:
    return action in _REGISTRY
