"""Hard vetoes on autonomous action - things Valkyrie may never do to itself
or its host, at any confidence.

WHY A VETO AND NOT A WEIGHT
---------------------------
Every other gate in the decision path is a matter of degree: confidence goes
up and down, coverage caps it, leases bound how long an action lasts. This one
is categorical. An invariant that could be outvoted by a high-enough score is
not an invariant, it is a strong opinion - and the failure mode being guarded
against is precisely a detector becoming very confident about something
catastrophic. If a rule is expressible as "make this less likely", it belongs
in scoring. Only rules of the form "never, regardless" belong here.

WHY IT SHIPS WITH OPINIONS
--------------------------
The two real outages on this host were both autonomous network actions:

  * a MAC-randomiser cycle left the wireless adapter disabled, and
  * an isolate/release cycle restored the wrong firewall policy and cut WiFi.

Neither was a scoring failure. In both cases the machinery worked exactly as
designed and the design permitted an action that should never have been on the
table. A user should not have to discover "do not let it disable my adapter"
by losing their network twice, so the defaults below are shipped ON and are
not user-removable. Users may ADD invariants; the built-ins are the floor.

The most consequential built-in is not from this project's history at all:
terminating ``lsass.exe`` causes an immediate Windows bugcheck. Credential-
dumping detections point at exactly that process, so an autonomous agent with
a kill responder and a T1003.001 rule is one confident detection away from
blue-screening the machine it is defending. That is a classic EDR footgun and
it is closed here by construction rather than by hoping the score stays low.
"""

from __future__ import annotations

import fnmatch
import json
import threading
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

from ..config import DATA_DIR

_LOCK = threading.RLock()

# Matches any action.
ANY = "*"


@dataclass(frozen=True)
class Invariant:
    """One categorical prohibition.

    ``action`` is an enforcement action name (or :data:`ANY`). ``target_glob``
    is matched case-insensitively against the action's target with
    :func:`fnmatch.fnmatch`, so ``"*wi-fi*"`` and ``"lsass.exe"`` both work.
    """

    invariant_id: str
    action: str
    target_glob: str
    reason: str
    builtin: bool = False

    def matches(self, action: str, target: str) -> bool:
        if self.action != ANY and self.action != action:
            return False
        return fnmatch.fnmatch((target or "").lower(), self.target_glob.lower())


# ---------------------------------------------------------------------------
#  Built-in floor. Not user-removable.
# ---------------------------------------------------------------------------

BUILTINS: tuple[Invariant, ...] = (
    # --- the two incidents that actually happened on this machine ----------
    Invariant(
        "no-adapter-disable", ANY, "*adapter*",
        "No autonomous action may disable, enable or cycle a network adapter. "
        "This host lost its wireless twice to exactly that, and an agent that "
        "takes the network down cannot be reached to be told it was wrong.",
        builtin=True),
    Invariant(
        "no-wifi-touch", ANY, "*wi-fi*",
        "Same rule, matching the adapter by its common Windows name.",
        builtin=True),
    Invariant(
        "no-wireless-touch", ANY, "*wireless*",
        "Same rule, matching the adapter by its other common name.",
        builtin=True),

    # --- self-preservation -------------------------------------------------
    Invariant(
        "no-self-terminate", "kill_process", "valkyrie*",
        "Valkyrie may not kill its own engine. A detector firing on the "
        "agent's own behaviour would otherwise disable the agent, which is "
        "both a self-inflicted outage and an obvious evasion primitive for "
        "anything that can influence what Valkyrie flags.",
        builtin=True),

    # --- OS processes whose termination is fatal to Windows -----------------
    # Killing any of these does not 'stop an attack', it bugchecks or wedges
    # the machine. lsass in particular is the TARGET of credential-dumping
    # detections, so a confident T1003.001 hit points the kill responder
    # straight at it.
    Invariant("no-kill-lsass", "kill_process", "lsass.exe",
              "Terminating lsass.exe causes an immediate Windows bugcheck. "
              "Credential-dumping rules point AT lsass, so this is the single "
              "most reachable catastrophic action in the product.",
              builtin=True),
    Invariant("no-kill-csrss", "kill_process", "csrss.exe",
              "Terminating csrss.exe bugchecks Windows.", builtin=True),
    Invariant("no-kill-wininit", "kill_process", "wininit.exe",
              "Terminating wininit.exe bugchecks Windows.", builtin=True),
    Invariant("no-kill-winlogon", "kill_process", "winlogon.exe",
              "Terminating winlogon.exe destroys the interactive session.",
              builtin=True),
    Invariant("no-kill-services", "kill_process", "services.exe",
              "Terminating services.exe bugchecks Windows.", builtin=True),
    Invariant("no-kill-smss", "kill_process", "smss.exe",
              "Terminating smss.exe bugchecks Windows.", builtin=True),
    Invariant("no-kill-system", "kill_process", "system",
              "The System process cannot be terminated and must never be "
              "targeted.", builtin=True),
    Invariant("no-kill-memcompression", "kill_process", "memory compression",
              "Terminating Memory Compression destabilises the memory manager.",
              builtin=True),
)


class Veto(Exception):
    """Raised when an invariant forbids an action. Never catchable into a retry."""

    def __init__(self, invariant: Invariant, action: str, target: str) -> None:
        super().__init__(
            f"invariant {invariant.invariant_id!r} forbids {action!r} on "
            f"{target!r}: {invariant.reason}")
        self.invariant = invariant
        self.action = action
        self.target = target


def _user_path() -> Path:
    return DATA_DIR / "invariants.json"


def load_user() -> list[Invariant]:
    """User-declared additions. Malformed entries are skipped, never fatal."""
    p = _user_path()
    if not p.exists():
        return []
    try:
        rows = json.loads(p.read_text(encoding="utf-8")).get("invariants", [])
    except (OSError, ValueError):
        return []
    out: list[Invariant] = []
    for row in rows:
        try:
            out.append(Invariant(
                invariant_id=str(row["invariant_id"]),
                action=str(row.get("action", ANY)),
                target_glob=str(row["target_glob"]),
                reason=str(row.get("reason", "user-declared")),
                builtin=False))
        except (KeyError, TypeError, ValueError):
            continue
    return out


def save_user(items: list[Invariant]) -> None:
    """Persist user additions. Built-ins are never written and never removable."""
    rows = [asdict(i) for i in items if not i.builtin]
    p = _user_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"version": 1, "invariants": rows}, indent=1),
                     encoding="utf-8")
    except OSError:
        pass


def all_invariants() -> list[Invariant]:
    """Built-ins first, then user additions. Built-ins always present."""
    with _LOCK:
        return [*BUILTINS, *load_user()]


def check(action: str, target: str) -> Optional[Invariant]:
    """Return the invariant forbidding this action, or None if permitted.

    Checked LAST, after confidence, coverage, leases and budget have all had
    their say - because it is the one gate none of them may overrule.
    """
    for inv in all_invariants():
        if inv.matches(action, target):
            return inv
    return None


def enforce(action: str, target: str) -> None:
    """Raise :class:`Veto` if forbidden. For call sites that must not proceed."""
    inv = check(action, target)
    if inv is not None:
        raise Veto(inv, action, target)
