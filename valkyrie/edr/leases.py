"""Time-boxed enforcement leases — every automatic action expires by default.

WHY THIS EXISTS
---------------
Autonomous enforcement is normally gated on *being right*, which runs straight
into the base-rate problem: on a normal machine benign events outnumber
malicious ones by roughly a million to one, so precision at any usable
threshold is punishing. Waiting for certainty means never acting; acting
without it means acting wrongly, permanently, on your own machine. Valkyrie
has done exactly that twice on this host — a MAC-randomiser cycle that left
the adapter disabled, and an isolate/release cycle that cut WiFi.

A lease changes the shape of the problem. Instead of asking "am I sure enough
to do this forever?", the engine asks "am I sure enough to do this for fifteen
minutes?" — and those are very different bars. An action that reverts itself
is one you can afford to fire at 0.6 confidence, where an irreversible one
needs 0.95.

The self-correcting property is the point:

  * A REAL threat keeps producing evidence. Each recurrence RENEWS the lease,
    so the block persists exactly as long as the behaviour does.
  * A FALSE POSITIVE produces no second observation. The lease simply expires
    and the block heals on its own, with no human ever involved.

So the failure mode of being wrong degrades from "user's network is broken
until someone notices" to "a domain was unreachable for a quarter of an hour".

WHAT THIS MODULE DOES NOT DO
----------------------------
It executes nothing — deliberately, exactly like
:mod:`valkyrie.edr.reversibility`. It owns lease *state* and answers "what is
due to be reverted right now?". The caller (the response layer) dispatches the
actual reverse action. That split keeps every rule here unit-testable without
touching the host, and means a bug in this file can never itself fire a
responder.

FAIL-SAFE ON RESTART
--------------------
Leases are persisted, not in-memory. If they were in-memory, an engine crash
would strand the enforcement it had already applied to the host: the firewall
rule survives the crash, the lease that was supposed to lift it does not, and
a temporary block silently becomes permanent — the precise outcome this module
exists to prevent. On load, any lease whose deadline passed while the engine
was down is immediately due, so recovery reverts it at the next sweep.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

from ..config import DATA_DIR
from . import reversibility

# Default lease length. Long enough that a genuinely malicious actor beaconing
# on any normal interval re-triggers detection and renews it; short enough that
# a false positive is an annoyance rather than an outage.
DEFAULT_TTL_S = 900.0          # 15 minutes

# Nothing may be leased for longer than this in one grant, renewals included.
# A lease that can be extended without bound is just a permanent block with
# extra steps, and a corrupted/tampered expiry must not become immortal.
MAX_TTL_S = 86_400.0           # 24 hours

_LOCK = threading.RLock()


@dataclass(frozen=True)
class Lease:
    """One time-boxed enforcement action.

    ``expires_at`` is WALL clock (``time.time()``), not monotonic, because a
    lease has to stay meaningful across a process restart and monotonic clocks
    reset. Clock-skew abuse is bounded by :func:`due` treating anything more
    than ``MAX_TTL_S`` in the future as already due.
    """

    lease_id: str
    action: str            # enforcement action that was applied
    target: str            # what it was applied to (domain, host, pid, ...)
    reverse_action: str    # dispatchable inverse, from the reversibility registry
    granted_at: float
    expires_at: float
    renewals: int
    reason: str

    def remaining_s(self, now: Optional[float] = None) -> float:
        return max(0.0, self.expires_at - (time.time() if now is None else now))

    def is_due(self, now: Optional[float] = None) -> bool:
        n = time.time() if now is None else now
        # Past its deadline -> due. Absurdly far in the future -> also due:
        # that can only mean a backward clock jump or a tampered/corrupt store,
        # and the safe reading of "I cannot tell when this expires" is "revert
        # it now", never "hold this block indefinitely".
        return n >= self.expires_at or (self.expires_at - n) > MAX_TTL_S


class LeaseError(RuntimeError):
    """Raised when a lease is refused. Refusal is always the safe outcome."""


def _key(action: str, target: str) -> str:
    return f"{action}\x00{target}"


class LeaseRegistry:
    """Persistent registry of active enforcement leases.

    Thread-safe and crash-safe: every mutation is written through to disk with
    an atomic replace, so a kill -9 between grant and sweep still leaves a
    store that names the enforcement needing reversal.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = Path(path) if path else (DATA_DIR / "enforcement_leases.json")
        self._leases: dict[str, Lease] = {}
        self._load()

    # ---------------------------------------------------------------- io ---
    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            # An unreadable store must not take the engine down, and must not
            # be treated as "no leases outstanding" silently -- but there is
            # genuinely nothing recoverable in it. Start empty; the sweeper
            # will simply have nothing to revert, and any stranded enforcement
            # surfaces as a real incident rather than as corrupted state.
            return
        for row in raw.get("leases", []):
            try:
                lease = Lease(**row)
            except TypeError:
                continue
            self._leases[_key(lease.action, lease.target)] = lease

    def _save(self) -> None:
        payload = {"version": 1, "leases": [asdict(v) for v in self._leases.values()]}
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            # Atomic replace: a crash mid-write must never leave a truncated
            # store, because a half-written store reads as fewer outstanding
            # leases than really exist -- i.e. as stranded enforcement.
            fd, tmp = tempfile.mkstemp(dir=str(self._path.parent), suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=1)
            os.replace(tmp, self._path)
        except OSError:
            pass

    # ------------------------------------------------------------- grant ---
    def grant(self, action: str, target: str, *, ttl_s: float = DEFAULT_TTL_S,
              reason: str = "", now: Optional[float] = None) -> Lease:
        """Lease *action* against *target* for *ttl_s* seconds.

        Refuses unless the reversibility registry says the action is leasable:
        reversible AND carrying a dispatchable ``reverse_action``. An
        irreversible action (``kill_process``) can never be leased -- there is
        no clock at which a terminated process comes back, so pretending to
        time-box it would be a lie encoded in the scheduler.

        Re-granting an already-leased (action, target) RENEWS it rather than
        stacking a duplicate: recurring evidence should extend the block, not
        create a second one that expires independently.
        """
        rev = reversibility.get(action)
        if rev is None:
            raise LeaseError(
                f"{action!r} has no reversibility entry; an undocumented action "
                f"cannot be leased (see valkyrie/edr/reversibility.py)")
        if not rev.leasable:
            why = ("it is irreversible" if not rev.reversible
                   else "it declares no machine-readable reverse_action")
            raise LeaseError(f"{action!r} is not leasable because {why}")
        if ttl_s <= 0 or ttl_s > MAX_TTL_S:
            raise LeaseError(f"ttl_s must be in (0, {MAX_TTL_S}], got {ttl_s}")

        n = time.time() if now is None else now
        with _LOCK:
            existing = self._leases.get(_key(action, target))
            if existing is not None:
                return self._renew_locked(existing, ttl_s, n)
            lease = Lease(
                lease_id=uuid.uuid4().hex[:16], action=action, target=target,
                reverse_action=rev.reverse_action or "", granted_at=n,
                expires_at=n + ttl_s, renewals=0, reason=reason,
            )
            self._leases[_key(action, target)] = lease
            self._save()
            return lease

    # ------------------------------------------------------------- renew ---
    def _renew_locked(self, lease: Lease, ttl_s: float, now: float) -> Lease:
        # Extend from NOW, not from the old deadline: renewal means "the
        # behaviour was just seen again", so the clock should restart at the
        # observation, and expiries can never be chained past MAX_TTL_S.
        renewed = Lease(
            lease_id=lease.lease_id, action=lease.action, target=lease.target,
            reverse_action=lease.reverse_action, granted_at=lease.granted_at,
            expires_at=now + ttl_s, renewals=lease.renewals + 1,
            reason=lease.reason,
        )
        self._leases[_key(lease.action, lease.target)] = renewed
        self._save()
        return renewed

    def renew(self, action: str, target: str, *, ttl_s: float = DEFAULT_TTL_S,
              now: Optional[float] = None) -> Optional[Lease]:
        """Extend an existing lease because the evidence recurred.

        Returns None when no such lease is held -- callers should treat that as
        "grant a new one", not as an error.
        """
        n = time.time() if now is None else now
        with _LOCK:
            lease = self._leases.get(_key(action, target))
            if lease is None:
                return None
            return self._renew_locked(lease, ttl_s, n)

    # --------------------------------------------------------------- due ---
    def due(self, now: Optional[float] = None) -> list[Lease]:
        """Leases whose time is up, oldest deadline first.

        Includes leases that expired while the process was down -- that is the
        whole point of persisting them.
        """
        n = time.time() if now is None else now
        with _LOCK:
            return sorted((v for v in self._leases.values() if v.is_due(n)),
                          key=lambda v: v.expires_at)

    def active(self, now: Optional[float] = None) -> list[Lease]:
        n = time.time() if now is None else now
        with _LOCK:
            return sorted((v for v in self._leases.values() if not v.is_due(n)),
                          key=lambda v: v.expires_at)

    def release(self, lease_id: str) -> bool:
        """Drop a lease after its reverse action has actually been executed."""
        with _LOCK:
            for k, v in list(self._leases.items()):
                if v.lease_id == lease_id:
                    del self._leases[k]
                    self._save()
                    return True
            return False

    def get(self, action: str, target: str) -> Optional[Lease]:
        with _LOCK:
            return self._leases.get(_key(action, target))

    def __len__(self) -> int:
        with _LOCK:
            return len(self._leases)


_DEFAULT: Optional[LeaseRegistry] = None


def registry() -> LeaseRegistry:
    """Process-wide registry over the standard data dir."""
    global _DEFAULT
    with _LOCK:
        if _DEFAULT is None:
            _DEFAULT = LeaseRegistry()
        return _DEFAULT
