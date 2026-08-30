"""Deterministic, local authority for privacy-sensitive browser egress.

This module answers a deliberately small question: did this outbound browser
action carry a fresh, scoped causal grant created by a trusted local gesture?
It does not inspect content, query reputation, call AI, or execute a response.

Raw values belong in the browser capture compartment.  Callers pass only
coarse data labels and origins.  Grants are one-shot, short-lived, and kept in
memory so there is nothing useful to upload or recover from disk.
"""

from __future__ import annotations

import heapq
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Iterable
from urllib.parse import urlsplit


DEFAULT_GRANT_TTL_S = 2.0
MAX_GRANT_TTL_S = 10.0
MAX_PENDING_GRANTS = 1024
MAX_CONSUMED_IDS = 4096

DATA_LABELS = frozenset({
    "ordinary",
    "email",
    "credential",
    "phone",
    "address",
    "payment",
    "government_id",
    "health",
    "file",
    "clipboard",
})

GRANT_ACTIONS = frozenset({"form_submit"})


class EgressDisposition(str, Enum):
    """The verifier's answer, separate from whether enforcement is enabled."""

    ALLOW = "allow"
    REFUSE = "refuse"


def normalize_labels(values: Iterable[object]) -> frozenset[str]:
    """Return the controlled, bounded label set represented by *values*."""
    labels = {str(value).strip().lower() for value in values}
    return frozenset(label for label in labels if label in DATA_LABELS)


def valid_uuid(value: object) -> str:
    """Return a canonical UUID or an empty string for invalid identifiers."""
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        return ""


def canonical_origin(value: object) -> str:
    """Return a canonical HTTP(S) origin or an empty string."""
    if not isinstance(value, str) or len(value) > 4096:
        return ""
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    host = parsed.hostname.lower().rstrip(".")
    if not host or len(host) > 253:
        return ""
    default_port = 80 if parsed.scheme == "http" else 443
    suffix = "" if port in {None, default_port} else f":{port}"
    return f"{parsed.scheme}://{host}{suffix}"


@dataclass(frozen=True)
class AuthorityGrant:
    """One local, one-shot permission derived from a trusted browser gesture."""

    grant_id: str
    interaction_id: str
    source_origin: str
    destination_origin: str
    tab_id: int
    frame_id: int
    action: str
    data_labels: frozenset[str]
    issued_at: float
    expires_at: float


@dataclass(frozen=True)
class EgressRequest:
    """Metadata-only description of an outbound action awaiting authority."""

    request_id: str
    interaction_id: str
    source_origin: str
    destination_origin: str
    tab_id: int
    frame_id: int
    action: str
    data_labels: frozenset[str] = field(default_factory=frozenset)
    observed_at: float = field(default_factory=time.time)


@dataclass(frozen=True)
class EgressVerdict:
    """Pure decision result.  It never performs or claims enforcement."""

    disposition: EgressDisposition
    reason: str
    grant_id: str = ""

    @property
    def allowed(self) -> bool:
        return self.disposition is EgressDisposition.ALLOW

    def to_dict(self) -> dict[str, object]:
        return {
            "disposition": self.disposition.value,
            "allowed": self.allowed,
            "reason": self.reason,
            "grant_id": self.grant_id,
        }


class CausalAuthorityEngine:
    """In-memory issue-and-consume authority verifier.

    The engine deliberately uses exact comparisons instead of scores.  Every
    scope dimension must match.  A wide-open dimension cannot compensate for
    a mismatch elsewhere.
    """

    def __init__(self, *, clock: Callable[[], float] = time.monotonic,
                 ttl_s: float = DEFAULT_GRANT_TTL_S,
                 max_pending: int = MAX_PENDING_GRANTS) -> None:
        self._clock = clock
        self._ttl_s = min(MAX_GRANT_TTL_S, max(0.05, float(ttl_s)))
        self._max_pending = max(1, int(max_pending))
        self._pending: dict[str, AuthorityGrant] = {}
        self._order: deque[str] = deque()
        self._expiry_heap: list[tuple[float, str, str]] = []
        self._consumed: set[str] = set()
        self._consumed_order: deque[str] = deque()
        self._lock = threading.RLock()
        self._issued = 0
        self._allowed = 0
        self._refused = 0

    def issue(self, *, interaction_id: object, source_origin: str,
              destination_origin: str, tab_id: int, frame_id: int,
              action: str, data_labels: Iterable[object]) -> AuthorityGrant | None:
        """Issue one bounded grant, or ``None`` for malformed/unsupported scope."""
        interaction = valid_uuid(interaction_id)
        labels = normalize_labels(data_labels)
        source = canonical_origin(source_origin)
        destination = canonical_origin(destination_origin)
        if (not interaction or not source or not destination
                or action not in GRANT_ACTIONS or not labels):
            return None
        now = self._clock()
        grant = AuthorityGrant(
            grant_id=str(uuid.uuid4()),
            interaction_id=interaction,
            source_origin=source,
            destination_origin=destination,
            tab_id=int(tab_id),
            frame_id=int(frame_id),
            action=action,
            data_labels=labels,
            issued_at=now,
            expires_at=now + self._ttl_s,
        )
        with self._lock:
            self._expire_locked(now)
            if interaction in self._consumed:
                return None
            old = self._pending.pop(interaction, None)
            if old is not None:
                self._remember_consumed_locked(old.grant_id)
            self._pending[interaction] = grant
            self._order.append(interaction)
            heapq.heappush(self._expiry_heap,
                           (grant.expires_at, interaction, grant.grant_id))
            self._issued += 1
            self._trim_locked()
        return grant

    def verify_and_consume(self, request: EgressRequest) -> EgressVerdict:
        """Atomically verify every scope dimension and consume the grant.

        Failed verification also consumes a referenced grant.  This prevents
        an attacker from probing scope until a combination succeeds.
        """
        interaction = valid_uuid(request.interaction_id)
        with self._lock:
            now = self._clock()
            self._expire_locked(now)
            if not interaction:
                return self._refuse_locked("missing or invalid causal interaction")
            grant = self._pending.pop(interaction, None)
            if grant is None:
                reason = ("causal grant was already consumed"
                          if interaction in self._consumed
                          else "no live causal grant")
                return self._refuse_locked(reason)
            self._remember_consumed_locked(interaction)
            self._remember_consumed_locked(grant.grant_id)

            mismatch = self._mismatch(grant, request)
            if mismatch:
                return self._refuse_locked(mismatch, grant.grant_id)
            self._allowed += 1
            return EgressVerdict(
                EgressDisposition.ALLOW,
                "fresh causal grant matches origin, destination, action, frame, and data labels",
                grant.grant_id,
            )

    @staticmethod
    def _mismatch(grant: AuthorityGrant, request: EgressRequest) -> str:
        checks = (
            (canonical_origin(request.source_origin) == grant.source_origin, "source origin changed"),
            (canonical_origin(request.destination_origin) == grant.destination_origin,
             "destination origin changed"),
            (request.tab_id == grant.tab_id, "browser tab changed"),
            (request.frame_id == grant.frame_id, "browser frame changed"),
            (request.action == grant.action, "action changed"),
            (normalize_labels(request.data_labels).issubset(grant.data_labels),
             "request gained data labels after authority was granted"),
        )
        for matches, reason in checks:
            if not matches:
                return reason
        return ""

    def _refuse_locked(self, reason: str, grant_id: str = "") -> EgressVerdict:
        self._refused += 1
        return EgressVerdict(EgressDisposition.REFUSE, reason, grant_id)

    def _expire_locked(self, now: float) -> None:
        while self._expiry_heap and self._expiry_heap[0][0] <= now:
            _expires_at, interaction, grant_id = heapq.heappop(self._expiry_heap)
            grant = self._pending.get(interaction)
            if grant is None or grant.grant_id != grant_id:
                continue
            self._pending.pop(interaction, None)
            self._remember_consumed_locked(interaction)
            self._remember_consumed_locked(grant.grant_id)

    def _trim_locked(self) -> None:
        while len(self._pending) > self._max_pending and self._order:
            interaction = self._order.popleft()
            grant = self._pending.pop(interaction, None)
            if grant is not None:
                self._remember_consumed_locked(interaction)
                self._remember_consumed_locked(grant.grant_id)

    def _remember_consumed_locked(self, value: str) -> None:
        if not value or value in self._consumed:
            return
        self._consumed.add(value)
        self._consumed_order.append(value)
        while len(self._consumed_order) > MAX_CONSUMED_IDS:
            self._consumed.discard(self._consumed_order.popleft())

    def status(self) -> dict[str, int | float]:
        with self._lock:
            self._expire_locked(self._clock())
            return {
                "pending": len(self._pending),
                "issued": self._issued,
                "allowed": self._allowed,
                "refused": self._refused,
                "ttl_s": self._ttl_s,
            }
