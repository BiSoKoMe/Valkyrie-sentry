"""A small, thread-safe publish/subscribe event bus.

Valkyrie has two independent, hand-rolled pub/sub implementations - one in
``Store`` (DNS-decision events) and one in ``EdrEngine`` (incident events) - each
with its own subscriber list, lock, and "swallow subscriber exceptions" loop.
This module provides a single tested primitive they both adopt, removing the
duplication and giving the platform one place to reason about event delivery.

Contract (matches the behavior the existing subscribers already rely on):

  * **Delivery is best-effort and isolated.** A subscriber that raises never
    prevents other subscribers from receiving the event, and never propagates
    back to the publisher. (A security tool must keep ingesting events even if a
    dashboard callback throws.)
  * **Thread-safe.** ``publish`` is called from the Store writer thread while
    ``subscribe``/``unsubscribe`` may be called from request threads; a snapshot
    of handlers is taken under a lock so the set can mutate during delivery.
  * **Synchronous, in-order.** Handlers run on the publishing thread in
    subscription order - identical to the loops it replaces. (Back-pressure and
    async fan-out belong to the transport layer, e.g. the WebSocket queue, not
    here.)

New capability over the old loops: a subscriber may filter by event type, so a
single shared bus can carry several event kinds without every subscriber seeing
all of them. Passing ``types=None`` (the default) subscribes to everything,
preserving the old "deliver every message" behavior exactly.

Events are plain dicts with a ``"type"`` key - the shape the current code already
publishes - so adoption requires no change to any existing subscriber.
"""

from __future__ import annotations

import threading
from typing import Callable, Iterable, Optional

Handler = Callable[[dict], None]


class EventBus:
    """Thread-safe, exception-isolating, synchronous pub/sub over dict events."""

    __slots__ = ("_name", "_subs", "_lock")

    def __init__(self, name: str = "") -> None:
        self._name = name
        # Each entry: (handler, allowed_types_or_None)
        self._subs: list[tuple[Handler, Optional[frozenset]]] = []
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Subscription
    # ------------------------------------------------------------------

    def subscribe(self, handler: Handler,
                  types: Optional[Iterable[str]] = None) -> None:
        """Register ``handler`` to receive published events.

        If ``types`` is given, the handler only receives events whose
        ``event["type"]`` is in that set; otherwise it receives all events.
        """
        allowed = frozenset(types) if types is not None else None
        with self._lock:
            self._subs.append((handler, allowed))

    def unsubscribe(self, handler: Handler) -> None:
        """Remove ``handler``. Idempotent - unknown handlers are ignored.

        Removes every registration of the same handler object (identity match).
        """
        with self._lock:
            self._subs = [(h, t) for (h, t) in self._subs if h is not handler]

    # ------------------------------------------------------------------
    # Publication
    # ------------------------------------------------------------------

    def publish(self, event: dict) -> None:
        """Deliver ``event`` to every matching subscriber.

        Best-effort and isolated: a handler raising is swallowed so neither the
        publisher nor other subscribers are affected.
        """
        etype = event.get("type") if isinstance(event, dict) else None
        with self._lock:
            subs = list(self._subs)
        for handler, allowed in subs:
            if allowed is not None and etype not in allowed:
                continue
            try:
                handler(event)
            except Exception:
                # Deliberate: one bad subscriber must never break ingestion.
                pass

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subs)

    def has_subscribers(self) -> bool:
        with self._lock:
            return bool(self._subs)

    def __repr__(self) -> str:
        return f"<EventBus {self._name!r} subscribers={self.subscriber_count()}>"
