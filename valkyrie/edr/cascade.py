"""Enforcement budget — a cascade detector, not a rate limit.

WHY A FLAT CAP IS THE WRONG TOOL
--------------------------------
"At most N enforcement actions per hour" punishes the good case and the bad
case identically. Blocking fifty distinct C2 domains during a real intrusion
is correct behaviour and should not be throttled; the same fifty actions
against the SAME target, driven by one detection re-firing, is a loop that
will keep going until something stops it. Volume does not distinguish them.

Shape does. Three signatures, checked independently:

``repetition``
    The same (action, target) enforced over and over. Valkyrie has a measured
    instance of exactly this: reconnaissance-burst completes six separate
    times per test battery instead of escalating one incident, because
    min_distinct resets after completion. A budget that only counted actions
    would see "six actions" and shrug.

``monotony``
    Many actions, few distinct targets. A real campaign fans out; a loop
    grinds. The ratio separates them without needing to know which is which.

``acceleration``
    The rate itself is rising. This is the signature that matters most,
    because it is what a runaway looks like BEFORE it hits any ceiling --
    and the derivative catches it while the absolute count still looks fine.

Plus an absolute ceiling as a backstop, on the principle that a cascade
detector with a bug should still not be able to authorise unlimited action.

When the budget trips, enforcement drops to observe-and-alert. Valkyrie keeps
detecting and keeps telling the user; it just stops acting on its own until
the window drains. Being noisy is recoverable, and a self-inflicted outage is
what this exists to prevent.

Pure and execution-free: the clock is injected, nothing is queried globally.
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass
from typing import Optional

# Rolling window all shape checks are computed over.
WINDOW_S = 3600.0

# Absolute backstop. Reaching this means a shape check should have fired
# earlier and did not -- it is a bug fuse, not the primary control.
MAX_TOTAL = 100

# Same (action, target) this many times in the window is a loop, not a
# campaign. Deliberately low: legitimately re-blocking one target more than a
# handful of times means the first block is not holding, and repeating a
# failing action is never the right answer.
MAX_PER_TARGET = 5

# actions / distinct-targets above this reads as grinding rather than fanning
# out. 3.0 tolerates ordinary retry noise while catching a stuck loop.
MAX_MONOTONY = 3.0

# Recent-quarter rate vs the preceding rate. Above this the series is
# accelerating and is tripped early, before the absolute ceiling.
MAX_ACCELERATION = 3.0

# Below this many actions the shape statistics are meaningless -- three
# actions can look infinitely accelerated. Never trip on noise.
MIN_SAMPLE = 6


@dataclass(frozen=True)
class ActionRecord:
    ts: float
    action: str
    target: str
    detector: str


class CascadeBudget:
    """Rolling-window shape analysis over recent enforcement actions."""

    def __init__(self, *, window_s: float = WINDOW_S) -> None:
        self._window_s = window_s
        self._events: deque[ActionRecord] = deque()
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ io
    def record(self, action: str, target: str, detector: str = "",
               now: Optional[float] = None) -> None:
        """Note that an enforcement action actually fired."""
        import time
        n = time.time() if now is None else now
        with self._lock:
            self._events.append(ActionRecord(n, action, target, detector))
            self._prune(n)

    def _prune(self, now: float) -> None:
        cutoff = now - self._window_s
        while self._events and self._events[0].ts < cutoff:
            self._events.popleft()

    def recent(self, now: Optional[float] = None) -> list[ActionRecord]:
        import time
        n = time.time() if now is None else now
        with self._lock:
            self._prune(n)
            return list(self._events)

    # --------------------------------------------------------------- shape
    def permits(self, now: Optional[float] = None) -> tuple[bool, str]:
        """(allowed, reason). Shaped for authority.authorize's budget gate."""
        import time
        n = time.time() if now is None else now
        with self._lock:
            self._prune(n)
            events = list(self._events)

        if len(events) >= MAX_TOTAL:
            return False, (f"absolute ceiling: {len(events)} enforcement actions "
                           f"in the last {int(self._window_s)}s")

        if len(events) < MIN_SAMPLE:
            # Too few to say anything about shape. Three actions can look
            # infinitely accelerated; refusing on that would make the agent
            # useless at exactly the moment an incident starts.
            return True, ""

        # -- repetition ----------------------------------------------------
        per_target: dict[tuple, int] = {}
        for e in events:
            k = (e.action, e.target)
            per_target[k] = per_target.get(k, 0) + 1
        worst = max(per_target.items(), key=lambda kv: kv[1])
        if worst[1] > MAX_PER_TARGET:
            return False, (f"loop: {worst[0][0]!r} applied to {worst[0][1]!r} "
                           f"{worst[1]}x — repeating a block that is not holding")

        # -- monotony ------------------------------------------------------
        distinct = len({(e.action, e.target) for e in events})
        monotony = len(events) / max(1, distinct)
        if monotony > MAX_MONOTONY:
            return False, (f"grinding: {len(events)} actions across only "
                           f"{distinct} distinct targets (ratio {monotony:.1f}) "
                           f"— a real campaign fans out, a loop repeats")

        # -- acceleration --------------------------------------------------
        quarter = self._window_s / 4.0
        recent = [e for e in events if e.ts >= n - quarter]
        prior = [e for e in events if e.ts < n - quarter]
        if prior and len(recent) >= MIN_SAMPLE:
            recent_rate = len(recent) / quarter
            # Divide by the span the prior activity ACTUALLY occupied, not by
            # the nominal window. Dividing by the whole window assumes activity
            # began when the window did, so any steady campaign that merely
            # STARTS mid-window has its prior rate understated -- proportional
            # to how late it began -- and reads as acceleration. Caught by
            # test [2]: 40 blocks against 40 distinct C2 domains at a perfectly
            # constant 30s cadence tripped as "2.0/min now vs 0.2/min before".
            # That is the exact false positive that would cut enforcement off
            # during a real intrusion, which is when it is needed most.
            prior_span = max(1e-9, (n - quarter) - prior[0].ts)
            prior_rate = len(prior) / prior_span
            if prior_rate > 0 and (recent_rate / prior_rate) > MAX_ACCELERATION:
                return False, (f"accelerating: {recent_rate * 60:.1f}/min now vs "
                               f"{prior_rate * 60:.1f}/min before — tripping "
                               f"before the absolute ceiling, which is the "
                               f"point of watching the derivative")

        return True, ""

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)


_DEFAULT: Optional[CascadeBudget] = None
_LOCK = threading.RLock()


def budget() -> CascadeBudget:
    global _DEFAULT
    with _LOCK:
        if _DEFAULT is None:
            _DEFAULT = CascadeBudget()
        return _DEFAULT
