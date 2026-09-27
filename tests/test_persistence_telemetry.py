#!/usr/bin/env python3
"""PersistenceCollector.poll_once() - the diff/emit stage's per-cycle budget.

Confirmed live on the owner's real, running installation (valkyrie.db's
edr_responses table): 243 distinct, completely standard Windows system
scheduled tasks (Microsoft\\Windows\\WlanSvc\\*, \\WOF\\*, \\Workplace Join\\*,
\\WwanSvc\\*, \\Work Folders\\*) were each flagged as new persistence and hit
a remove_persistence response roughly every cycle for three weeks running -
10,703 "refusing to delete system scheduled task" skips out of a database
with 16,401 total incidents. The safety guard correctly refused every single
deletion, so nothing was ever actually removed - but the FALSE DETECTION
itself fired constantly and never stopped, for legitimate, unchanging,
built-in OS tasks.

Root cause: poll_once()'s diff/emit stage shares ONE wall-clock deadline
(``_emit_budget``, 4s default) across all four ASEP categories, processed in
a fixed order (run_keys, services, scheduled_tasks, startup_folders - see
snapshot()'s own dict literal). An item that cannot be emitted before the
deadline is deliberately left OUT of the new baseline "so the next poll's
diff rediscovers it" - the right idea for a handful of stragglers, but fatal
combined with a shared deadline and a fixed category order: if run_keys and
services alone can exhaust the 4s budget, EVERY scheduled_task entry is
skipped, EVERY cycle, forever - they can never enter the baseline, so they
can never stop looking "new". A backlog in an earlier category can
permanently starve a later one instead of merely delaying it.

Fix: each activity category gets its OWN fair slice of the total emit_budget
and its own independent deadline/flag, so one category's backlog can no
longer prevent every other category from ever making progress, and any
category's own backlog is guaranteed to shrink (not stay constant) over
successive polls.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks
from valkyrie.persistence_telemetry import (
    PersistenceCollector, PERSIST_RUN_KEY, PERSIST_SCHEDULED_TASK,
)


def _make_collector(*, emit_delay: float, emit_budget: float) -> tuple[PersistenceCollector, list]:
    emitted: list = []

    def _slow_emit(event) -> None:
        time.sleep(emit_delay)
        emitted.append(event)

    c = PersistenceCollector(_slow_emit, emit_budget=emit_budget)
    return c, emitted


def _snapshot(run_keys: int, scheduled_tasks: int) -> dict:
    return {
        PERSIST_RUN_KEY: {f"run_key::{i}": "" for i in range(run_keys)},
        "service": {},
        PERSIST_SCHEDULED_TASK: {f"scheduled_task::task-{i}": "" for i in range(scheduled_tasks)},
        "startup_folder": {},
    }


def main() -> int:
    c = Checks("PersistenceCollector.poll_once() per-category emit budget", expect_min=5)

    # Each emit costs ~20ms; a shared 4-category, 0.08s total budget can fit
    # only ~4 emits total if spent entirely on one category first.
    EMIT_DELAY = 0.02
    EMIT_BUDGET = 0.08

    print("[1] a large run_key backlog must not permanently starve "
          "scheduled_task out of ANY progress in the same cycle")
    coll, emitted = _make_collector(emit_delay=EMIT_DELAY, emit_budget=EMIT_BUDGET)
    coll._last = _snapshot(run_keys=0, scheduled_tasks=0)   # establish empty baseline
    big = _snapshot(run_keys=50, scheduled_tasks=50)        # both categories now have 50 new items
    coll.snapshot = lambda: big                             # noqa: E731 - test double
    coll.poll_once()
    scheduled_emitted = sum(1 for e in emitted if e.activity == PERSIST_SCHEDULED_TASK)
    c.check(f"scheduled_task got SOME emits in the very first cycle, not zero (got {scheduled_emitted})",
            scheduled_emitted > 0)

    print("\n[2] a persistent backlog actually DRAINS over successive polls "
          "instead of staying at the same size forever (the actual bug)")
    coll2, emitted2 = _make_collector(emit_delay=EMIT_DELAY, emit_budget=EMIT_BUDGET)
    coll2._last = _snapshot(run_keys=0, scheduled_tasks=0)
    backlog = _snapshot(run_keys=20, scheduled_tasks=60)
    coll2.snapshot = lambda: backlog
    still_new_counts = []
    for _cycle in range(15):
        coll2.poll_once()
        still_new = sum(1 for ident in backlog[PERSIST_SCHEDULED_TASK]
                        if ident not in coll2._last.get(PERSIST_SCHEDULED_TASK, {}))
        still_new_counts.append(still_new)
    c.check(f"the scheduled_task backlog shrinks over time "
            f"({still_new_counts[0]} -> {still_new_counts[-1]})",
            still_new_counts[-1] < still_new_counts[0])
    c.check(f"the backlog fully drains within 15 cycles of this size {still_new_counts}",
            still_new_counts[-1] == 0)

    print("\n[3] once drained, the SAME unchanged tasks never reappear as "
          "\"new\" again (the false-positive loop is actually over)")
    emitted2.clear()
    coll2.poll_once()
    c.check("a fully-baselined, unchanged snapshot emits nothing new",
            emitted2 == [])

    print("\n[4] regression: an ordinary small workload still emits "
          "everything in a single cycle, exactly as before")
    coll3, emitted3 = _make_collector(emit_delay=EMIT_DELAY, emit_budget=4.0)
    coll3._last = _snapshot(run_keys=0, scheduled_tasks=0)
    small = _snapshot(run_keys=2, scheduled_tasks=3)
    coll3.snapshot = lambda: small
    n = coll3.poll_once()
    c.check("a small, ordinary workload is fully emitted in one cycle",
            n == 5 and len(emitted3) == 5)
    c.check("nothing was left truncated for a workload well inside budget",
            "diff_normalize_emit" not in coll3._truncated)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
