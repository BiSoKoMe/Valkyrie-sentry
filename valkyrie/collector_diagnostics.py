"""Cheap, thread-safe progress diagnostics for polling collectors."""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager


class PollDiagnostics:
    """Expose what a collector is doing without changing its stale contract."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._poll_started_at = 0.0
        self._current_stage: str | None = None
        self._current_stage_started_at = 0.0
        self._last_poll_duration_s = 0.0
        self._longest_poll_duration_s = 0.0
        self._last_stage_durations_s: dict[str, float] = {}
        self._active_stage_durations_s: dict[str, float] = {}

    def poll_started(self) -> None:
        with self._lock:
            self._poll_started_at = time.time()
            self._active_stage_durations_s = {}

    @contextmanager
    def stage(self, name: str):
        wall = time.time()
        mono = time.monotonic()
        with self._lock:
            self._current_stage = name
            self._current_stage_started_at = wall
        try:
            yield
        finally:
            duration = time.monotonic() - mono
            with self._lock:
                self._active_stage_durations_s[name] = round(duration, 6)
                self._current_stage = None
                self._current_stage_started_at = 0.0

    def poll_completed(self) -> None:
        now = time.time()
        with self._lock:
            duration = max(0.0, now - self._poll_started_at) if self._poll_started_at else 0.0
            self._last_poll_duration_s = duration
            self._longest_poll_duration_s = max(self._longest_poll_duration_s, duration)
            self._last_stage_durations_s = dict(self._active_stage_durations_s)
            self._poll_started_at = 0.0
            self._current_stage = None
            self._current_stage_started_at = 0.0

    def status(self) -> dict:
        now = time.time()
        with self._lock:
            return {
                "poll_started_at": self._poll_started_at,
                "poll_running_for_s": (
                    max(0.0, now - self._poll_started_at) if self._poll_started_at else 0.0
                ),
                "current_stage": self._current_stage,
                "current_stage_started_at": self._current_stage_started_at,
                "current_stage_running_for_s": (
                    max(0.0, now - self._current_stage_started_at)
                    if self._current_stage_started_at else 0.0
                ),
                "last_poll_duration_s": self._last_poll_duration_s,
                "longest_poll_duration_s": self._longest_poll_duration_s,
                "last_stage_durations_s": dict(self._last_stage_durations_s),
            }
