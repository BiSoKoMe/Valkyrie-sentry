"""AnomalyDetector - scores connections on their behavioural signature,
independent of the domain name.

Surveillance looks like: a background process calling the same domain on
a metronome-regular interval with small, same-sized payloads - sometimes
even after the app was closed - to a domain this machine has never
contacted before.  Each of those signals contributes to a 0.0-1.0 score:

    background process               +0.3
    regular-interval heartbeat       +0.4
    app closed but still connecting  +0.5
    domain never seen from process   +0.3
    deviates from baseline timing    +0.2
    asymmetric small-out traffic     +0.3

The score is capped at 1.0.  ``explain()`` returns the human-readable
reason for the most recent score of a (process, domain) pair.
"""

from __future__ import annotations

import statistics
import threading
import time
from typing import Callable, Optional

from ..config import (
    INTEL_HEARTBEAT_MAX_CV,
    INTEL_HEARTBEAT_MAX_GAP,
    INTEL_HEARTBEAT_MIN_GAP,
    INTEL_HEARTBEAT_MIN_SAMPLES,
    INTEL_SMALL_PAYLOAD_BYTES,
    SYSTEM_PROCESSES,
)
from .baseline import BaselineLearner

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False


# Well-known background/service process names beyond the Windows system set.
_BACKGROUND_NAMES: frozenset[str] = frozenset(SYSTEM_PROCESSES) | frozenset({
    "runtimebroker.exe", "sihclient.exe", "usoclient.exe", "mousocoreworker.exe",
    "compattelrunner.exe", "wsappx.exe", "searchindexer.exe", "spoolsv.exe",
    "officeclicktorun.exe", "onedrive.exe", "yourphone.exe", "cortana.exe",
    "gamingservices.exe", "widgets.exe", "phoneexperiencehost.exe",
    "updater.exe", "googleupdate.exe", "microsoftedgeupdate.exe",
    "adobearm.exe", "armsvc.exe", "jusched.exe",
})

# Signal weights (spec-fixed)
W_BACKGROUND   = 0.3
W_HEARTBEAT    = 0.4
W_APP_CLOSED   = 0.5
W_NEVER_SEEN   = 0.3
W_TIMING_DEV   = 0.2
W_ASYMMETRIC   = 0.3


class AnomalyDetector:
    """Behaviour-based suspicion scoring on top of the BaselineLearner.

    ``is_background_fn`` and ``is_running_fn`` are injectable for tests:
      is_background_fn(process_name) -> bool
      is_running_fn(process_name)    -> bool | None  (None = unknown)
    """

    def __init__(
        self,
        baseline: BaselineLearner,
        is_background_fn: Optional[Callable[[str], bool]] = None,
        is_running_fn:    Optional[Callable[[str], Optional[bool]]] = None,
    ) -> None:
        self._baseline = baseline
        self._is_background = is_background_fn or self._default_is_background
        self._is_running    = is_running_fn or self._default_is_running
        self._explanations: dict[tuple[str, str], list[str]] = {}
        self._lock = threading.RLock()
        # process-liveness cache: name -> (verdict, checked_at)
        self._alive_cache: dict[str, tuple[Optional[bool], float]] = {}

    # ------------------------------------------------------------------
    # Default signal providers
    # ------------------------------------------------------------------

    @staticmethod
    def _default_is_background(process: str) -> bool:
        return (process or "").lower() in _BACKGROUND_NAMES

    def _default_is_running(self, process: str) -> Optional[bool]:
        """Best-effort liveness by process name (cached 5s).  None = unknown."""
        if not _PSUTIL or not process or process == "unknown":
            return None
        name = process.lower()
        now = time.monotonic()
        cached = self._alive_cache.get(name)
        if cached and now - cached[1] < 5.0:
            return cached[0]
        verdict: Optional[bool] = False
        try:
            for proc in psutil.process_iter(["name"]):
                if (proc.info.get("name") or "").lower() == name:
                    verdict = True
                    break
        except Exception:
            verdict = None
        self._alive_cache[name] = (verdict, now)
        return verdict

    # ------------------------------------------------------------------
    # Heartbeat detection
    # ------------------------------------------------------------------

    def is_heartbeat(self, process: str, domain: str) -> bool:
        """True when queries from process->domain arrive at regular intervals."""
        profile = self._baseline.history(process, domain)
        if profile is None:
            return False
        gaps = [g for g in profile.gaps()
                if INTEL_HEARTBEAT_MIN_GAP <= g <= INTEL_HEARTBEAT_MAX_GAP]
        if len(gaps) < INTEL_HEARTBEAT_MIN_SAMPLES:
            return False
        mean = statistics.fmean(gaps)
        if mean <= 0:
            return False
        stdev = statistics.pstdev(gaps)
        return (stdev / mean) < INTEL_HEARTBEAT_MAX_CV

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score(self, process: str, domain: str, timestamp: float,
              payload: int = 0) -> float:
        """Return a 0.0-1.0 suspicion score for this observation.

        Call AFTER BaselineLearner.record() so timing history includes the
        current query.
        """
        process = (process or "unknown").lower()
        domain  = domain.lower().rstrip(".")
        learning = self._baseline.is_learning()

        # --- STRONG C2 tells: each is a real beaconing signature that stands on
        # its own (metronome heartbeat, an app that closed but keeps connecting,
        # repeated tiny same-size payloads). These drive the score. ---
        strong = 0.0
        strong_reasons: list[str] = []
        if self.is_heartbeat(process, domain):
            strong += W_HEARTBEAT
            strong_reasons.append("regular-interval heartbeat")
        if self._is_running(process) is False:
            strong += W_APP_CLOSED
            strong_reasons.append("process not running but still connecting")
        if self._asymmetric_small_out(process, domain, payload):
            strong += W_ASYMMETRIC
            strong_reasons.append("repeated small same-size payloads (beacon-like)")

        # --- WEAK CONTEXT tells: "background process", "domain never seen from
        # this process", "timing deviation". Each describes perfectly NORMAL OS
        # behaviour on its own - every Windows service is a background process
        # and queries new domains (updates, telemetry, CDNs) constantly. On their
        # own they were summing to 0.6 and FLAGGING thousands of legit domains
        # (the "baseline:anomaly" flood). They now only SHARPEN a score once a
        # strong beacon tell is already present, and never flag a domain alone. ---
        weak = 0.0
        weak_reasons: list[str] = []
        if self._is_background(process):
            weak += W_BACKGROUND
            weak_reasons.append("background process")
        if not learning and not self._baseline.is_normal(process, domain, timestamp):
            weak += W_NEVER_SEEN
            weak_reasons.append("domain never seen from this process")
        if not learning and self._timing_deviates(process, domain):
            weak += W_TIMING_DEV
            weak_reasons.append("deviates from learned timing")

        if strong > 0:
            score = min(1.0, strong + weak)
            reasons = strong_reasons + weak_reasons
        else:
            score = 0.0            # weak signals alone are normal OS behaviour
            reasons = []
        with self._lock:
            self._explanations[(process, domain)] = reasons
        return score

    # ------------------------------------------------------------------
    # Signal health (no silent failures - see PHASE 0)
    # ------------------------------------------------------------------

    def signal_health(self) -> list[dict]:
        """Report each anomaly sub-signal's live status in the CURRENT state.

        This is dynamic on purpose: never-seen and timing-deviation are gated
        off while the baseline is still in its learning window, and app-closed
        depends on psutil being importable. A signal that cannot fire is
        reported DISABLED with the reason, so it can never quietly contribute 0
        while appearing active.
        """
        learning = self._baseline.is_learning()
        gate = ("DISABLED: gated off during the learning window "
                "(baseline still learning this machine's normal)")
        return [
            {"signal": "background_process", "active": True,
             "note": "fires for known service/background binaries"},
            {"signal": "heartbeat", "active": True,
             "note": f"fires on >= {INTEL_HEARTBEAT_MIN_SAMPLES} regular-interval "
                     f"gaps (needs repeat queries of the same pair)"},
            {"signal": "app_closed", "active": _PSUTIL,
             "note": "live process-liveness via psutil"
                     if _PSUTIL else "DISABLED: psutil not installed"},
            {"signal": "never_seen", "active": not learning,
             "note": gate if learning else "fires on first-seen (process, domain) pair"},
            {"signal": "timing_deviation", "active": not learning,
             "note": gate if learning else "fires when query rhythm is much faster than learned"},
            {"signal": "asymmetric_payload", "active": True,
             "note": f"fires on >= {INTEL_HEARTBEAT_MIN_SAMPLES} small same-size payloads"},
        ]

    def _timing_deviates(self, process: str, domain: str) -> bool:
        """True when the current query rhythm is much faster than learned."""
        profile = self._baseline.history(process, domain)
        if profile is None or profile.avg_gap <= 0:
            return False
        recent = profile.gaps()[-3:]
        if len(recent) < 2:
            return False
        observed = statistics.fmean(recent)
        return observed < profile.avg_gap / 3.0

    def _asymmetric_small_out(self, process: str, domain: str, payload: int) -> bool:
        """Repeated small, near-identical payload sizes -> beacon pattern."""
        profile = self._baseline.history(process, domain)
        if profile is None:
            return False
        sizes = list(profile.payloads)
        if payload > 0:
            sizes.append(payload)
        if len(sizes) < INTEL_HEARTBEAT_MIN_SAMPLES:
            return False
        mean = statistics.fmean(sizes)
        return mean < INTEL_SMALL_PAYLOAD_BYTES and statistics.pstdev(sizes) < 64

    # ------------------------------------------------------------------
    # Explanation
    # ------------------------------------------------------------------

    def explain(self, process: str, domain: str) -> str:
        """Human-readable reason for the most recent score of this pair."""
        process = (process or "unknown").lower()
        domain  = domain.lower().rstrip(".")
        with self._lock:
            reasons = self._explanations.get((process, domain), [])
        if not reasons:
            return f"{domain}: no anomaly signals from {process}"
        return f"{domain} via {process}: " + "; ".join(reasons)
