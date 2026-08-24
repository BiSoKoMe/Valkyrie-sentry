"""Efficacy measurement — the test → measure → fix → retest loop.

This is what turns "I think Valkyrie is broken" into a number, and it exists
because of a real, expensive lesson: Valkyrie appeared to "miss obvious malware"
for days when in fact its detection rules were fine — the command-line SENSOR
was dark, so nothing fed them. A blind engine with perfect rules scores zero.

So measurement has two parts, and the ORDER matters:

  1. sensor_health() — CAN Valkyrie see? Checks the command-line eye (Windows
     4688 + cmdline audit, or Sysmon), so a missed technique can be correctly
     attributed to BLINDNESS (a plumbing failure) vs a real rule gap. Never
     tune a rule when the preflight is red — you'd be tuning a blindfold.

  2. score() — pure scoring of observed detections against an expected set:
     detection rate, response rate, and false-positive rate. FP rate is first
     among equals: a security tool users don't trust is worse than none.

Both halves are importable and unit-tested (tests/test_efficacy.py); the CLI
(tools/efficacy.py) wires them to the live engine on a test box.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

# The regression baseline: techniques Valkyrie is expected to catch. Every entry
# is a committed promise — if a change drops one, the harness fails. Keyed by
# ATT&CK id so matching is exact regardless of wording.
ATOMIC_REGRESSION_SET: dict[str, str] = {
    "T1003.001": "LSASS memory dump (comsvcs / procdump)",
    "T1003.002": "SAM / SYSTEM hive theft",
    "T1218.010": "Regsvr32 Squiblydoo",
    "T1218.005": "Mshta remote script",
    "T1218.011": "Rundll32 script proxy",
    "T1140":     "Certutil decode",
    "T1105":     "Ingress tool transfer",
    "T1053.005": "Scheduled task persistence",
    "T1543.003": "Windows service persistence",
    "T1547.001": "Registry Run key persistence",
    "T1059.001": "Malicious PowerShell",
    "T1490":     "Inhibit system recovery (shadow delete)",
    "T1047":     "WMI process creation",
    "T1027":     "Obfuscated / encoded command",
}


# ── 1. Sensor health (the preflight) ────────────────────────────────────────

@dataclass
class SensorHealth:
    command_line_eye_open: bool
    command_line_source: str          # "sysmon" | "windows-4688" | "none"
    detail: str
    ready: bool                       # can the engine see command lines at all?

    def to_dict(self) -> dict:
        return {
            "command_line_eye_open": self.command_line_eye_open,
            "command_line_source": self.command_line_source,
            "detail": self.detail,
            "ready": self.ready,
        }


def sensor_health() -> SensorHealth:
    """Is the command-line eye open? Sysmon (richest) OR Windows 4688+cmdline.

    Pure of the engine — reads the OS directly, so it works even if the engine
    is down. Never raises."""
    # Sysmon: the richer source. Present if its operational channel is readable.
    try:
        from .etw.wineventlog import ChannelReader
        if ChannelReader("Microsoft-Windows-Sysmon/Operational", (1,)).available():
            return SensorHealth(True, "sysmon",
                                "Sysmon operational channel is readable "
                                "(process creation with command line).", True)
    except Exception:
        pass
    # Windows' own auditing: 4688 + the command-line inclusion policy.
    try:
        from .native_audit import is_process_auditing_enabled
        if is_process_auditing_enabled():
            return SensorHealth(True, "windows-4688",
                                "Security 4688 process auditing with command "
                                "line is enabled.", True)
    except Exception:
        pass
    return SensorHealth(
        False, "none",
        "NO command-line source is live: Sysmon isn't ingesting and Windows "
        "4688+cmdline auditing is off. Command-line detection rules cannot fire "
        "— a miss here is BLINDNESS, not a rule gap. Start the engine as "
        "admin/SYSTEM (it auto-enables 4688) or install Sysmon.",
        False)


# ── 2. Scoring (pure) ───────────────────────────────────────────────────────

@dataclass
class Scorecard:
    detected: list[str] = field(default_factory=list)      # technique ids
    missed: list[str] = field(default_factory=list)
    detection_rate: float = 0.0
    responded: list[str] = field(default_factory=list)      # ids with a response
    response_rate: float = 0.0
    false_positives: list[str] = field(default_factory=list)  # benign things flagged
    fp_count: int = 0
    total_expected: int = 0
    total_incidents: int = 0

    def to_dict(self) -> dict:
        return self.__dict__.copy()

    def summary(self) -> str:
        return (f"detection {len(self.detected)}/{self.total_expected} "
                f"({self.detection_rate:.0%}) · response {self.response_rate:.0%} "
                f"· false positives {self.fp_count}")


def _tech_ids(text: str) -> set[str]:
    """Pull ATT&CK ids (T1234 / T1234.001) out of a technique/title string."""
    import re
    return set(re.findall(r"T\d{4}(?:\.\d{3})?", text or ""))


def _incident_ids(inc: dict) -> set[str]:
    return _tech_ids(str(inc.get("technique", ""))) | _tech_ids(str(inc.get("title", "")))


def filter_window(incidents: Iterable[dict], since_iso: Optional[str] = None) -> list[dict]:
    """Keep only incidents created at/after ``since_iso`` (ISO-8601).

    THIS is the fix for the most dangerous measurement bug: scoring against
    every incident in the DB sweeps up STALE ones from earlier runs — including
    false positives you already fixed — and reports them as if they were current.
    Always window the scoring to the run you're measuring (e.g. the moment the
    engine last started). ISO-8601 with a fixed offset compares correctly as a
    string; a best-effort parse guards odd formats."""
    if not since_iso:
        return list(incidents)
    out: list[dict] = []
    for inc in incidents:
        t = str(inc.get("created_at") or inc.get("updated_at") or "")
        if t and t >= since_iso:
            out.append(inc)
    return out


def is_false_positive(inc: dict) -> bool:
    """A flagged incident on something unambiguously benign.

    Deliberately CONSERVATIVE: it must NOT count real detections as FPs. A signed
    OS binary is *not* enough to call something benign — the LOLBins that real
    attacks abuse (rundll32, powershell, reg, schtasks) all live in System32, and
    an LSASS dump via rundll32 is a true positive, not noise. So we only count
    the two classes that are benign by construction:

      * Valkyrie flagging its OWN components (self-FP).
      * A well-known public DNS resolver (8.8.8.8 / 1.1.1.1 …) flagged as a threat.

    Fuzzier noise (baseline-anomaly on OS processes, an installer that trips the
    chain correlator) is better *fixed at the source* than guessed at here, so it
    is intentionally not classified as FP by this scorer."""
    from .trust import is_self, is_public_resolver_ip
    import re
    proc = str(inc.get("process_name", ""))
    entity = str(inc.get("entity", ""))
    if is_self(proc, entity):
        return True
    if is_public_resolver_ip(entity):
        return True
    for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", entity):
        if is_public_resolver_ip(ip):
            return True
    return False


def score(observed_incidents: Iterable[dict],
          expected: Optional[dict] = None,
          responses: Optional[Iterable[dict]] = None,
          since: Optional[str] = None,
          only_ran: Optional[Iterable[str]] = None) -> Scorecard:
    """Score observed EDR incidents against the expected regression set. Pure.

    * since — ISO-8601 cutoff; only incidents at/after it are scored. Pass the
      engine's last-start time so STALE incidents (and old, already-fixed false
      positives) from earlier runs never pollute the result.
    * only_ran — if given, restrict the expected set to techniques that were
      actually EXERCISED this run, so a technique the atomic battery never ran
      (e.g. wmic absent on modern Windows) is 'not tested', not 'missed'.

    * detection_rate — fraction of expected techniques that appear in incidents.
    * response_rate  — fraction of DETECTED techniques that had a real (non
      dry-run, succeeded) response.
    * false_positives — incidents flagged on benign (self / signed-OS) entities.
    """
    expected = expected or ATOMIC_REGRESSION_SET
    incidents = filter_window(observed_incidents, since)
    exp_ids = set(expected)
    if only_ran is not None:
        exp_ids &= set(only_ran)   # don't penalise techniques that never ran

    seen: set[str] = set()
    fps: list[str] = []
    for inc in incidents:
        seen |= _incident_ids(inc)
        if is_false_positive(inc):
            fps.append(str(inc.get("process_name") or inc.get("entity") or "?"))

    detected = sorted(exp_ids & seen)
    missed = sorted(exp_ids - seen)

    # Which detected techniques actually got an enforced response?
    responded_ids: set[str] = set()
    for r in (responses or []):
        if str(r.get("status")) == "succeeded" and not r.get("dry_run", True):
            responded_ids |= _tech_ids(str(r.get("technique", "")) +
                                       " " + str(r.get("target", "")))
    responded = sorted(set(detected) & responded_ids) if responded_ids else []

    n_exp = len(exp_ids) or 1
    return Scorecard(
        detected=detected, missed=missed,
        detection_rate=len(detected) / n_exp,
        responded=responded,
        response_rate=(len(responded) / len(detected)) if detected else 0.0,
        false_positives=sorted(set(fps)), fp_count=len(fps),
        total_expected=len(exp_ids), total_incidents=len(incidents),
    )
