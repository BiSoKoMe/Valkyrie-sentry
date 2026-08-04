"""Runtime evidence about the HOST the evaluation is running on.

## Why this file exists

Three techniques in the catalog -- `evasion-process-injection` (T1055) and both
`cred-lsass-*` (T1003.001) -- were labelled `predicted_tier_b="CONDITIONAL"`
with the note "the condition is binary and absolute: Sysmon must be installed."

Their classifier logic was always correct and always fired. What was unknown was
whether the *event would ever reach it*. That is not a property of Valkyrie's
code; it is a property of the machine. So the score depended on a fact no test
was checking.

The tempting fix -- now that Sysmon IS installed here -- is to edit the labels
to `DETECT` and move on. That converts an honest "we don't know" into a claim
that is true on this host and **false on a bare Windows box**, with nothing in
the repo to notice the difference. The catalog would assert real-time process-
injection coverage on a machine that has zero visibility into it.

So the precondition is checked at run time instead. `predicted_tier_b` is
`DETECT` because the classifier genuinely detects; whether that detection is
*credited* additionally requires the delivering event source to be present and
live, verified here, on this host, at this moment. On a host without Sysmon the
same catalog scores those three as misses again, automatically, and says why.

## What counts as proof that an EID is available

Deliberately not "the service is running." Sysmon with a config that excludes an
event type produces nothing for it, and a stopped/disabled driver produces
nothing at all while the service still reports Running. All of the following
must hold:

  1. The Sysmon service exists and is Running.
  2. The Operational log exists, is enabled, and holds an event newer than
     ``FRESHNESS_SECONDS`` -- i.e. collection is live *now*, not historically.
  3. The event type appears in the ACTIVE rule configuration (`Sysmon64 -c`),
     which is what decides whether the EID is emitted at all.

Note what is *not* required: that the EID has recently been observed. EID 8
(CreateRemoteThread) is genuinely rare -- 1 event in a 6000-event sample on an
idle desktop -- so "not seen lately" is not evidence of absence. Requiring it
would make the score depend on whether something happened to inject a thread in
the last few minutes, which is noise, not signal. Configuration presence plus
live collection is the honest test.

Everything degrades to "unavailable, and here is the reason" rather than
raising: an evaluation harness that crashes because a host lacks Sysmon has
turned an environment fact into a broken run.
"""

from __future__ import annotations

import platform
import re
import subprocess
from dataclasses import dataclass, field, asdict

# An event newer than this proves the pipeline is delivering right now. Ten
# minutes is loose enough to survive an idle desktop (Sysmon EID 3/7 traffic
# never really stops) and tight enough that a service stopped an hour ago fails.
FRESHNESS_SECONDS = 600

# Sysmon rule-config section names, keyed by the EID this project consumes.
_EID_RULE_SECTION = {
    1:  "ProcessCreate",
    3:  "NetworkConnect",
    7:  "ImageLoad",
    8:  "CreateRemoteThread",
    10: "ProcessAccess",
}

_LOG_NAME = "Microsoft-Windows-Sysmon/Operational"


@dataclass
class SysmonEnvironment:
    """What is actually true about Sysmon on this host, with the evidence."""
    present: bool = False
    service_state: str = "not-found"
    log_enabled: bool = False
    log_record_count: int = 0
    newest_event_age_seconds: float | None = None
    collection_live: bool = False
    configured_eids: tuple[int, ...] = ()
    config_hash: str = ""
    detail: str = ""
    errors: tuple[str, ...] = field(default_factory=tuple)

    def provides(self, eid: int) -> bool:
        """True only if this host will actually deliver `eid` to a classifier."""
        return (self.present and self.collection_live
                and eid in self.configured_eids)

    def why_not(self, eid: int) -> str:
        if not self.present:
            return f"Sysmon not installed/running on this host ({self.service_state})"
        if not self.collection_live:
            age = self.newest_event_age_seconds
            age_s = "no events at all" if age is None else f"newest event {age:.0f}s old"
            return (f"Sysmon present but collection is not live "
                    f"({age_s}, threshold {FRESHNESS_SECONDS}s)")
        if eid not in self.configured_eids:
            section = _EID_RULE_SECTION.get(eid, f"EID {eid}")
            return (f"Sysmon running, but '{section}' is absent from the active "
                    f"rule configuration -- EID {eid} is never emitted")
        return ""

    def as_dict(self) -> dict:
        return asdict(self)


def _powershell(script: str, timeout: int = 30) -> tuple[bool, str]:
    try:
        p = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
        )
        return p.returncode == 0, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _decode_sysmon_config(raw: str) -> str:
    """`Sysmon64.exe -c` writes UTF-16 that arrives as text with NUL-ish gaps.

    Captured through a pipe it commonly lands as 'P r o c e s s A c c e s s'.
    Collapsing single-space-separated single characters recovers it. Cheap and
    tolerant: if the output was already sane this is close to a no-op.
    """
    if "\x00" in raw:
        raw = raw.replace("\x00", "")
    # Join runs of "X Y Z" single characters back into words.
    return re.sub(r"(?<=\b\w) (?=\w\b)", "", raw)


def probe_sysmon() -> SysmonEnvironment:
    env = SysmonEnvironment()
    if platform.system() != "Windows":
        env.service_state = "n/a-not-windows"
        env.detail = "Sysmon is Windows-only; this host is " + platform.system()
        return env

    errors: list[str] = []

    ok, out = _powershell(
        "$s = Get-Service -Name Sysmon64,Sysmon -ErrorAction SilentlyContinue | "
        "Select-Object -First 1; if ($s) { $s.Status.ToString() } else { 'not-found' }"
    )
    env.service_state = out.strip().splitlines()[-1].strip() if ok and out.strip() else "not-found"
    if env.service_state != "Running":
        env.detail = f"Sysmon service state is '{env.service_state}'"
        env.errors = tuple(errors)
        return env
    env.present = True

    # Log enabled + record count + freshness of the newest event.
    #
    # Three separate one-value queries rather than one script building an
    # interpolated "a|b|c" string. Nested quoting across
    # python -> powershell.exe -Command -> PowerShell string interpolation has
    # three levels of escaping, and getting it subtly wrong returns the LITERAL
    # text '$($l.RecordCount)' instead of a number -- which parses as "no data"
    # and would silently report Sysmon as dead on a host where it is healthy.
    # A probe whose failure mode is a false negative must not be clever.
    ok, out = _powershell(
        "(Get-WinEvent -ListLog '" + _LOG_NAME + "' -ErrorAction SilentlyContinue).IsEnabled"
    )
    env.log_enabled = ok and out.strip().lower().endswith("true")

    ok, out = _powershell(
        "(Get-WinEvent -ListLog '" + _LOG_NAME + "' -ErrorAction SilentlyContinue).RecordCount"
    )
    tail = out.strip().splitlines()[-1].strip() if out.strip() else ""
    try:
        env.log_record_count = int(float(tail))
    except ValueError:
        if env.log_enabled:
            errors.append(f"unparsable RecordCount {tail!r}")

    ok, out = _powershell(
        "$e = Get-WinEvent -LogName '" + _LOG_NAME + "' -MaxEvents 1 "
        "-ErrorAction SilentlyContinue; "
        "if ($e) { ((Get-Date) - $e.TimeCreated).TotalSeconds } else { -1 }"
    )
    tail = out.strip().splitlines()[-1].strip() if out.strip() else ""
    try:
        a = float(tail)
        env.newest_event_age_seconds = None if a < 0 else a
    except ValueError:
        errors.append(f"unparsable newest-event age {tail!r}")

    env.collection_live = bool(
        env.log_enabled
        and env.newest_event_age_seconds is not None
        and env.newest_event_age_seconds <= FRESHNESS_SECONDS
    )

    # Which event types the ACTIVE configuration emits.
    ok, out = _powershell(
        "$p = (Get-CimInstance Win32_Service -Filter \"Name='Sysmon64' or Name='Sysmon'\" "
        "| Select-Object -First 1).PathName; "
        "if ($p) { $exe = ($p -replace '\"','').Trim(); & $exe -c }",
        timeout=60,
    )
    cfg = _decode_sysmon_config(out)
    if ok or "Rule configuration" in cfg or "Ruleconfiguration" in cfg:
        found = []
        for eid, section in _EID_RULE_SECTION.items():
            # Section names appear as rule-config headings; match with the
            # spaces already collapsed by _decode_sysmon_config.
            if re.search(rf"\b{section}\b", cfg):
                found.append(eid)
        env.configured_eids = tuple(sorted(found))
        m = re.search(r"Confighash:\s*(\S+)", cfg) or re.search(r"Config hash:\s*(\S+)", cfg)
        if m:
            env.config_hash = m.group(1)
    else:
        errors.append("could not read active Sysmon rule configuration")

    env.errors = tuple(errors)
    env.detail = (
        f"service={env.service_state} log_enabled={env.log_enabled} "
        f"records={env.log_record_count} "
        f"newest_event_age={env.newest_event_age_seconds}s "
        f"configured_eids={list(env.configured_eids)}"
    )
    return env


# Precondition tokens usable in Technique.requires.
def check_requirements(requires: tuple[str, ...],
                       sysmon: SysmonEnvironment) -> tuple[bool, str]:
    """Return (all_met, reason_if_not). Unknown tokens fail CLOSED.

    Failing closed matters: a typo'd requirement token must never silently
    behave like "no requirement" and hand the technique free credit.
    """
    for token in requires:
        m = re.fullmatch(r"sysmon_eid(\d+)", token)
        if m:
            eid = int(m.group(1))
            if not sysmon.provides(eid):
                return False, sysmon.why_not(eid)
            continue
        return False, f"unknown precondition token {token!r} (failing closed)"
    return True, ""


if __name__ == "__main__":
    e = probe_sysmon()
    print(f"Sysmon present        : {e.present}  ({e.service_state})")
    print(f"Log enabled           : {e.log_enabled}  records={e.log_record_count}")
    print(f"Newest event age (s)  : {e.newest_event_age_seconds}")
    print(f"Collection live       : {e.collection_live} (threshold {FRESHNESS_SECONDS}s)")
    print(f"Configured EIDs       : {list(e.configured_eids)}")
    print(f"Config hash           : {e.config_hash or '(unread)'}")
    if e.errors:
        print(f"Errors                : {list(e.errors)}")
    for eid in (1, 3, 7, 8, 10):
        verdict = "AVAILABLE" if e.provides(eid) else f"NOT AVAILABLE -- {e.why_not(eid)}"
        print(f"  EID {eid:<3}            : {verdict}")
