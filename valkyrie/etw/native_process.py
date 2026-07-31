"""Native process-creation sensor — command-line detection with NO extra install.

THE PROBLEM THIS SOLVES
-----------------------
Valkyrie's strongest detection (the four-classifier stack over a process's
image, command line, parent and ancestry) needs to SEE the command line in real
time. Until now the only real-time source for that was **Sysmon EID 1** — and
Sysmon is a separate download. A normal person who installs Valkyrie will never
install Sysmon, so for a real customer the good detection path was dark and the
engine fell back to a racy 2-second poller that misses short-lived commands.

Windows already emits exactly the event we need, for free, with no install:
**Security event 4688 (A new process has been created)**. When the "Audit
Process Creation" policy is on — and, crucially, the "Include command line in
process creation events" policy — 4688 carries `NewProcessName`,
`ParentProcessName` and the full `CommandLine`. That is the same information
Sysmon EID 1 provides. It is simply off by default; `native_audit.py` turns it
on (a built-in Windows config change, not a download).

WHAT THIS SENSOR DOES
---------------------
Reads Security/4688 through the same `ChannelReader` the Sysmon sensor uses,
maps each event onto the exact dict shape `classify_sysmon(1, ...)` already
consumes, and runs the identical classifier stack. No detection logic is
duplicated — this is a second *source* feeding the one existing brain.

It stands down when Sysmon is present (Sysmon is the richer source: hashes,
signature, integrity), so the two never double-report the same process. Sysmon
if you have it; Windows' own auditing if you don't; either way the command-line
rules fire in real time.

HONEST BOUNDARY
---------------
4688 lacks what Sysmon adds beyond the command line — image hashes, signature
status, load events, CreateRemoteThread, LSASS-access. So this closes the
*command-line* gap (Execution / Defense-Evasion / Discovery — the tactics that
were 0% without Sysmon), not the memory-tradecraft gap. It is the single
highest-value step toward "works for a real customer with nothing to install",
not a claim of parity with a Sysmon-equipped host.
"""

from __future__ import annotations

import time

from .framework import Sensor
from .sysmon import classify_sysmon
from .wineventlog import ChannelReader, parse_event_xml
from ..telemetry import (
    ACT_FLAGGED, ACT_OBSERVED, SEV_MEDIUM, severity_rank, TelemetryEvent,
)

_CHANNEL = "Security"
_EVENT_IDS = (4688,)


def _hex_to_dec(text: str) -> str:
    """4688 reports PIDs as hex ('0x1f4'); classify_sysmon wants a decimal int.

    Returns a decimal string, or '0' for anything unparseable — never raises,
    because every field here is attacker-influenced event text.
    """
    s = (text or "").strip()
    try:
        return str(int(s, 16) if s.lower().startswith("0x") else int(s))
    except (TypeError, ValueError):
        return "0"


def map_4688(data: dict) -> dict:
    """Map a Security-4688 EventData dict onto the Sysmon-EID-1 shape.

    Pure and total: unknown/missing fields become empty, so a truncated or
    old-Windows 4688 (which may omit ParentProcessName or CommandLine) still
    produces a usable dict rather than raising. The keys chosen are exactly the
    ones ``classify_sysmon`` and its ``_context`` read.
    """
    d = data or {}
    return {
        "Image":            d.get("NewProcessName", "") or "",
        "CommandLine":      d.get("CommandLine", "") or "",
        "ParentImage":      d.get("ParentProcessName", "") or "",
        "ProcessId":        _hex_to_dec(d.get("NewProcessId", "")),
        "User":             d.get("SubjectUserName", "") or "",
        # 4688 has no CurrentDirectory / Hashes / integrity NAME; leave blank so
        # _context() simply reports them empty rather than inventing values.
        "IntegrityLevel":   "",
        "LogonId":          d.get("SubjectLogonId", "") or "",
    }


class NativeProcessSensor(Sensor):
    """Security/4688 process-creation sensor. Sysmon-free command-line detection."""

    name = "native_process"
    interval = 1.5

    def __init__(self, *, suppress_when=None) -> None:
        super().__init__()
        self._reader = ChannelReader(_CHANNEL, _EVENT_IDS)
        # A predicate that returns True when a richer source (Sysmon) is live,
        # in which case this sensor stands down to avoid double-reporting.
        self._suppress_when = suppress_when

    def available(self) -> bool:
        # Skip cleanly if the Security channel cannot be read (non-elevated dev
        # run) or a richer source is already covering process creation.
        if self._suppress_when is not None:
            try:
                if self._suppress_when():
                    return False
            except Exception:
                pass
        return self._reader.available()

    def _collect_once(self) -> None:
        for xml in self._reader.read_new():
            ev = parse_event_xml(xml)
            if not ev or ev.get("event_id") != 4688:
                continue
            args = classify_sysmon(1, map_4688(ev.get("data", {})))
            if args:
                self._emit(ev, args)

    def _emit(self, ev: dict, args: dict) -> None:
        sev = args["severity"]
        action = ACT_FLAGGED if severity_rank(sev) >= severity_rank(SEV_MEDIUM) else ACT_OBSERVED
        context = args.pop("context", {})
        technique = args.pop("technique", "")
        tgt = args.get("target", {})
        dedup = f"native:4688:{args['actor_pid']}:{tgt.get('path', '')}"
        self.submit(TelemetryEvent(
            category=args["category"], activity=args["activity"], action=action,
            ts=time.time(),
            actor_pid=args["actor_pid"], actor_name=args["actor_name"],
            actor_path=args.get("actor_path", ""),
            target=tgt, severity=sev, reason=args["reason"], source="etw.native",
            labels=args.get("labels", []),
            fields={"technique": technique, "event_id": 4688,
                    "user_sid": ev.get("user_sid", ""), "_dedup": dedup[:200],
                    **context},
        ))
