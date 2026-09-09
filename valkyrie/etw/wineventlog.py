"""Windows Event Log reader over the native wevtapi (ctypes).

The modern Windows Event Log channels (PowerShell/Operational, WMI-Activity,
Sysmon, ...) are **ETW-backed**: providers write ETW events that the Event Log
service persists to a channel. Reading a channel with `EvtQuery`/`EvtNext`/
`EvtRender` therefore gives real, ETW-sourced telemetry with:

  * **no third-party dependency** (wevtapi ships with Windows),
  * **no console / no subprocess** (direct API calls, unlike `wevtutil`),
  * **incremental, near-real-time** delivery (poll by EventRecordID bookmark).

This is the strongest practical alternative to a raw NT-Kernel-Logger ETW session
(which would need a native trace consumer or a driver - see ADR 0003). The pure
``parse_event_xml`` helper is separated from the ctypes reader so parsing is unit-
testable without Windows.
"""

from __future__ import annotations

import logging
import re
import time
import xml.etree.ElementTree as ET
from typing import Optional

log = logging.getLogger("valkyrie.sensors.evtlog")

# --- pure XML parsing (testable anywhere) ---
# Remove xmlns declarations so ElementTree yields un-namespaced tags we can
# find() by plain name (Windows event XML uses a single default namespace).
_XMLNS = re.compile(r"\sxmlns(:\w+)?=(['\"])[^'\"]*\2")
_RECORD_ID = re.compile(r"<EventRecordID>(\d+)</EventRecordID>")


def record_id_of(xml: str) -> int:
    m = _RECORD_ID.search(xml or "")
    return int(m.group(1)) if m else 0


def _int_or(text, default: int = 0) -> int:
    """Best-effort int from event XML text. Never raises.

    Every numeric field here comes from a rendered event, and an event's fields
    are attacker-influenced: a process can write a malformed record, and a
    provider can emit a non-numeric EventID. `int()` on that text raises
    ValueError, which escaped the `except ET.ParseError` below and crashed the
    caller - the exact shape of the CrowdStrike channel-file failure, where a
    trusted-path parser assumed its input's shape. Found by fuzzing
    (tests/test_fuzz_parsers.py); the docstring already promised it could not
    happen.
    """
    try:
        return int(text)
    except (TypeError, ValueError):
        return default


def parse_event_xml(xml: str) -> dict:
    """Parse a rendered Windows event XML into a flat dict:
    {event_id, record_id, time, computer, process_id, thread_id, user_sid,
     provider, data:{Name->value}}. Never raises - returns {} on bad input."""
    try:
        root = ET.fromstring(_XMLNS.sub("", xml or ""))
    except ET.ParseError:
        return {}
    except (ValueError, TypeError):
        # Entity-expansion and encoding-declaration failures surface as
        # ValueError rather than ParseError on some inputs.
        return {}
    out: dict = {"data": {}}
    system = root.find("System")
    if system is not None:
        def _txt(tag):
            el = system.find(tag)
            return el.text if el is not None else None
        out["event_id"] = _int_or(_txt("EventID"))
        out["record_id"] = _int_or(_txt("EventRecordID"))
        out["computer"] = _txt("Computer") or ""
        prov = system.find("Provider")
        out["provider"] = prov.get("Name") if prov is not None else ""
        tc = system.find("TimeCreated")
        out["time"] = tc.get("SystemTime") if tc is not None else ""
        exe = system.find("Execution")
        if exe is not None:
            out["process_id"] = _int_or(exe.get("ProcessID"))
            out["thread_id"] = _int_or(exe.get("ThreadID"))
        sec = system.find("Security")
        out["user_sid"] = sec.get("UserID") if sec is not None else ""
    # EventData: <Data Name="X">val</Data>  (also handle unnamed <Data>)
    data = root.find("EventData")
    if data is not None:
        unnamed = []
        for d in data.findall("Data"):
            name = d.get("Name")
            if name:
                out["data"][name] = d.text or ""
            else:
                unnamed.append(d.text or "")
        if unnamed:
            out["data"]["_unnamed"] = unnamed
    # UserData: <UserData><Operation_X><Field>val</Field>...</Operation_X></UserData>
    # Used by WMI-Activity (5861), Task Scheduler, and many providers. Flatten
    # the operation's children into the same data map by tag name.
    ud = root.find("UserData")
    if ud is not None:
        for op in list(ud):
            out.setdefault("operation", op.tag)
            for child in list(op):
                if child.text:
                    out["data"].setdefault(child.tag, child.text)
    return out


# --- ctypes channel reader (Windows only) ---
_EvtQueryChannelPath        = 0x1
_EvtQueryForwardDirection   = 0x100
_EvtQueryReverseDirection   = 0x200
_EvtQueryTolerateQueryErrors = 0x1000
_EvtRenderEventXml          = 1

try:
    import ctypes
    from ctypes import wintypes
    _wevtapi = ctypes.WinDLL("wevtapi", use_last_error=True)

    _wevtapi.EvtQuery.restype = wintypes.HANDLE
    _wevtapi.EvtQuery.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    _wevtapi.EvtNext.restype = wintypes.BOOL
    _wevtapi.EvtNext.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                 ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
                                 wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    _wevtapi.EvtRender.restype = wintypes.BOOL
    _wevtapi.EvtRender.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD,
                                   wintypes.DWORD, wintypes.LPVOID,
                                   ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
    _wevtapi.EvtClose.restype = wintypes.BOOL
    _wevtapi.EvtClose.argtypes = [wintypes.HANDLE]
    # Canonical "does this channel exist?" check - returns NULL for an unknown
    # channel (e.g. Sysmon not installed), unlike EvtQuery which tolerates it.
    _wevtapi.EvtOpenChannelConfig.restype = wintypes.HANDLE
    _wevtapi.EvtOpenChannelConfig.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
    _WEVT_OK = True
except Exception:                                  # non-Windows or missing API
    _WEVT_OK = False


def _render_xml(handle) -> Optional[str]:
    used = wintypes.DWORD(0)
    prop = wintypes.DWORD(0)
    _wevtapi.EvtRender(None, handle, _EvtRenderEventXml, 0, None,
                       ctypes.byref(used), ctypes.byref(prop))
    if used.value == 0:
        return None
    buf = ctypes.create_unicode_buffer(used.value // 2 + 1)
    if not _wevtapi.EvtRender(None, handle, _EvtRenderEventXml, used.value, buf,
                              ctypes.byref(used), ctypes.byref(prop)):
        return None
    return buf.value


class ChannelReader:
    """Incremental reader for one event-log channel, filtered by event id.

    First use establishes a silent baseline at the channel's newest record;
    ``read_new()`` thereafter returns rendered XML for records created since.
    """

    def __init__(self, channel: str, event_ids: tuple[int, ...]):
        self.channel = channel
        self.event_ids = tuple(event_ids)
        self._last_record: Optional[int] = None
        id_clause = " or ".join(f"EventID={i}" for i in self.event_ids) or "EventID>0"
        self._id_clause = id_clause
        # Diagnostics for the drain loop: "" when it caught up, else which bound
        # stopped it ("budget" / "max_events"). Falling behind must be visible.
        self.last_read_truncated: str = ""
        self.last_read_count: int = 0

    def available(self) -> bool:
        # The channel must actually exist. EvtOpenChannelConfig returns NULL for
        # an unknown channel (Sysmon not installed) - unlike EvtQuery, which with
        # TolerateQueryErrors hands back a usable handle even for a missing path.
        if not _WEVT_OK:
            return False
        h = _wevtapi.EvtOpenChannelConfig(None, self.channel, 0)
        if h:
            _wevtapi.EvtClose(h)
            return True
        return False

    def _newest_record(self) -> int:
        h = _wevtapi.EvtQuery(
            None, self.channel, f"*[System[({self._id_clause})]]",
            _EvtQueryChannelPath | _EvtQueryReverseDirection | _EvtQueryTolerateQueryErrors)
        if not h:
            return 0
        rid = 0
        try:
            handles = (wintypes.HANDLE * 1)()
            returned = wintypes.DWORD(0)
            if _wevtapi.EvtNext(h, 1, handles, 1000, 0, ctypes.byref(returned)) and returned.value:
                xml = _render_xml(handles[0])
                _wevtapi.EvtClose(handles[0])
                if xml:
                    rid = record_id_of(xml)
        finally:
            _wevtapi.EvtClose(h)
        return rid

    def read_new(self, max_events: int = 8192,
                 budget_seconds: float = 2.0) -> list[str]:
        """Drain records newer than the bookmark, bounded by WALL CLOCK first.

        This used to be bounded only by ``max_events=256``. With SysmonSensor
        polling every 1.5s that is a hard ceiling of ~170 events/sec, and the
        Sysmon channel it subscribes to includes EID 11 (FileCreate) and 12/13/14
        (registry) - the chattiest events Windows produces. Any burst above that
        rate makes the bookmark fall behind, and because each poll drains only
        256 it never catches up: the backlog grows monotonically and every
        detection arrives later than the last.

        That is the mid-run "deafness" behind docs/LIVE_FIRE_EVALUATION.md's
        per-run variance (39 / 23 / 14 of the same 73 techniques). Its signature
        is exactly what a growing queue produces: detection latency climbing
        (2.09s -> 5.53s -> 7.94s in run 33828591735) until it passes the
        harness's 30s window, after which everything reads MISS - while Sysmon
        itself stays Running and its log readable, because nothing was ever
        lost, only ever further behind.

        Now the drain continues until it is genuinely caught up, or the budget
        expires - so a burst is absorbed in one poll instead of being metered
        out 256 at a time. ``max_events`` remains as a hard backstop against a
        pathological flood. ``last_read_truncated`` records which bound stopped
        it, so falling behind can never again be silent.
        """
        self.last_read_truncated = ""
        self.last_read_count = 0
        if not _WEVT_OK:
            return []
        if self._last_record is None:
            self._last_record = self._newest_record()      # baseline, emit nothing
            return []
        deadline = time.monotonic() + max(0.1, float(budget_seconds))
        query = (f"*[System[({self._id_clause}) and "
                 f"(EventRecordID>{self._last_record})]]")
        h = _wevtapi.EvtQuery(
            None, self.channel, query,
            _EvtQueryChannelPath | _EvtQueryForwardDirection | _EvtQueryTolerateQueryErrors)
        if not h:
            return []
        out: list[str] = []
        try:
            while len(out) < max_events:
                if time.monotonic() >= deadline:
                    # Still more to read, but this poll has spent its budget.
                    # The bookmark has advanced over everything already
                    # returned, so the remainder is picked up next poll - the
                    # backlog is reported, never silently carried.
                    self.last_read_truncated = "budget"
                    break
                handles = (wintypes.HANDLE * 16)()
                returned = wintypes.DWORD(0)
                if not _wevtapi.EvtNext(h, 16, handles, 1000, 0, ctypes.byref(returned)):
                    break
                if returned.value == 0:
                    break
                for i in range(returned.value):
                    xml = _render_xml(handles[i])
                    _wevtapi.EvtClose(handles[i])
                    if xml:
                        out.append(xml)
                        rid = record_id_of(xml)
                        if rid > self._last_record:
                            self._last_record = rid
            else:
                self.last_read_truncated = "max_events"
        finally:
            _wevtapi.EvtClose(h)
        self.last_read_count = len(out)
        return out
