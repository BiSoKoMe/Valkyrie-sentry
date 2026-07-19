"""Windows Event Log reader over the native wevtapi (ctypes).

The modern Windows Event Log channels (PowerShell/Operational, WMI-Activity,
Sysmon, …) are **ETW-backed**: providers write ETW events that the Event Log
service persists to a channel. Reading a channel with `EvtQuery`/`EvtNext`/
`EvtRender` therefore gives real, ETW-sourced telemetry with:

  * **no third-party dependency** (wevtapi ships with Windows),
  * **no console / no subprocess** (direct API calls, unlike `wevtutil`),
  * **incremental, near-real-time** delivery (poll by EventRecordID bookmark).

This is the strongest practical alternative to a raw NT-Kernel-Logger ETW session
(which would need a native trace consumer or a driver — see ADR 0003). The pure
``parse_event_xml`` helper is separated from the ctypes reader so parsing is unit-
testable without Windows.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from typing import Optional

log = logging.getLogger("valkyrie.sensors.evtlog")

# ── pure XML parsing (testable anywhere) ────────────────────────────────────
# Remove xmlns declarations so ElementTree yields un-namespaced tags we can
# find() by plain name (Windows event XML uses a single default namespace).
_XMLNS = re.compile(r"\sxmlns(:\w+)?=(['\"])[^'\"]*\2")
_RECORD_ID = re.compile(r"<EventRecordID>(\d+)</EventRecordID>")


def record_id_of(xml: str) -> int:
    m = _RECORD_ID.search(xml or "")
    return int(m.group(1)) if m else 0


def parse_event_xml(xml: str) -> dict:
    """Parse a rendered Windows event XML into a flat dict:
    {event_id, record_id, time, computer, process_id, thread_id, user_sid,
     provider, data:{Name->value}}. Never raises — returns {} on bad input."""
    try:
        root = ET.fromstring(_XMLNS.sub("", xml))
    except ET.ParseError:
        return {}
    out: dict = {"data": {}}
    system = root.find("System")
    if system is not None:
        def _txt(tag):
            el = system.find(tag)
            return el.text if el is not None else None
        out["event_id"] = int((_txt("EventID") or "0") or 0)
        out["record_id"] = int((_txt("EventRecordID") or "0") or 0)
        out["computer"] = _txt("Computer") or ""
        prov = system.find("Provider")
        out["provider"] = prov.get("Name") if prov is not None else ""
        tc = system.find("TimeCreated")
        out["time"] = tc.get("SystemTime") if tc is not None else ""
        exe = system.find("Execution")
        if exe is not None:
            out["process_id"] = int(exe.get("ProcessID") or 0)
            out["thread_id"] = int(exe.get("ThreadID") or 0)
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
    # UserData: <UserData><Operation_X><Field>val</Field>…</Operation_X></UserData>
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


# ── ctypes channel reader (Windows only) ────────────────────────────────────
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
    # Canonical "does this channel exist?" check — returns NULL for an unknown
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

    def available(self) -> bool:
        # The channel must actually exist. EvtOpenChannelConfig returns NULL for
        # an unknown channel (Sysmon not installed) — unlike EvtQuery, which with
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

    def read_new(self, max_events: int = 256) -> list[str]:
        if not _WEVT_OK:
            return []
        if self._last_record is None:
            self._last_record = self._newest_record()      # baseline, emit nothing
            return []
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
        finally:
            _wevtapi.EvtClose(h)
        return out
