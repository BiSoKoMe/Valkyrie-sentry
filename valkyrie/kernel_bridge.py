"""Kernel-driver bridge — user-mode side of the Valkyrie kernel driver.

Reads fixed-size telemetry records out of the Valkyrie kernel driver
(driver/valkyrie_km) over its control device and normalises them into the SAME
``TelemetryEvent`` stream every other sensor produces, so kernel signals flow
through the existing EventBus → correlation → kill-chain pipeline with zero new
plumbing. It is a ``Sensor``, hosted by the resilient ``SensorManager`` (dedup,
backpressure, watchdog) exactly like the ETW sensors.

Honest operational contract:
  * ``available()`` returns False unless the driver's device actually opens, so
    on any machine WITHOUT the signed driver loaded (the default — see
    driver/README.md) this sensor cleanly does nothing and the product behaves
    exactly as it does today. There is no fake "kernel protection active".
  * The record layout is the single shared contract in
    driver/valkyrie_km/valkyrie_shared.h; the constants below mirror it and are
    version-checked, so a mismatched driver/bridge refuses to parse rather than
    silently misreading kernel memory.

The record PARSER (``parse_records`` / ``record_to_event``) is pure and
unit-tested against synthesised bytes; the device I/O is a thin, isolated,
Windows-only layer that never runs in tests or on non-Windows.
"""

from __future__ import annotations

import os
import struct
import sys
from typing import Optional

from .etw.framework import Sensor
from .telemetry import CAT_PROCESS, TelemetryEvent

# ── Wire contract — MUST match driver/valkyrie_km/valkyrie_shared.h ──────────
VLK_PROTO_VERSION = 1
VLK_PATH_LEN = 260                     # WCHARs incl. null
_HEADER = struct.Struct("<IIQIIII")    # version,type,ts,pid,ppid,flags,granted
_PATH_BYTES = VLK_PATH_LEN * 2         # UTF-16-LE
RECORD_SIZE = _HEADER.size + 2 * _PATH_BYTES   # 32 + 520 + 520 = 1072

VLK_EVT_PROCESS_CREATE = 1
VLK_EVT_PROCESS_EXIT = 2
VLK_EVT_IMAGE_LOAD = 3
VLK_EVT_LSASS_ACCESS_BLOCKED = 4

VLK_FLAG_SYSTEM_PROC = 0x01
VLK_FLAG_REMOTE_IMAGE = 0x02

VLK_USERMODE_PATH = r"\\.\ValkyrieKm"

# 100ns ticks between 1601-01-01 (Windows epoch) and 1970-01-01 (Unix epoch).
_EPOCH_DELTA_TICKS = 116444736000000000


def _win_filetime_to_epoch(ticks: int) -> float:
    """Convert a Windows FILETIME (100ns since 1601) to Unix epoch seconds."""
    if ticks <= 0:
        return 0.0
    return (ticks - _EPOCH_DELTA_TICKS) / 1e7


def _wstr(buf: bytes) -> str:
    """Decode a fixed WCHAR[VLK_PATH_LEN] field to str, stopping at the null."""
    s = buf.decode("utf-16-le", errors="replace")
    nul = s.find("\x00")
    return s[:nul] if nul != -1 else s


def _basename(path: str) -> str:
    return path.rsplit("\\", 1)[-1] if path else ""


def record_to_event(raw: bytes) -> Optional[dict]:
    """Pure: one raw kernel record → a telemetry event dict (or None to skip).

    The dict shape matches what ``EdrEngine.ingest_telemetry`` consumes; lineage
    (ppid / parent) rides in ``fields`` so the kill-chain correlator links a
    child to its parent's chain. Returns None for a version mismatch or an event
    kind that carries no actionable signal.
    """
    if len(raw) < RECORD_SIZE:
        return None
    version, etype, ts, pid, ppid, flags, granted = _HEADER.unpack_from(raw, 0)
    if version != VLK_PROTO_VERSION:
        return None
    off = _HEADER.size
    image = _wstr(raw[off:off + _PATH_BYTES])
    extra = _wstr(raw[off + _PATH_BYTES:off + 2 * _PATH_BYTES])
    ts_epoch = _win_filetime_to_epoch(ts)

    if etype == VLK_EVT_LSASS_ACCESS_BLOCKED:
        # The single highest-value signal: a process tried to read LSASS memory
        # and the driver STRIPPED the rights. High-severity credential-access
        # (T1003.001 via the "lsass_access" label), flagged so it becomes a
        # detection and can anchor a kill chain. Actor = the requestor.
        requestor = _basename(extra) or f"pid {pid}"
        return {
            "category": CAT_PROCESS, "activity": "lsass_access", "action": "flagged",
            "severity": "high", "ts": ts_epoch,
            "actor_pid": pid, "actor_name": requestor, "actor_path": extra,
            "reason": f"Kernel blocked credential-theft access to LSASS by {requestor}",
            "labels": ["lsass_access"], "source": "kernel.ob",
            "fields": {"granted_access": granted, "kernel": True},
        }

    if etype == VLK_EVT_PROCESS_CREATE:
        # Authoritative process lineage (pid, ppid, image) straight from the
        # kernel. Visibility, not a detection on its own — but it supplies the
        # ground-truth ppid the correlator's lineage linking depends on.
        return {
            "category": CAT_PROCESS, "activity": "exec", "action": "observed",
            "severity": "info", "ts": ts_epoch,
            "actor_pid": pid, "actor_name": _basename(image), "actor_path": image,
            "reason": "", "labels": [], "source": "kernel.proc",
            "fields": {"ppid": ppid, "kernel": True},
        }

    if etype == VLK_EVT_IMAGE_LOAD:
        # Module load. Signature verdicts are user-mode's job (Authenticode);
        # the driver reports the fact. A remote/UNC backing path is a weak
        # anomaly worth surfacing but never blocked here.
        remote = bool(flags & VLK_FLAG_REMOTE_IMAGE)
        return {
            "category": CAT_PROCESS, "activity": "image_load",
            "action": "flagged" if remote else "observed",
            "severity": "medium" if remote else "info", "ts": ts_epoch,
            "actor_pid": pid, "actor_name": "", "actor_path": "",
            "reason": (f"Module loaded from a remote/UNC path: {extra}" if remote else ""),
            "labels": (["remote_module"] if remote else []),
            "source": "kernel.image",
            "fields": {"module": extra, "remote": remote, "kernel": True},
        }

    # PROCESS_EXIT and anything else: no actionable signal for the pipeline.
    return None


def parse_records(buf: bytes) -> list[dict]:
    """Split a pulled buffer into normalised event dicts (drops empties)."""
    out: list[dict] = []
    for i in range(0, len(buf) - RECORD_SIZE + 1, RECORD_SIZE):
        ev = record_to_event(buf[i:i + RECORD_SIZE])
        if ev is not None:
            out.append(ev)
    return out


class KernelSensor(Sensor):
    """Hosts the kernel driver as a Valkyrie sensor. Self-disables when the
    driver device is absent, so it is safe to register unconditionally."""

    name = "kernel.driver"
    interval = 0.5            # poll the ring twice a second
    _PULL_EVENTS = 256        # records per IOCTL pull

    # IOCTL codes (must match valkyrie_shared.h: CTL_CODE(FILE_DEVICE_UNKNOWN,
    # 0x800/0x801, METHOD_BUFFERED, FILE_READ_DATA)).
    _IOCTL_PULL = (0x22 << 16) | (0x1 << 14) | (0x800 << 2) | 0
    _IOCTL_STATS = (0x22 << 16) | (0x1 << 14) | (0x801 << 2) | 0

    def __init__(self) -> None:
        super().__init__()
        self._handle = None

    def available(self) -> bool:
        """True only if the driver device actually opens. On non-Windows, or
        when the driver isn't loaded, this is False and the sensor stays dark."""
        if sys.platform != "win32":
            return False
        h = self._open()
        if h is None:
            return False
        self._close(h)
        return True

    # --- Windows device I/O (isolated; never exercised in tests) -------------
    def _open(self):
        try:
            import ctypes
            from ctypes import wintypes
            GENERIC_READ = 0x80000000
            OPEN_EXISTING = 3
            FILE_ATTRIBUTE_NORMAL = 0x80
            CreateFile = ctypes.windll.kernel32.CreateFileW
            CreateFile.restype = wintypes.HANDLE
            h = CreateFile(VLK_USERMODE_PATH, GENERIC_READ, 0, None,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
            if h == wintypes.HANDLE(-1).value or not h:
                return None
            return h
        except Exception:
            return None

    def _close(self, h) -> None:
        try:
            import ctypes
            ctypes.windll.kernel32.CloseHandle(h)
        except Exception:
            pass

    def _pull(self, h) -> bytes:
        import ctypes
        from ctypes import wintypes
        buf = ctypes.create_string_buffer(RECORD_SIZE * self._PULL_EVENTS)
        returned = wintypes.DWORD(0)
        ok = ctypes.windll.kernel32.DeviceIoControl(
            h, self._IOCTL_PULL, None, 0, buf, len(buf),
            ctypes.byref(returned), None)
        if not ok:
            return b""
        return buf.raw[:returned.value]

    def start(self) -> None:
        if self._running or not self.available():
            return
        self._handle = self._open()
        super().start()

    def stop(self) -> None:
        super().stop()
        if self._handle is not None:
            self._close(self._handle)
            self._handle = None

    def _collect_once(self) -> None:
        if self._handle is None:
            return
        raw = self._pull(self._handle)
        if not raw:
            return
        for ev in parse_records(raw):
            self.submit(TelemetryEvent.from_dict(ev))
