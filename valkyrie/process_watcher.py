"""Process attribution — map a UDP source (ip, port) to a running process.

DNS queries arrive as stateless UDP datagrams.  They never appear as
persistent connections, so the old approach of reading psutil TCP/UDP
connection entries doesn't work reliably.

Strategy by platform
--------------------
Linux:
  Read /proc/net/udp (and /proc/net/udp6) to get the kernel's UDP socket
  table, which includes the inode number for each socket.  Then walk every
  /proc/<pid>/fd/ symlink to find which PID owns each inode.  This is the
  same technique used by tools like ss(8) and lsof(1).  No root required
  for sockets owned by the current user; root gives full visibility.

Windows:
  psutil.net_connections(kind='udp') on Windows does return UDP entries
  with PIDs when run as Administrator.  We use that table directly.
  Without admin, fall back to a heuristic: return the most recently
  created non-system process as a best-effort guess.

The public interface is identical on both platforms:
  watcher.lookup(src_ip: str, src_port: int) -> ProcessInfo
"""

from __future__ import annotations

import os
import platform
import re
import socket
import struct
import threading
import time
from typing import Optional

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

_SYSTEM = platform.system()   # "Linux" | "Windows" | "Darwin"


# ---------------------------------------------------------------------------
# ProcessInfo
# ---------------------------------------------------------------------------

class ProcessInfo:
    __slots__ = ("name", "pid", "path")

    def __init__(self, name: str = "", pid: int = 0, path: str = "") -> None:
        self.name = name
        self.pid  = pid
        self.path = path

    def __repr__(self) -> str:
        return f"<Process {self.name!r} pid={self.pid}>"


_UNKNOWN = ProcessInfo(name="unknown", pid=0, path="")


# ---------------------------------------------------------------------------
# Linux: /proc/net/udp  →  inode  →  /proc/<pid>/fd
# ---------------------------------------------------------------------------

def _hex_to_ip4(hex_addr: str) -> str:
    """Convert little-endian hex address from /proc/net/udp to dotted-quad."""
    packed = struct.pack("<I", int(hex_addr, 16))
    return socket.inet_ntoa(packed)


def _hex_to_ip6(hex_addr: str) -> str:
    """Convert little-endian hex address from /proc/net/udp6 to IPv6 string."""
    # Four 32-bit words, each in little-endian byte order
    words = [hex_addr[i:i+8] for i in range(0, 32, 8)]
    packed = b"".join(struct.pack("<I", int(w, 16)) for w in words)
    return socket.inet_ntop(socket.AF_INET6, packed)


def _parse_proc_net_udp(path: str, ipv6: bool = False) -> dict[tuple[str, int], int]:
    """Parse /proc/net/udp[6] and return {(ip, port): inode}."""
    result: dict[tuple[str, int], int] = {}
    try:
        with open(path, "r") as f:
            next(f)  # skip header
            for line in f:
                parts = line.split()
                if len(parts) < 10:
                    continue
                local = parts[1]          # "hex_ip:hex_port"
                inode = int(parts[9])
                hex_ip, hex_port = local.split(":")
                port = int(hex_port, 16)
                ip   = _hex_to_ip6(hex_ip) if ipv6 else _hex_to_ip4(hex_ip)
                result[(ip, port)] = inode
    except (FileNotFoundError, PermissionError, ValueError):
        pass
    return result


def _build_inode_to_pid() -> dict[int, int]:
    """Walk /proc/*/fd/ and return {inode: pid} for all socket fds."""
    inode_to_pid: dict[int, int] = {}
    _socket_re = re.compile(r"socket:\[(\d+)\]")
    try:
        for entry in os.scandir("/proc"):
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            fd_dir = f"/proc/{pid}/fd"
            try:
                for fd in os.scandir(fd_dir):
                    try:
                        target = os.readlink(fd.path)
                        m = _socket_re.match(target)
                        if m:
                            inode_to_pid[int(m.group(1))] = pid
                    except (OSError, PermissionError):
                        pass
            except (OSError, PermissionError):
                pass
    except (OSError, PermissionError):
        pass
    return inode_to_pid


def _pid_to_info(pid: int) -> ProcessInfo:
    if not _PSUTIL:
        return ProcessInfo(pid=pid)
    try:
        proc = psutil.Process(pid)
        return ProcessInfo(
            name = proc.name(),
            pid  = pid,
            path = _safe_exe(proc),
        )
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return ProcessInfo(pid=pid)


def _build_table_linux() -> dict[tuple[str, int], ProcessInfo]:
    """Build (ip, port) → ProcessInfo table on Linux via /proc."""
    inode_map: dict[tuple[str, int], int] = {}
    inode_map.update(_parse_proc_net_udp("/proc/net/udp",  ipv6=False))
    inode_map.update(_parse_proc_net_udp("/proc/net/udp6", ipv6=True))

    if not inode_map:
        return {}

    inode_to_pid = _build_inode_to_pid()

    table: dict[tuple[str, int], ProcessInfo] = {}
    pid_cache: dict[int, ProcessInfo] = {}
    for endpoint, inode in inode_map.items():
        pid = inode_to_pid.get(inode)
        if pid is None:
            continue
        if pid not in pid_cache:
            pid_cache[pid] = _pid_to_info(pid)
        table[endpoint] = pid_cache[pid]
    return table


# ---------------------------------------------------------------------------
# Windows: psutil UDP connections  →  table; heuristic fallback
# ---------------------------------------------------------------------------

def _build_table_windows() -> dict[tuple[str, int], ProcessInfo]:
    """Build (ip, port) → ProcessInfo table on Windows."""
    if not _PSUTIL:
        return {}

    table: dict[tuple[str, int], ProcessInfo] = {}
    try:
        for conn in psutil.net_connections(kind="udp"):
            if conn.pid is None or not conn.laddr:
                continue
            info = _pid_to_info(conn.pid)
            table[(conn.laddr.ip, conn.laddr.port)] = info
    except psutil.AccessDenied:
        # No admin — table stays empty; lookup() will use heuristic fallback
        pass
    return table


def _windows_heuristic_fallback() -> ProcessInfo:
    """Best-effort: most recently created non-system process."""
    if not _PSUTIL:
        return _UNKNOWN
    _SYSTEM_NAMES = {"system", "svchost.exe", "services.exe", "lsass.exe",
                     "csrss.exe", "wininit.exe", "smss.exe", "registry"}
    best_pid   = 0
    best_ctime = 0.0
    try:
        for proc in psutil.process_iter(["pid", "name", "create_time"]):
            name = (proc.info.get("name") or "").lower()
            if name in _SYSTEM_NAMES or proc.info["pid"] in (0, 4):
                continue
            ct = proc.info.get("create_time") or 0.0
            if ct > best_ctime:
                best_ctime = ct
                best_pid   = proc.info["pid"]
    except psutil.AccessDenied:
        pass
    if best_pid:
        return _pid_to_info(best_pid)
    return _UNKNOWN


# ---------------------------------------------------------------------------
# Unified builder
# ---------------------------------------------------------------------------

def _build_table() -> dict[tuple[str, int], ProcessInfo]:
    if _SYSTEM == "Linux":
        return _build_table_linux()
    elif _SYSTEM == "Windows":
        return _build_table_windows()
    else:
        # macOS / other: psutil UDP connections (best-effort)
        if not _PSUTIL:
            return {}
        table: dict[tuple[str, int], ProcessInfo] = {}
        try:
            for conn in psutil.net_connections(kind="udp"):
                if conn.pid and conn.laddr:
                    table[(conn.laddr.ip, conn.laddr.port)] = _pid_to_info(conn.pid)
        except psutil.AccessDenied:
            pass
        return table


# ---------------------------------------------------------------------------
# ProcessWatcher
# ---------------------------------------------------------------------------

class ProcessWatcher:
    """Resolves (src_ip, src_port) → ProcessInfo for UDP DNS datagrams.

    Refreshes the platform-specific table every REFRESH_INTERVAL seconds
    so per-query lookup is O(1) dict access.
    """

    REFRESH_INTERVAL = 2.0

    def __init__(self) -> None:
        self._table: dict[tuple[str, int], ProcessInfo] = {}
        self._lock  = threading.RLock()
        self._watcher = threading.Thread(
            target=self._refresh_loop, daemon=True, name="proc-watcher"
        )

    def start(self) -> None:
        self._refresh()
        self._watcher.start()

    def lookup(self, src_ip: str, src_port: int) -> ProcessInfo:
        """Return ProcessInfo for the given UDP source endpoint."""
        with self._lock:
            info = self._table.get((src_ip, src_port))
        if info is not None:
            return info
        # On Windows without admin, table may be empty — use heuristic
        if _SYSTEM == "Windows":
            return _windows_heuristic_fallback()
        return _UNKNOWN

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        new_table = _build_table()
        with self._lock:
            self._table = new_table

    def _refresh_loop(self) -> None:
        while True:
            time.sleep(self.REFRESH_INTERVAL)
            self._refresh()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_exe(proc: "psutil.Process") -> str:
    try:
        return proc.exe()
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        return ""
