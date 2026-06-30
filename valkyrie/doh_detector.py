"""DoH (DNS-over-HTTPS) bypass detector.

Scans live TCP connections every DOH_SCAN_INTERVAL seconds looking for
established HTTPS connections to known public DoH resolver IPs.  When found,
logs a "doh_bypass" event via the Store and emits a warning to the UI.

Root requirement:
  - Windows/macOS: psutil.net_connections() gives full info unprivileged in
    most cases but may need admin for per-connection PID on Windows.
  - Linux: no root needed for own-process connections; /proc/net/tcp readable
    by any user.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Optional

from .config import DOH_PORT, DOH_PROVIDER_IPS, DOH_SCAN_INTERVAL
from .store import DnsEvent, Store

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False


class DoHDetector:
    """Background thread that scans for DoH bypass attempts."""

    def __init__(self, store: Store, on_alert: Optional[Callable[[str, str, int], None]] = None) -> None:
        """
        Args:
            store:    event log to write alerts to
            on_alert: optional callback(process_name, remote_ip, pid) for UI notification
        """
        self._store    = store
        self._on_alert = on_alert
        self._seen: set[tuple[int, str, int]] = set()   # (pid, remote_ip, remote_port) already alerted
        self._thread = threading.Thread(
            target=self._scan_loop, daemon=True, name="doh-detector"
        )

    def start(self) -> None:
        if not _PSUTIL:
            return
        self._thread.start()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _scan_loop(self) -> None:
        while True:
            self._scan()
            time.sleep(DOH_SCAN_INTERVAL)

    def _scan(self) -> None:
        try:
            conns = psutil.net_connections(kind="tcp")
        except psutil.AccessDenied:
            return

        for conn in conns:
            if conn.status != "ESTABLISHED":
                continue
            raddr = conn.raddr
            if not raddr:
                continue
            if raddr.port != DOH_PORT:
                continue
            if raddr.ip not in DOH_PROVIDER_IPS:
                continue

            key = (conn.pid or 0, raddr.ip, raddr.port)
            if key in self._seen:
                continue
            self._seen.add(key)

            proc_name = "unknown"
            proc_path = ""
            pid       = conn.pid or 0
            if pid:
                try:
                    proc = psutil.Process(pid)
                    proc_name = proc.name()
                    try:
                        proc_path = proc.exe()
                    except (psutil.AccessDenied, OSError):
                        pass
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            event = DnsEvent.now(
                domain       = raddr.ip,
                decision     = "flagged",
                process_name = proc_name,
                process_pid  = pid,
                process_path = proc_path,
                reason       = f"DoH bypass attempt → {raddr.ip}:{raddr.port}",
                suspicion    = 0.9,
                raw_category = "doh_bypass",
            )
            self._store.log(event)

            if self._on_alert:
                try:
                    self._on_alert(proc_name, raddr.ip, pid)
                except Exception:
                    pass
