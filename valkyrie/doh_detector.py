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
        self._running = False
        self._scan_errors = 0
        self._last_error = ""
        self._thread = threading.Thread(
            target=self._scan_loop, daemon=True, name="doh-detector"
        )

    def start(self) -> None:
        if not _PSUTIL:
            return
        self._running = True
        # A fresh Thread when the previous has finished: a Thread object cannot
        # be started twice, so without this a restart (including a watchdog
        # recovery) would raise instead of reviving the detector.
        if self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._scan_loop, daemon=True, name="doh-detector"
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def is_running(self) -> bool:
        return bool(self._running and self._thread.is_alive())

    def status(self) -> dict:
        return {
            "running": self.is_running(),
            "available": _PSUTIL,
            "alerts_seen": len(self._seen),
            "scan_errors": self._scan_errors,
            "last_error": self._last_error,
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _scan_loop(self) -> None:
        # _scan() only caught psutil.AccessDenied around net_connections(), but
        # that call also raises OSError/psutil.Error transiently, and the rest of
        # the scan body was unguarded entirely. One raise killed this thread and
        # DoH-bypass detection stopped silently for the life of the run - the
        # detector that exists to notice DNS being routed around Valkyrie would
        # itself be gone, with nothing reporting it.
        while self._running:
            try:
                self._scan()
            except BaseException as exc:      # noqa: BLE001
                self._scan_errors += 1
                self._last_error = f"{type(exc).__name__}: {exc}"
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
