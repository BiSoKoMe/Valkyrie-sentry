"""Browser credential-store watch - endpoint visibility for T1555.003.

A tool that steals saved browser passwords does not need to touch the
registry or write a file that any of the other collectors would see: it just
opens Chrome's/Edge's/Firefox's own credential-store file and reads it. Valkyrie
has no filesystem minifilter to catch that read at the instant it happens (see
docs/adr/0026-kernel-driver.md - the honest boundary every userland collector
in this codebase shares), but psutil CAN enumerate which processes currently
hold a handle open to a given path. Polling that for the small, well-known set
of credential-store files is the same class of technique the ransomware
shield's suspect-ranking already uses (``open_files()`` against a directory),
just narrowed to a specific set of files instead of a directory tree.

The signal is deliberately narrow and strong: the credential-store files are
opened constantly by the OWNING browser itself (that is not a threat), so this
watch explicitly excludes the known browser processes (and Valkyrie itself).
Any OTHER process holding one of these files open is a real, specific tell -
"why does powershell.exe have Chrome's Login Data open" has essentially no
innocent answer - so a hit is HIGH severity on its own, unlike the Discovery
LOLBins in process_telemetry.classify_discovery which must never fire alone.

Honest boundary: this is a poll (default 5s), not a kernel hook - a tool that
opens the file, copies its bytes, and closes the handle inside the poll
interval can be missed. It also does not (and cannot, without a minifilter)
distinguish a read from a write. Real-time, tamper-resistant capture is the
same kernel-driver seam every other honest boundary in this codebase points
to; this collector is the same "as far as a real EDR can go without a signed
driver" seam the process/persistence collectors already accept.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Callable, Iterable, Optional

from .telemetry import (
    ACT_FLAGGED, CAT_PROCESS, SEV_HIGH, TelemetryEvent,
)

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

# Processes allowed to hold their OWN credential store open - never the alert.
_BROWSER_PROCS = frozenset({
    "chrome.exe", "msedge.exe", "brave.exe", "vivaldi.exe", "opera.exe",
    "firefox.exe", "librewolf.exe", "chromium.exe",
})

# Directories (relative to a user's AppData) that hold a Chromium-family
# credential store. Profile folders vary ("Default", "Profile 1", ...), so
# these are globbed, not enumerated literally.
_CHROMIUM_USER_DATA = (
    r"AppData\Local\Google\Chrome\User Data",
    r"AppData\Local\Microsoft\Edge\User Data",
    r"AppData\Local\BraveSoftware\Brave-Browser\User Data",
    r"AppData\Local\Vivaldi\User Data",
)
_CHROMIUM_CRED_FILES = ("Login Data", "Login Data For Account")

_FIREFOX_PROFILES = r"AppData\Roaming\Mozilla\Firefox\Profiles"
_FIREFOX_CRED_FILES = ("logins.json", "key4.db")


def credential_store_paths(users_root: Optional[Path] = None) -> list[Path]:
    """Enumerate every real user profile's known browser credential-store
    files. Enumerates C:\\Users explicitly (the engine runs as a service - no
    single "current user" - the same reasoning already applied in decoys.py
    and persistence_telemetry.py). Never raises; a path that does not exist
    on this machine is simply absent from the result, not an error."""
    root = users_root or Path(os.environ.get("SystemDrive", "C:") + "\\") / "Users"
    skip = {"public", "default", "default user", "all users", "defaultuser0"}
    paths: list[Path] = []
    if not root.is_dir():
        return paths
    try:
        profiles = list(root.iterdir())
    except OSError:
        return paths
    for prof in profiles:
        if not prof.is_dir() or prof.name.lower() in skip:
            continue
        for rel in _CHROMIUM_USER_DATA:
            user_data = prof / rel
            if not user_data.is_dir():
                continue
            try:
                sub_dirs = list(user_data.iterdir())
            except OSError:
                continue
            for sub in sub_dirs:
                if not sub.is_dir():
                    continue
                for fname in _CHROMIUM_CRED_FILES:
                    paths.append(sub / fname)
        ff_profiles = prof / _FIREFOX_PROFILES
        if ff_profiles.is_dir():
            try:
                for sub in ff_profiles.iterdir():
                    if not sub.is_dir():
                        continue
                    for fname in _FIREFOX_CRED_FILES:
                        paths.append(sub / fname)
            except OSError:
                pass
    return paths


class CredentialStoreWatch:
    """Polls running processes' open file handles for a hit against a known
    browser credential-store path. Emits a HIGH-severity TelemetryEvent
    (T1555.003) the first time a non-browser process is seen holding one open,
    then stays quiet on that same (pid, path) until ``cooldown`` elapses -
    a handle held open across several poll ticks must not spam one incident
    per tick."""

    def __init__(self, emit: Callable[[TelemetryEvent], None],
                 interval: float = 5.0, cooldown: float = 300.0,
                 paths: Optional[Iterable[Path]] = None) -> None:
        self._emit = emit
        self._interval = max(1.0, float(interval))
        self._cooldown = max(0.0, float(cooldown))
        self._explicit_paths = [Path(p) for p in paths] if paths is not None else None
        self._paths_lower: set[str] = set()
        self._last_seen: dict[tuple, float] = {}   # (pid, path) -> last-emitted ts
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def available(self) -> bool:
        return os.name == "nt" and _PSUTIL

    def target_paths(self) -> list[Path]:
        if self._explicit_paths is not None:
            return self._explicit_paths
        return credential_store_paths()

    # -- scan (overridable seam for tests - mirrors ProcessCollector.snapshot) -
    def _scan(self) -> list[dict]:
        """Return [{pid, name, path}] for every CURRENT non-browser, non-self
        process holding a handle open to a known credential-store path. Never
        raises: per-process access errors are skipped."""
        hits: list[dict] = []
        if not _PSUTIL or not self._paths_lower:
            return hits
        from .trust import is_self
        for p in psutil.process_iter(["pid", "name"]):
            try:
                name = (p.info.get("name") or "")
                lname = name.lower()
                if lname in _BROWSER_PROCS or is_self(lname, ""):
                    continue
                for f in p.open_files():
                    fp = str(f.path).lower()
                    if fp in self._paths_lower:
                        hits.append({"pid": p.pid, "name": name, "path": f.path})
            except (psutil.Error, OSError):
                continue
        return hits

    # -- poll ----------------------------------------------------------------
    def poll_once(self) -> int:
        """Run one scan, emit an event for each NEW (pid, path) hit (or one
        whose cooldown has expired). Returns the count emitted."""
        now = time.time()
        count = 0
        for hit in self._scan():
            key = (hit["pid"], str(hit["path"]).lower())
            last = self._last_seen.get(key, 0.0)
            if now - last < self._cooldown:
                continue
            self._last_seen[key] = now
            self._emit_hit(hit)
            count += 1
        return count

    def _emit_hit(self, hit: dict) -> None:
        ev = TelemetryEvent(
            category=CAT_PROCESS, activity="credential_store_access",
            action=ACT_FLAGGED, actor_pid=int(hit["pid"]), actor_name=hit["name"],
            target={"path": str(hit["path"])},
            severity=SEV_HIGH, source="browser_cred_watch",
            reason=f"non-browser process holds a browser credential store open ({hit['path']})",
            labels=["browser_cred_access"],
            fields={"technique": "T1555.003 — Credentials from Password Stores: Web Browsers"},
        )
        try:
            self._emit(ev)
        except Exception:
            pass   # a bad emitter must never stop the watch

    # -- lifecycle -------------------------------------------------------------
    def start(self) -> None:
        if self._running or not self.available():
            return
        self._paths_lower = {str(p).lower() for p in self.target_paths()}
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="browser-cred-watch")
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _loop(self) -> None:
        while self._running:
            time.sleep(self._interval)
            if not self._running:
                break
            try:
                self.poll_once()
            except Exception:
                pass
