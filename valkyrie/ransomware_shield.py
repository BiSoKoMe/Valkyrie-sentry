"""Ransomware Shield - local behavioral ransomware defense.

Strategy (all local, no cloud, no signatures, no global telemetry):

  1. **Canary tripwires** - decoy files planted in the file areas ransomware
     targets (every real user's Documents / Desktop / Pictures / Downloads).
     Ransomware enumerating and encrypting files hits them. Because normal
     software never touches these specific files, a modified/deleted/renamed
     canary is a near-zero-false-positive, high-confidence signal.
  2. **Entropy confirmation** - a tripped canary is read back; encrypted content
     is ~7.99 bits/byte (near-maximal Shannon entropy). This distinguishes real
     encryption from an accidental touch.
  3. **I/O attribution (heuristic)** - the process most likely responsible is
     ranked by recent disk-write bytes (psutil per-process io_counters) sampled
     each poll, corroborated by open file handles in the affected directory.
  4. **Response** - per configured mode: *monitor* (alert only), *suspend*
     (default - reversible, halts encryption in place), or *kill*. A CRITICAL
     incident (MITRE T1486 Data Encrypted for Impact) is raised through the EDR
     correlation pipeline, and tripped canaries are restored.

HONEST BOUNDARY: attribution is a documented I/O heuristic, not deterministic.
Pre-write blocking with exact per-write PID attribution requires a signed
filesystem **minifilter** driver (the commercial approach). See the "Extension
points" section of docs/RANSOMWARE_SHIELD.md. This module is the strongest
defense achievable in user space, with clean seams for that upgrade.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

log = logging.getLogger("valkyrie.ransomware")

try:
    import psutil
except Exception:  # pragma: no cover - psutil is a hard dep in practice
    psutil = None  # type: ignore

# Windows system processes we must NEVER suspend/kill, whatever the heuristic says.
_PROTECTED_PROCESSES = frozenset({
    "system", "system idle process", "registry", "smss.exe", "csrss.exe",
    "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe", "svchost.exe",
    "explorer.exe", "dwm.exe", "fontdrvhost.exe", "valkyrie.exe", "python.exe",
    "memory compression",
})

# Directories inside each user profile that ransomware overwhelmingly targets.
_TARGET_SUBDIRS = ("Documents", "Desktop", "Pictures", "Downloads")

# Canary file specs: names chosen to sit at the extremes of an alphabetical
# enumeration (ransomware often walks directories in order), across the file
# types ransomware prizes. Content is deliberately low-entropy readable text.
_CANARY_NAMES = (
    "!Valkyrie_Protected_ReadMe.docx",
    "~$Valkyrie_backup_2024.xlsx",
    "zzz_valkyrie_vault.jpg",
    "_Valkyrie_Financials.pdf",
)
_CANARY_BODY = (
    b"VALKYRIE RANSOMWARE SHIELD - PROTECTED DECOY FILE\r\n"
    b"Do not delete or modify. This file is a tripwire used to detect and stop\r\n"
    b"ransomware. If a program other than you modifies it, Valkyrie will act.\r\n"
    * 40
)
_ENTROPY_ENCRYPTED = 7.5   # bits/byte above which content is treated as encrypted


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of a byte string in bits/byte (0..8). Pure, testable."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


@dataclass
class Canary:
    path: str
    sha256: str
    size: int

    def current(self) -> Optional["Canary"]:
        """Return the canary's on-disk state now, or None if it's gone."""
        try:
            data = Path(self.path).read_bytes()
        except (FileNotFoundError, OSError):
            return None
        return Canary(self.path, hashlib.sha256(data).hexdigest(), len(data))

    def is_intact(self) -> bool:
        cur = self.current()
        return cur is not None and cur.sha256 == self.sha256


# ---------------------------------------------------------------------------
# Canary management
# ---------------------------------------------------------------------------
class CanaryManager:
    """Deploys, verifies, and restores canary tripwires; persists a manifest so
    the set survives restarts and crashes."""

    def __init__(self, manifest_path: Path, dirs: Optional[Iterable[Path]] = None):
        self.manifest_path = Path(manifest_path)
        self._explicit_dirs = [Path(d) for d in dirs] if dirs is not None else None
        self.canaries: list[Canary] = []

    # -- target discovery ---------------------------------------------------
    def target_dirs(self) -> list[Path]:
        """Directories to plant canaries in. Enumerates EVERY real user profile
        (the engine runs as SYSTEM, so ~ would be the service profile - wrong),
        placing a dedicated 'Valkyrie Protected' subfolder in each target area."""
        if self._explicit_dirs is not None:
            return [d for d in self._explicit_dirs]
        dirs: list[Path] = []
        users_root = Path(os.environ.get("SystemDrive", "C:") + "\\Users")
        skip = {"public", "default", "default user", "all users", "defaultuser0"}
        if users_root.exists():
            for prof in users_root.iterdir():
                if not prof.is_dir() or prof.name.lower() in skip or prof.name.startswith("."):
                    continue
                for sub in _TARGET_SUBDIRS:
                    p = prof / sub
                    if p.is_dir():
                        dirs.append(p / "Valkyrie Protected")
        if not dirs:                      # dev / non-Windows fallback
            dirs.append(Path.home() / "Valkyrie Protected")
        return dirs

    # -- deploy / verify / restore -----------------------------------------
    def deploy(self) -> int:
        """Create canaries in every target dir. Idempotent: existing intact
        canaries are reused. Returns the number of canaries now armed."""
        armed: list[Canary] = []
        digest = hashlib.sha256(_CANARY_BODY).hexdigest()
        for d in self.target_dirs():
            try:
                d.mkdir(parents=True, exist_ok=True)
                self._write_readme(d)
            except OSError as e:
                log.warning("canary dir unavailable %s: %s", d, e)
                continue
            for name in _CANARY_NAMES:
                path = d / name
                try:
                    if not path.exists() or path.read_bytes() != _CANARY_BODY:
                        path.write_bytes(_CANARY_BODY)
                    armed.append(Canary(str(path), digest, len(_CANARY_BODY)))
                except OSError as e:
                    log.warning("could not write canary %s: %s", path, e)
        self.canaries = armed
        self._save_manifest()
        log.info("ransomware shield armed with %d canaries", len(armed))
        return len(armed)

    def _write_readme(self, d: Path) -> None:
        readme = d / "README.txt"
        if not readme.exists():
            try:
                readme.write_text(
                    "This folder contains Valkyrie ransomware decoy files.\n"
                    "They are harmless tripwires. If ransomware tries to encrypt your\n"
                    "files, it will touch these first and Valkyrie will stop it.\n"
                    "You can safely ignore this folder.\n", encoding="utf-8")
            except OSError:
                pass

    def verify(self) -> list[Canary]:
        """Return canaries that have been modified or deleted (tripped)."""
        return [c for c in self.canaries if not c.is_intact()]

    def restore(self, tripped: Iterable[Canary]) -> int:
        n = 0
        for c in tripped:
            try:
                Path(c.path).parent.mkdir(parents=True, exist_ok=True)
                Path(c.path).write_bytes(_CANARY_BODY)
                n += 1
            except OSError as e:
                log.warning("could not restore canary %s: %s", c.path, e)
        return n

    # -- manifest persistence ----------------------------------------------
    def _save_manifest(self) -> None:
        try:
            self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
            self.manifest_path.write_text(
                json.dumps([c.__dict__ for c in self.canaries], indent=2),
                encoding="utf-8")
        except OSError as e:
            log.warning("could not save canary manifest: %s", e)

    def load_manifest(self) -> int:
        try:
            rows = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            self.canaries = [Canary(**r) for r in rows]
        except (OSError, ValueError):
            self.canaries = []
        return len(self.canaries)


# ---------------------------------------------------------------------------
# The shield
# ---------------------------------------------------------------------------
class RansomwareShield:
    """Monitors canaries, confirms with entropy, attributes and responds.

    Thread-safe, crash-resilient (the monitor loop never lets an exception
    escape), observable via status(), and recoverable (canaries reload/redeploy
    on start). Response is conservative by default (suspend, reversible)."""

    RESPONSE_MODES = ("monitor", "suspend", "kill")

    def __init__(
        self,
        manifest_path: Path,
        *,
        edr=None,
        store=None,
        response_mode: str = "suspend",
        poll_interval: float = 2.0,
        cooldown: float = 30.0,
        dirs: Optional[Iterable[Path]] = None,
        alert_cb: Optional[Callable[[dict], None]] = None,
    ):
        if response_mode not in self.RESPONSE_MODES:
            response_mode = "suspend"
        self.manager = CanaryManager(manifest_path, dirs=dirs)
        self.edr = edr
        self.store = store
        self.response_mode = response_mode
        self.poll_interval = max(0.5, float(poll_interval))
        self.cooldown = float(cooldown)
        self.alert_cb = alert_cb

        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._io_prev: dict[int, int] = {}
        self._last_trip = 0.0
        self.armed = False
        self.stats = {
            "canaries": 0, "detections": 0, "processes_stopped": 0,
            "last_event": None, "last_error": None,
        }

    # -- lifecycle ----------------------------------------------------------
    def start(self) -> bool:
        if self._thread and self._thread.is_alive():
            return True
        # Recover prior canaries, then (re)deploy to fill any gaps.
        self.manager.load_manifest()
        try:
            count = self.manager.deploy()
        except Exception as e:                       # never block engine startup
            log.error("canary deploy failed: %s", e)
            self.stats["last_error"] = str(e)
            count = len(self.manager.canaries)
        self.stats["canaries"] = count
        self.armed = count > 0
        self._sample_io()
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="ransomware-shield", daemon=True)
        self._thread.start()
        log.info("ransomware shield started (mode=%s, canaries=%d)", self.response_mode, count)
        return self.armed

    def stop(self) -> None:
        self._stop.set()
        t = self._thread
        if t and t.is_alive():
            t.join(timeout=3.0)

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    # -- monitor loop -------------------------------------------------------
    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                tripped = self.manager.verify()
                if tripped:
                    self._on_trip(tripped)
                self._sample_io()
            except Exception as e:                   # resilience: log and continue
                log.exception("ransomware monitor iteration failed: %s", e)
                self.stats["last_error"] = str(e)
            self._stop.wait(self.poll_interval)

    # -- I/O sampling for attribution --------------------------------------
    def _sample_io(self) -> None:
        if psutil is None:
            return
        snap: dict[int, int] = {}
        for p in psutil.process_iter():
            # p.pid is a plain attribute set at construction - it never raises and
            # is never absent, unlike p.info["pid"], which KeyError'd here and
            # crash-looped the whole monitor thread.
            try:
                snap[p.pid] = p.io_counters().write_bytes  # type: ignore[attr-defined]
            except (psutil.Error, AttributeError, OSError, KeyError):
                continue
        self._io_prev = snap

    def _rank_suspects(self, affected_dir: Optional[str]) -> list[dict]:
        """Rank likely culprits by recent write-byte delta, corroborated by open
        handles in the affected directory. Best-effort heuristic."""
        if psutil is None:
            return []
        suspects: list[dict] = []
        for p in psutil.process_iter(["name"]):
            try:
                pid = p.pid                       # plain attribute; never KeyErrors
                pname = p.info.get("name") or ""
                name = pname.lower()
                if pid in (0, 4) or name in _PROTECTED_PROCESSES:
                    continue
                delta = p.io_counters().write_bytes - self._io_prev.get(pid, 0)
                if delta <= 0:
                    continue
                score = float(delta)
                if affected_dir:
                    try:
                        for f in p.open_files():
                            if str(f.path).lower().startswith(affected_dir.lower()):
                                score *= 4.0
                                break
                    except (psutil.Error, OSError):
                        pass
                suspects.append({"pid": pid, "name": pname, "write_delta": delta, "score": score})
            except (psutil.Error, OSError, KeyError):
                continue
        suspects.sort(key=lambda s: s["score"], reverse=True)
        return suspects[:5]

    # -- trip handling ------------------------------------------------------
    def _on_trip(self, tripped: list[Canary]) -> None:
        now = time.time()
        affected_dir = str(Path(tripped[0].path).parent)

        # Entropy confirmation from any tripped canary that still has content.
        entropy = 0.0
        for c in tripped:
            cur = c.current()
            if cur is not None:
                try:
                    entropy = max(entropy, shannon_entropy(Path(c.path).read_bytes()[:65536]))
                except OSError:
                    pass
        encrypted = entropy >= _ENTROPY_ENCRYPTED

        with self._lock:
            debounced = (now - self._last_trip) < self.cooldown
            self._last_trip = now

        suspects = self._rank_suspects(affected_dir)
        action_taken = "none"
        stopped: list[dict] = []
        if not debounced and self.response_mode != "monitor":
            stopped = self._respond(suspects)
            action_taken = self.response_mode

        # Always restore canaries so the tripwire re-arms.
        restored = self.manager.restore(tripped)
        # Reload manifest hashes for restored ones (content is identical -> hash same).

        self.stats["detections"] += 1
        self.stats["processes_stopped"] += len(stopped)
        event = {
            "type": "ransomware",
            "affected_dir": affected_dir,
            "tripped": [c.path for c in tripped],
            "entropy": round(entropy, 3),
            "encrypted": encrypted,
            "suspects": suspects,
            "stopped": stopped,
            "action": action_taken,
            "restored": restored,
            "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "debounced": debounced,
        }
        self.stats["last_event"] = event
        log.critical("RANSOMWARE tripwire: dir=%s entropy=%.2f encrypted=%s action=%s stopped=%s",
                     affected_dir, entropy, encrypted, action_taken, [s["name"] for s in stopped])

        if not debounced:
            self._raise_incident(event)
            if self.alert_cb:
                try:
                    self.alert_cb(event)
                except Exception:
                    pass

    def _respond(self, suspects: list[dict]) -> list[dict]:
        """Suspend (default) or kill the top suspect(s). Reversible-first."""
        if psutil is None or not suspects:
            return []
        stopped = []
        for s in suspects[:2]:                       # act on the top 1-2 only
            try:
                proc = psutil.Process(s["pid"])
                if (proc.name() or "").lower() in _PROTECTED_PROCESSES:
                    continue
                if self.response_mode == "kill":
                    proc.kill()
                else:
                    proc.suspend()
                stopped.append({"pid": s["pid"], "name": s["name"], "action": self.response_mode})
            except (psutil.Error, OSError) as e:
                log.warning("could not %s pid %s: %s", self.response_mode, s["pid"], e)
        return stopped

    def _raise_incident(self, event: dict) -> None:
        """Raise a CRITICAL incident through the EDR correlation pipeline."""
        if self.edr is None:
            return
        try:
            from .edr.schema import Detection
            top = event["suspects"][0] if event["suspects"] else {}
            det = Detection(
                source="ransomware_shield",
                severity="critical",
                category="ransomware",
                title="Ransomware behavior: canary files encrypted/modified",
                entity=event["affected_dir"],
                process_name=str(top.get("name", "")),
                process_pid=int(top.get("pid", 0) or 0),
                technique="T1486",   # Data Encrypted for Impact
                details=event,
            )
            self.edr.report_detection(det)
        except Exception as e:
            log.warning("could not raise ransomware incident: %s", e)

    # -- observability ------------------------------------------------------
    def status(self) -> dict:
        return {
            "enabled": True,
            "armed": self.armed,
            "running": self.is_running(),
            "response_mode": self.response_mode,
            "poll_interval": self.poll_interval,
            "canaries": self.stats["canaries"],
            "detections": self.stats["detections"],
            "processes_stopped": self.stats["processes_stopped"],
            "last_event": self.stats["last_event"],
            "last_error": self.stats["last_error"],
        }

    # -- safe self-test (no real processes touched) ------------------------
    def simulate(self, sandbox: Path) -> dict:
        """Run the *detection* path against a throwaway canary in `sandbox`,
        proving the tripwire + entropy logic without harming anything. Used by
        the /api self-test and unit tests."""
        sandbox = Path(sandbox)
        sandbox.mkdir(parents=True, exist_ok=True)
        mgr = CanaryManager(sandbox / "manifest.json", dirs=[sandbox])
        mgr.deploy()
        canary = Path(mgr.canaries[0].path)
        # Simulate encryption: overwrite with high-entropy bytes.
        canary.write_bytes(os.urandom(len(_CANARY_BODY)))
        tripped = mgr.verify()
        ent = shannon_entropy(canary.read_bytes())
        return {
            "tripped": len(tripped),
            "entropy": round(ent, 3),
            "detected": len(tripped) > 0,
            "encrypted_flagged": ent >= _ENTROPY_ENCRYPTED,
        }
