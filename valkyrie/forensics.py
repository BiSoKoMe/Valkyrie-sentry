"""Digital forensics - one-command triage collection for an incident.

When an analyst decides an incident matters, the next question is always
"preserve everything now, before it changes." This module collects a
**triage bundle**: a zip of JSON artifacts capturing the incident record,
its detections/responses/timeline, the surrounding event window from the
store, a live process snapshot, the persistence (ASEP) surface, active
network connections, and host context - each artifact SHA256-hashed into a
signed-shape manifest for evidence integrity (chain of custody starts with
"what was collected, when, and its hash").

Design contract:

  * **Local only.** Bundles are written to ``DATA_DIR/forensics``; nothing
    is uploaded anywhere. Bundles contain security-relevant host state -
    treat them as sensitive, ship them only by operator action.
  * **Best-effort, never fatal.** Any single artifact that cannot be
    collected (psutil missing, access denied) records an error entry in
    the manifest instead of failing the bundle - a partial triage beats no
    triage, and the manifest says exactly what is and isn't inside.
  * **Deterministic + testable.** Collection functions are injectable;
    tests exercise the full bundle path offline with synthetic services.
"""

from __future__ import annotations

import hashlib
import json
import platform
import socket
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from . import __version__
from .config import DATA_DIR

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

FORENSICS_DIR = DATA_DIR / "forensics"
_EVENT_WINDOW_MIN = 30      # minutes of store events either side of creation
_MAX_EVENTS = 2000


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Artifact collectors (each returns a JSON-serializable object; may raise -
# the bundler catches and records the failure per-artifact)
# ---------------------------------------------------------------------------

def collect_host_context() -> dict:
    info = {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "collected_at": _utcnow(),
    }
    if _PSUTIL:
        info["boot_time"] = datetime.fromtimestamp(
            psutil.boot_time(), tz=timezone.utc).isoformat()
        info["users"] = [u._asdict() for u in psutil.users()]
    return info


def collect_process_tree() -> list[dict]:
    """Live process snapshot with ancestry - the state most likely to vanish."""
    if not _PSUTIL:
        raise RuntimeError("psutil unavailable")
    out = []
    for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline",
                                  "username", "create_time"]):
        try:
            d = dict(p.info)
            ct = d.get("create_time")
            if ct:
                d["create_time"] = datetime.fromtimestamp(
                    ct, tz=timezone.utc).isoformat()
            d["cmdline"] = " ".join(d.get("cmdline") or [])
            out.append(d)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return out


def collect_network_connections() -> list[dict]:
    if not _PSUTIL:
        raise RuntimeError("psutil unavailable")
    out = []
    for c in psutil.net_connections(kind="inet"):
        try:
            out.append({
                "pid": c.pid,
                "status": getattr(c, "status", ""),
                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
            })
        except Exception:
            continue
    return out


def collect_asep_snapshot() -> dict:
    """Persistence surface via the existing collector (registry Run keys,
    services, scheduled tasks, startup folders)."""
    from .persistence_telemetry import PersistenceCollector
    coll = PersistenceCollector(emit=lambda ev: None)
    if not coll.available():
        raise RuntimeError("persistence collector unavailable on this platform")
    return coll.snapshot()


def collect_event_slice(store, around_iso: str,
                        window_min: int = _EVENT_WINDOW_MIN) -> list[dict]:
    """Store events within ±window of the incident's creation time."""
    events = store.recent_events(limit=_MAX_EVENTS)
    try:
        center = datetime.fromisoformat(str(around_iso).replace("Z", "+00:00"))
        if center.tzinfo is None:
            center = center.replace(tzinfo=timezone.utc)
    except ValueError:
        return events   # unparseable center: preserve everything we have
    lo = center - timedelta(minutes=window_min)
    hi = center + timedelta(minutes=window_min)
    out = []
    for ev in events:
        try:
            ts = datetime.fromisoformat(
                str(ev.get("timestamp", "")).replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if lo <= ts <= hi:
            out.append(ev)
    return out


# ---------------------------------------------------------------------------
# Bundler
# ---------------------------------------------------------------------------

class TriageCollector:
    """Builds a triage bundle zip for one incident."""

    def __init__(self, edr, store, out_dir: Optional[Path] = None) -> None:
        self._edr = edr
        self._store = store
        self._dir = Path(out_dir) if out_dir else FORENSICS_DIR

    def collect(self, incident_id: str) -> dict:
        """Collect and write the bundle. Returns the manifest (which includes
        the bundle path). Raises KeyError only if the incident doesn't exist -
        every artifact failure is recorded, not raised."""
        incident = self._edr.get_incident(incident_id)
        if incident is None:
            raise KeyError(f"incident not found: {incident_id}")

        artifacts: dict[str, object] = {"incident.json": incident}
        errors: dict[str, str] = {}

        def _try(name: str, fn) -> None:
            try:
                artifacts[name] = fn()
            except Exception as exc:   # noqa: BLE001 - recorded, not raised
                errors[name] = f"{type(exc).__name__}: {exc}"

        _try("host.json", collect_host_context)
        _try("processes.json", collect_process_tree)
        _try("connections.json", collect_network_connections)
        _try("persistence.json", collect_asep_snapshot)
        _try("events.json", lambda: collect_event_slice(
            self._store, incident.get("created_at", "")))

        # Serialize + hash every artifact, then zip with the manifest.
        self._dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        bundle_path = self._dir / f"triage_{incident_id[:12]}_{stamp}.zip"

        blobs: dict[str, bytes] = {}
        hashes: dict[str, str] = {}
        for name, obj in artifacts.items():
            data = json.dumps(obj, indent=1, sort_keys=True,
                              default=str).encode("utf-8")
            blobs[name] = data
            hashes[name] = hashlib.sha256(data).hexdigest()

        manifest = {
            "bundle_format": 1,
            "tool": "Valkyrie TriageCollector",
            "tool_version": __version__,
            "incident_id": incident_id,
            "collected_at": _utcnow(),
            "artifacts": {n: {"sha256": h, "bytes": len(blobs[n])}
                          for n, h in hashes.items()},
            "collection_errors": errors,
        }
        mdata = json.dumps(manifest, indent=1, sort_keys=True).encode("utf-8")

        with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("MANIFEST.json", mdata)
            for name, data in blobs.items():
                z.writestr(name, data)

        manifest["bundle_path"] = str(bundle_path)
        manifest["bundle_sha256"] = hashlib.sha256(
            bundle_path.read_bytes()).hexdigest()
        return manifest


def verify_bundle(path: Path) -> dict:
    """Re-hash every artifact inside a bundle against its manifest.

    Returns {"ok": bool, "mismatched": [...], "missing": [...]} - the
    integrity half of chain of custody, runnable anywhere, stdlib only.
    """
    with zipfile.ZipFile(path) as z:
        manifest = json.loads(z.read("MANIFEST.json"))
        names = set(z.namelist()) - {"MANIFEST.json"}
        mismatched, missing = [], []
        for name, meta in manifest.get("artifacts", {}).items():
            if name not in names:
                missing.append(name)
                continue
            if hashlib.sha256(z.read(name)).hexdigest() != meta.get("sha256"):
                mismatched.append(name)
    return {"ok": not mismatched and not missing,
            "mismatched": mismatched, "missing": missing,
            "artifacts": len(manifest.get("artifacts", {})),
            "collection_errors": manifest.get("collection_errors", {})}
