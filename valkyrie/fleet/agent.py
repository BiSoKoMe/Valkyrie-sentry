"""FleetAgent — device side of the control plane.

Enrolls this device once (persisting its issued id + token locally), then
sends a privacy-preserving heartbeat on a timer. Uses only the standard
library (urllib) so a protected endpoint needs no extra runtime dependency.

The heartbeat payload is built from a `status_provider` callable the caller
supplies — typically wrapping the local Store.stats(). This module extracts
ONLY counts/categories/health from that dict; it never forwards domains (see
protocol.py). If a caller's provider returns domain strings, they are dropped
here rather than sent.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Optional

from .. import __version__
from ..config import (
    FLEET_AGENT_IDENTITY_PATH,
    FLEET_HEARTBEAT_INTERVAL,
)
from .protocol import EnrollmentRequest, Heartbeat


class FleetAgent:
    def __init__(
        self,
        server_url: str,
        status_provider: Callable[[], dict],
        identity_path: Path = FLEET_AGENT_IDENTITY_PATH,
        label: str = "",
        interval: float = FLEET_HEARTBEAT_INTERVAL,
        console=None,
    ) -> None:
        self._server   = server_url.rstrip("/")
        self._provider = status_provider
        self._identity_path = Path(identity_path)
        self._label    = label or _default_label()
        self._interval = interval
        self._console  = console
        self._device_id: Optional[str]    = None
        self._device_token: Optional[str] = None
        self._running  = False
        self._thread: Optional[threading.Thread] = None
        self._load_identity()

    # ------------------------------------------------------------------

    def _print(self, msg: str) -> None:
        if self._console:
            self._console.print(msg)

    def is_enrolled(self) -> bool:
        return bool(self._device_id and self._device_token)

    def enroll(self, enroll_token: str) -> bool:
        """Enroll this device with the control plane. Idempotent: if already
        enrolled (identity file present) this is a no-op returning True."""
        if self.is_enrolled():
            return True
        req = EnrollmentRequest(
            enroll_token  = enroll_token,
            label         = self._label,
            platform      = _platform_string(),
            agent_version = __version__,
        )
        try:
            resp = self._post("/api/agent/enroll", req.to_dict(), auth=None)
        except _HttpError as exc:
            self._print(f"[red]Fleet enroll failed:[/red] {exc}")
            return False
        self._device_id    = resp.get("device_id")
        self._device_token = resp.get("device_token")
        if not self.is_enrolled():
            self._print("[red]Fleet enroll: server returned no device credentials[/red]")
            return False
        self._save_identity()
        self._print(f"[green]✓[/green] Fleet enrolled as device {self._device_id}")
        return True

    def send_heartbeat(self) -> bool:
        if not self.is_enrolled():
            return False
        hb = self._build_heartbeat()
        payload = {
            "device_id":    self._device_id,
            "device_token": self._device_token,
            "heartbeat":    hb.to_dict(),
        }
        try:
            self._post("/api/agent/heartbeat", payload, auth=None)
            return True
        except _HttpError as exc:
            self._print(f"[yellow]Fleet heartbeat failed:[/yellow] {exc}")
            return False

    def start(self) -> None:
        """Start the background heartbeat loop (no-op if not enrolled)."""
        if not self.is_enrolled() or self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="fleet-agent")
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _loop(self) -> None:
        while self._running:
            self.send_heartbeat()
            # Sleep in short slices so stop() is responsive.
            slept = 0.0
            while self._running and slept < self._interval:
                time.sleep(0.5)
                slept += 0.5

    def _build_heartbeat(self) -> Heartbeat:
        """Extract a privacy-preserving heartbeat from the status provider.

        Pulls ONLY integer counts, category tallies, and component health.
        Any domain-shaped data in the provider dict is ignored — it is never
        placed on the wire.
        """
        try:
            raw = self._provider() or {}
        except Exception:
            raw = {}

        counts = {
            "blocked": _as_int(raw.get("blocked_24h") or raw.get("blocked")),
            "allowed": _as_int(raw.get("allowed_24h") or raw.get("allowed")),
            "flagged": _as_int(raw.get("flagged_24h") or raw.get("flagged")),
        }
        categories = raw.get("categories") if isinstance(raw.get("categories"), dict) else {}
        categories = {str(k): _as_int(v) for k, v in categories.items()}
        components = raw.get("components") if isinstance(raw.get("components"), dict) else {}
        components = {str(k): bool(v) for k, v in components.items()}

        return Heartbeat(
            counts        = counts,
            categories    = categories,
            components    = components,
            agent_version = __version__,
        )

    def _load_identity(self) -> None:
        if not self._identity_path.exists():
            return
        try:
            data = json.loads(self._identity_path.read_text(encoding="utf-8"))
            self._device_id    = data.get("device_id")
            self._device_token = data.get("device_token")
        except (ValueError, OSError):
            self._device_id = self._device_token = None

    def _save_identity(self) -> None:
        try:
            self._identity_path.parent.mkdir(parents=True, exist_ok=True)
            self._identity_path.write_text(
                json.dumps({"device_id": self._device_id,
                            "device_token": self._device_token}),
                encoding="utf-8",
            )
            # Best-effort tighten perms (POSIX only; no-op on Windows).
            try:
                import os
                os.chmod(self._identity_path, 0o600)
            except OSError:
                pass
        except OSError as exc:
            self._print(f"[yellow]Fleet: could not persist identity: {exc}[/yellow]")

    def _post(self, path: str, body: dict, auth: Optional[str]) -> dict:
        url = self._server + path
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        if auth:
            req.add_header("Authorization", f"Bearer {auth}")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = json.loads(exc.read().decode("utf-8")).get("error", "")
            except Exception:
                pass
            raise _HttpError(f"HTTP {exc.code}: {detail or exc.reason}")
        except urllib.error.URLError as exc:
            raise _HttpError(f"cannot reach control plane at {url}: {exc.reason}")


class _HttpError(Exception):
    pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _as_int(v) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _default_label() -> str:
    import socket
    try:
        return socket.gethostname() or "unnamed-device"
    except OSError:
        return "unnamed-device"


def _platform_string() -> str:
    import platform
    try:
        return f"{platform.system()}-{platform.release()}"
    except Exception:
        return "unknown"
