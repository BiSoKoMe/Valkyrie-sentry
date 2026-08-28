"""FleetAgent - device side of the control plane.

Enrolls this device once (persisting its issued id + token locally), then
sends a privacy-preserving heartbeat on a timer. Uses only the standard
library (urllib) so a protected endpoint needs no extra runtime dependency.

The heartbeat payload is built from a `status_provider` callable the caller
supplies - typically wrapping the local Store.stats(). This module extracts
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
from ..updater import UpdateError
from .command import SignedCommand, verify_signed_command
from .policy import SignedPolicy, verify_signed_policy
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
        policy_public_key_hex: str = "",
        policy_applier: Optional[Callable[[object], None]] = None,
        command_runner: Optional[Callable[[str, str], tuple]] = None,
    ) -> None:
        self._server   = server_url.rstrip("/")
        self._provider = status_provider
        self._identity_path = Path(identity_path)
        self._label    = label or _default_label()
        self._interval = interval
        self._console  = console
        # Pinned Ed25519 key the pushed policy must verify against, plus a
        # callback that actually applies a verified policy locally (e.g. merges
        # block_domains into the blocklist). Both optional: with no key/applier
        # the agent simply never applies policy.
        self._policy_pubkey  = policy_public_key_hex or ""
        self._policy_applier = policy_applier
        # A verified remote command is executed by this callback - typically
        # EdrEngine.respond(action, target). With no key/runner the agent never
        # runs remote commands (the channel is simply inert).
        self._command_runner = command_runner
        self._device_id: Optional[str]    = None
        self._device_token: Optional[str] = None
        self._applied_policy_version: int = -1
        self._running  = False
        # Cycle health, so a repeatedly-failing agent is visible rather than
        # looking identical to a healthy-but-quiet one.
        self._cycle_errors = 0
        self._last_error = ""
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

    def fetch_and_apply_policy(self) -> bool:
        """Pull the org policy, verify its signature against the pinned key,
        and apply it - but ONLY if it is authentic AND strictly newer than the
        version already applied (anti-rollback). Returns True if a new policy
        was applied. Any verification failure is refused, not applied."""
        if not self.is_enrolled() or not self._policy_pubkey or self._policy_applier is None:
            return False
        payload = {"device_id": self._device_id, "device_token": self._device_token}
        try:
            raw = self._post("/api/agent/policy", payload, auth=None)
        except _HttpError:
            return False   # 404 (no policy) / transient - nothing to apply
        try:
            bundle = SignedPolicy.from_dict(raw)
            policy = verify_signed_policy(bundle, self._policy_pubkey)  # raises if bad
        except UpdateError as exc:
            self._print(f"[red]Fleet: refusing unverified policy:[/red] {exc}")
            return False
        if policy.version <= self._applied_policy_version:
            return False   # equal/older -> ignore (replay/rollback protection)
        try:
            self._policy_applier(policy)
        except Exception as exc:
            self._print(f"[yellow]Fleet: policy applier raised: {exc}[/yellow]")
            return False
        self._applied_policy_version = policy.version
        self._save_identity()
        self._print(f"[green]✓[/green] Fleet policy v{policy.version} applied "
                    f"({len(policy.block_domains)} block, {len(policy.allow_domains)} allow)")
        return True

    def fetch_and_run_commands(self) -> int:
        """Pull pending remote-response commands, verify each against the pinned
        key, run it through the local responder, and ack the result. Returns the
        number of commands executed. Any unverifiable command is refused, not
        run. Inert unless both a pinned key AND a command runner are configured."""
        if not self.is_enrolled() or not self._policy_pubkey or self._command_runner is None:
            return 0
        payload = {"device_id": self._device_id, "device_token": self._device_token}
        try:
            raw = self._post("/api/agent/commands", payload, auth=None)
        except _HttpError:
            return 0
        ran = 0
        for bundle in (raw.get("commands") or []):
            try:
                sc = SignedCommand.from_dict(bundle)
                cmd = verify_signed_command(sc, self._policy_pubkey)   # raises if bad
            except UpdateError as exc:
                self._print(f"[red]Fleet: refusing unverified command:[/red] {exc}")
                continue
            try:
                status, result = self._command_runner(cmd.action, cmd.target)
            except Exception as exc:          # noqa: BLE001
                status, result = "failed", f"runner error: {exc}"
            # Ack regardless of outcome - the ack is what stops the command
            # being handed back to us (anti-replay) and reports status upstream.
            try:
                self._post("/api/agent/commands/ack", {
                    "device_id":  self._device_id,
                    "device_token": self._device_token,
                    "command_id": cmd.id,
                    "status":     status,
                    "result":     result,
                }, auth=None)
            except _HttpError:
                pass
            self._print(f"[green]✓[/green] Fleet command {cmd.action} → {status}")
            ran += 1
        return ran

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
        # All three calls below do network I/O to the fleet server, which fails
        # routinely - server restart, DNS blip, expired token, TLS error. None
        # of it was guarded, so the FIRST such failure killed this thread and
        # the endpoint silently dropped off fleet management for the rest of the
        # run: no heartbeats, no policy updates, no commands. On the server side
        # it would simply look like a machine that went quiet, which is
        # indistinguishable from one that was switched off.
        while self._running:
            try:
                self.send_heartbeat()
                self.fetch_and_apply_policy()
                self.fetch_and_run_commands()
            except BaseException as exc:      # noqa: BLE001
                self._cycle_errors += 1
                self._last_error = f"{type(exc).__name__}: {exc}"
            # Sleep in short slices so stop() is responsive.
            slept = 0.0
            while self._running and slept < self._interval:
                time.sleep(0.5)
                slept += 0.5

    def _build_heartbeat(self) -> Heartbeat:
        """Extract a privacy-preserving heartbeat from the status provider.

        Pulls ONLY integer counts, category tallies, and component health.
        Any domain-shaped data in the provider dict is ignored - it is never
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
            # Persisted so anti-rollback survives a restart - a captured older
            # signed policy can't be replayed after the agent bounces.
            self._applied_policy_version = int(data.get("applied_policy_version", -1))
        except (ValueError, OSError):
            self._device_id = self._device_token = None

    def _save_identity(self) -> None:
        try:
            self._identity_path.parent.mkdir(parents=True, exist_ok=True)
            self._identity_path.write_text(
                json.dumps({"device_id": self._device_id,
                            "device_token": self._device_token,
                            "applied_policy_version": self._applied_policy_version}),
                encoding="utf-8",
            )
            # This file holds the device's fleet ENROLMENT TOKEN - the
            # credential that authenticates this endpoint to the fleet server
            # and lets it fetch policy and report status. Reading it is enough
            # to impersonate the endpoint to the server.
            #
            # This used to be `os.chmod(..., 0o600)` guarded by a comment
            # saying "POSIX only; no-op on Windows" - i.e. the token was
            # knowingly left readable by every local account on the platform
            # the product actually ships on. secure_file.harden() covers both.
            from ..secure_file import harden as _harden_secret
            _ok, _detail = _harden_secret(self._identity_path)
            if not _ok:
                self._print(f"[yellow]Fleet: identity token could not be "
                            f"restricted: {_detail}[/yellow]")
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
