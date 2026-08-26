"""Meeting Mode - a one-command network kill switch for sensitive moments.

Activating flips the Windows Firewall to default-deny **outbound** on every
profile, which instantly stops all internet egress from the machine. Windows
Firewall never filters loopback traffic, so the local dashboard stays
reachable and can turn Meeting Mode back off.

Deactivating restores the Windows default policy (block inbound / allow
outbound). The active/inactive state and the activation timestamp are
persisted to ``data/meeting_mode_state.json`` so status survives a restart and
a stale kill switch is always visible.

Windows-only. On other platforms every method degrades gracefully with a clear
message rather than raising.

SAFETY: activate() genuinely cuts the machine off the internet. It requires
Administrator rights and never runs automatically - only in response to an
explicit --meeting-on, or an authenticated dashboard/API request.
"""

from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from typing import Optional

from .config import DATA_DIR

_STATE_PATH = DATA_DIR / "meeting_mode_state.json"

# The stock Windows default we restore to on deactivate. Using the well-known
# default (rather than trying to parse the pre-existing per-profile policy,
# which is localised and brittle) keeps restore robust across locales.
_DEFAULT_POLICY = "blockinbound,allowoutbound"
_BLOCK_POLICY   = "blockinbound,blockoutbound"


def _is_windows() -> bool:
    return os.name == "nt"


def _is_admin() -> bool:
    if not _is_windows():
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _set_firewall_policy(policy: str) -> tuple[bool, str]:
    """Run ``netsh advfirewall set allprofiles firewallpolicy <policy>``.

    Returns (ok, detail)."""
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", policy],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return True, "ok"
        return False, (result.stderr or result.stdout or "netsh returned nonzero").strip()
    except FileNotFoundError:
        return False, "netsh not found"
    except subprocess.TimeoutExpired:
        return False, "netsh timed out"
    except OSError as exc:
        return False, str(exc)


class MeetingMode:
    """Controls the outbound firewall kill switch and its persisted state."""

    def __init__(self, state_path=_STATE_PATH) -> None:
        self._state_path = state_path

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def activate(self) -> dict:
        """Block all outbound network traffic. Returns a status dict.

        No-op with an ``error`` field when not on Windows or not elevated -
        never raises, never partially applies.
        """
        if not _is_windows():
            return {"active": False, "error": "Meeting Mode is Windows-only"}
        if not _is_admin():
            return {"active": False,
                    "error": "Administrator rights required to change the firewall policy"}
        if self.status().get("active"):
            return self.status()   # already on - idempotent

        ok, detail = _set_firewall_policy(_BLOCK_POLICY)
        if not ok:
            return {"active": False, "error": f"could not enable kill switch: {detail}"}

        self._save({
            "active": True,
            "activated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "restore_policy": _DEFAULT_POLICY,
        })
        return self.status()

    def deactivate(self) -> dict:
        """Restore normal outbound traffic. Returns a status dict."""
        if not _is_windows():
            return {"active": False, "error": "Meeting Mode is Windows-only"}
        if not _is_admin():
            return {"active": False,
                    "error": "Administrator rights required to change the firewall policy"}

        state = self._load()
        restore = state.get("restore_policy", _DEFAULT_POLICY)
        ok, detail = _set_firewall_policy(restore)
        if not ok:
            # Leave the state file in place so the kill switch is still shown as
            # active - a failed restore must not be reported as success.
            return {"active": True, "error": f"could not restore firewall policy: {detail}"}

        self._clear()
        return {"active": False, "activated_at": None, "duration_minutes": 0}

    def status(self) -> dict:
        """Return ``{active, activated_at, duration_minutes}``."""
        state = self._load()
        active = bool(state.get("active"))
        activated_at = state.get("activated_at")
        duration = 0
        if active and activated_at:
            try:
                started = datetime.fromisoformat(activated_at)
                if started.tzinfo is None:
                    started = started.replace(tzinfo=timezone.utc)
                duration = int((datetime.now(timezone.utc) - started).total_seconds() // 60)
            except ValueError:
                duration = 0
        return {
            "active": active,
            "activated_at": activated_at,
            "duration_minutes": duration,
        }

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------

    def _load(self) -> dict:
        try:
            return json.loads(self._state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def _save(self, state: dict) -> None:
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            self._state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
        except OSError:
            pass

    def _clear(self) -> None:
        try:
            self._state_path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
