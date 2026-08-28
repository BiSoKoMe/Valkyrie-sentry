"""Privacy-preserving browser semantic-context ingestion.

The browser extension deliberately sends a tiny event vocabulary through a
native-messaging host.  It never sends page text, full URLs, form values,
cookies, DOM snapshots, or consent-dialog contents.  This module validates and
normalizes that data before it crosses into the endpoint event pipeline.

Browser events are *context*, not proof and not an enforcement trigger.  They
currently have no reliable Windows PID, so they are retained as local telemetry
but are not falsely attached to a process-provenance node.
"""

from __future__ import annotations

import json
import math
import secrets
import threading
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .config import DATA_DIR
from .telemetry import ACT_OBSERVED, CAT_PRIVACY, SEV_INFO, TelemetryEvent


BROWSER_CONTEXT_TOKEN_PATH = DATA_DIR / "browser_context_token.txt"
_MAX_REQUEST_BYTES = 16 * 1024
_MAX_RECENT = 200
_EVENTS = frozenset({"page_view", "user_gesture", "form_submit", "consent_signal"})
_GESTURES = frozenset({"pointer", "keyboard", "submit", "unknown"})
_CONSENT = frozenset({"accepted", "rejected", "dismissed", "unknown"})


def _origin(value: object) -> str:
    """Return only the HTTP(S) origin; paths, queries, credentials are dropped."""
    if not isinstance(value, str) or len(value) > 4096:
        return ""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return ""
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return ""
    host = parsed.hostname.lower().rstrip(".")
    if not host or len(host) > 253:
        return ""
    try:
        port = parsed.port
    except ValueError:
        return ""
    suffix = "" if port in (None, 80 if parsed.scheme == "http" else 443) else f":{port}"
    return f"{parsed.scheme}://{host}{suffix}"


def _bounded_int(value: object, *, low: int = -1, high: int = 2**31 - 1) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return low
    return number if low <= number <= high else low


class BrowserContextCollector:
    """Validate browser-native messages and emit metadata-only privacy telemetry."""

    def __init__(self, edr: object | None = None, *, token_path: Path | None = None,
                 token: str = "") -> None:
        self._edr = edr
        self._token_path = Path(token_path or BROWSER_CONTEXT_TOKEN_PATH)
        self._native_host_ready = False
        self._token = str(token) if len(str(token)) >= 32 else self._load_or_create_token()
        self._recent: deque[dict[str, Any]] = deque(maxlen=_MAX_RECENT)
        self._lock = threading.RLock()
        self._accepted = 0
        self._rejected = 0

    def _load_or_create_token(self) -> str:
        try:
            existing = self._token_path.read_text(encoding="utf-8").strip()
            from .secure_file import verify
            protected, _detail = verify(self._token_path)
            if len(existing) >= 32 and protected:
                self._native_host_ready = True
                return existing
        except OSError:
            pass
        token = secrets.token_urlsafe(32)
        try:
            self._token_path.parent.mkdir(parents=True, exist_ok=True)
            self._token_path.write_text(token, encoding="utf-8")
            from .secure_file import harden, verify
            hardened, _detail = harden(self._token_path)
            verified, _detail = verify(self._token_path)
            if hardened and verified:
                self._native_host_ready = True
                return token
            self._token_path.unlink(missing_ok=True)
        except OSError:
            try:
                self._token_path.unlink(missing_ok=True)
            except OSError:
                pass
        # Keep a process-local token rather than weakening the API boundary.
        return token

    def token_ok(self, candidate: object) -> bool:
        return isinstance(candidate, str) and bool(candidate) and secrets.compare_digest(candidate, self._token)

    @staticmethod
    def sanitize(payload: object) -> dict[str, Any] | None:
        """Validate one wire event and return its metadata-only representation."""
        if not isinstance(payload, dict):
            return None
        try:
            if len(json.dumps(payload, ensure_ascii=False).encode("utf-8")) > _MAX_REQUEST_BYTES:
                return None
        except (TypeError, ValueError):
            return None
        if int(payload.get("version", 0) or 0) != 1:
            return None
        event_type = str(payload.get("event_type", ""))
        origin = _origin(payload.get("url") or payload.get("origin"))
        if event_type not in _EVENTS or not origin:
            return None
        browser = str(payload.get("browser", "unknown")).lower()
        if browser not in {"chrome", "edge", "brave", "chromium", "unknown"}:
            browser = "unknown"
        gesture = str(payload.get("gesture", "unknown")).lower()
        consent = str(payload.get("consent_state", "unknown")).lower()
        try:
            event_id = str(uuid.UUID(str(payload.get("event_id") or "")))
        except (ValueError, AttributeError):
            event_id = str(uuid.uuid4())
        try:
            observed_at = float(payload.get("ts") or time.time())
        except (TypeError, ValueError):
            observed_at = time.time()
        if not math.isfinite(observed_at) or abs(observed_at - time.time()) > 24 * 60 * 60:
            observed_at = time.time()
        return {
            "event_id": event_id,
            "event_type": event_type,
            "first_party_origin": origin,
            "tab_id": _bounded_int(payload.get("tab_id")),
            "frame_id": _bounded_int(payload.get("frame_id")),
            "user_initiated": bool(payload.get("user_initiated", False)),
            "gesture": gesture if gesture in _GESTURES else "unknown",
            "consent_state": consent if consent in _CONSENT else "unknown",
            "browser": browser,
            "ts": observed_at,
        }

    def ingest(self, payload: object) -> dict[str, Any]:
        event = self.sanitize(payload)
        if event is None:
            with self._lock:
                self._rejected += 1
            return {"accepted": False, "reason": "invalid browser context event"}
        with self._lock:
            self._accepted += 1
            self._recent.append(dict(event))
        if self._edr is not None:
            telemetry = TelemetryEvent(
                category=CAT_PRIVACY,
                activity="browser_context",
                action=ACT_OBSERVED,
                ts=event["ts"], severity=SEV_INFO,
                reason="Browser supplied local interaction context",
                source="browser_native_messaging",
                labels=["browser_context", event["event_type"]],
                target={"origin": event["first_party_origin"]},
                fields={
                    "artifact_kind": "browser_context",
                    "event_id": event["event_id"],
                    "first_party_origin": event["first_party_origin"],
                    "browser_event_type": event["event_type"],
                    "user_initiated": str(event["user_initiated"]).lower(),
                    "gesture": event["gesture"],
                    "consent_state": event["consent_state"],
                    "attribution_confidence": "browser_semantic_no_process_pid",
                },
            )
            try:
                self._edr.ingest_telemetry(telemetry)
            except Exception:
                # Browser observation must never destabilize the endpoint engine.
                pass
        return {"accepted": True, "event": event}

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "enabled": self._edr is not None,
                "native_host_ready": self._native_host_ready,
                "accepted": self._accepted,
                "rejected": self._rejected,
                "recent": list(self._recent),
                "privacy_boundary": "origin and interaction metadata only; no page text, form values, cookies, DOM, paths, or query strings",
            }
