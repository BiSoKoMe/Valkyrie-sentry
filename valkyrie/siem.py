"""SIEM export — stream Valkyrie incidents to enterprise log pipelines.

Enterprises do not adopt a security product they cannot see inside their
SOC. This module forwards EDR incidents (and, opt-in, blocked/flagged DNS
events) to any standard log pipeline:

  formats    CEF (ArcSight standard; ingested by Splunk, Sentinel, QRadar,
             Elastic) or JSON Lines (one JSON object per line)
  transports udp://host:port   classic syslog datagrams
             tcp://host:port   newline-framed syslog stream
             tls://host:port   the same over TLS (system trust store)
             file:///path      append-only local file (air-gapped pull)

Design contract (same posture as every Valkyrie service):

  * OFF by default. Exporting security events to a SIEM is an explicit
    operator decision (``--siem <url>``): it sends data OFF this machine.
    Incident records carry process names/entities, not browsing history;
    forwarding DNS block events (domains!) is a separate opt-in flag.
  * Fault-isolated and non-blocking: emitters enqueue onto a bounded
    in-memory queue and return immediately; a background thread does I/O
    with reconnect + backoff. When the SIEM is down the queue keeps the
    newest events and counts what it dropped — the protection pipeline
    never stalls or raises because logging infrastructure is broken.
  * Deterministic formatting: CEF escaping follows the spec (backslash,
    pipe in prefix, equals in extensions); severities map onto the CEF
    0–10 scale. Pure functions, unit-tested offline.
"""

from __future__ import annotations

import json
import queue
import select
import socket
import ssl
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from . import __version__

# CEF severity scale is 0-10.
_CEF_SEV = {"info": 2, "low": 3, "medium": 5, "high": 8, "critical": 10}

_QUEUE_SIZE = 2048
_RECONNECT_MIN = 1.0     # seconds; doubles per failure
_RECONNECT_MAX = 60.0


# ---------------------------------------------------------------------------
# Formatting (pure functions)
# ---------------------------------------------------------------------------

def _cef_prefix_escape(value: str) -> str:
    """Escape a CEF header field: backslash and pipe."""
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def _cef_ext_escape(value: str) -> str:
    """Escape a CEF extension value: backslash, equals, newlines."""
    return (str(value).replace("\\", "\\\\").replace("=", "\\=")
            .replace("\n", "\\n").replace("\r", ""))


def format_cef(record: dict) -> str:
    """Render one normalized export record as a CEF line.

    Record keys (all optional except event_type/title/severity):
      event_type, title, severity, category, entity, process_name, id,
      detection_count, created_at, extra (dict merged into extensions)
    """
    sev = _CEF_SEV.get(str(record.get("severity", "info")).lower(), 2)
    sig = record.get("category") or record.get("event_type", "event")
    name = record.get("title") or sig
    ext_pairs: list[tuple[str, str]] = []
    if record.get("id"):
        ext_pairs.append(("externalId", record["id"]))
    if record.get("process_name"):
        ext_pairs.append(("sproc", record["process_name"]))
    if record.get("entity"):
        ext_pairs.append(("cs1", record["entity"]))
        ext_pairs.append(("cs1Label", "entity"))
    if record.get("detection_count") is not None:
        ext_pairs.append(("cnt", str(record["detection_count"])))
    if record.get("created_at"):
        ext_pairs.append(("start", record["created_at"]))
    ext_pairs.append(("cat", str(record.get("event_type", "incident"))))
    for k, v in (record.get("extra") or {}).items():
        ext_pairs.append((str(k), str(v)))
    ext = " ".join(f"{k}={_cef_ext_escape(v)}" for k, v in ext_pairs)
    return ("CEF:0|Valkyrie|Valkyrie|{ver}|{sig}|{name}|{sev}|{ext}".format(
        ver=_cef_prefix_escape(__version__),
        sig=_cef_prefix_escape(sig),
        name=_cef_prefix_escape(name),
        sev=sev, ext=ext))


def format_jsonl(record: dict) -> str:
    """Render one export record as a single JSON line (stable key order)."""
    out = {"vendor": "Valkyrie", "version": __version__,
           "exported_at": datetime.now(timezone.utc).isoformat()}
    out.update({k: v for k, v in record.items() if k != "extra"})
    out.update(record.get("extra") or {})
    return json.dumps(out, sort_keys=True, default=str)


def incident_record(payload: dict) -> Optional[dict]:
    """Normalize an EdrEngine bus payload into an export record.

    Only ``{"type": "incident", ...}`` payloads export; returns None for
    anything else. Updates to an existing incident export too (severity may
    have escalated), distinguished by ``valkyrieNew``.
    """
    # A non-dict payload returns None rather than raising: this is invoked from
    # an event-bus subscriber, and an exception there propagates into the
    # publisher's thread rather than staying local to the exporter.
    if not isinstance(payload, dict) or payload.get("type") != "incident":
        return None
    inc = payload.get("incident") or {}
    return {
        "event_type": "incident",
        "id": inc.get("id", ""),
        "title": inc.get("title", "incident"),
        "severity": inc.get("severity", "info"),
        "category": inc.get("category", ""),
        "entity": inc.get("entity", ""),
        "process_name": inc.get("process_name", ""),
        "detection_count": inc.get("detection_count"),
        "created_at": inc.get("created_at", ""),
        "extra": {"valkyrieNew": bool(payload.get("new")),
                  "status": inc.get("status", "")},
    }


def dns_block_record(msg: dict) -> Optional[dict]:
    """Normalize a Store bus DNS event into an export record (opt-in path).

    Exports only blocked/flagged decisions — never allowed traffic — because
    this is the one exporter path that carries domains off the machine.
    """
    if not isinstance(msg, dict):
        return None
    ev = msg.get("event") or {}
    if ev.get("decision") not in ("blocked", "behavioral", "flagged"):
        return None
    return {
        "event_type": "dns_" + ev.get("decision", "blocked"),
        "title": f"DNS {ev.get('decision')}: {ev.get('domain', '')}",
        "severity": "medium" if ev.get("decision") != "flagged" else "low",
        "category": ev.get("raw_category", "dns"),
        "entity": ev.get("domain", ""),
        "process_name": ev.get("process_name", ""),
        "created_at": ev.get("timestamp", ""),
        "extra": {"reason": ev.get("reason", "")},
    }


# ---------------------------------------------------------------------------
# Exporter
# ---------------------------------------------------------------------------

class SiemExporter:
    """Bounded-queue, reconnecting exporter for one destination URL."""

    def __init__(self, url: str, fmt: str = "cef") -> None:
        u = urlparse(url)
        if u.scheme not in ("udp", "tcp", "tls", "file"):
            raise ValueError(f"unsupported SIEM scheme: {u.scheme!r} "
                             "(use udp:// tcp:// tls:// or file://)")
        if u.scheme != "file" and (not u.hostname or not u.port):
            raise ValueError("SIEM url needs host:port, e.g. tcp://10.0.0.5:514")
        if fmt not in ("cef", "json"):
            raise ValueError(f"unsupported SIEM format: {fmt!r} (cef|json)")
        self._url = url
        self._scheme = u.scheme
        self._host = u.hostname or ""
        self._port = u.port or 0
        # file:///C:/path or file:///var/log/x — urlparse leaves the path.
        self._path = Path(u.path.lstrip("/")) if (
            u.scheme == "file" and ":" in u.path[:4].replace("/", "")
        ) else Path(u.path) if u.scheme == "file" else None
        self._fmt = fmt
        self._format = format_cef if fmt == "cef" else format_jsonl
        self._q: queue.Queue[str] = queue.Queue(maxsize=_QUEUE_SIZE)
        self._dropped = 0
        self._sent = 0
        self._errors = 0
        self._last_error = ""
        self._sock = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

    # -- ingest (called from pipeline threads; must never block/raise) ------

    def export_incident(self, payload: dict) -> None:
        rec = incident_record(payload)
        if rec is not None:
            self._enqueue(rec)

    def export_dns(self, msg: dict) -> None:
        rec = dns_block_record(msg)
        if rec is not None:
            self._enqueue(rec)

    def _enqueue(self, record: dict) -> None:
        try:
            line = self._format(record)
        except Exception:
            return   # a formatting bug must never reach the caller
        try:
            self._q.put_nowait(line)
        except queue.Full:
            # Keep the newest events: drop one oldest, then retry once.
            self._dropped += 1
            try:
                self._q.get_nowait()
                self._q.put_nowait(line)
            except Exception:
                pass

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._send_loop, daemon=True, name="siem-export")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        try:
            self._q.put_nowait("")   # wake sentinel
        except queue.Full:
            pass
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        self._close()

    def status(self) -> dict:
        return {"url": self._url, "format": self._fmt,
                "sent": self._sent, "dropped": self._dropped,
                "errors": self._errors, "last_error": self._last_error,
                "queued": self._q.qsize(), "running": self._running}

    # -- transport ----------------------------------------------------------

    def _close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def _connect(self) -> None:
        if self._scheme == "udp":
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif self._scheme in ("tcp", "tls"):
            s = socket.create_connection((self._host, self._port), timeout=10)
            if self._scheme == "tls":
                ctx = ssl.create_default_context()
                s = ctx.wrap_socket(s, server_hostname=self._host)
            self._sock = s
        # file scheme opens per-write (append) — nothing to hold.

    def _send(self, line: str) -> None:
        data = (line + "\n").encode("utf-8", errors="replace")
        if self._scheme == "file":
            assert self._path is not None
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "ab") as f:
                f.write(data)
            return
        if self._sock is None:
            self._connect()
        if self._scheme == "udp":
            self._sock.sendto(data, (self._host, self._port))
        else:
            # A peer that closed the stream doesn't fail sendall() — the data
            # is buffered locally and silently lost when the RST arrives. A
            # syslog server never sends us bytes, so a readable socket means
            # EOF/error: detect it and reconnect BEFORE sending.
            readable, _, _ = select.select([self._sock], [], [], 0)
            if readable and not self._sock.recv(1, socket.MSG_PEEK):
                self._close()
                self._connect()
            self._sock.sendall(data)

    def _send_loop(self) -> None:
        backoff = _RECONNECT_MIN
        while self._running:
            try:
                line = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            if not line:          # wake sentinel
                continue
            while self._running:
                try:
                    self._send(line)
                    self._sent += 1
                    backoff = _RECONNECT_MIN
                    break
                except Exception as exc:
                    self._errors += 1
                    self._last_error = f"{type(exc).__name__}: {exc}"
                    self._close()
                    # Requeue the line (bounded) and back off before retry.
                    self._enqueue_raw(line)
                    time.sleep(min(backoff, _RECONNECT_MAX))
                    backoff = min(backoff * 2, _RECONNECT_MAX)
                    break   # take next item after backoff (order best-effort)

    def _enqueue_raw(self, line: str) -> None:
        try:
            self._q.put_nowait(line)
        except queue.Full:
            self._dropped += 1
