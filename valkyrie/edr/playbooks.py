"""SOAR playbooks — declarative incident → response automation.

An analyst-authored YAML file maps incident conditions onto the response
actions the EDR already ships (``block_domain``, ``kill_process``,
``isolate_host``, plugin-provided actions). Every execution flows through
the same audited ``ResponseManager`` path a human operator uses — a
playbook is an *operator that never sleeps*, not a second response system.

Safety model (automation of response is the most dangerous feature in an
EDR, so every default is conservative):

  * **Dry-run by default.** A playbook simulates unless it explicitly says
    ``mode: enforce`` — and even then each execution is audited with
    ``operator: playbook:<id>`` so the timeline shows exactly which rule
    acted.
  * **Cooldowns.** A (playbook, target) pair will not re-fire inside
    ``cooldown_seconds`` (default 300) — no response loops, no hammering.
  * **Severity floor + category allowlist.** A playbook only sees incidents
    at/above its ``min_severity`` and, if given, in its ``categories``.
  * **Fail-open to humans.** A malformed playbook is skipped with a load
    error recorded in status; a failing action is audited as failed; the
    engine never raises into the correlation pipeline.

Playbook file (``data/playbooks.yaml``):

    playbooks:
      - id: contain-ransomware
        min_severity: critical
        categories: [ransomware]
        mode: enforce            # omit for dry-run
        cooldown_seconds: 600
        actions:
          - action: kill_process
            target_from: process_name
      - id: block-c2-domains
        min_severity: high
        categories: [c2, threat_intel]
        actions:
          - action: block_domain
            target_from: entity
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..config import DEFAULT_PLAYBOOKS_PATH, PLAYBOOKS_PATH
from .schema import severity_rank

log = logging.getLogger("valkyrie.playbooks")

_DEFAULT_COOLDOWN = 300.0


@dataclass
class PlaybookAction:
    action: str
    target_from: str = "entity"     # entity | process_name | process_pid | literal
    target: str = ""                # used when target_from == "literal"


@dataclass
class Playbook:
    id: str
    min_severity: str = "high"
    categories: tuple = ()          # empty = any category
    mode: str = "dry_run"           # dry_run | enforce
    cooldown_seconds: float = _DEFAULT_COOLDOWN
    actions: list = field(default_factory=list)

    def matches(self, incident: dict) -> bool:
        if severity_rank(incident.get("severity", "info")) < severity_rank(self.min_severity):
            return False
        if self.categories and incident.get("category") not in self.categories:
            return False
        return True


def _parse_playbook(raw: dict) -> Playbook:
    """Strict parse of one playbook dict; raises ValueError on bad shape."""
    pb_id = str(raw.get("id") or "").strip()
    if not pb_id:
        raise ValueError("playbook missing id")
    mode = str(raw.get("mode", "dry_run")).lower()
    if mode not in ("dry_run", "enforce"):
        raise ValueError(f"{pb_id}: mode must be dry_run|enforce")
    actions = []
    for a in raw.get("actions") or []:
        act = str(a.get("action") or "").strip()
        if not act:
            raise ValueError(f"{pb_id}: action entry missing 'action'")
        tf = str(a.get("target_from", "entity"))
        if tf not in ("entity", "process_name", "process_pid", "literal"):
            raise ValueError(f"{pb_id}: bad target_from {tf!r}")
        actions.append(PlaybookAction(action=act, target_from=tf,
                                      target=str(a.get("target", ""))))
    if not actions:
        raise ValueError(f"{pb_id}: no actions")
    return Playbook(
        id=pb_id,
        min_severity=str(raw.get("min_severity", "high")).lower(),
        categories=tuple(raw.get("categories") or ()),
        mode=mode,
        cooldown_seconds=float(raw.get("cooldown_seconds", _DEFAULT_COOLDOWN)),
        actions=actions,
    )


class PlaybookEngine:
    """Evaluates playbooks against live incidents from the EdrEngine bus."""

    def __init__(self, edr, path: Optional[Path] = None) -> None:
        self._edr = edr
        self._path = Path(path) if path else PLAYBOOKS_PATH
        self._playbooks: list[Playbook] = []
        self._load_errors: list[str] = []
        self._lock = threading.Lock()
        # (playbook_id, target) -> monotonic time of last fire
        self._fired: dict[tuple[str, str], float] = {}
        self._executed = 0
        self._suppressed = 0
        self._active = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> int:
        """(Re)load the playbook file. Returns count. Never raises.

        Reads the user's editable copy; if that is absent (first launch on a
        read-only volume where config's seed-copy could not write) it falls
        back to the bundled read-only default, so shipped auto-response is
        active out of the box rather than depending on the copy succeeding.
        """
        path = self._path
        if not path.exists() and DEFAULT_PLAYBOOKS_PATH.exists():
            path = DEFAULT_PLAYBOOKS_PATH
        playbooks: list[Playbook] = []
        errors: list[str] = []
        try:
            import yaml
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for entry in raw.get("playbooks") or []:
                try:
                    playbooks.append(_parse_playbook(entry))
                except ValueError as exc:
                    errors.append(str(exc))
        except FileNotFoundError:
            pass          # no playbooks configured — engine stays idle
        except Exception as exc:   # noqa: BLE001 — bad YAML must not kill EDR
            errors.append(f"playbook file unreadable: {exc}")
        with self._lock:
            self._playbooks = playbooks
            self._load_errors = errors
        return len(playbooks)

    def start(self) -> None:
        if not self._active:
            self._edr.subscribe(self._on_incident)
            self._active = True

    def stop(self) -> None:
        if self._active:
            try:
                self._edr.unsubscribe(self._on_incident)
            except Exception:
                pass
            self._active = False

    def status(self) -> dict:
        with self._lock:
            return {
                "active": self._active,
                "path": str(self._path),
                "playbooks": [{"id": p.id, "mode": p.mode,
                               "min_severity": p.min_severity,
                               "categories": list(p.categories),
                               "actions": [a.action for a in p.actions]}
                              for p in self._playbooks],
                "load_errors": list(self._load_errors),
                "executed": self._executed,
                "suppressed_by_cooldown": self._suppressed,
            }

    # ------------------------------------------------------------------
    # Evaluation (runs on the EDR bus thread; must never raise)
    # ------------------------------------------------------------------

    def _on_incident(self, payload: dict) -> None:
        try:
            if payload.get("type") != "incident":
                return
            incident = payload.get("incident") or {}
            with self._lock:
                books = list(self._playbooks)
            for pb in books:
                if pb.matches(incident):
                    self._run_playbook(pb, incident)
        except Exception:
            # A playbook bug must never break incident correlation — but it
            # must not vanish either. This used to be a bare `pass`, which
            # made a real failure here indistinguishable from "no playbook
            # matched": both looked like "nothing happened," with nothing
            # to grep for afterward.
            log.exception("playbook evaluation failed for incident %s",
                          (payload.get("incident") or {}).get("id", "?"))

    def _run_playbook(self, pb: Playbook, incident: dict) -> None:
        now = time.monotonic()
        for act in pb.actions:
            target = (act.target if act.target_from == "literal"
                      else str(incident.get(act.target_from) or ""))
            if not target:
                continue
            key = (pb.id, f"{act.action}:{target}")
            with self._lock:
                last = self._fired.get(key, 0.0)
                if now - last < pb.cooldown_seconds:
                    self._suppressed += 1
                    continue
                self._fired[key] = now
                # Bound the memory of the cooldown map.
                if len(self._fired) > 4096:
                    cutoff = now - max(p.cooldown_seconds for p in self._playbooks)
                    self._fired = {k: v for k, v in self._fired.items()
                                   if v >= cutoff}
                self._executed += 1
            self._edr.respond(
                act.action, target,
                dry_run=(pb.mode != "enforce"),
                operator=f"playbook:{pb.id}",
                incident_id=incident.get("id", ""),
                severity=incident.get("severity", ""),
            )
