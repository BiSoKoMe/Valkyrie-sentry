"""Plugin architecture for the EDR layer.

Three plugin kinds, one registry:

  DetectionPlugin  — turns a normalised event into zero or more Detections.
  ResponderPlugin  — knows how to carry out response actions (block/kill/…).
  EnrichmentPlugin — adds context to a Detection (threat-intel notes, tags…).

Built-in plugins are registered in code (see :mod:`valkyrie.edr.builtin`).
Third-party plugins are discovered from a directory of ``*.py`` files, each
exposing a top-level ``register(registry)`` function. Discovery is opt-in and
scoped to a directory the operator controls — plugins are ordinary trusted
Python (like a pytest plugin or a Django app), NOT a sandbox, and the loader
says so plainly rather than pretending otherwise.

Everything is stdlib-only.
"""

from __future__ import annotations

import hashlib
import importlib.util
import threading
import traceback
from pathlib import Path
from typing import Callable, Iterable, Optional

from .schema import Detection


# ---------------------------------------------------------------------------
# Plugin trust helpers (SHA-256 allowlist)
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    """Return the hex SHA-256 of a file's bytes."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_allowlist_file(path: Path) -> set[str]:
    """Parse an ``allowed.sha256`` manifest: one hex digest per line, ``#``
    comments and inline ``  # note`` allowed. Case-insensitive."""
    allowed: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        token = line.split("#", 1)[0].strip().lower()
        if token:
            allowed.add(token)
    return allowed


def _normalize_allowlist(allowlist: Optional[Iterable[str]]) -> Optional[set[str]]:
    if allowlist is None:
        return None
    return {str(x).strip().lower() for x in allowlist if str(x).strip()}


# ---------------------------------------------------------------------------
# Base classes
# ---------------------------------------------------------------------------

class PluginBase:
    """Common metadata for every plugin. Subclass one of the three kinds."""

    #: unique, stable, dotted name — e.g. "dns.tracker"
    name: str = "unnamed"
    #: free-text version, informational only
    version: str = "1.0"
    #: one-line description shown in the console
    description: str = ""

    def __init__(self) -> None:
        self.enabled: bool = True

    def info(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "kind": self.kind,
            "enabled": self.enabled,
        }

    # Set by subclasses.
    kind: str = "base"


class DetectionPlugin(PluginBase):
    """Consumes a normalised event and emits Detections.

    An *event* is a plain dict with at least: ``domain``, ``decision``,
    ``process_name``, ``process_pid``, ``category``, ``suspicion``, ``reason``.
    This is exactly the shape the Store publishes to subscribers, so detection
    plugins run against Valkyrie's real live traffic.
    """
    kind = "detection"

    def analyze(self, event: dict, ctx: "PluginContext") -> Iterable[Detection]:
        raise NotImplementedError


class ResponderPlugin(PluginBase):
    """Carries out response actions. May advertise several action names."""
    kind = "responder"

    def actions(self) -> list[str]:
        """Return the action names this responder handles."""
        return []

    def can_handle(self, action: str) -> bool:
        return action in self.actions()

    def execute(self, action: str, target: str, *, dry_run: bool,
                ctx: "PluginContext") -> tuple[str, str]:
        """Perform (or simulate) an action.

        Returns ``(status, result_message)`` where status is one of
        schema.RESPONSE_STATES. Implementations MUST honour ``dry_run`` by
        describing what *would* happen without doing it.
        """
        raise NotImplementedError


class EnrichmentPlugin(PluginBase):
    """Adds context to a detection just before it is persisted."""
    kind = "enrichment"

    def enrich(self, det: Detection, ctx: "PluginContext") -> None:
        """Mutate ``det.details`` (and/or ``det.technique``) in place."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Plugin context — the handles plugins are allowed to touch
# ---------------------------------------------------------------------------

class PluginContext:
    """A small, explicit surface passed to plugins.

    Kept deliberately narrow so plugins depend on a stable contract, not on
    Valkyrie internals. Any attribute may be None when the corresponding
    subsystem isn't wired in (e.g. no intelligence layer).
    """

    def __init__(self, store=None, intelligence=None, firewall=None,
                 rules=None, blocklist=None) -> None:
        self.store        = store          # valkyrie.store.Store
        self.intelligence = intelligence   # valkyrie.intelligence.Intelligence
        self.firewall     = firewall       # valkyrie.firewall.FirewallManager
        self.rules        = rules          # valkyrie.rules.RulesLoader
        self.blocklist    = blocklist      # valkyrie.blocklist.BlocklistManager


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class PluginRegistry:
    """Holds plugins by kind and runs them defensively.

    A broken plugin must never take down the pipeline: every plugin call is
    wrapped so an exception is captured (and counted) rather than propagated.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._detection: list[DetectionPlugin] = []
        self._responder: list[ResponderPlugin] = []
        self._enrichment: list[EnrichmentPlugin] = []
        self._errors: list[dict] = []
        # Provenance for every third-party module loaded via discover():
        # {name, path, sha256, verified}. `verified` is True only when a
        # SHA-256 allowlist was in force and this module matched it.
        self._loaded: list[dict] = []

    # -- registration --------------------------------------------------

    def register(self, plugin: PluginBase) -> None:
        with self._lock:
            if isinstance(plugin, DetectionPlugin):
                self._detection.append(plugin)
            elif isinstance(plugin, ResponderPlugin):
                self._responder.append(plugin)
            elif isinstance(plugin, EnrichmentPlugin):
                self._enrichment.append(plugin)
            else:
                raise TypeError(f"unknown plugin kind: {plugin!r}")

    def all(self) -> list[PluginBase]:
        with self._lock:
            return [*self._detection, *self._responder, *self._enrichment]

    def list_info(self) -> list[dict]:
        return [p.info() for p in self.all()]

    def errors(self) -> list[dict]:
        with self._lock:
            return list(self._errors)

    def loaded_plugins(self) -> list[dict]:
        """Provenance of every third-party module loaded via discover()."""
        with self._lock:
            return list(self._loaded)

    def _record_error(self, plugin: str, exc: Exception) -> None:
        with self._lock:
            self._errors.append({
                "plugin": plugin,
                "error": f"{type(exc).__name__}: {exc}",
                "trace": traceback.format_exc(limit=3),
            })
            self._errors = self._errors[-50:]

    # -- execution -----------------------------------------------------

    def run_detections(self, event: dict, ctx: PluginContext) -> list[Detection]:
        out: list[Detection] = []
        with self._lock:
            plugins = list(self._detection)
        for p in plugins:
            if not p.enabled:
                continue
            try:
                produced = p.analyze(event, ctx) or []
                for det in produced:
                    self._run_enrichment(det, ctx)
                    out.append(det)
            except Exception as exc:          # noqa: BLE001 — isolate plugin faults
                self._record_error(p.name, exc)
        return out

    def _run_enrichment(self, det: Detection, ctx: PluginContext) -> None:
        with self._lock:
            plugins = list(self._enrichment)
        for p in plugins:
            if not p.enabled:
                continue
            try:
                p.enrich(det, ctx)
            except Exception as exc:          # noqa: BLE001
                self._record_error(p.name, exc)

    def responder_for(self, action: str) -> Optional[ResponderPlugin]:
        with self._lock:
            for p in self._responder:
                if p.enabled and p.can_handle(action):
                    return p
        return None

    def available_actions(self) -> list[str]:
        seen: list[str] = []
        with self._lock:
            for p in self._responder:
                if not p.enabled:
                    continue
                for a in p.actions():
                    if a not in seen:
                        seen.append(a)
        return seen

    # -- discovery -----------------------------------------------------

    def discover(self, directory,
                 allowlist: Optional[Iterable[str]] = None) -> list[str]:
        """Load ``*.py`` plugin modules from ``directory`` behind a trust gate.

        Each module may define ``register(registry)``; it is called with this
        registry so it can add its plugins. Returns the module names successfully
        loaded. Import/registration errors are captured (not raised) so one bad
        file can't stop the others.

        **Trust gate.** Discovered plugins execute with Valkyrie's privileges, so
        loading is gated on a SHA-256 allowlist:

          * ``allowlist`` — an explicit iterable of approved hex digests, or
          * an ``allowed.sha256`` manifest in ``directory`` (one digest per line)
            used when ``allowlist`` is None.

        When an allowlist is in force, only modules whose SHA-256 matches are
        loaded; every other ``*.py`` is skipped and recorded (fail closed —
        an empty allowlist loads nothing). When **no** allowlist is configured,
        modules still load (preserving existing behavior) but each is flagged
        ``verified=False`` and a single warning is recorded, so unverified code
        execution is explicit and auditable rather than silent.

        Every loaded module's name, path, SHA-256, and verification state is
        recorded in :meth:`loaded_plugins`.
        """
        loaded: list[str] = []
        d = Path(directory)
        if not d.is_dir():
            return loaded

        # Resolve the allowlist: explicit arg wins; else an in-dir manifest.
        allowed = _normalize_allowlist(allowlist)
        if allowed is None:
            manifest = d / "allowed.sha256"
            if manifest.exists():
                try:
                    allowed = _read_allowlist_file(manifest)
                except OSError as exc:
                    self._record_error("allowed.sha256", exc)
        enforcing = allowed is not None
        unverified_loaded = 0

        for path in sorted(d.glob("*.py")):
            if path.name.startswith("_"):
                continue
            try:
                digest = sha256_file(path)
            except OSError as exc:
                self._record_error(path.name, exc)
                continue

            if enforcing and digest not in allowed:
                self._record_error(
                    path.name,
                    RuntimeError(
                        f"not in allowlist (sha256={digest[:12]}…) — skipped"))
                continue

            mod_name = f"valkyrie_plugin_{path.stem}"
            try:
                spec = importlib.util.spec_from_file_location(mod_name, path)
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                reg = getattr(module, "register", None)
                if callable(reg):
                    reg(self)
                    loaded.append(path.stem)
                    with self._lock:
                        self._loaded.append({
                            "name": path.stem,
                            "path": str(path),
                            "sha256": digest,
                            "verified": enforcing,
                        })
                    if not enforcing:
                        unverified_loaded += 1
                else:
                    self._record_error(path.name,
                                       RuntimeError("no register(registry) function"))
            except Exception as exc:          # noqa: BLE001
                self._record_error(path.name, exc)

        if unverified_loaded:
            self._record_error(
                "plugin-trust",
                RuntimeError(
                    f"{unverified_loaded} plugin(s) loaded WITHOUT hash "
                    f"verification — add an allowed.sha256 manifest in "
                    f"{d} to lock this down"))
        return loaded
