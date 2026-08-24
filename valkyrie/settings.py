"""Layered, validated configuration overlay.

`config.py` still declares every constant and its documented default. This module
sits *underneath* those constants and lets an operator override a curated subset
without editing code, with clear precedence and validation:

    code defaults  (config.py)   <   config file   <   environment variables

- **Config file:** ``$VALKYRIE_CONFIG`` if set (must exist), else
  ``<data>/valkyrie.yaml`` / ``.yml`` if present. A flat mapping of the constant
  names to values (see docs/valkyrie.example.yaml).
- **Environment:** ``VALKYRIE_<CONSTANT_NAME>`` for each overridable setting,
  e.g. ``VALKYRIE_DNS_LISTEN_PORT=53``, ``VALKYRIE_WEB_HOST=0.0.0.0``.

Design invariants:
  * With no file and no matching env vars, resolution returns the defaults
    **unchanged** — a stock deployment behaves exactly as before.
  * An *explicitly provided* value that is the wrong type or out of range raises
    ``ConfigError`` and stops startup. A security tool must not silently run on a
    misconfiguration; but a missing file or unset var is never an error.
  * Only the overlaid values are coerced/validated — trusted code defaults pass
    through untouched, so a schema range mistake can never brick the defaults.

Stdlib-only except for the optional YAML parse (pyyaml is already a dependency;
JSON is accepted as a fallback).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional


class ConfigError(Exception):
    """Raised when an explicitly-provided config value is invalid."""


# ---------------------------------------------------------------------------
# Coercion helpers
# ---------------------------------------------------------------------------

def _to_bool(raw: Any) -> bool:
    if isinstance(raw, bool):
        return raw
    s = str(raw).strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"not a boolean: {raw!r}")


_COERCERS: dict[str, Callable[[Any], Any]] = {
    "int":   lambda r: int(str(r).strip(), 10) if not isinstance(r, bool) else int(r),
    "float": lambda r: float(str(r).strip()),
    "bool":  _to_bool,
    "str":   lambda r: str(r),
}


# ---------------------------------------------------------------------------
# Setting specification
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Spec:
    key: str                       # the config.py constant name (and file key)
    type: str                      # "int" | "float" | "bool" | "str"
    help: str
    minv: Optional[float] = None
    maxv: Optional[float] = None
    choices: Optional[tuple] = None

    @property
    def env(self) -> str:
        return "VALKYRIE_" + self.key

    def coerce_and_validate(self, raw: Any, source: str) -> Any:
        coerce = _COERCERS[self.type]
        try:
            val = coerce(raw)
        except (ValueError, TypeError):
            raise ConfigError(
                f"{source}: {self.key} must be {self.type}, got {raw!r}")
        if self.type in ("int", "float"):
            if self.minv is not None and val < self.minv:
                raise ConfigError(
                    f"{source}: {self.key}={val} is below minimum {self.minv}")
            if self.maxv is not None and val > self.maxv:
                raise ConfigError(
                    f"{source}: {self.key}={val} is above maximum {self.maxv}")
        if self.choices is not None and val not in self.choices:
            raise ConfigError(
                f"{source}: {self.key}={val!r} not in {self.choices}")
        return val


_PORT = dict(type="int", minv=1, maxv=65535)

# The curated set of overridable settings. Defaults are NOT stored here — they
# come from config.py — so there is a single source of truth for defaults.
SPECS: list[Spec] = [
    # ── DNS ──────────────────────────────────────────────────────────────
    Spec("DNS_LISTEN_HOST", "str", "Address the DNS sinkhole binds to"),
    Spec("DNS_LISTEN_PORT", **_PORT, help="DNS sinkhole listen port"),
    Spec("DNS_UPSTREAM", "str", "Primary upstream resolver (e.g. local Unbound)"),
    Spec("DNS_UPSTREAM_PORT", **_PORT, help="Upstream resolver port"),
    Spec("DNS_TIMEOUT", "float", "Upstream query timeout (seconds)", minv=0.1, maxv=60.0),
    Spec("DNS_LOCAL_ONLY", "bool", "Fail closed: never fall back to public resolvers"),
    # ── Web dashboard ────────────────────────────────────────────────────
    Spec("WEB_HOST", "str", "Dashboard bind address (127.0.0.1 = loopback-only)"),
    Spec("WEB_PORT", **_PORT, help="Dashboard port"),
    # ── Fleet control plane ──────────────────────────────────────────────
    # FLEET_* specs removed 2026-08-04: the fleet control plane moved to
    # experimental/ (ADR 0044). Leaving a user-settable knob for a subsystem
    # that no longer loads is a SILENT NO-OP — the operator sets it, validation
    # accepts it, and nothing happens. That is precisely the failure mode this
    # project's no-silent-success rule exists to prevent. The underlying
    # constants remain in config.py because experimental/fleet still imports
    # them; restoring these specs is part of the unfreeze checklist.
    # ── Behavioral heuristics ────────────────────────────────────────────
    Spec("ENTROPY_THRESHOLD", "float", "Domain entropy above which it is suspicious", minv=0.0, maxv=8.0),
    Spec("RATE_WINDOW_SECONDS", "int", "Sliding window for per-process query rate", minv=1, maxv=3600),
    Spec("RATE_MAX_QUERIES", "int", "Queries per window per process before suspicious", minv=1, maxv=1_000_000),
    Spec("BEHAVIORAL_BLOCK_SCORE", "float", "Suspicion score at/above which to block", minv=0.0, maxv=1.0),
    # ── Updaters / caches ────────────────────────────────────────────────
    Spec("BLOCKLIST_MAX_AGE_DAYS", "int", "Refresh domain blocklist after this many days", minv=0, maxv=365),
    Spec("FIREWALL_MAX_AGE_DAYS", "int", "Refresh IP blocklist after this many days", minv=0, maxv=365),
    # ── Store tuning ─────────────────────────────────────────────────────
    Spec("STORE_QUEUE_SIZE", "int", "Async event write-queue depth", minv=100, maxv=10_000_000),
    Spec("STORE_FLUSH_EVERY", "int", "Rows to batch before a DB commit", minv=1, maxv=100_000),
]

_SPECS_BY_KEY = {s.key: s for s in SPECS}


# ---------------------------------------------------------------------------
# File loading
# ---------------------------------------------------------------------------

def _load_file(config_dir: Path, environ) -> tuple[dict, Optional[Path]]:
    """Return (mapping, path) from the resolved config file, or ({}, None)."""
    explicit = environ.get("VALKYRIE_CONFIG")
    path: Optional[Path] = None
    if explicit:
        path = Path(explicit)
        if not path.exists():
            raise ConfigError(f"VALKYRIE_CONFIG points to a missing file: {path}")
    else:
        for name in ("valkyrie.yaml", "valkyrie.yml"):
            cand = Path(config_dir) / name
            if cand.exists():
                path = cand
                break
    if path is None:
        return {}, None

    text = path.read_text(encoding="utf-8")
    try:
        import yaml
        data = yaml.safe_load(text) or {}
    except ImportError:
        import json
        data = json.loads(text or "{}")
    except Exception as exc:  # malformed YAML/JSON
        raise ConfigError(f"could not parse config file {path}: {exc}")
    if not isinstance(data, dict):
        raise ConfigError(f"config file {path} must be a mapping of setting: value")
    return data, path


# ---------------------------------------------------------------------------
# Public resolution
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Override:
    key: str
    value: Any
    source: str   # "config file (<path>)" | "env VALKYRIE_..."


def load(base: dict, *, config_dir: Path, environ=None) -> tuple[dict, list[Override]]:
    """Resolve the overridable settings.

    Args:
        base: {key: default_value} taken from config.py's current constants.
        config_dir: directory searched for valkyrie.yaml/.yml.
        environ: mapping (defaults to os.environ) — injectable for tests.

    Returns:
        (resolved, overrides) where ``resolved`` is ``base`` with file+env
        overlays applied, and ``overrides`` lists what actually changed and why.
    """
    environ = os.environ if environ is None else environ
    resolved = dict(base)
    overrides: list[Override] = []

    # 1. File overlay (lowest override precedence)
    file_vals, file_path = _load_file(config_dir, environ)
    src_file = f"config file ({file_path})" if file_path else "config file"
    for key, raw in file_vals.items():
        spec = _SPECS_BY_KEY.get(key)
        if spec is None:
            continue   # ignore keys that are not overridable settings
        val = spec.coerce_and_validate(raw, src_file)
        if val != base.get(key):
            resolved[key] = val
            overrides.append(Override(key, val, src_file))

    # 2. Environment overlay (wins over the file)
    for spec in SPECS:
        if spec.env in environ:
            val = spec.coerce_and_validate(environ[spec.env], f"env {spec.env}")
            resolved[spec.key] = val
            # replace any file-sourced override record for the same key
            overrides = [o for o in overrides if o.key != spec.key]
            if val != base.get(spec.key):
                overrides.append(Override(spec.key, val, f"env {spec.env}"))

    return resolved, overrides


def describe() -> list[dict]:
    """Introspection: every overridable setting, its env var, type, and help."""
    return [
        {"key": s.key, "env": s.env, "type": s.type, "help": s.help,
         "min": s.minv, "max": s.maxv, "choices": s.choices}
        for s in SPECS
    ]
