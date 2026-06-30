"""YAML user rules loader.

Watches valkyrie_rules.yaml for changes (file mtime polling) and reloads
automatically.  Supports SIGHUP on POSIX systems.

Rule schema:
  always_allow:
    - domain: "*.zoom.us"
      process: "zoom"          # optional — if omitted, applies to any process
  always_block:
    - domain: "*.doubleclick.net"

Wildcards: leading '*.' matches any subdomain.  No regex support.
"""

from __future__ import annotations

import fnmatch
import os
import signal
import threading
import time
from pathlib import Path
from typing import Optional

from .config import RULES_PATH

DEFAULT_RULES_YAML = """\
# Valkyrie user rules — edit and save; changes take effect within 5 seconds.
#
# always_allow: never block these domains (e.g. work tools, trusted services)
# always_block: force-block these domains regardless of other decisions
#
# Wildcards: use *.example.com to match any subdomain.
# Process filter: add 'process: appname' to restrict a rule to one process.

always_allow:
  - domain: "*.zoom.us"
  - domain: "*.slack.com"
  - domain: "*.microsoft.com"
    process: "teams"

always_block:
  - domain: "*.doubleclick.net"
  - domain: "*.googlesyndication.com"
  - domain: "*.facebook.com"
    process: "chrome"
"""


class RuleSet:
    """Immutable snapshot of parsed rules."""

    def __init__(self, allow: list[dict], block: list[dict]) -> None:
        self._allow = allow
        self._block = block

    def is_always_allowed(self, domain: str, process_name: str = "") -> bool:
        return self._matches(self._allow, domain, process_name)

    def is_always_blocked(self, domain: str, process_name: str = "") -> bool:
        return self._matches(self._block, domain, process_name)

    @staticmethod
    def _matches(rules: list[dict], domain: str, process_name: str) -> bool:
        for rule in rules:
            pattern = rule.get("domain", "")
            proc    = rule.get("process", "")
            if proc and proc.lower() not in process_name.lower():
                continue    # rule is process-specific and doesn't match
            if fnmatch.fnmatch(domain, pattern):
                return True
        return False

    def __repr__(self) -> str:
        return f"<RuleSet allow={len(self._allow)} block={len(self._block)}>"


class RulesLoader:
    """Loads and hot-reloads valkyrie_rules.yaml.

    Thread-safe: .get() always returns the latest parsed snapshot.
    """

    def __init__(self, path: Path = RULES_PATH) -> None:
        self._path = path
        self._ruleset: RuleSet = RuleSet([], [])
        self._mtime:   float   = 0.0
        self._lock = threading.RLock()
        self._watcher = threading.Thread(
            target=self._watch_loop, daemon=True, name="rules-watcher"
        )

    def start(self) -> None:
        """Create default file if absent, load it, start file watcher."""
        if not self._path.exists():
            self._path.write_text(DEFAULT_RULES_YAML, encoding="utf-8")
        self._load()
        self._watcher.start()
        # POSIX SIGHUP reload
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, lambda *_: self._load())

    def get(self) -> RuleSet:
        with self._lock:
            return self._ruleset

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _load(self) -> None:
        try:
            import yaml
        except ImportError:
            return

        try:
            text = self._path.read_text(encoding="utf-8")
            data = yaml.safe_load(text) or {}
            allow = data.get("always_allow", []) or []
            block = data.get("always_block", []) or []
            with self._lock:
                self._ruleset = RuleSet(allow, block)
                self._mtime   = self._path.stat().st_mtime
        except Exception:
            pass    # keep stale ruleset on parse error

    def _watch_loop(self) -> None:
        while True:
            time.sleep(5)
            try:
                mtime = self._path.stat().st_mtime
                if mtime != self._mtime:
                    self._load()
            except FileNotFoundError:
                pass
