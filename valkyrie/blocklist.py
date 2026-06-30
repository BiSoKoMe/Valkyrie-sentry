"""Blocklist loader and auto-updater.

On startup:
  1. Check if blocklist.txt is older than BLOCKLIST_MAX_AGE_DAYS.
  2. If stale, fetch all BLOCKLIST_SOURCES in parallel, merge, deduplicate,
     compare hash against existing file, and write only if changed.
  3. Load the merged list into an in-memory set for O(1) lookups.

The updater shows a Rich progress bar while downloading.
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import (
    BLOCKLIST_MAX_AGE_DAYS,
    BLOCKLIST_PATH,
    BLOCKLIST_SOURCES,
)

# Matches lines like "0.0.0.0 tracker.example.com" or "127.0.0.1 ..."
_HOSTS_PATTERN = re.compile(r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.\-_]+)")
# Matches raw domain lines (no IP prefix) — for OISD domainswild format
_DOMAIN_PATTERN = re.compile(r"^\s*([a-zA-Z0-9.\-_*]+)\s*$")
# Skip localhost / self-references
_SKIP = {"localhost", "localhost.localdomain", "local", "broadcasthost", "0.0.0.0"}


def _parse_source(text: str) -> set[str]:
    """Parse one downloaded source text into a set of domain strings."""
    domains: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _HOSTS_PATTERN.match(line)
        if m:
            domain = m.group(1).lower()
            if domain not in _SKIP:
                domains.add(domain)
            continue
        m = _DOMAIN_PATTERN.match(line)
        if m:
            domain = m.group(1).lower()
            if domain not in _SKIP and "." in domain:
                domains.add(domain)
    return domains


def _fetch_one(url: str, timeout: int = 30) -> str:
    """Download a single URL and return its text."""
    import urllib.request
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _file_age_days(path: Path) -> Optional[float]:
    if not path.exists():
        return None
    mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    return (datetime.now(tz=timezone.utc) - mtime).total_seconds() / 86_400


def update_blocklist(console=None) -> int:
    """Fetch all sources, merge, and write blocklist.txt if changed.

    Returns the number of domains written.  Pass a Rich Console for output.
    """
    def _print(msg: str):
        if console:
            console.print(msg)
        else:
            print(msg)

    _print(f"[bold cyan]Blocklist update:[/bold cyan] fetching {len(BLOCKLIST_SOURCES)} sources…")
    all_domains: set[str] = set()

    with ThreadPoolExecutor(max_workers=len(BLOCKLIST_SOURCES)) as ex:
        futures = {ex.submit(_fetch_one, url): url for url in BLOCKLIST_SOURCES}
        for i, future in enumerate(as_completed(futures), 1):
            url = futures[future]
            label = url.split("/")[2][:30]
            try:
                text    = future.result()
                domains = _parse_source(text)
                all_domains |= domains
                _print(f"  [{i}/{len(BLOCKLIST_SOURCES)}] {label}: {len(domains):,} domains")
            except Exception as exc:
                _print(f"  [yellow]Warning:[/yellow] {label}: {exc}")

    if not all_domains:
        _print("[red]No domains fetched — keeping existing blocklist.[/red]")
        return 0

    new_text   = "\n".join(sorted(all_domains)) + "\n"
    new_hash   = hashlib.sha256(new_text.encode()).hexdigest()
    old_hash   = ""
    if BLOCKLIST_PATH.exists():
        old_hash = hashlib.sha256(BLOCKLIST_PATH.read_bytes()).hexdigest()

    if new_hash == old_hash:
        _print(f"[green]Blocklist unchanged[/green] ({len(all_domains):,} domains).")
        BLOCKLIST_PATH.touch()   # update mtime so we don't check again for 7 days
        return len(all_domains)

    BLOCKLIST_PATH.write_text(new_text, encoding="utf-8")
    _print(f"[green]Blocklist updated:[/green] {len(all_domains):,} domains → {BLOCKLIST_PATH}")
    return len(all_domains)


class BlocklistManager:
    """In-memory blocklist with wildcard support and auto-update scheduling."""

    def __init__(self) -> None:
        self._exact:    set[str] = set()
        self._wildcards: list[str] = []    # stored without leading '*.'
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self, console=None) -> int:
        """Load or update blocklist.  Returns domain count."""
        age = _file_age_days(BLOCKLIST_PATH)
        if age is None or age > BLOCKLIST_MAX_AGE_DAYS:
            count = update_blocklist(console)
        else:
            count = self._read_from_disk()
            if console:
                console.print(
                    f"[dim]Blocklist loaded from cache ({BLOCKLIST_PATH.name},"
                    f" {age:.1f}d old, {count:,} entries)[/dim]"
                )
        return count

    def _read_from_disk(self) -> int:
        if not BLOCKLIST_PATH.exists():
            return 0
        exact: set[str] = set()
        wildcards: list[str] = []
        for line in BLOCKLIST_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("*."):
                wildcards.append(line[2:])
            else:
                exact.add(line)
        with self._lock:
            self._exact    = exact
            self._wildcards = wildcards
        return len(exact) + len(wildcards)

    def reload(self) -> int:
        """Force re-read from disk (called after update)."""
        return self._read_from_disk()

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def is_blocked(self, domain: str) -> bool:
        """Return True if domain matches any blocklist entry."""
        d = domain.rstrip(".").lower()
        with self._lock:
            if d in self._exact:
                return True
            # Check wildcard parents: sub.tracker.com → tracker.com, com
            parts = d.split(".")
            for i in range(1, len(parts)):
                parent = ".".join(parts[i:])
                if parent in self._wildcards:
                    return True
        return False

    def count(self) -> int:
        with self._lock:
            return len(self._exact) + len(self._wildcards)
