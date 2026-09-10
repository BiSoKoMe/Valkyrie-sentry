"""Decoy files & credentials - honeytokens that make an intruder announce himself.

The ransomware shield's canaries catch *encryption* (mass writes). Decoys catch
*reconnaissance/exfiltration*: an attacker who has a foothold goes looking for
confidential documents and credential stores. So Valkyrie plants tempting fakes -
``passwords``, ``id_rsa``, ``aws_credentials``, a fake ``.kdbx`` vault, a
"CONFIDENTIAL - case notes" document - each stamped with a unique, unguessable
token in its NAME and CONTENT.

Detection reuses the command-line eye Valkyrie already has: legitimate work never
runs ``type``/``copy``/``Get-Content``/``findstr``/``tar`` against these exact
files, so any process whose command line references a decoy token is - by
construction - an intruder browsing the box. That is a near-zero-false-positive,
HIGH-confidence signal, which the decision policy routes straight to CONTAIN.

No file-system auditing / driver needed: planting is plain file writes, and the
match is a substring check the engine already performs on every process command
line. Persisted so tokens survive restarts; degrades to a no-op off Windows.
"""

from __future__ import annotations

import os
import re
import secrets
import threading
from pathlib import Path
from typing import Iterable, Optional

# Decoy file templates: (filename stem, extension, tempting content header). The
# unique token is appended to both the name and the body at plant time.
_TEMPLATES = [
    ("passwords", "txt", "# personal passwords (KEEP PRIVATE)\n"),
    ("id_rsa", "", "-----BEGIN OPENSSH PRIVATE KEY-----\n"),
    ("aws_credentials", "", "[default]\naws_access_key_id = AKIA"),
    ("vault", "kdbx", "KeePass decoy vault\n"),
    ("CONFIDENTIAL-case-notes", "docx", "PRIVILEGED & CONFIDENTIAL\n"),
]

_TOKEN_PREFIX = "VLK7Y"          # makes a decoy token recognisable in a match


def _norm(s: str) -> str:
    return (s or "").lower().replace("\\", "/")


class DecoyManager:
    """Plants decoy files and answers 'does this text reference a decoy?'."""

    def __init__(self, manifest_path: Optional[Path] = None,
                 dirs: Optional[Iterable[Path]] = None) -> None:
        self._manifest = Path(manifest_path) if manifest_path else None
        self._dirs = [Path(d) for d in dirs] if dirs is not None else None
        self._tokens: set[str] = set()
        self._paths: list[str] = []
        # path -> on-disk token. Lets deploy() tell "this tripwire is gone"
        # apart from "this tripwire could not be read this pass".
        self._pairs: dict[str, str] = {}
        self._lock = threading.Lock()

    # -- targets ------------------------------------------------------------
    def target_dirs(self) -> list[Path]:
        if self._dirs is not None:
            return self._dirs
        # os.path.expanduser("~") resolves to the CALLING PROCESS's own home -
        # for Valkyrie's shipped default (a Windows service with no configured
        # logon account, so nssm runs it as LocalSystem), that is
        # C:\Windows\System32\config\systemprofile, a folder no real user or
        # intruder ever browses. A live VM run confirmed exactly this: zero
        # decoys existed under the interactive user's actual Desktop/Documents.
        # Enumerate every real user profile under %SystemDrive%\Users instead,
        # mirroring persistence_telemetry._startup_dirs's existing pattern for
        # the identical service-vs-interactive-user problem.
        dirs: list[Path] = []
        users_root = Path(os.environ.get("SystemDrive", "C:") + os.sep) / "Users"
        skip = {"public", "default", "default user", "all users", "defaultuser0"}
        found_any = False
        if users_root.is_dir():
            try:
                entries = list(users_root.iterdir())
            except OSError:
                entries = []
            for entry in entries:
                if not entry.is_dir() or entry.name.lower() in skip:
                    continue
                found_any = True
                for sub in ("Desktop", "Documents", os.path.join("Documents", "Private")):
                    dirs.append(entry / sub)
        if not found_any:
            # Fallback: non-Windows dev run, or a non-standard profile layout.
            home = Path(os.path.expanduser("~"))
            for sub in ("Desktop", "Documents", os.path.join("Documents", "Private")):
                dirs.append(home / sub)
        return dirs

    # -- planting -----------------------------------------------------------
    def deploy(self) -> int:
        """Write decoy files; return how many were planted. Never raises."""
        planted = 0
        with self._lock:
            pairs: dict[str, str] = {}
            # A path we could not read is NOT a path we know is gone. Dropping
            # one leaves the bait file on disk with nothing watching it - a
            # silently disarmed tripwire, persisted to the manifest on save.
            # Windows hands out sharing violations routinely (AV scan, backup,
            # cloud sync), so retention is the fail-safe direction here.
            unverified: list[str] = []
            for d in self.target_dirs():
                names = [f"{stem}.{ext}" if ext else stem
                         for stem, ext, _ in _TEMPLATES]
                try:
                    d.mkdir(parents=True, exist_ok=True)
                except OSError:
                    unverified.extend(str(d / n) for n in names)
                    continue
                for stem, ext, header in _TEMPLATES:
                    token = _TOKEN_PREFIX + secrets.token_hex(5)
                    name = f"{stem}.{ext}" if ext else stem
                    path = d / name
                    try:
                        try:
                            # Exclusive creation never overwrites an existing
                            # user file, even if it appears during deployment.
                            with path.open("x", encoding="utf-8") as out:
                                out.write(header + f"\n# ref:{token}\n")
                        except FileExistsError:
                            if path.is_symlink() or not path.is_file():
                                continue
                            with path.open(encoding="utf-8") as existing:
                                content = existing.read(4096)
                            owned = re.fullmatch(
                                re.escape(header) + r"\n# ref:(VLK7Y[0-9a-f]{10})\n",
                                content,
                            )
                            if owned is None:
                                continue  # a user's own file is never a decoy
                            token = owned.group(1)
                        pairs[str(path)] = token.lower()
                    except UnicodeError:
                        # Decoding as our UTF-8 template is part of the
                        # ownership proof, so this is someone else's file.
                        continue
                    except OSError:
                        unverified.append(str(path))
            known = set(self._paths)
            stale = {q: self._pairs[q] for q in unverified
                     if q in self._pairs and q not in pairs}
            # Tripwires planted before the manifest carried path->token pairs:
            # we cannot say which token is theirs, so keep the previous set
            # rather than disarm them. A token outliving its file cannot cause
            # a false positive - nothing but the file itself puts an
            # unguessable VLK7Y string on a command line.
            orphaned = {q for q in unverified
                        if q in known and q not in self._pairs and q not in pairs}
            pairs.update(stale)
            # Everything not retained above is confirmed: created, adopted from
            # disk, or proven to be a user's own file. Restarts must not
            # accumulate phantom tokens or duplicate paths.
            self._tokens = set(pairs.values()) | (set(self._tokens) if orphaned
                                                  else set())
            self._pairs = pairs
            self._paths = sorted(set(pairs) | orphaned)
            planted = len(self._paths)
            self._save()
        return planted

    def tokens(self) -> set[str]:
        with self._lock:
            return set(self._tokens)

    def paths(self) -> list[str]:
        with self._lock:
            return list(self._paths)

    # -- detection (pure) ---------------------------------------------------
    def references_decoy(self, *texts: str) -> Optional[str]:
        """Return the decoy token/path a text references, or None. This is the
        HIGH-confidence intruder signal (a process touching a planted fake)."""
        toks = self.tokens()
        paths = [_norm(p) for p in self.paths()]
        for raw in texts:
            t = _norm(raw)
            if not t:
                continue
            for tok in toks:
                if tok in t:
                    return tok
            for p in paths:
                if p and p in t:
                    return p
        return None

    # -- persistence --------------------------------------------------------
    def _save(self) -> None:
        if not self._manifest:
            return
        try:
            import json
            self._manifest.parent.mkdir(parents=True, exist_ok=True)
            self._manifest.write_text(
                json.dumps({"tokens": sorted(self._tokens),
                            "paths": self._paths,
                            "pairs": self._pairs}),
                encoding="utf-8")
        except OSError:
            pass

    def load(self) -> int:
        if not self._manifest or not self._manifest.exists():
            return 0
        try:
            import json
            data = json.loads(self._manifest.read_text(encoding="utf-8"))
            with self._lock:
                self._tokens = {str(t).lower() for t in data.get("tokens", [])}
                self._paths = [str(p) for p in data.get("paths", [])]
                pairs = data.get("pairs")
                self._pairs = ({str(k): str(v).lower() for k, v in pairs.items()}
                               if isinstance(pairs, dict) else {})
            return len(self._tokens)
        except (OSError, ValueError):
            return 0


# Process-global singleton so the hot detection path (which sees every command
# line) can ask "is this a decoy hit?" without threading the manager through.
_ACTIVE: Optional[DecoyManager] = None
_ACTIVE_LOCK = threading.Lock()


def set_active(mgr: Optional[DecoyManager]) -> None:
    global _ACTIVE
    with _ACTIVE_LOCK:
        _ACTIVE = mgr


def decoy_hit(*texts: str) -> Optional[str]:
    """Module-level convenience for the engine: does any text touch a live decoy?
    Returns the matched token/path, or None. Safe when no decoys are deployed."""
    mgr = _ACTIVE
    if mgr is None:
        return None
    try:
        return mgr.references_decoy(*texts)
    except Exception:
        return None
