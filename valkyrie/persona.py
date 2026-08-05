"""Persona engine — one CONSISTENT synthetic identity for the deception layer.

WHY THIS EXISTS
---------------
`decision.py` has had a DECEIVE action since the beginning, but what it
actually did was return `0.0.0.0` — the same answer as BLOCK, under a different
name. That is not deception, and it is worse than it sounds:

  * The tracker learns nothing false. It learns *nothing*, which is itself
    information: a beacon that reliably fails to resolve, on a machine whose
    other traffic resolves fine, marks that machine as "runs a blocker."
  * "Runs a blocker" is a small, stable, high-entropy population. Being in it
    is a fingerprint. The user set out to be less identifiable and became more
    identifiable in a rarer bucket.

The alternative is to answer — plausibly. But an inconsistent lie is worse
still, and this is the trap this module exists to avoid:

    Session 1: locale en-US, timezone America/New_York, screen 1920x1080
    Session 2: locale ja-JP, timezone Europe/Berlin, screen 1366x768

No human generates that. Contradiction across sessions is a *stronger* signal
than blocking, because it is unique to synthetic traffic. Real users are
boring: the same person, on the same laptop, in the same city, for months.

So the lie must be:
  1. INTERNALLY COHERENT  — locale, timezone, and language agree with each
     other; screen metrics are physically possible.
  2. STABLE ACROSS SESSIONS — the same machine tells the same story next week.
  3. COMMON, NOT RANDOM — drawn from configurations many real people have.
     Uniform randomness maximises entropy, which is the opposite of the goal:
     a 3-in-a-billion screen size identifies you as precisely as your real one.
     We aim for a large crowd, not a novel disguise.

RELATIONSHIP TO farble.py — THEY PULL IN OPPOSITE DIRECTIONS, DELIBERATELY
--------------------------------------------------------------------------
`farble.py` makes browser-surface values DIFFER per site and per session, so
two trackers cannot correlate one user. This module makes values IDENTICAL
across sessions. That is not a contradiction; they defend different things:

  * farble operates on surfaces the tracker reads from a REAL browser, where
    the honest answer would be a durable ID. Decorrelation is the win.
  * persona operates on answers WE fabricate for beacons we already
    intercepted. Here the tracker has no true value to correlate — the only
    thing that can betray us is our own inconsistency. Stability is the win.

Put plainly: farble hides a real user in noise; persona builds a fake user who
is unremarkable. Applying either strategy to the other's surface would break it.

HONEST BOUNDARIES
-----------------
* This does not make a user untrackable. A tracker with a first-party cookie,
  a login, or an IP address does not need any of these fields.
* The persona is per-machine, not per-site. A tracker present on two sites sees
  one consistent identity — which is what a real user looks like. Cross-site
  decorrelation is farble's job, on surfaces we can actually rewrite.
* Nothing here touches real system values. It never reads or reports the user's
  actual locale, timezone, or screen; it fabricates a plausible one instead.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

PERSONA_SCHEMA = 1

# ---------------------------------------------------------------------------
# Coherence tables.
#
# Every row is a SELF-CONSISTENT bundle: the locale, the language list, the
# IANA timezone and the UTC offset all describe the same plausible person.
# They are chosen as a unit precisely so no combination of them can contradict
# itself -- picking locale and timezone independently is exactly how you get
# "ja-JP in Europe/Berlin", which no real user is.
#
# `weight` biases selection toward large populations. The goal is to land in a
# big crowd; a rare-but-valid combination is a worse disguise than a common one.
#
# NOTE ON UTC OFFSET: these are STANDARD-time offsets. Real clients in DST
# report the shifted value, and `utc_offset_minutes` is derived at report time
# (see Persona.current_utc_offset_minutes) rather than frozen here, because a
# client whose offset never changes across a DST boundary while claiming a
# DST-observing zone is itself a contradiction.
# ---------------------------------------------------------------------------
_LOCALES: tuple[dict, ...] = (
    {"locale": "en-US", "languages": ("en-US", "en"), "tz": "America/New_York",
     "std_offset": -300, "dst": True,  "country": "US", "weight": 26},
    {"locale": "en-US", "languages": ("en-US", "en"), "tz": "America/Chicago",
     "std_offset": -360, "dst": True,  "country": "US", "weight": 12},
    {"locale": "en-US", "languages": ("en-US", "en"), "tz": "America/Los_Angeles",
     "std_offset": -480, "dst": True,  "country": "US", "weight": 14},
    {"locale": "en-GB", "languages": ("en-GB", "en"), "tz": "Europe/London",
     "std_offset": 0,    "dst": True,  "country": "GB", "weight": 9},
    {"locale": "de-DE", "languages": ("de-DE", "de", "en"), "tz": "Europe/Berlin",
     "std_offset": 60,   "dst": True,  "country": "DE", "weight": 8},
    {"locale": "fr-FR", "languages": ("fr-FR", "fr", "en"), "tz": "Europe/Paris",
     "std_offset": 60,   "dst": True,  "country": "FR", "weight": 6},
    {"locale": "es-ES", "languages": ("es-ES", "es", "en"), "tz": "Europe/Madrid",
     "std_offset": 60,   "dst": True,  "country": "ES", "weight": 5},
    {"locale": "pt-BR", "languages": ("pt-BR", "pt", "en"), "tz": "America/Sao_Paulo",
     "std_offset": -180, "dst": False, "country": "BR", "weight": 6},
    {"locale": "en-CA", "languages": ("en-CA", "en", "fr"), "tz": "America/Toronto",
     "std_offset": -300, "dst": True,  "country": "CA", "weight": 4},
    {"locale": "en-AU", "languages": ("en-AU", "en"), "tz": "Australia/Sydney",
     "std_offset": 600,  "dst": True,  "country": "AU", "weight": 3},
    {"locale": "it-IT", "languages": ("it-IT", "it", "en"), "tz": "Europe/Rome",
     "std_offset": 60,   "dst": True,  "country": "IT", "weight": 4},
    {"locale": "nl-NL", "languages": ("nl-NL", "nl", "en"), "tz": "Europe/Amsterdam",
     "std_offset": 60,   "dst": True,  "country": "NL", "weight": 3},
)

# Real desktop resolutions, ordered roughly by market share. `taskbar` is the
# vertical chrome subtracted to produce availHeight -- a real client never
# reports availHeight == height on Windows, and reporting it is a tell.
_SCREENS: tuple[dict, ...] = (
    {"w": 1920, "h": 1080, "taskbar": 48, "ratio": 1.0,  "weight": 30},
    {"w": 1366, "h": 768,  "taskbar": 40, "ratio": 1.0,  "weight": 14},
    {"w": 1536, "h": 864,  "taskbar": 48, "ratio": 1.25, "weight": 11},
    {"w": 1280, "h": 720,  "taskbar": 40, "ratio": 1.0,  "weight": 7},
    {"w": 1440, "h": 900,  "taskbar": 48, "ratio": 1.0,  "weight": 7},
    {"w": 1600, "h": 900,  "taskbar": 48, "ratio": 1.0,  "weight": 6},
    {"w": 2560, "h": 1440, "taskbar": 48, "ratio": 1.0,  "weight": 8},
    {"w": 3840, "h": 2160, "taskbar": 64, "ratio": 1.5,  "weight": 4},
    {"w": 1680, "h": 1050, "taskbar": 48, "ratio": 1.0,  "weight": 3},
)

# navigator.hardwareConcurrency / deviceMemory. Powers of two only; real
# machines report these, and an odd core count is close to nonexistent.
_CORES: tuple[dict, ...] = (
    {"v": 4, "weight": 20}, {"v": 8, "weight": 34}, {"v": 12, "weight": 20},
    {"v": 16, "weight": 18}, {"v": 6, "weight": 8},
)
# deviceMemory is CLAMPED BY SPEC to one of 0.25/0.5/1/2/4/8 -- browsers never
# report more than 8 even on a 64GB machine. Reporting 16 or 32 would be an
# immediate tell that the value was not produced by a real browser.
_MEMORY: tuple[dict, ...] = (
    {"v": 4, "weight": 30}, {"v": 8, "weight": 55}, {"v": 2, "weight": 15},
)


def _weighted_pick(table: tuple[dict, ...], token: int) -> dict:
    """Deterministically pick a row, honouring `weight`.

    `token` is an arbitrary non-negative integer derived from the seed; the
    same token always yields the same row, which is what makes the persona
    reproducible without storing every field.
    """
    total = sum(r["weight"] for r in table)
    point = token % total
    upto = 0
    for row in table:
        upto += row["weight"]
        if point < upto:
            return row
    return table[-1]                                     # unreachable; total>0


@dataclass(frozen=True)
class Persona:
    """A fabricated but coherent identity. Frozen: a persona that can be
    mutated in place is a persona that can drift, and drift is the failure
    this module exists to prevent."""
    schema: int
    advertising_id: str          # GUID, the shape Windows/Android ad IDs take
    locale: str
    languages: tuple
    timezone: str                # IANA name
    std_utc_offset_minutes: int
    observes_dst: bool
    country: str
    screen_width: int
    screen_height: int
    avail_width: int
    avail_height: int
    color_depth: int
    pixel_ratio: float
    hardware_concurrency: int
    device_memory: int
    platform: str

    def as_dict(self) -> dict:
        d = asdict(self)
        d["languages"] = list(self.languages)
        return d

    # -- coherence self-check ------------------------------------------------
    def coherence_errors(self) -> list[str]:
        """Return every way this persona contradicts itself. Empty == coherent.

        This is the module's own auditor, exposed so tests and the deception
        endpoint can assert on it rather than trusting construction. Anything
        listed here is something a tracker could use to tell that the client is
        not a real machine.
        """
        errs: list[str] = []

        row = next((r for r in _LOCALES if r["tz"] == self.timezone), None)
        if row is None:
            errs.append(f"timezone {self.timezone!r} is not a known IANA zone here")
        else:
            if row["locale"] != self.locale:
                errs.append(
                    f"locale {self.locale!r} does not match timezone "
                    f"{self.timezone!r} (expected {row['locale']!r})")
            if row["std_offset"] != self.std_utc_offset_minutes:
                errs.append(
                    f"UTC offset {self.std_utc_offset_minutes} contradicts "
                    f"timezone {self.timezone!r} (expected {row['std_offset']})")
            if row["country"] != self.country:
                errs.append(f"country {self.country!r} contradicts timezone "
                            f"{self.timezone!r}")

        if not self.languages:
            errs.append("empty language list -- no real browser reports none")
        elif self.languages[0] != self.locale:
            errs.append(f"languages[0] {self.languages[0]!r} != locale "
                        f"{self.locale!r}")

        if self.avail_width > self.screen_width:
            errs.append("availWidth exceeds screen width")
        if self.avail_height > self.screen_height:
            errs.append("availHeight exceeds screen height")
        if self.avail_height == self.screen_height:
            errs.append("availHeight == height (no window chrome) -- a tell "
                        "on a desktop platform")
        if self.screen_width <= 0 or self.screen_height <= 0:
            errs.append("non-positive screen dimensions")

        if self.color_depth not in (24, 30, 32):
            errs.append(f"implausible colorDepth {self.color_depth}")
        if self.pixel_ratio <= 0:
            errs.append("non-positive devicePixelRatio")
        # deviceMemory is spec-clamped to <=8; anything larger cannot come from
        # a real browser and marks the client immediately.
        if self.device_memory not in (0.25, 0.5, 1, 2, 4, 8):
            errs.append(f"deviceMemory {self.device_memory} is outside the "
                        f"values the spec permits a browser to report")
        if self.hardware_concurrency <= 0 or self.hardware_concurrency > 128:
            errs.append(f"implausible hardwareConcurrency "
                        f"{self.hardware_concurrency}")

        try:
            uuid.UUID(self.advertising_id)
        except (ValueError, AttributeError, TypeError):
            errs.append(f"advertising_id {self.advertising_id!r} is not a GUID")

        return errs

    def is_coherent(self) -> bool:
        return not self.coherence_errors()


def _derive(seed: bytes, field: str) -> int:
    """Stable per-field token. HMAC (not plain concat-hash) so that knowing one
    field's token tells you nothing about the seed or any other field."""
    mac = hmac.new(seed, field.encode("utf-8"), hashlib.sha256).digest()
    return int.from_bytes(mac[:8], "big")


def build_persona(seed: bytes) -> Persona:
    """Derive a coherent persona from `seed`. Pure and total: the same seed
    always produces the same persona, on any machine, forever. That property is
    what makes the identity survive restarts without persisting every field."""
    loc = _weighted_pick(_LOCALES, _derive(seed, "locale"))
    scr = _weighted_pick(_SCREENS, _derive(seed, "screen"))
    cores = _weighted_pick(_CORES, _derive(seed, "cores"))
    mem = _weighted_pick(_MEMORY, _derive(seed, "memory"))

    # A GUID derived from the seed rather than uuid4(), so it survives restarts.
    # Version/variant bits are set so it is a well-formed v4 UUID -- a GUID that
    # fails version validation is a tell in exactly the systems that parse it.
    raw = bytearray(hmac.new(seed, b"advertising_id", hashlib.sha256).digest()[:16])
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    ad_id = str(uuid.UUID(bytes=bytes(raw)))

    return Persona(
        schema=PERSONA_SCHEMA,
        advertising_id=ad_id,
        locale=loc["locale"],
        languages=tuple(loc["languages"]),
        timezone=loc["tz"],
        std_utc_offset_minutes=loc["std_offset"],
        observes_dst=loc["dst"],
        country=loc["country"],
        screen_width=scr["w"],
        screen_height=scr["h"],
        avail_width=scr["w"],
        avail_height=scr["h"] - scr["taskbar"],
        color_depth=24,
        pixel_ratio=scr["ratio"],
        hardware_concurrency=cores["v"],
        device_memory=mem["v"],
        platform="Win32",
    )


class PersonaStore:
    """Loads-or-creates the machine's persona seed and caches the persona.

    ONLY THE SEED IS PERSISTED, not the derived fields. If a future version
    adds a field or re-weights a table, the persona changes shape -- and it
    changes the SAME way on every restart, because it is a pure function of a
    stored seed. Persisting the derived dict instead would freeze v1 personas
    forever and quietly accumulate schema drift between what is on disk and
    what the code believes.
    """

    def __init__(self, path: Optional[Path] = None):
        if path is None:
            from .config import DATA_DIR
            path = Path(DATA_DIR) / "persona_seed.json"
        self._path = Path(path)
        self._lock = threading.Lock()
        self._persona: Optional[Persona] = None
        self._seed: Optional[bytes] = None

    @property
    def path(self) -> Path:
        return self._path

    def _load_or_create_seed(self) -> bytes:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            seed_hex = raw.get("seed")
            if isinstance(seed_hex, str) and len(seed_hex) >= 32:
                return bytes.fromhex(seed_hex)
        except (OSError, ValueError, AttributeError):
            pass                                  # absent/corrupt -> regenerate

        seed = secrets.token_bytes(32)
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"schema": PERSONA_SCHEMA,
                                       "seed": seed.hex()}), encoding="utf-8")
            os.replace(tmp, self._path)           # atomic; no torn seed file
        except OSError:
            # Cannot persist. The persona is still coherent for THIS session,
            # but it will differ next boot. Degrading to an in-memory identity
            # beats refusing to deceive at all -- and the caller can detect it
            # via `persisted`.
            pass
        return seed

    @property
    def persisted(self) -> bool:
        return self._path.exists()

    def persona(self) -> Persona:
        with self._lock:
            if self._persona is None:
                self._seed = self._load_or_create_seed()
                self._persona = build_persona(self._seed)
            return self._persona

    def rotate(self) -> Persona:
        """Deliberately become a different person.

        Not automatic, and not scheduled. Rotation destroys the stability this
        module exists to provide, so it is a user-initiated act (e.g. "new
        identity"), never a background timer. A persona that rotates on its own
        recreates the contradiction problem with extra steps.
        """
        with self._lock:
            seed = secrets.token_bytes(32)
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self._path.with_suffix(".tmp")
                tmp.write_text(json.dumps({"schema": PERSONA_SCHEMA,
                                           "seed": seed.hex()}), encoding="utf-8")
                os.replace(tmp, self._path)
            except OSError:
                pass
            self._seed = seed
            self._persona = build_persona(seed)
            return self._persona


_DEFAULT: Optional[PersonaStore] = None
_DEFAULT_LOCK = threading.Lock()


def default_store() -> PersonaStore:
    global _DEFAULT
    with _DEFAULT_LOCK:
        if _DEFAULT is None:
            _DEFAULT = PersonaStore()
        return _DEFAULT


def current_persona() -> Persona:
    return default_store().persona()
