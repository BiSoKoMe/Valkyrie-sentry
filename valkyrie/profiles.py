"""Risk profiles — the user's current posture, which the decision policy reads.

A high-risk user is not always in the same situation: at the office they want
minimal disruption; travelling through a hostile network, or in a "clean room"
handling a sensitive source, they want everything locked down. The profile is a
single switch that shifts Valkyrie's block-vs-deceive trade-off (see
:mod:`valkyrie.decision`).

  * standard    — minimal disruption; deceive trackers, block only clear threats
  * high_risk   — block non-essential telemetry/uploads by default; alert more
  * travel      — high_risk + treat unusual network patterns as hostile
  * clean_room  — most aggressive: any targeted signal steps up toward contain

Persistence is a tiny JSON file in the data dir so the choice survives restarts.
Reading never raises; an unreadable/absent file means Standard.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Optional

from .decision import Profile

_LOCK = threading.Lock()
_VALID = {p.value for p in Profile}


def _path() -> Path:
    # Imported lazily so config's first-run seeding has already run.
    from .config import DATA_DIR
    return DATA_DIR / "profile.json"


def get_profile() -> Profile:
    """Current profile; Standard if unset or unreadable."""
    try:
        data = json.loads(_path().read_text(encoding="utf-8"))
        val = str(data.get("profile", "")).lower()
        if val in _VALID:
            return Profile(val)
    except Exception:
        pass
    return Profile.STANDARD


def set_profile(profile: Profile | str) -> Profile:
    """Persist a new profile. Accepts the enum or its string; returns the value
    actually set (unchanged on an invalid input)."""
    val = profile.value if isinstance(profile, Profile) else str(profile).lower()
    if val not in _VALID:
        return get_profile()
    with _LOCK:
        try:
            p = _path()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps({"profile": val}), encoding="utf-8")
        except OSError:
            pass
    return Profile(val)


def list_profiles() -> list[dict]:
    """Profiles + one-line descriptions, for the UI picker."""
    desc = {
        Profile.STANDARD:  "Minimal disruption — deceive trackers, block clear threats.",
        Profile.HIGH_RISK: "Block non-essential telemetry and uploads by default.",
        Profile.TRAVEL:    "High-Risk plus: treat unusual network patterns as hostile.",
        Profile.CLEAN_ROOM:"Lock down — any targeted signal escalates toward isolation.",
    }
    cur = get_profile()
    return [{"id": p.value, "description": desc[p], "active": p == cur} for p in Profile]
