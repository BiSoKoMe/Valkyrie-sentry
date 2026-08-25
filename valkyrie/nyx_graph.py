"""Nyx correlation graph - the data brain that connects the dots.

Nyx's observe/act layers each see ONE request in isolation. This is the layer
that REMEMBERS and CORRELATES: it links a tracker's identity across every
surface it touches - the first-party sites it rode in on, the channels it used
(outbound data leaks, blocked beacons, cleaned page-trackers, faked replies),
the categories of *you* it reached for, and the different hostnames (masks) it
wore. That turns "this one request leaked your ID" into the real picture:

    "adnet.example has followed you across 14 of your sites, on 3 channels,
     wearing 4 different hostnames - reaching for your ID and location."

That is the Threat-Graph idea the commercial EDRs are famous for, pointed at
privacy and done ENTIRELY LOCALLY - it is your own data flows correlated on your
own machine, so it needs no cloud (which is the whole point; the fleet-fed graph
is the thing Valkyrie deliberately refuses).

The core (TrackerGraph) is a pure in-memory structure, fully testable with
explicit observe() calls. build_from_events() is a best-effort adapter that
feeds it from the event store.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .dns_tunnel import registrable_base

# raw_category / decision -> the channel a tracker was seen on.
_CHANNEL = {
    "nyx_leak":         "data-leak",      # personal data seen leaving (observed)
    "nyx_fake":         "data-leak",      # personal data leaving, fed fake (acted)
    "page_clean":       "page-tracker",   # tracker element stripped from a page
    "tracker_pixel":    "blocked-beacon",
    "tracker_js":       "blocked-beacon",
    "fingerprint":      "fingerprint",
    "blocked":          "blocked-beacon",
    "threat_intel_url": "blocked-beacon",
    "behavioral":       "blocked-beacon",
    "exfil":            "data-leak",
}

# Nyx's own sentences are "<first_party> sent your <label> to an unrelated
# server (<dest>)" - a format this module owns, so parsing it back is reliable.
_SENTENCE = re.compile(
    r"^(?P<fp>\S+) sent your (?P<cat>.+?) to an unrelated server \((?P<dest>[^)]+)\)")
_FAKE_SENTENCE = re.compile(
    r"fake data for your (?P<cat>.+?) to (?P<dest>\S+)")


@dataclass
class _Record:
    first_parties: set = field(default_factory=set)
    channels: set = field(default_factory=set)
    categories: set = field(default_factory=set)
    hosts: set = field(default_factory=set)      # distinct hostnames = "masks"
    hits: int = 0
    first_seen: str = ""                          # ISO ts of the earliest sighting
    last_seen: str = ""                           # ISO ts of the latest sighting


def _span_hours(first: str, last: str) -> float:
    """Hours between two ISO timestamps; 0 if either is missing/unparseable.
    This is the memory: how long a tracker has been observed following you."""
    from datetime import datetime
    try:
        a = datetime.fromisoformat(first.replace("Z", ""))
        b = datetime.fromisoformat(last.replace("Z", ""))
        return round(max(0.0, (b - a).total_seconds() / 3600.0), 1)
    except (ValueError, AttributeError):
        return 0.0


class TrackerGraph:
    """Correlates tracker sightings by registrable domain. Pure, in-memory."""

    def __init__(self) -> None:
        self._t: dict[str, _Record] = {}

    def observe(self, tracker_host: str, first_party: str = "",
                channel: str = "", category: str = "", ts: str = "") -> None:
        base = registrable_base(tracker_host) if tracker_host else ""
        if not base:
            return
        r = self._t.setdefault(base, _Record())
        r.hits += 1
        r.hosts.add(tracker_host.lower())
        fp = registrable_base(first_party) if first_party else ""
        if fp and fp != base:                 # a tracker on its OWN site is not "reach"
            r.first_parties.add(fp)
        if channel:
            r.channels.add(channel)
        if category:
            r.categories.add(category)
        if ts:
            if not r.first_seen or ts < r.first_seen:
                r.first_seen = ts
            if ts > r.last_seen:
                r.last_seen = ts

    def reach(self, tracker_host: str) -> int:
        r = self._t.get(registrable_base(tracker_host))
        return len(r.first_parties) if r else 0

    def top_trackers(self, n: int = 10) -> list[dict]:
        rows = []
        for base, r in self._t.items():
            rows.append({
                "tracker":       base,
                "reach":         len(r.first_parties),   # how many of YOUR sites it rode
                "channels":      sorted(r.channels),
                "categories":    sorted(r.categories),
                "masks":         len(r.hosts),           # distinct hostnames / aliases
                "hits":          r.hits,
                "cross_channel": len(r.channels) >= 2,   # many surfaces = many masks
                "first_seen":    r.first_seen,
                "last_seen":     r.last_seen,
                "span_hours":    _span_hours(r.first_seen, r.last_seen),
            })
        # Rank by reach first (a tracker on many sites is the real menace),
        # then by cross-channel breadth, then raw volume.
        rows.sort(key=lambda x: (x["reach"], len(x["channels"]), x["hits"]),
                  reverse=True)
        return rows[:n]

    def summary(self) -> dict:
        total = len(self._t)
        cross = sum(1 for r in self._t.values() if len(r.channels) >= 2)
        widest = max((len(r.first_parties) for r in self._t.values()), default=0)
        longest = max((_span_hours(r.first_seen, r.last_seen)
                       for r in self._t.values()), default=0.0)
        return {"distinct_trackers": total,
                "cross_channel_trackers": cross,
                "widest_reach": widest,
                "longest_following_hours": longest}


def _channel_and_category(rc: str, dec: str, reason: str) -> tuple[str, str, str]:
    """Best-effort (channel, first_party, category) from one event row."""
    channel = _CHANNEL.get(rc) or ("fake-beacon" if dec == "deceived" else "")
    fp = category = ""
    m = _SENTENCE.match(reason or "")
    if m:
        fp = m.group("fp")
        category = m.group("cat")
    else:
        m = _FAKE_SENTENCE.search(reason or "")
        if m:
            category = m.group("cat")
    return channel, fp, category


def build_from_events(events) -> TrackerGraph:
    """Feed a TrackerGraph from event-store rows (dicts with domain / reason /
    raw_category / decision). Robust: an unrecognised row is simply skipped."""
    g = TrackerGraph()
    for e in events or []:
        try:
            rc = e.get("raw_category", "") or ""
            dec = e.get("decision", "") or ""
            channel, fp, cat = _channel_and_category(rc, dec, e.get("reason", ""))
            if not channel:
                continue
            g.observe(e.get("domain", ""), first_party=fp,
                      channel=channel, category=cat,
                      ts=e.get("timestamp", "") or "")
        except (AttributeError, TypeError):
            continue
    return g
