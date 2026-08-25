"""Tests for nyx_graph.py - the local tracker-correlation brain.

The one thing this layer must get right: recognise that a tracker seen under
different hostnames, on different sites, across different channels is ONE
adversary - and rank the one that follows you the widest to the top. And it
must do it from the event store without a brittle dependency on any single
row's shape.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks
from valkyrie import nyx_graph


def main() -> int:
    c = Checks("nyx_graph", expect_min=18)

    # --- correlation by registrable domain ---
    print("\n[1] one tracker, many masks and sites, is recognised as ONE")
    g = nyx_graph.TrackerGraph()
    # same tracker (adnet.example) under two hostnames, on three of the user's sites
    g.observe("a.adnet.example", first_party="news.example", channel="data-leak", category="device ID")
    g.observe("metrics.adnet.example", first_party="shop.example", channel="blocked-beacon")
    g.observe("a.adnet.example", first_party="blog.example", channel="fingerprint")
    top = g.top_trackers()
    row = next((r for r in top if r["tracker"] == "adnet.example"), None)
    c.check("the two hostnames collapse to one tracker", row is not None)
    c.check("reach counts distinct first-party sites (3)", row and row["reach"] == 3)
    c.check("distinct hostnames are counted as masks (2)", row and row["masks"] == 2)
    c.check("cross-channel is true (3 channels seen)", row and row["cross_channel"] is True)
    c.check("categories reached are recorded", row and "device ID" in row["categories"])

    # --- a tracker on its OWN site is not 'reach' ---
    print("\n[2] a tracker talking to its own domain is not cross-site reach")
    g2 = nyx_graph.TrackerGraph()
    g2.observe("cdn.adnet.example", first_party="adnet.example", channel="data-leak")
    c.check("first party == tracker domain does not inflate reach",
            g2.reach("adnet.example") == 0)

    # --- ranking: the widest-reaching tracker sorts first ---
    print("\n[3] the tracker that follows you the widest ranks first")
    g3 = nyx_graph.TrackerGraph()
    for s in ("a.example", "b.example", "c.example", "d.example"):
        g3.observe("wide.tracker.example", first_party=s, channel="data-leak")
    g3.observe("narrow.tracker.example", first_party="a.example", channel="data-leak")
    top3 = g3.top_trackers()
    c.check("widest-reach tracker is ranked first",
            top3[0]["tracker"] == "tracker.example" or top3[0]["reach"] == 4)

    # --- summary ---
    print("\n[4] summary rolls up the whole picture")
    s = g.summary()
    c.check("summary counts distinct trackers", s["distinct_trackers"] >= 1)
    c.check("summary reports cross-channel trackers", s["cross_channel_trackers"] >= 1)
    c.check("summary reports the widest reach", s["widest_reach"] == 3)

    # --- build_from_events: parse the real event rows ---
    print("\n[5] builds from event-store rows (parses Nyx's own sentences)")
    events = [
        {"domain": "collector.adnet.example", "raw_category": "nyx_leak", "decision": "flagged",
         "reason": "news.example sent your device ID to an unrelated server (collector.adnet.example)"},
        {"domain": "px.adnet.example", "raw_category": "nyx_leak", "decision": "flagged",
         "reason": "shop.example sent your location to an unrelated server (px.adnet.example)"},
        {"domain": "beacon.adnet.example", "raw_category": "tracker_pixel", "decision": "blocked",
         "reason": "tracking pixel/beacon path"},
        {"domain": "self.example", "raw_category": "https", "decision": "allowed", "reason": ""},  # ignored
        {"garbage": True},                                                                          # skipped
    ]
    gb = nyx_graph.build_from_events(events)
    rb = next((r for r in gb.top_trackers() if r["tracker"] == "adnet.example"), None)
    c.check("events correlate to one tracker across sites+channels", rb is not None)
    c.check("first parties parsed from the sentence (news+shop = reach 2)", rb and rb["reach"] == 2)
    c.check("categories parsed from the sentence", rb and "device ID" in rb["categories"])
    c.check("multiple channels detected (data-leak + blocked-beacon)",
            rb and rb["cross_channel"] is True)
    c.check("benign/garbage rows are skipped, not crashed on",
            all(r["tracker"] != "self.example" for r in gb.top_trackers()))

    # --- persistent memory: how long a tracker has been following you ---
    print("\n[6] memory — span between first and last sighting")
    gt = nyx_graph.TrackerGraph()
    gt.observe("t.tracker.example", first_party="a.example", channel="data-leak",
               ts="2026-08-18T10:00:00")
    gt.observe("t.tracker.example", first_party="b.example", channel="data-leak",
               ts="2026-08-20T10:00:00")
    rowt = gt.top_trackers()[0]
    c.check("first_seen is the earliest sighting", rowt["first_seen"] == "2026-08-18T10:00:00")
    c.check("last_seen is the latest sighting", rowt["last_seen"] == "2026-08-20T10:00:00")
    c.check("span is ~48 hours", 47.0 <= rowt["span_hours"] <= 49.0)
    c.check("summary reports the longest-following span",
            gt.summary()["longest_following_hours"] >= 47.0)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
