"""Tests for nyx.py — the data-guard brain (SEE & REPORT, observe-only).

Nyx has two jobs in this slice and both are tested here as invariants:

  IT MUST SEE  — personal data (device ID, location, contact, fingerprint
      bundle) crossing to a THIRD party is reported, by data-shape, with no
      domain list involved.
  IT MUST NOT LIE ABOUT SEEING — the two failure modes that would make Nyx
      untrustworthy are false positives (flagging your own first-party data, or
      a benign request) and, above all, TOUCHING the request. Observe-only is
      not a promise in a docstring; the wiring test proves flow.response is left
      untouched after inspection.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks
from valkyrie import nyx

FP = "https://news.example/article"          # the page the user is on
THIRD = "https://collector.tracker.example/collect"   # an unrelated server
HDR = {"Referer": FP, "Content-Type": "application/x-www-form-urlencoded"}


def _cats(obs):
    return {o.category for o in obs}


def main() -> int:
    c = Checks("nyx", expect_min=18)

    # ── IT MUST SEE: each category, crossing to a third party ────────────────
    print("\n[1] sees personal data leaving to a THIRD party")
    ident = nyx.inspect_outbound(
        "POST", THIRD, HDR, b"adid=550e8400-e29b-41d4-a716-446655440000&n=1")
    c.check("advertising/device ID caught", nyx.CAT_IDENTIFIER in _cats(ident))

    bare_uuid = nyx.inspect_outbound(
        "POST", THIRD, HDR, b"payload=550e8400-e29b-41d4-a716-446655440000")
    c.check("a bare UUID in the body is caught", nyx.CAT_IDENTIFIER in _cats(bare_uuid))

    loc = nyx.inspect_outbound(
        "POST", THIRD, HDR, b"latitude=40.7128&longitude=-74.0060&z=1")
    c.check("location (lat+lon) caught", nyx.CAT_LOCATION in _cats(loc))

    contact = nyx.inspect_outbound(
        "POST", THIRD, HDR, b"user=alice%40example.com&ok=1")
    c.check("contact (email) caught", nyx.CAT_CONTACT in _cats(contact))

    fp = nyx.inspect_outbound(
        "POST", THIRD, HDR,
        b"screen=1920x1080&timezone=America/New_York&lang=en-US&cores=8")
    c.check("fingerprint bundle (>=3 surfaces) caught", nyx.CAT_FINGERPRINT in _cats(fp))

    # Same signals also readable from a JSON body and from the URL query.
    js = nyx.inspect_outbound(
        "POST", THIRD, {"Referer": FP, "Content-Type": "application/json"},
        b'{"device":{"uuid":"550e8400-e29b-41d4-a716-446655440000"}}')
    c.check("reads JSON bodies (nested device id)", nyx.CAT_IDENTIFIER in _cats(js))

    q = nyx.inspect_outbound(
        "GET", THIRD + "?idfa=550e8400-e29b-41d4-a716-446655440000", {"Referer": FP})
    c.check("reads the URL query, not only the body", nyx.CAT_IDENTIFIER in _cats(q))

    # ── IT MUST NOT LIE: false-positive guards ───────────────────────────────
    print("\n[2] does NOT flag your own data or benign traffic (FP guards)")
    # Same request, but going to the FIRST party (the site you're on) → yours.
    first_party_post = nyx.inspect_outbound(
        "POST", "https://news.example/login", HDR, b"user=alice%40example.com")
    c.check("first-party data (your own login) is NOT flagged", first_party_post == [])

    # A cross-site request carrying nothing personal → silence.
    benign = nyx.inspect_outbound(
        "POST", THIRD, HDR, b"page=3&sort=asc&q=shoes")
    c.check("benign third-party request is NOT flagged", benign == [])

    # No Referer/Origin → no first party to compare → stay silent, don't guess.
    no_ref = nyx.inspect_outbound(
        "POST", THIRD, {"Content-Type": "application/x-www-form-urlencoded"},
        b"adid=550e8400-e29b-41d4-a716-446655440000")
    c.check("no first-party context → silent (no guessing)", no_ref == [])

    # A short code under an id-ish key is not a durable identifier.
    short = nyx.inspect_outbound("POST", THIRD, HDR, b"cid=42&x=1")
    c.check("a short code is not mistaken for a device ID", nyx.CAT_IDENTIFIER not in _cats(short))

    # One fingerprint surface alone is not a bundle.
    one_fp = nyx.inspect_outbound("POST", THIRD, HDR, b"lang=en-US")
    c.check("a single surface is not a fingerprint bundle", nyx.CAT_FINGERPRINT not in _cats(one_fp))

    # ── The report is human and does not leak the raw value ──────────────────
    print("\n[3] the observation is human-readable and never stores the raw value")
    ob = ident[0]
    c.check("sentence names the first party and the destination",
            "news.example" in ob.sentence and "collector.tracker.example" in ob.sentence)
    c.check("sentence is plain language, not a code",
            "your device ID" in ob.sentence and "unrelated server" in ob.sentence)
    c.check("the raw identifier is NOT present (masked)",
            "550e8400-e29b-41d4-a716-446655440000" not in ob.sentence
            and "550e8400-e29b-41d4-a716-446655440000" not in ob.masked_sample)
    c.check("email is masked, not echoed whole",
            "alice@example.com" not in contact[0].masked_sample)

    # ── OBSERVE-ONLY WIRING: the addon logs, and NEVER touches the flow ──────
    print("\n[4] wired into the addon: it records, and leaves the request untouched")
    from valkyrie.tls_addon import ValkyrieAddon

    class _FakeStore:
        def __init__(self): self.events = []
        def log(self, event): self.events.append(event)

    # A path that is NOT itself a tracker/fingerprint path, so the request
    # reaches Nyx's observe step (already-blocked traffic has nothing to see).
    submit_url = "https://collector.tracker.example/api/submit"

    class _Req:
        method = "POST"
        pretty_host = "collector.tracker.example"
        path = "/api/submit"
        pretty_url = submit_url
        headers = {"Referer": FP, "Content-Type": "application/x-www-form-urlencoded"}
        raw_content = b"adid=550e8400-e29b-41d4-a716-446655440000&n=1"

    class _Conn:
        peername = ("10.0.0.5", 51000)

    class _Flow:
        def __init__(self):
            self.request = _Req()
            self.response = None            # must remain None (observe-only)
            self.client_conn = _Conn()

    store = _FakeStore()
    addon = ValkyrieAddon(store, blocklist=None, behavioral=None,
                          rules=None, threat_intel=None)
    flow = _Flow()
    addon._handle_request(flow)

    nyx_events = [e for e in store.events if getattr(e, "raw_category", "") == "nyx_leak"]
    c.check("addon logged a nyx_leak observation", len(nyx_events) >= 1)
    c.check("the logged reason is the human sentence",
            bool(nyx_events) and "your device ID" in nyx_events[0].reason)
    c.check("observe-only: flow.response was NEVER set (nothing blocked/altered)",
            flow.response is None)
    c.check("the request still went through the normal 'allowed' path",
            any(getattr(e, "raw_category", "") == "https" for e in store.events))

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
