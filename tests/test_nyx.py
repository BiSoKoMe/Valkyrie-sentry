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
    c = Checks("nyx", expect_min=33)

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

    card = nyx.inspect_outbound("POST", THIRD, HDR, b"cc=4111111111111111")
    c.check("payment card (Luhn-valid) caught", nyx.CAT_FINANCIAL in _cats(card))

    cook = nyx.inspect_outbound("GET", THIRD, {"Referer": FP, "Cookie": "id=a1b2c3d4e5f6g7h8i9j0"})
    c.check("persistent third-party tracking cookie caught", nyx.CAT_COOKIE in _cats(cook))

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

    # A random 16-digit id is not a card — Luhn is the precision boundary.
    non_luhn = nyx.inspect_outbound("POST", THIRD, HDR, b"session=1234567890123456")
    c.check("a non-Luhn 16-digit id is NOT flagged as a card",
            nyx.CAT_FINANCIAL not in _cats(non_luhn))

    # A short functional cookie is not a tracking id.
    func_cook = nyx.inspect_outbound("GET", THIRD, {"Referer": FP, "Cookie": "lang=en; theme=dark; s=1"})
    c.check("a short functional cookie is NOT flagged as tracking",
            nyx.CAT_COOKIE not in _cats(func_cook))

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

    # ── ACT MODE: feed fake data, keep the request working, never touch benign ─
    print("\n[5] ACT mode: rewrites third-party leaks into consistent persona fakes")
    from valkyrie.persona import current_persona
    persona = current_persona()

    u, bdy, faked = nyx.fake_outbound(
        "POST", THIRD, HDR, b"adid=550e8400-e29b-41d4-a716-446655440000&x=1", persona)
    c.check("identifier is rewritten (real id gone, persona id in)",
            b"550e8400-e29b-41d4-a716-446655440000" not in bdy
            and persona.advertising_id.encode() in bdy)
    c.check("request still well-formed after faking (x=1 preserved)", b"x=1" in bdy)

    u, bdy, faked = nyx.fake_outbound(
        "POST", THIRD, HDR, b"latitude=40.71&longitude=-74.00", persona)
    c.check("location rewritten to persona coordinates",
            str(persona.lat).encode() in bdy and b"40.71" not in bdy)

    u, bdy, faked = nyx.fake_outbound("POST", THIRD, HDR, b"e=alice%40example.com", persona)
    c.check("contact email rewritten to a consistent persona fake",
            b"alice" not in bdy and b"gmail.com" in bdy)

    u, bdy, faked = nyx.fake_outbound("POST", THIRD, HDR, b"cc=4242424242424242", persona)
    c.check("payment card rewritten to a fake (real card gone)",
            b"4242424242424242" not in bdy and b"4111111111111111" in bdy)

    # Consistency: the SAME persona value across two different requests (the tell
    # a sloppy spoof would fail — two requests must not disagree about the user).
    _, b1, _ = nyx.fake_outbound("POST", THIRD, HDR, b"adid=550e8400-e29b-41d4-a716-446655440000", persona)
    _, b2, _ = nyx.fake_outbound("POST", "https://other.tracker.example/x", HDR,
                                 b"deviceid=550e8400-e29b-41d4-a716-446655440000", persona)
    c.check("the lie is CONSISTENT across requests (same persona id both times)",
            persona.advertising_id.encode() in b1 and persona.advertising_id.encode() in b2)

    # FP guards for the act path: your own data and benign traffic are untouched.
    _, bfp, ffp = nyx.fake_outbound("POST", "https://news.example/login", HDR,
                                    b"e=alice%40example.com", persona)
    c.check("act: first-party data is NOT faked", ffp == [] and bfp == b"e=alice%40example.com")
    _, bbn, fbn = nyx.fake_outbound("POST", THIRD, HDR, b"page=3&sort=asc", persona)
    c.check("act: benign request is NOT touched", fbn == [] and bbn == b"page=3&sort=asc")

    # Wired through the addon: ACT rewrites the live flow; OBSERVE leaves it alone.
    print("\n[6] wired: NYX_ACT rewrites the flow; observe mode leaves it untouched")
    import valkyrie.config as _cfg
    from valkyrie.tls_addon import ValkyrieAddon as _Addon

    class _S:
        def __init__(self): self.events = []
        def log(self, e): self.events.append(e)

    class _R:
        method = "POST"
        def __init__(self):
            self.url = THIRD
            self.headers = {"Referer": FP, "Content-Type": "application/x-www-form-urlencoded"}
            self.raw_content = b"adid=550e8400-e29b-41d4-a716-446655440000&x=1"
        def set_content(self, b): self.raw_content = b

    class _F:
        def __init__(self): self.request = _R(); self.response = None

    _saved = _cfg.NYX_ACT
    try:
        addon2 = _Addon.__new__(_Addon)
        addon2.store = _S()
        # ACT on
        _cfg.NYX_ACT = True
        f = _F()
        addon2._nyx_observe(f, "collector.tracker.example", THIRD, "test")
        c.check("ACT: flow body was rewritten (real id removed)",
                b"550e8400-e29b-41d4-a716-446655440000" not in f.request.raw_content)
        c.check("ACT: a 'deceived' nyx_fake event was logged",
                any(getattr(e, "raw_category", "") == "nyx_fake"
                    and e.decision == "deceived" for e in addon2.store.events))
        # ACT off (observe)
        _cfg.NYX_ACT = False
        addon2.store = _S()
        f2 = _F()
        addon2._nyx_observe(f2, "collector.tracker.example", THIRD, "test")
        c.check("OBSERVE: flow body is left UNTOUCHED",
                f2.request.raw_content == b"adid=550e8400-e29b-41d4-a716-446655440000&x=1")
        c.check("OBSERVE: a 'flagged' nyx_leak event was logged",
                any(getattr(e, "raw_category", "") == "nyx_leak" for e in addon2.store.events))
    finally:
        _cfg.NYX_ACT = _saved

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
