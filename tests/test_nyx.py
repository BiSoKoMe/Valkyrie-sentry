"""Tests for nyx.py - the data-guard brain (SEE & REPORT, observe-only).

Nyx has two jobs in this slice and both are tested here as invariants:

  IT MUST SEE  - personal data (device ID, location, contact, fingerprint
      bundle) crossing to a THIRD party is reported, by data-shape, with no
      domain list involved.
  IT MUST NOT LIE ABOUT SEEING - the two failure modes that would make Nyx
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
    c = Checks("nyx", expect_min=45)

    # --- IT MUST SEE: each category, crossing to a third party ---
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

    hdr_id = nyx.inspect_outbound(
        "GET", THIRD, {"Referer": FP, "X-Device-Id": "550e8400-e29b-41d4-a716-446655440000"})
    c.check("device ID in a request header (X-Device-Id) caught",
            nyx.CAT_IDENTIFIER in _cats(hdr_id))

    # Same signals also readable from a JSON body and from the URL query.
    js = nyx.inspect_outbound(
        "POST", THIRD, {"Referer": FP, "Content-Type": "application/json"},
        b'{"device":{"uuid":"550e8400-e29b-41d4-a716-446655440000"}}')
    c.check("reads JSON bodies (nested device id)", nyx.CAT_IDENTIFIER in _cats(js))

    q = nyx.inspect_outbound(
        "GET", THIRD + "?idfa=550e8400-e29b-41d4-a716-446655440000", {"Referer": FP})
    c.check("reads the URL query, not only the body", nyx.CAT_IDENTIFIER in _cats(q))

    # --- IT MUST NOT LIE: false-positive guards ---
    print("\n[2] does NOT flag your own data or benign traffic (FP guards)")
    # Same request, but going to the FIRST party (the site you're on) -> yours.
    first_party_post = nyx.inspect_outbound(
        "POST", "https://news.example/login", HDR, b"user=alice%40example.com")
    c.check("first-party data (your own login) is NOT flagged", first_party_post == [])

    # A cross-site request carrying nothing personal -> silence.
    benign = nyx.inspect_outbound(
        "POST", THIRD, HDR, b"page=3&sort=asc&q=shoes")
    c.check("benign third-party request is NOT flagged", benign == [])

    # No Referer/Origin -> no first party to compare -> stay silent, don't guess.
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

    # A random 16-digit id is not a card - Luhn is the precision boundary.
    non_luhn = nyx.inspect_outbound("POST", THIRD, HDR, b"session=1234567890123456")
    c.check("a non-Luhn 16-digit id is NOT flagged as a card",
            nyx.CAT_FINANCIAL not in _cats(non_luhn))

    # A short functional cookie is not a tracking id.
    func_cook = nyx.inspect_outbound("GET", THIRD, {"Referer": FP, "Cookie": "lang=en; theme=dark; s=1"})
    c.check("a short functional cookie is NOT flagged as tracking",
            nyx.CAT_COOKIE not in _cats(func_cook))

    # A per-request trace header (name not id-ish) is not a device ID.
    trace_hdr = nyx.inspect_outbound(
        "GET", THIRD, {"Referer": FP, "X-Request-Id": "550e8400-e29b-41d4-a716-446655440000"})
    c.check("a per-request trace header (X-Request-Id) is NOT flagged",
            nyx.CAT_IDENTIFIER not in _cats(trace_hdr))

    # --- The report is human and does not leak the raw value ---
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

    # --- OBSERVE-ONLY WIRING: the addon logs, and NEVER touches the flow ---
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

    # --- ACT MODE: feed fake data, keep the request working, never touch benign -
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

    u, bdy, faked = nyx.fake_outbound(
        "POST", THIRD, HDR,
        b"screen=2560x1440&timezone=America/New_York&lang=en-US&cores=16", persona)
    c.check("fingerprint bundle rewritten to consistent persona device values",
            b"2560x1440" not in bdy
            and f"{persona.screen_width}x{persona.screen_height}".encode() in bdy)

    # Consistency: the SAME persona value across two different requests (the tell
    # a sloppy spoof would fail - two requests must not disagree about the user).
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

    # --- self-test: the live demo runs the whole pipeline end to end ---
    print("\n[7] self-test runs the whole guard on synthetic leaks")
    st = nyx.self_test()
    c.check("self-test catches every synthetic leak",
            st["caught"] == st["total"] and st["total"] >= 5)
    c.check("self-test fakes the actionable categories", st["faked"] >= 4)
    c.check("self-test shows the card actually changing (before != after)",
            any(r["case"] == "payment card" and r["before"] != r["after"]
                for r in st["cases"]))

    # --- ROBUSTNESS: a component in front of ALL traffic must never crash ---
    print("\n[8] never crashes on malformed / hostile input")
    _edge = [
        ("POST", THIRD, HDR, None),
        ("POST", THIRD, None, b"adid=x"),
        ("POST", THIRD, HDR, bytes(range(256))),
        ("POST", "not a url", HDR, b"x"),
        ("POST", THIRD, {"Referer": FP, "Content-Type": "application/json"}, b"{bad json"),
        ("POST", THIRD, [("Referer", FP)], b"x"),   # non-dict headers
        ("", "", "", ""),
        ("POST", THIRD, HDR, "ключ=значение&emoji=🎭".encode()),
    ]
    crashes = 0
    for args in _edge:
        try:
            nyx.inspect_outbound(*args)
            nyx.fake_outbound(*args)
        except Exception:
            crashes += 1
    c.check("inspect_outbound + fake_outbound never crash on edge input", crashes == 0)

    # --- PERFORMANCE: a huge body must be BOUNDED, never a hang ---
    # Nyx is on the request hot path; without a scan cap + length-bounded
    # regexes a big upload took 13 seconds (O(n^2) backtracking) - a stall on
    # the user's own browsing. This guards the fix stays in.
    print("\n[9] a huge body is bounded, not a hang")
    import time as _time
    huge = b"x" * 5_000_000
    _t0 = _time.perf_counter()
    nyx.inspect_outbound("POST", THIRD, HDR, huge)
    nyx.fake_outbound("POST", THIRD, HDR, huge)
    _elapsed = _time.perf_counter() - _t0
    c.check(f"5MB body handled in well under 200ms (got {_elapsed*1000:.0f}ms)",
            _elapsed < 0.2)
    lead = nyx.inspect_outbound(
        "POST", THIRD, HDR,
        b"adid=550e8400-e29b-41d4-a716-446655440000&" + b"p=1&" * 50000)
    c.check("a leak in the first 16KB is still caught under the cap",
            nyx.CAT_IDENTIFIER in _cats(lead))

    # --- END-TO-END: ACT through the REAL _handle_request pipeline ---
    # Unit tests prove the pieces; this proves the whole request path in ACT
    # mode - the decision steps run, Nyx rewrites the body IN PLACE, the request
    # is NOT blocked, and it proceeds. Catches wiring bugs between the pipeline
    # and _nyx_observe that isolated tests miss.
    print("\n[10] end-to-end: ACT through the real request pipeline")
    import valkyrie.config as _cfg2
    from valkyrie.tls_addon import ValkyrieAddon as _A

    class _S2:
        def __init__(self): self.events = []
        def log(self, e): self.events.append(e)

    class _R2:
        def __init__(self):
            self.method = "POST"
            self.pretty_host = "collector.tracker.example"
            self.path = "/api/submit"
            self.url = "https://collector.tracker.example/api/submit"
            self.pretty_url = self.url
            self.headers = {"Referer": FP, "Content-Type": "application/x-www-form-urlencoded"}
            self.raw_content = b"adid=550e8400-e29b-41d4-a716-446655440000&n=1"
        def set_content(self, b): self.raw_content = b

    class _C2:
        peername = ("10.0.0.9", 40000)

    class _F2:
        def __init__(self):
            self.request = _R2(); self.response = None; self.client_conn = _C2()

    _sv = _cfg2.NYX_ACT
    try:
        _cfg2.NYX_ACT = True
        a = _A(_S2(), blocklist=None, behavioral=None, rules=None, threat_intel=None)
        f = _F2()
        a._handle_request(f)
        c.check("e2e ACT: body rewritten in the real pipeline (real id gone)",
                b"550e8400-e29b-41d4-a716-446655440000" not in f.request.raw_content)
        c.check("e2e ACT: request was NOT blocked (response stays None)",
                f.response is None)
        c.check("e2e ACT: a nyx_fake deception event was logged",
                any(getattr(e, "raw_category", "") == "nyx_fake" for e in a.store.events))
    finally:
        _cfg2.NYX_ACT = _sv

    # --- Normalized privacy telemetry wiring (ADR 0058): a Nyx observation
    # reaches the same EDR ingest seam as every other sensor, via the process
    # resolved for the flow's local port. It carries metadata only and stays
    # silent when unresolved or no engine reference was given. ---
    print("\n[7] wired as normalized privacy telemetry (ADR 0058)")
    import valkyrie.network_telemetry as _NT

    class _FakeEdr:
        def __init__(self):
            self.events = []

        def ingest_telemetry(self, event):
            self.events.append(event.to_dict())

    class _Req3:
        method = "POST"
        pretty_host = "collector.tracker.example"
        path = "/api/submit"
        pretty_url = submit_url
        headers = {"Referer": FP, "Content-Type": "application/x-www-form-urlencoded"}
        raw_content = b"adid=550e8400-e29b-41d4-a716-446655440000&n=1"

    class _Conn3:
        peername = ("127.0.0.1", 55000)

    class _Flow3:
        def __init__(self):
            self.request = _Req3()
            self.response = None
            self.client_conn = _Conn3()

    real_lookup = _NT.pid_for_local_port
    _NT.pid_for_local_port = lambda port: (4242, "chrome.exe", r"C:\chrome.exe") \
        if port == 55000 else None
    try:
        fake_edr = _FakeEdr()
        addon2 = ValkyrieAddon(_FakeStore(), blocklist=None, behavioral=None,
                               rules=None, threat_intel=None, edr=fake_edr)
        addon2._handle_request(_Flow3())
        c.check("the leak is emitted for the resolved process",
                any(event["actor_pid"] == 4242
                    and event["fields"].get("artifact_kind") == "nyx_leak"
                    for event in fake_edr.events))
        c.check("the resolved process name travels with telemetry",
                any(event["actor_name"] == "chrome.exe" for event in fake_edr.events))
        c.check("telemetry excludes the sentence and masked sample",
                all("your device ID" not in repr(event)
                    and "550e8400-e29b-41d4-a716-446655440000" not in repr(event)
                    for event in fake_edr.events))

        # No edr reference at all: must attribute nothing, and must not raise
        # or otherwise change the observe/act pipeline above it.
        addon3 = ValkyrieAddon(_FakeStore(), blocklist=None, behavioral=None,
                               rules=None, threat_intel=None)   # edr=None default
        addon3._handle_request(_Flow3())
        c.check("addon works unchanged with no edr reference (default None)",
                any(getattr(e, "raw_category", "") == "nyx_leak"
                    for e in addon3.store.events))

        # Unresolvable process (e.g. the port lookup raced or found nothing):
        # dropped, not guessed - same rule causality.attribute() itself keeps.
        _NT.pid_for_local_port = lambda port: None
        fake_edr2 = _FakeEdr()
        addon4 = ValkyrieAddon(_FakeStore(), blocklist=None, behavioral=None,
                               rules=None, threat_intel=None, edr=fake_edr2)
        addon4._handle_request(_Flow3())
        c.check("an unresolvable process attributes nothing (dropped, not guessed)",
                fake_edr2.events == [])
    finally:
        _NT.pid_for_local_port = real_lookup

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
