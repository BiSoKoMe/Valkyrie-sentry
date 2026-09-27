#!/usr/bin/env python3
"""Nyx's disclosure gate - "is this request a disclosure to a third party at all?"

Audit of 2026-09-24, reproduced against the real inspect_outbound /
fake_outbound pipeline before anything was changed. With NYX_ACT on (one click
in the Electron Settings page since the settings API landed), Nyx rewrote:

  * the client_id of an MSAL-style token exchange a single-page app sends
    straight from the browser                       -> "Sign in with Microsoft" fails
  * the client_id of an Auth0-style JSON token exchange -> Auth0 login fails
  * the authorization code in an OAuth callback navigation -> Cognito login fails
  * the token in a password-reset link clicked in webmail -> the link is dead
  * the client_id and login_hint of an OIDC authorize redirect
  * a UUID-named image on a CDN (the path, not a parameter) -> broken image,
    reported to the user as "notion.so sent your device ID"
  * a row id in an app's own signed-in backend call -> the write hits nothing

...and in the other direction, a tracker on a page whose Referrer-Policy
withholds the page's address was invisible (the scorecard's named gap).

Separately, the third-party test itself used "last two labels" as the site, so
bbc.co.uk and tracker.co.uk were the SAME first party (a blind spot across every
multi-label public suffix) and every UK site shared one site-scoped persona.

Everything here is pure: no proxy, no network, no settings file.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402

from valkyrie import nyx  # noqa: E402

GUID = "0a1b2c3d-4e5f-4061-8a7b-9c0d1e2f3a4b"
EMAIL = "alice@contoso.example"
FETCH_CORS = {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"}
FETCH_NAV = {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate",
             "Sec-Fetch-Dest": "document", "Sec-Fetch-User": "?1"}
FORM = {"Content-Type": "application/x-www-form-urlencoded"}


def _act(method, url, headers, body=b""):
    """(observed categories, faked categories, request changed?) - the same
    three calls tls_addon._nyx_observe makes."""
    obs = nyx.inspect_outbound(method, url, headers, body)
    new_url, new_body, faked = nyx.fake_outbound(method, url, headers, body)
    new_headers, hfaked = nyx.fake_outbound_headers(method, url, headers, body)
    changed = new_url != url or new_body != body or bool(new_headers)
    return sorted({o.category for o in obs}), sorted(set(faked + hfaked)), changed


def main() -> int:
    c = Checks("Nyx disclosure gate (navigation / identity protocol / signed-in API / "
               "Fetch Metadata / Public Suffix List)", expect_min=30)
    # The act path derives fakes from the default persona store; point it at a
    # throwaway seed so this test never reads or creates a real one.
    import tempfile
    from valkyrie import persona as persona_mod
    persona_mod._DEFAULT = persona_mod.PersonaStore(Path(tempfile.mkdtemp()) / "seed.json")

    # --- 1. Things that must never be touched (each was rewritten before) ---
    must_not_touch = {
        "MSAL-style token exchange (form body, client_id GUID)": (
            "POST", "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            {"Origin": "https://app.contoso.com", **FORM, **FETCH_CORS},
            f"client_id={GUID}&grant_type=authorization_code&code=0.AX&redirect_uri=x".encode()),
        "Auth0-style token exchange (JSON body, 32-char client_id)": (
            "POST", "https://acme.us.auth0.com/oauth/token",
            {"Origin": "https://app.acme.io", "Content-Type": "application/json", **FETCH_CORS},
            json.dumps({"client_id": "Xk9pQ2rT7vW4yZ1aB3cD5eF8gH0jK6mN",
                        "grant_type": "authorization_code", "code": "q1"}).encode()),
        "device-code grant (URN grant_type)": (
            "POST", "https://login.idp.example/token",
            {"Origin": "https://tv.app.example", **FORM, **FETCH_CORS},
            f"client_id={GUID}&grant_type=urn:ietf:params:oauth:grant-type:device_code"
            f"&device_code=abc".encode()),
        "OAuth callback navigation (code is a UUID, Cognito-style)": (
            "GET", f"https://app.acme.io/callback?code={GUID}&state=s1",
            {"Referer": "https://acme.auth.us-east-1.amazoncognito.com/", **FETCH_NAV}, b""),
        "OIDC authorize redirect (client_id GUID + login_hint email)": (
            "GET", f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id={GUID}"
                   f"&response_type=code&scope=openid&login_hint={EMAIL}&state=s1",
            {"Referer": "https://app.contoso.com/", **FETCH_NAV}, b""),
        "SAML POST binding": (
            "POST", "https://sso.idp.example/saml2",
            {"Origin": "https://app.example.com", **FORM, **FETCH_CORS},
            f"SAMLRequest=PHNhbWw%2B&RelayState={GUID}".encode()),
        "password-reset link clicked in webmail (top-level navigation)": (
            "GET", f"https://app.example.com/reset?token={GUID}&uid={GUID}",
            {"Referer": "https://mail.google.com/", **FETCH_NAV}, b""),
        "app's own signed-in backend on another domain (Bearer)": (
            "PATCH", f"https://abcd.supabase.co/rest/v1/todos?id=eq.{GUID}",
            {"Origin": "https://myapp.com", "Content-Type": "application/json", **FETCH_CORS,
             "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig"},
            json.dumps({"owner_email": EMAIL, "device_id": GUID}).encode()),
        "UUID-named image on a CDN (UUID only in the PATH)": (
            "GET", f"https://bucket.s3.amazonaws.com/uploads/{GUID}.jpg",
            {"Referer": "https://www.notion.so/", "Sec-Fetch-Site": "cross-site",
             "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"}, b""),
    }
    for label, (m, url, h, body) in must_not_touch.items():
        obs, faked, changed = _act(m, url, h, body)
        c.check(f"untouched + unreported: {label} (observed={obs}, faked={faked})",
                not obs and not faked and not changed)

    # --- 2. An unkeyed UUID in the payload is still REPORTED, never REWRITTEN.
    obs, faked, changed = _act(
        "POST", "https://api.vendor-cloud.io/v2/query",
        {"Origin": "https://dashboard.acme.com", "Content-Type": "application/json", **FETCH_CORS},
        json.dumps({"project_id": GUID, "q": "select 1"}).encode())
    c.check(f"unkeyed payload UUID: observed as identifier (got {obs})", obs == ["identifier"])
    c.check(f"unkeyed payload UUID: NOT rewritten (faked={faked}, changed={changed})",
            not faked and not changed)

    # --- 3. Things that must STILL be caught (no over-correction) ---
    obs, faked, changed = _act(
        "GET", f"https://tracker.example/p.gif?device_id={GUID}",
        {"Referer": "https://news.example.com/", "Sec-Fetch-Site": "cross-site",
         "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"})
    c.check(f"ordinary tracker pixel with Referer still observed+faked ({obs}/{faked})",
            obs == ["identifier"] and faked == ["identifier"] and changed)

    obs, faked, _ = _act(
        "GET", f"https://tracker.example/frame?adid={GUID}",
        {"Referer": "https://news.example.com/", "Sec-Fetch-Site": "cross-site",
         "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "iframe"})
    c.check(f"a tracker IFRAME navigation is still judged (Dest: iframe != document) ({obs})",
            obs == ["identifier"] and faked == ["identifier"])

    obs, faked, _ = _act(
        "POST", "https://dataplane.rudder.example/v1/track",
        {"Origin": "https://shop.example.com", "Content-Type": "application/json", **FETCH_CORS,
         "Authorization": "Basic d3JpdGVLZXk6"},
        json.dumps({"anonymousId": "x", "context": {"device": {"id": GUID}},
                    "device_id": GUID}).encode())
    c.check(f"Basic auth (a tracker SDK's static write key) is NOT an exemption ({obs})",
            "identifier" in obs and "identifier" in faked)

    # "code" + "state" alone are ordinary words: a promo code and a US state
    # copied out of a checkout form to a tracker must NOT pass as an OAuth
    # authorization response - neither in a body nor in a mixed query.
    obs, faked, _ = _act("POST", "https://collector.tracker.example/c",
                         {"Referer": "https://shop.example.com/", **FORM, **FETCH_CORS},
                         f"code=SAVE10&state=CA&email={EMAIL}&device_id={GUID}".encode())
    c.check(f"checkout form (code+state+email) in a BODY to a tracker is still caught ({obs})",
            obs == ["contact", "identifier"] and faked == ["contact", "identifier"])
    obs, _, _ = _act("GET", f"https://collector.tracker.example/p?code=SAVE10&state=CA&device_id={GUID}",
                     {"Referer": "https://shop.example.com/", "Sec-Fetch-Site": "cross-site",
                      "Sec-Fetch-Dest": "image"})
    c.check(f"a mixed query (code+state+device_id) is not an OAuth response ({obs})",
            obs == ["identifier"])
    obs, faked, _ = _act("GET", f"https://app.acme.io/callback?code={GUID}&state=s1&session_state=x",
                         {"Referer": "https://acme.auth.us-east-1.amazoncognito.com/"})
    c.check("a PURE authorization-response query is exempt even with no Fetch Metadata "
            f"(older client) ({obs}/{faked})", obs == [] and faked == [])

    # --- 4. The named gap: no Referer/Origin, but the browser vouches cross-site
    obs, faked, changed = _act(
        "GET", f"https://tracker.example/p.gif?device_id={GUID}",
        {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"})
    c.check(f"no-Referer pixel + Sec-Fetch-Site: cross-site -> observed+faked ({obs}/{faked})",
            obs == ["identifier"] and faked == ["identifier"] and changed)
    obs, faked, _ = _act(
        "POST", "https://tracker.example/collect",
        {"Origin": "null", "Content-Type": "text/plain", "Sec-Fetch-Site": "cross-site",
         "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "empty"},
        f"device_id={GUID}&email={EMAIL}".encode())
    c.check(f"Origin: null beacon + cross-site -> identifier and contact caught ({obs})",
            obs == ["contact", "identifier"] and faked == ["contact", "identifier"])
    sent = nyx.inspect_outbound("GET", f"https://tracker.example/p?device_id={GUID}",
                                {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Dest": "image"})
    c.check("unattributed observation names no invented site (first_party_origin == '')",
            bool(sent) and sent[0].first_party_origin == "")
    c.check(f"unattributed sentence says the page withheld its address ({sent[0].sentence if sent else ''!r})",
            bool(sent) and sent[0].sentence.startswith(nyx.UNATTRIBUTED_SUBJECT + " sent your"))
    for site in ("same-origin", "same-site", "none"):
        o = nyx.inspect_outbound("GET", f"https://tracker.example/p?device_id={GUID}",
                                 {"Sec-Fetch-Site": site, "Sec-Fetch-Dest": "image"})
        c.check(f"no Referer + Sec-Fetch-Site: {site} -> silent", o == [])
    o = nyx.inspect_outbound("GET", f"https://tracker.example/p?device_id={GUID}", {})
    c.check("no Referer and no Fetch Metadata (native app / old browser) -> silent, as before",
            o == [])

    # Unattributed fakes are per-tracker stable and differ between trackers -
    # never the one machine persona every tracker would share.
    def _fake_id(dest):
        u, _, _ = nyx.fake_outbound("GET", f"https://{dest}/p?device_id={GUID}",
                                    {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Dest": "image"}, b"")
        return u.split("device_id=")[1]
    a1, a2, b1 = _fake_id("t1.alpha.example"), _fake_id("t2.alpha.example"), _fake_id("beta.example")
    c.check("unattributed fake id is stable for one tracker site", a1 == a2 and a1 != GUID)
    c.check("unattributed fake id differs between two unrelated trackers", a1 != b1)

    # --- 5. The tracker graph: unattributed rows count, but never as "reach"
    from valkyrie.nyx_graph import build_from_events
    rows = [{"domain": "px.tracker.example", "raw_category": "nyx_leak", "decision": "flagged",
             "reason": f"{nyx.UNATTRIBUTED_SUBJECT} sent your device ID to an unrelated server "
                       "(px.tracker.example)", "timestamp": "2026-09-24T10:00:00"},
            {"domain": "px.tracker.example", "raw_category": "nyx_leak", "decision": "flagged",
             "reason": "news.example.com sent your device ID to an unrelated server "
                       "(px.tracker.example)", "timestamp": "2026-09-24T11:00:00"}]
    g = build_from_events(rows)
    top = g.top_trackers(1)
    c.check(f"graph counts the unattributed sighting (hits={top[0]['hits'] if top else 0})",
            bool(top) and top[0]["hits"] == 2)
    c.check(f"graph reach counts only the one real site (reach={top[0]['reach'] if top else -1})",
            bool(top) and top[0]["reach"] == 1)
    c.check("graph keeps the category for the unattributed row",
            bool(top) and top[0]["categories"] == ["device ID"])

    # --- 6. Public Suffix List: what "same site" means ---
    try:
        from valkyrie.psl import site_of, status
    except ImportError as exc:
        c.fail("valkyrie.psl importable", repr(exc))
        return c.finish()
    st = status()
    c.check(f"the vendored Public Suffix List actually loaded ({st})",
            st["loaded"] and st["rules"] > 5000 and st["version"])
    for host, want in [("a.b.co.uk", "b.co.uk"), ("alice.github.io", "alice.github.io"),
                       ("bucket.s3.amazonaws.com", "bucket.s3.amazonaws.com"),
                       ("www.example.com", "example.com"), ("a.www.ck", "www.ck"),
                       ("192.168.1.5", "192.168.1.5"), ("github.io", "github.io")]:
        c.check(f"site_of({host!r}) == {want!r} (got {site_of(host)!r})", site_of(host) == want)
    obs = nyx.inspect_outbound("POST", "https://collect.tracker.co.uk/c",
                               {"Referer": "https://www.bbc.co.uk/news", **FORM},
                               f"device_id={GUID}".encode())
    c.check(f"bbc.co.uk -> tracker.co.uk is a THIRD party now (was one 'co.uk' site) ({[o.category for o in obs]})",
            [o.category for o in obs] == ["identifier"])
    c.check("...and the sentence names the real site, not 'co.uk'",
            bool(obs) and obs[0].sentence.startswith("bbc.co.uk sent your"))
    obs = nyx.inspect_outbound("POST", "https://mallory.github.io/c",
                               {"Referer": "https://alice.github.io/", **FORM},
                               f"device_id={GUID}".encode())
    c.check("two different github.io owners are different sites", len(obs) == 1)
    obs = nyx.inspect_outbound("POST", "https://api.shop.co.uk/c",
                               {"Referer": "https://www.shop.co.uk/", **FORM},
                               f"device_id={GUID}".encode())
    c.check("www.shop.co.uk -> api.shop.co.uk is still the SAME site (silent)", obs == [])

    spec = (Path(__file__).resolve().parent.parent / "valkyrie.spec").read_text(encoding="utf-8")
    c.check("valkyrie.spec bundles the Public Suffix List into the installed build",
            "valkyrie/defaults/public_suffix_list.dat" in spec)

    return c.finish()


if __name__ == "__main__":
    sys.exit(main())
