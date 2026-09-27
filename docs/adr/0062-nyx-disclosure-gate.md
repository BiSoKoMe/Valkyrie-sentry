# ADR 0062 - Nyx disclosure gate: what counts as a third-party disclosure

Date: 2026-09-24 . Status: accepted . Amends: ADR 0050

## Context

Nyx's whole model rests on one question asked before any leak detector runs:
*is this request a disclosure to a third party at all?* Until now the answer
was three copies of the same two-line test (in `inspect_outbound`,
`_personal_values` and `fake_outbound_headers`): take the Referer or Origin,
reduce it and the destination to "the last two labels", and call the request
third-party if they differ. With `NYX_ACT` default-off and reachable only by
hand-editing a config file, that test's mistakes stayed mostly theoretical.
The settings API and the one-click "active protection" toggle in the Electron
Settings page changed that: act mode is now an ordinary user's choice.

An audit on 2026-09-24 ran realistic request shapes through the real
`inspect_outbound` / `fake_outbound` / `fake_outbound_headers` pipeline before
anything was changed. With act mode on, Nyx rewrote:

| Request | What Nyx rewrote | Effect |
|---|---|---|
| MSAL-style token exchange a single-page app sends from the browser | `client_id` (a GUID) | "Sign in with Microsoft" fails |
| Auth0-style JSON token exchange | 32-char `client_id` | Auth0 login fails |
| OAuth callback navigation (Cognito issues UUID codes) | the authorization `code` | login fails |
| OIDC authorize redirect | `client_id` and `login_hint` | wrong app / wrong account pre-filled |
| Password-reset link clicked in webmail | the link's token | link is dead |
| An app's own signed-in backend on another domain (Supabase, API gateways) | a row id in `?id=eq.<uuid>` | the write silently hits nothing |
| An image whose file name is a UUID (S3 / CDN uploads) | the path | broken image; reported to the user as "notion.so sent your device ID" |

In the other direction, a tracker on a page whose Referrer-Policy withholds
the page's address sent a device id and an email in plain sight and Nyx saw
nothing: the scorecard's one named gap, `gap-no-referer-context`.

And the "last two labels" site test was wrong wherever a public suffix has more
than one label: `bbc.co.uk` and `tracker.co.uk` were the same first party, so a
disclosure between them was invisible, and every UK/Australian/Japanese/...
site shared one site-scoped persona. The same collapse merged every tenant of
shared hosts (`github.io`, `s3.amazonaws.com`, `cloudfront.net`, `vercel.app`),
which the Public Suffix List's private section exists to keep apart.

## Decision

One function, `nyx._disclosure()`, now owns the question for observe and both
act paths, so they cannot drift apart again. It uses facts the browser or the
protocol already states, not new heuristics:

1. **Site = eTLD+1 from the Public Suffix List** (`valkyrie/psl.py`, list
   vendored in `valkyrie/defaults/public_suffix_list.dat`, MPL-2.0, bundled
   by `valkyrie.spec`). Nyx, the tracker graph and the deception listener's
   persona scoping all use it. If the file is missing, lookups fall back to
   the old rule, and `psl.status()` reports `loaded: False` so the degraded
   state is visible.
2. **`Sec-Fetch-Dest: document` is never a disclosure.** A top-level
   navigation is the user going to that site, which becomes the first party.
   Frames are still judged (`Dest: iframe`), so tracker iframes are covered.
3. **`Authorization: Bearer` / `DPoP` is never a disclosure.** The request
   carries the user's own session credential for that server: the app's
   backend, which the user is signed in to. `Basic` does not qualify, because
   some tracker SDKs (RudderStack) send a static write key that way.
4. **Identity-protocol messages are never a disclosure**, recognised by the
   protocol's own required parameters rather than a provider list:
   `grant_type` from the RFC 6749 vocabulary or a registered URN;
   `client_id` + `response_type`; `SAMLRequest` / `SAMLResponse`; and an
   authorization *response* only when the URL query consists entirely of
   response parameters (`code`, `state`, `iss`, `session_state`...). "code"
   and "state" alone are ordinary words, since a promo code and a US state
   copied from a checkout form to a tracker must still be caught, and are.
5. **No Referer/Origin (or `Origin: null`) plus `Sec-Fetch-Site: cross-site`
   is a disclosure.** The browser vouches that the request crossed sites; only
   the page's address was withheld. The observation's `first_party_origin` is
   empty, never invented. The sentence reads "A page that withheld its address
   sent your ...". The tracker graph counts it without adding a fake site to
   "reach". Fakes come from a per-tracker persona, not the one machine persona
   every such tracker would otherwise share.
6. **Act rewrites only identifiers the request itself names as one** (an
   id-shaped key or header). An unkeyed UUID in the payload is still
   *reported*, because observe can afford to be broader than act. It is never
   *rewritten*, since a bare UUID is as often a row or project id as a
   person's. A UUID that appears only in the URL path is not looked at: a path
   addresses a resource.

Fetch Metadata was chosen because a page's script cannot forge it: every
`Sec-` header is a forbidden header name for `fetch()`/XHR. Chromium 80+,
Firefox 90+ and Safari 16.4+ all send it. Requests without it (older clients,
native apps) keep the previous Referer/Origin behaviour exactly.

## Evidence

- `tests/test_nyx_disclosure_gate.py` has 43 checks. It was run against the
  unmodified HEAD in a scratch copy, and every targeted behaviour failed there:
  all nine breakage shapes, the unkeyed-UUID rewrite, the no-Referer gap, and
  the unattributed persona handling. The over-correction guards (an ordinary
  tracker pixel, a tracker iframe, Basic auth, a checkout form carrying
  code+state, a mixed query) pass on both old and new code, as they should.
- `redteam/evaluation/nyx_scorecard.py` gained five cross-site *authorized*
  scenarios, one Fetch-Metadata unauthorized scenario, and one benign UUID-path
  asset. Result: authorized 12/12 untouched, benign 5/5 untouched, unauthorized
  12/13 deceived (the 13th is the tracking cookie, observe-only by design),
  p99 < 1 ms. The unmodified HEAD, scored on the same corpus from a scratch
  copy: 7/12, 4/5, 11/13.
- Unchanged: `tests/test_nyx.py` 70/70, `tests/test_nyx_graph.py` 19/19,
  `tests/nyx_battery.py` 71/74 with 0/22 false positives (the same three
  accepted path-match non-coverage entries as before), `test_lie_consistency`
  112/112, persona/contract pytest files 28/28.

## Honest boundaries

- **Bounce tracking through a top-level redirect** (`click.tracker/?uid=...`
  → destination) is no longer seen by Nyx, because every hop is a document
  navigation. That traffic belongs to the blocker layer (SLD blocking), and
  browsers ship their own bounce-tracking mitigations. It is a deliberate
  trade: rewriting top-level navigations is what broke emailed links and
  sign-ins.
- A tracker that sends `Authorization: Bearer`, or that dresses its beacon as a
  pure OAuth response or token request, is exempt. No known browser tracker
  SDK does either today. This is a precision-over-recall choice, consistent
  with the project's rule that breaking a site is worse than missing a tracker.
- Requests from clients that send neither Referer/Origin nor Fetch Metadata
  (native apps, older browsers) are still invisible:
  `gap-no-referer-context` remains a named gap, narrowed to exactly that case.
- Changing the site function changes the site-scoped persona key for sites
  under multi-label suffixes. Those sites each get their own fake identity
  from now on, instead of sharing one. That is the intended behaviour, and it
  is a one-time change a tracker would see.
- Everything here is still synthetic mechanism evidence. The live check is
  `nyx_live/nyx_live_test.py` on CI, which has not been re-run for this
  change.
