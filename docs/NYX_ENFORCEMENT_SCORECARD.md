# Nyx Enforcement Scorecard

**Evidence class:** synthetic mechanism evaluation.
**Independent:** no.

## Research question

Across realistic workflow shapes (login, signup, checkout, upload,
messaging, sync, background telemetry, a cross-site embed), does Nyx's
disclosure-authority mechanism (`valkyrie/nyx.py`: `inspect_outbound` +
`fake_outbound`) prevent unauthorized third-party disclosures while never
touching authorized or benign traffic, and without retaining a raw value it
claims to have faked?

Individual leak categories are already unit-tested in `tests/test_nyx.py`
(53 checks). This harness (`redteam/evaluation/nyx_scorecard.py`,
`tests/test_nyx_scorecard.py`) asks the aggregate question instead: does
catching the unauthorized case ever break the authorized one, measured
across one corpus in a single pass.

## Corpus

31 synthetic scenarios: 12 authorized (7 first-party, plus 5 cross-site
flows the user chose: an OIDC token exchange and authorize redirect, an OAuth
callback, a link clicked in webmail, and the app's own signed-in backend), 14
unauthorized (third-party disclosure, one of them the named gap below), and 5
benign (third-party, no personal data). Every request is fabricated; nothing
here is a live browser capture. (24 scenarios before 2026-09-24; see the
disclosure-gate section at the end.)

## Result

| Metric | Value |
|---|---:|
| Authorized flows left byte-identical | 100% (12/12) |
| Benign flows left byte-identical | 100% (5/5) |
| Unauthorized disclosures deceived (scored subset) | 92.3% (12/13) |
| Tracking cookie ever entered the act path | never (by design) |
| Raw sentinel value retained after a claimed fake | never |
| p99 latency (inspect + fake, per request) | < 1 ms |

The one scored-but-undeceived case is `unauth-tracking-cookie`: a
third-party tracking cookie is deliberately excluded from the rewrite path,
because blanking it can break a legitimately logged-in embed. That is an
intentional design choice in `tls_addon.py`, not a miss.

## A gap this scorecard found and closed

Building this harness surfaced a real production gap: `inspect_outbound`'s
header scan correctly *saw* a device id sent via a request header (e.g.
`X-Device-Id`, a real pattern used by some tracker SDKs), but
`fake_outbound()` only ever returned a rewritten `(url, body)` -- there was
no header-rewrite path in Nyx, and `tls_addon.py`'s wiring never touched
`flow.request.headers` either. The identifier was observed and reported to
the user, but never deceived.

That gap is now closed: `nyx.fake_outbound_headers()` is a new, additive
companion to `fake_outbound()` that scans headers the same way
`inspect_outbound` already does and returns persona-consistent replacements;
`tls_addon.py`'s `_nyx_observe` calls it alongside the existing url/body
rewrite and applies both. `unauth-header-device-id` is scored as an ordinary
unauthorized scenario now, not a named gap.

## Named gaps (not folded into the pass rate)

One scenario is still filed separately rather than averaged into the 92.3%,
because doing so would hide a real, deliberate limitation inside a passing
number:

- **`gap-no-referer-context`** -- a request with no `Referer`/`Origin`
  header AND no Fetch Metadata (an older browser or a native app) gives Nyx
  no evidence the request crossed sites at all, so it stays silent by design.
  Narrowed on 2026-09-24: the same disclosure from a current browser, which
  sends `Sec-Fetch-Site: cross-site`, is now caught and scored as
  `unauth-no-referer-fetch-metadata` (see below).

## Limitations

- Scenarios are synthetic and committed with the harness, not captured from
  a live browser or a real tracker.
- Nyx reasons over cleartext request shape; an exfil path that encrypts or
  obfuscates its body is invisible to this mechanism and this harness.
- This does not measure live network egress -- it does not prove the faked
  bytes are what actually left a real machine's NIC. That is the next
  falsifiable step below.

## Next falsifiable hypothesis

On a real, controlled browser environment (login/signup/checkout/upload/
messaging/sync flows against a local test server, with a packet capture on
the egress interface), Nyx's deception mechanism should prevent unauthorized
raw-value disclosure from ever reaching the wire, while every authorized and
benign flow completes unchanged, within the same sub-millisecond budget
measured here. That is the "big missing piece is enforcement" gap the
research plan names -- this scorecard is the mechanism-level prerequisite
for it, not a replacement for it.

## Follow-up 2026-09-24: the disclosure gate (ADR 0062)

With the settings API, the one-click "active protection" toggle made
`NYX_ACT` an ordinary user's choice. Running realistic cross-site shapes
through the real pipeline showed that act mode rewrote the `client_id` or
authorization `code` of OIDC/OAuth sign-ins (MSAL, Auth0 and Cognito shapes),
the token in a password-reset link clicked in webmail, a row id in an app's own
signed-in backend call, and the path of a UUID-named image. Each of those
breaks the thing the user was doing. The site test itself ("last two labels")
made `bbc.co.uk` and `tracker.co.uk` the same first party.

`nyx._disclosure()` now decides "is this a third-party disclosure at all" for
observe and both act paths. It uses the Public Suffix List for "site",
`Sec-Fetch-Dest: document` for navigations, `Authorization: Bearer` for
signed-in backends, the protocols' own required parameters for OAuth/OIDC/SAML,
and `Sec-Fetch-Site: cross-site` to close the no-Referer gap for current
browsers. Act now rewrites only identifiers the request names as one. Details,
evidence and the honest boundaries (notably, bounce tracking through top-level
redirects is left to the blocker layer) are in
`docs/adr/0062-nyx-disclosure-gate.md`.

The expanded 31-scenario corpus, scored against both versions of `nyx.py`
(the unmodified HEAD was scored from a scratch copy, measured, not inferred):

| Metric | Before the gate | After |
|---|---:|---:|
| Authorized flows left byte-identical | 58.3% (7/12) | 100% (12/12) |
| Benign flows left byte-identical | 80% (4/5) | 100% (5/5) |
| Unauthorized disclosures deceived | 84.6% (11/13) | 92.3% (12/13) |

Before the gate, each of the five new cross-site authorized scenarios was
rewritten, as was the UUID-named image. The Fetch-Metadata version of the old
gap went through untouched.
