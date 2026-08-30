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

24 synthetic scenarios: 7 authorized (first-party), 13 unauthorized
(third-party disclosure), 4 benign (third-party, no personal data). Every
request is fabricated; nothing here is a live browser capture.

## Result

| Metric | Value |
|---|---:|
| Authorized flows left byte-identical | 100% (7/7) |
| Benign flows left byte-identical | 100% (4/4) |
| Unauthorized disclosures deceived (scored subset) | 90.9% (10/11) |
| Tracking cookie ever entered the act path | never (by design) |
| Raw sentinel value retained after a claimed fake | never |
| p99 latency (inspect + fake, per request) | < 0.3 ms |

The one scored-but-undeceived case is `unauth-tracking-cookie`: a
third-party tracking cookie is deliberately excluded from the rewrite path,
because blanking it can break a legitimately logged-in embed. That is an
intentional design choice in `tls_addon.py`, not a miss.

## Named gaps (not folded into the pass rate)

Two scenarios are filed separately rather than averaged into the 90.9%,
because doing so would either hide a real limitation inside a passing
number or unfairly count a case the mechanism cannot act on as a failure:

- **`gap-no-referer-context`** -- a request with no `Referer`/`Origin`
  header gives Nyx no first party to compare against, so it stays silent by
  design (`nyx.first_party_of`). A real device-id disclosure over such a
  connection is invisible to Nyx today.
- **`gap-header-only-identifier`** -- `inspect_outbound`'s header scan
  correctly *sees* a device id sent via a request header (e.g. `X-Device-Id`,
  a real pattern used by some tracker SDKs), but `fake_outbound()` only
  returns a rewritten `(url, body)`. There is no header-rewrite path in Nyx,
  and `tls_addon.py`'s wiring never touches `flow.request.headers` either.
  This is observed and reported to the user, but never deceived.

The second gap is the more actionable one: it is a concrete, scoped
production change (teach `fake_outbound` to return replacement headers, and
wire `tls_addon.py` to apply them) rather than a fundamental limitation.

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
