# Causal Authority Without Content Retention: A Deterministic Local Browser Experiment

**Project:** Valkyrie

**Evidence level:** Synthetic mechanism experiment

**Platform target:** Windows endpoint

**Decision method:** Deterministic comparisons, no AI model and no reputation lookup

## Abstract

This paper asks whether a local endpoint can authorize a privacy-sensitive
browser consequence from its immediate cause instead of adding another list of
domains or behavioral signatures. Valkyrie's experimental answer is a
short-lived, one-shot causal grant created by a trusted form gesture. The grant
is scoped to source origin, destination origin, browser tab, frame, action, and
coarse data labels. A consequence is allowed only when every scope dimension
matches. Raw form values remain inside the browser capture compartment and are
not included in the grant, telemetry, evidence record, or graph state.

A fixed synthetic corpus exercised the real browser-context collector and
authority engine with 500 authorized consequences and 100 unauthorized
variants. The unauthorized variants included absent grants, replay, changed
source or destination, changed tab or frame, label escalation, and expiry. The
local development run classified all 600 cases correctly, produced zero false
allows, zero false refusals, and zero retained copies of a raw sentinel. The
in-process submit-observation-to-verdict latency was 0.0404 ms at p50, 0.0708 ms
at p95, and 0.1139 ms at p99 on that run.

These results establish only that the deterministic mechanism works on its
fixed synthetic corpus and is fast inside one Python process. They do not
establish browser-wide mediation, real network blocking, trustworthy Windows
process attribution, production false-positive behavior, or end-to-end
latency.

## 1. Research question

Can a local endpoint make a fast, explainable decision about a browser
consequence by requiring fresh causal authority from the user's action, while
keeping raw personal values outside persistent telemetry?

The experiment tests a narrow hypothesis:

> A fresh one-shot grant scoped to origin, destination, tab, frame, action, and
> data labels can distinguish a fixed authorized and unauthorized corpus with
> no raw-value retention.

This differs from asking whether a request matches a known tracker, malicious
domain, or learned model. The decision is relational. It asks whether the
observed consequence still matches the exact authority created by its cause.

## 2. Architecture

The experimental path has four stages:

1. A trusted pointer or Enter gesture targets a form submission.
2. The extension classifies form controls into a bounded vocabulary such as
   `ordinary`, `email`, `credential`, `payment`, or `file`. Values are read only
   long enough to assign a label and are not transmitted.
3. The local collector issues a two-second, one-shot grant scoped to source and
   destination origins, tab, frame, action, and labels.
4. A matching form-submit observation consumes the grant. Any missing,
   expired, replayed, or changed scope is refused.

The verifier performs exact comparisons under a lock. It makes no cloud call,
database query, reputation lookup, content scan, or AI inference. Failed
verification consumes the referenced grant so a caller cannot probe scope
combinations until one succeeds.

The current implementation records the verdict as metadata-only telemetry. It
does not cancel the browser request. That distinction is central to the claim.

## 3. Method

The corpus and success criteria were fixed before the evidence run:

- 500 authorized matching-grant cases
- 100 unauthorized cases distributed across eight failure modes
- 100% required decision accuracy
- zero permitted false allows
- zero permitted false refusals
- zero permitted retained instances of a raw sentinel
- p99 below 10 ms for the in-process collector decision path

Every case used the production `BrowserContextCollector` sanitizer,
`CausalAuthorityEngine`, and normalized telemetry construction. Inputs included
a unique raw sentinel in URL paths, queries, form-value placeholders, page-text
placeholders, cookies, and an invalid data label. After the corpus completed,
the runner searched its retained collector state, telemetry records, and trial
evidence for that sentinel.

The latency clock starts immediately before the form-submit observation enters
the collector and stops after the verdict and telemetry object are created. It
therefore excludes browser execution, extension delivery, native messaging,
loopback HTTP, Windows scheduling outside the process, network I/O, and
enforcement.

The complete runner is `tools/authority_experiment.py`. Each GitHub Actions run
uploads a JSON record containing every trial, expected and actual verdict,
reason, latency, environment, source revision, thresholds, and refused claims.

## 4. Results

The local development run produced:

| Measure | Result |
|---|---:|
| Total cases | 600 |
| Correct decisions | 600 |
| False allows | 0 |
| False refusals | 0 |
| Raw sentinel leaks | 0 |
| In-process p50 | 0.0404 ms |
| In-process p95 | 0.0708 ms |
| In-process p99 | 0.1139 ms |
| Maximum observed | 0.3033 ms |

The experiment passed every predeclared criterion. This result supports the
mechanism hypothesis for this corpus. It does not prove the broader product
hypothesis that Valkyrie can mediate all browser or endpoint consequences.

## 5. Engineering failures and corrections

The design changed in response to concrete failure modes rather than feature
count. Independent native messages could arrive out of causal order, so the
extension moved to one persistent native-messaging channel. A reusable grant
could authorize more than one consequence, so grants became one-shot. A failed
scope probe could otherwise leave a valid grant available, so failed
verification now consumes it. Process IDs from browser context would be a
guess, so the collector explicitly records `browser_semantic_no_process_pid`
instead of inventing an attribution edge. Raw values would make the privacy
system itself a data store, so only controlled labels and canonical origins
cross the boundary.

These choices make the current system less impressive on paper but more
defensible. Refusing unsafe authority is part of the design, not an error case
hidden from the result.

## 6. Limitations

The corpus is synthetic and generated by the project itself. It can expose
regressions in the specified mechanism but cannot estimate a population-level
false-positive rate. The test does not run Chromium or the native host. It does
not cover every browser egress primitive, service worker, WebSocket, extension,
cookie operation, cross-origin frame, or programmatic submission. A Manifest V3
extension is not a complete browser reference monitor.

The recorded refusal is not enforcement. The request is not canceled. Browser
context has no authoritative Windows PID link, and the unsigned kernel driver
is not loaded. The experiment says nothing about malware detection efficacy,
resistance to a compromised browser, or production reliability under sustained
workloads.

The latency result is a mechanism measurement on one run. It must not be
described as one-to-ten-millisecond end-to-end response.

## 7. Next hypothesis

The next experiment should replace synthetic collector calls with a controlled
Chromium instance and local test server in a disposable Windows VM. It should
measure gesture-to-native-host, native-host-to-verdict, and verdict-to-request-
cancellation latency separately. It should include ordinary browsing and form
workloads, background submissions, cross-origin frames, service workers,
replays, extension restarts, and bypass attempts.

The next hypothesis is:

> Browser-level mediation can preserve the exact causal-authority semantics
> while keeping p99 decision latency below 10 ms and producing no false
> refusals in a controlled benign workload.

That hypothesis remains untested. If browser ordering or bypass resistance
fails, the correct result is to reject the extension as an enforcement boundary
and move the authority check to a stronger integration point.

## 8. Conclusion

Valkyrie's potential is not that it has more detection rules than commercial
EDR products. This experiment demonstrates a smaller architectural idea: a
local system can make a deterministic, explainable decision from the exact
relationship between an action and its consequence without retaining the raw
personal value. The mechanism passed its fixed synthetic corpus and latency
budget. The difficult work still ahead is proving that the same semantics
survive a real browser, Windows attribution, enforcement, and ordinary user
behavior.
