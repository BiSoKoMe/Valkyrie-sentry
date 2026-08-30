# ADR 0059: Causal Authority Reflex

## Status

Experimental, metadata-only, and observation-only. Implemented locally with
focused tests. It has not been live validated in an isolated browser VM and it
does not currently block browser traffic.

## Decision

Valkyrie will distinguish request authority from host-response authority.
`valkyrie/edr/authority.py` continues to answer whether Valkyrie may modify host
state. `valkyrie/causal_authority.py` separately answers whether a browser
egress consequence carries a fresh, matching causal grant.

A causal grant is:

- created only from a browser-reported trusted gesture with explicit form scope;
- held only in process memory;
- valid for two seconds by default and never more than ten seconds;
- scoped to source origin, destination origin, tab, frame, action, and data labels;
- consumed after one verification attempt, whether that attempt succeeds or fails;
- decided with exact comparisons, not a confidence score.

Nyx-style classification is performed at the browser capture point. Raw values
are reduced to a controlled label set and discarded before the event crosses
native messaging. The authority engine receives no page content, form values,
cookies, paths, queries, or key identities.

## Why

Signature lists answer whether an object resembles previously described bad
behavior. Causal authority answers a different question: whether this specific
consequence is justified by a recent, scoped user action. This makes the first
experiment independent of domain reputation, attack rules, and runtime AI.

## Safety boundary

The current browser bridge records `allow` and `refuse` verdicts but does not
cancel submission. Browser context has no authoritative Windows PID and cannot
authorize destructive endpoint responses. Missing, expired, replayed, or
mismatched grants fail closed at the verifier while the product remains in
observation mode.

## Falsifiable experiment

1. A trusted click or Enter action scopes a form submission.
2. An unchanged submission within the grant lifetime receives `allow`.
3. Scripted submission without a grant receives `refuse`.
4. Replay, destination change, frame change, or newly added data labels receive
   `refuse`.
5. A unique raw secret inserted into ignored payload fields, form labels, and a
   destination query must not appear in collector state, telemetry, or graph input.
6. The isolated verifier benchmark reports p50, p95, and p99 latency separately
   from browser, native-host, HTTP, graph, and enforcement latency.

## Known limitations

An ordinary Manifest V3 extension is not a complete browser reference monitor.
Programmatic submissions that emit no DOM event, arbitrary fetch and worker
traffic, WebSockets, browser UI, inaccessible frames, and complete cookie flows
are outside this experiment. Claiming complete mediation would require a much
stronger browser integration and separate validation.
