# Browser Context Bridge

Valkyrie now includes an experimental Chromium-family browser-context bridge.
It supplies a narrow semantic signal that TLS interception and DNS telemetry
cannot provide: a navigation, trusted user gesture, form submission, or
consent-control interaction occurred in a tab/frame at a specific origin.

The flow is local only:

```text
Manifest V3 extension -> Chromium native messaging -> loopback bridge API
    -> BrowserContextCollector -> normalized privacy TelemetryEvent -> EDR
```

The extension emits only these fields: event type, HTTP(S) source and intended
destination origins, tab/frame identifiers, whether the browser marked the
event trusted/user initiated, a coarse gesture type, a coarse consent outcome,
a random interaction identifier, and controlled data labels. The collector
recomputes and validates both origins. It rejects file URLs, malformed payloads,
oversized messages, unknown event types, invalid timestamps, unbounded event
IDs, and drops unknown labels.

For a scoped form gesture, the content script reads form-control values only
long enough to assign coarse labels such as `ordinary`, `email`, `credential`,
`payment`, or `file`. It never transmits or stores those values. Full URLs,
paths, query strings, page text, form values, key identities, cookies, DOM
snapshots, and consent-dialog text remain outside telemetry and graph state.
Browser events intentionally have no fabricated Windows PID: they are context,
not an asserted process-provenance edge.

## Causal authority experiment

Version 0.2 adds a deterministic, in-memory authority experiment:

```text
trusted pointer/Enter on form submit
    -> local form labels + source/destination scope
    -> short-lived, one-shot causal grant
    -> matching form-submit observation
    -> allow/refuse verdict recorded in metadata
```

Every grant is scoped to source origin, destination origin, tab, frame, action,
and the exact set of data labels observed when authority was created. It expires
after two seconds by default and is consumed after one verification attempt,
including a failed attempt. Replays, cross-origin reuse, frame changes, and data
labels added after the gesture are refused.

The extension uses one persistent native-messaging channel so gesture and
submit observations remain ordered. The authority engine performs no network
lookup, database operation, reputation lookup, signature match, or AI call.
`scripts/authority_benchmark.py` measures only this isolated reflex operation;
it does not claim end-to-end browser or enforcement latency.

## Installation

Load `browser_extension/` as an unpacked extension in Chrome, Edge, Brave, or
another Chromium-family browser. Then register its native host after obtaining
the extension ID:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\browser_extension\Install-ValkyrieBrowserBridge.ps1 -ExtensionId <32-character-extension-id>
```

Start Valkyrie with `--web`; the bridge posts only to its loopback endpoint.
The native host reads a dedicated local token that the extension never receives.
The server accepts browser events only from a loopback peer with that token.

Token persistence is fail-closed. If Valkyrie cannot restrict and verify the
token file ACL, it deletes the file and reports `native_host_ready: false`; the
extension then has no working relay rather than a weak credential. This host is
currently in that state because its PowerShell security module cannot load.

## Current boundary

This is an **experimental observation and decision layer**, not browser
enforcement. The submit event is not cancelled, so an `allow` or `refuse`
verdict currently records what the deterministic gate would do. It is not yet
joined to Windows process identity, does not decide whether a consent dialog
was legally valid, cannot observe programmatic `form.submit()` calls that emit
no DOM submit event, and cannot mediate every fetch, worker, WebSocket, browser
UI, cookie, or cross-origin frame operation. A standard Manifest V3 extension
is not complete browser mediation.

Automatic blocking remains disabled until controlled browser integration proves
ordering, bypass resistance, end-to-end latency, rollback behavior, and an
acceptable false-refusal rate. Existing host consequence playbooks remain
separately policy/authority gated and dry-run.
