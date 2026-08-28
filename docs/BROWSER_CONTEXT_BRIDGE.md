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

The extension emits only these fields: event type, HTTP(S) origin, tab/frame
identifiers, whether the browser marked the event trusted/user initiated, a
coarse gesture type, and a coarse consent outcome. The collector recomputes and
validates the origin. It rejects file URLs, malformed payloads, oversized
messages, unknown event types, invalid timestamps, and unbounded event IDs.

It never emits or stores full URLs, paths, query strings, page text, form
values, keystrokes, cookies, DOM snapshots, or consent-dialog text. Browser
events intentionally have no fabricated Windows PID: they are context, not an
asserted process-provenance edge.

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

This is an **experimental observation layer**, not browser enforcement. It is
not yet joined to Windows process identity, does not decide whether a consent
dialog was legally valid, and cannot block a request by itself. The existing
consequence playbook remains policy/authority gated and dry-run until isolated
VM validation demonstrates acceptable attribution, latency, and false-positive
behavior.
