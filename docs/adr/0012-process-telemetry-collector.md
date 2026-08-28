# ADR 0012 - Process telemetry collector (endpoint visibility beyond DNS)

- **Status:** Accepted
- **Phase:** 3 (real endpoint telemetry)
- **Date:** 2026-07-12

## Context

The audit's single biggest finding: Valkyrie sees only DNS, so its "EDR" and
"behavioral detection" never observe a process. With the normalized event schema
in place (ADR-0011), the next step is a real second signal source.

A full kernel sensor (ETW on Windows, eBPF on Linux) is the eventual answer but
is platform-specific, privileged, and large. The portable, immediately-useful
first step is a **userland process collector** that emits the same normalized
schema those kernel sensors will later emit - so the rest of the pipeline is
built once.

## Decision

Add `valkyrie/process_telemetry.py`:

- **`classify_process(name, path, parent_name)`** - a pure, unit-tested heuristic
  returning `(severity, labels, reason)`. Starter behavioral detections:
  living-off-the-land binaries, Office-app-spawns-shell (macro-malware pattern),
  and execution from temp/download directories (separator-normalized so it works
  on Windows and Unix). Deliberately small and explainable - a seed, not a
  detection-engineering pipeline, and documented as such.
- **`ProcessCollector`** - polls the process table (psutil), diffs against the
  previous snapshot, and emits a `TelemetryEvent` (`category=process`,
  `activity=exec`, `action=flagged` when severity >= medium) per newly-started
  process via an injected `emit` callback. The first poll seeds a baseline
  silently so launch doesn't flood the pipeline with every running process.

Honesty about scope is built into the module docstring: it is a poller, not a
kernel sensor; short-lived processes between polls can be missed; it needs no
privileges for the current user and degrades to a no-op without psutil, never
raising into the caller.

Built **additively** - nothing wires it into the live pipeline yet (that is the
next increment), so this change cannot affect the running product.

## Change report

- **What changed:** new `valkyrie/process_telemetry.py` (+ tests).
- **Why:** give Valkyrie its first non-DNS endpoint signal and the honest,
  portable seam that ETW/eBPF collectors will replace/augment.
- **Security impact:** foundational positive - this is the beginning of actual
  endpoint behavioral visibility (LOLBins, suspicious spawns) the product claimed
  but lacked. Emits observations only; it does not act on processes.
- **Performance impact:** none yet (not started by anything). When wired, a
  process-table poll every ~2s is cheap; work is bounded and off the DNS hot path.
- **Compatibility impact:** none - purely additive.
- **Risks:** low. Heuristics will produce some false positives (e.g. an admin
  legitimately using PowerShell) - mitigated because events are severity-tagged
  observations feeding correlation, not autonomous blocks, and the heuristics are
  small/explainable. Polling can miss ultra-short-lived processes - documented,
  and the reason a kernel sensor is the roadmap.
- **Tests added:** `tests/test_process_telemetry.py` - heuristic cases (benign,
  LOLBin, Office->shell, temp-dir, combinations), `diff_snapshots`,
  `ProcInfo.to_event`, baseline-then-emit via injected snapshots, and
  emitter-exception isolation. Also verified live (spawning `sleep` is captured).
  Full suite: 29 passed, 0 failed, 2 skipped.
- **Rollback plan:** delete the module and its test; nothing imports it yet.

## Consequences

Valkyrie can now observe process executions with explainable behavioral tagging,
emitting the normalized schema. The next increment wires it in: start it from
`__main__`, publish onto the shared `EventBus`, have the EDR engine ingest
`process` telemetry as detections, and surface it on the dashboard - turning
"sees only DNS" into "sees DNS + endpoint process activity".
