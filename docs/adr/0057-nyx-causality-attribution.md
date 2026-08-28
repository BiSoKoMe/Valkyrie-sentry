# ADR 0057 - Attribute Nyx observations onto the causality graph

Date: 2026-08-27 . Status: accepted . Follows: ADR 0049 (causality graph)

## Context

Valkyrie has two graphs answering two different questions. The causality
graph (ADR 0049) attributes process, network, DNS and detection observations
to the process node that caused them, so an attack alert becomes a point in a
walkable structure. Nyx's own graph (`nyx_graph.py`) separately correlates a
tracker's identity across every site it has touched. Neither knows the other
exists. A process that both spawns a suspicious child *and* leaks personal
data to a tracker shows up as two disconnected facts in two different places,
not one actor's total behavior in one place.

Closing that gap requires knowing which OS process made a given outbound
request Nyx inspected - and Valkyrie did not actually have that. Nyx's real
integration point, `tls_addon.py`'s `ValkyrieAddon`, runs as a mitmproxy
addon; its own `_process_name()` carries an honest comment that resolving the
real process "would require a transparent-mode + psutil socket lookup" and,
lacking that, falls back to the client's IP address as a coarse identifier.
So every Nyx observation to date has been logged with no real process
identity at all - not merely disconnected from the causality graph, but
unattributable to it even in principle.

## Decision

Two additive pieces, neither of which changes Nyx's detection logic, its
false-positive guards, or the request pipeline:

**1. Real local-process resolution.** `network_telemetry.pid_for_local_port()`
- new, and a direct reuse of the psutil connection-table pattern
`NetworkCollector.snapshot()` already uses for the opposite lookup direction
(there: remote address, for threat-intel reputation; here: local port, to
identify the process that opened a connection *out* to the interception
proxy). `tls_addon.py`'s `_resolve_causality_pid()` calls it with the flow's
`client_conn.peername` port and returns `(pid, name)`, or `(0, "")` when
unresolved. This is deliberately a NEW method, not a change to the existing
`_process_name()` - every current log line's content is untouched; only the
new causality-attribution path depends on the richer resolution.

**2. A public attribution entry point on the engine.**
`EdrEngine.attribute_causality(pid, kind, summary, *, name, data)` - a thin,
guarded wrapper around `CausalityGraph.attribute()` for a sensor that lives
outside the telemetry/`ingest_telemetry` pipeline. `ValkyrieAddon` takes an
optional `edr=None` constructor argument (the same pattern already used for
`store`/`blocklist`/`behavioral`/`rules`/`threat_intel`) and, when given one,
calls it once per Nyx `Observation` via `_attribute_nyx_observations()`.

**Wiring is same-process, not cross-process.** `TLSInspector` runs mitmproxy's
`DumpMaster` on a background thread via the mitmproxy *library*, inside
Valkyrie's own process - not as a separate `mitmdump` subprocess, despite a
comment in `tls_addon.py` that reads as if it were. `store`/`blocklist`/etc.
are already passed to `ValkyrieAddon` by direct object reference for exactly
this reason. `__main__.py` passes the same `edr_engine` object it already
constructs earlier in startup; when EDR is disabled `edr_engine` is `None`,
which `TLSInspector`/`ValkyrieAddon` already treat as "behave exactly as
before this ADR."

**Honesty carried through, not bolted on.** `attribute_causality()` inherits
`CausalityGraph.attribute()`'s existing rule: an unresolvable pid is dropped,
not guessed at. `pid_for_local_port()` is racy by nature (a local port can be
reused between the connection opening and the lookup running) and returns
`None` rather than a wrong answer when no established match exists.

## Honest boundaries

- **This changes no verdict.** Exactly like ADR 0049's own causality
  recording, this attributes structure; it raises no detection, blocks
  nothing, and cannot make Nyx catch anything it did not already catch. What
  it adds is that a Nyx observation is now *locatable* on the same subgraph as
  that process's other behavior.
- **Resolution is best-effort, same as the rest of this codebase's userland
  pollers.** `pid_for_local_port()` can fail to resolve (permissions, a port
  reused in the race window, mitmproxy transparent-mode topologies where the
  client-visible port isn't the real originating socket) - it then attributes
  nothing rather than attributing to a guessed process.
- **No new detection or scoring logic exists yet.** A shared graph is a
  prerequisite for asking "does this process's total behavior - lineage AND
  outbound content - look explicable," not an answer to it. That question is
  deliberately not addressed by this ADR; per this project's own track
  record, that kind of unification should be designed from a real observed
  case once the two kinds of artifact actually coexist on nodes, not
  speculatively in advance.

## Validation

`tests/test_network_telemetry.py` [7]/[8] - `pid_for_local_port()` against a
faked psutil connection table: resolves a matching local port, returns `None`
for no match, rejects a falsy port without calling psutil, and degrades
cleanly when psutil itself is unavailable.

`tests/test_causality.py` [11] - `EdrEngine.attribute_causality()` against a
live engine and an already-observed process: attributes successfully, the
observation appears as an artifact on `causality_subgraph()`, attaching it
raises no incident of its own, and an unresolvable pid is dropped exactly as
`CausalityGraph.attribute()`'s own [6] already proves for the telemetry path.

`tests/test_nyx.py` [7] - the full addon wiring: a Nyx observation reaches a
fake `edr.attribute_causality` call carrying the resolved pid, name, and the
human-readable sentence; the addon works completely unchanged with no `edr`
reference (the default); an unresolvable process attributes nothing. Found
and fixed one real bug in writing this: a pre-existing test constructs
`ValkyrieAddon` via `__new__`, bypassing `__init__`, so `self.edr` did not
exist as an attribute at all - `self.edr is None` raised `AttributeError`,
silently swallowed by `_nyx_observe`'s own outer `except Exception: pass`,
which aborted the ACT/OBSERVE logic entirely for every test using that
construction path. Fixed with `getattr(self, "edr", None)`; all 53 checks
(48 pre-existing + 5 new) pass.

**Structural correctness only, same scope statement as ADR 0049**: this is
not a detection-rate measurement, and nothing here changes Valkyrie's live-fire
evaluation result.
