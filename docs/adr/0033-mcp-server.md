# ADR 0033 — MCP server: an AI-agent interface to Valkyrie

Date: 2026-07-27 · Status: accepted

## Context

Research into CrowdStrike's [`falcon-mcp`](https://github.com/CrowdStrike/falcon-mcp)
surfaced a capability gap that is not about detection at all. falcon-mcp is a
**Model Context Protocol server** that exposes the Falcon platform to AI agents
as tools (25 modules: detections, hosts, intel, hunting, IOC, RTR, …), so an
analyst can investigate and triage in natural language rather than by clicking a
console.

Valkyrie already had a rich facade — `list_incidents`, `get_incident`,
`investigate`, `saved_hunts`, `run_saved_hunt`, `hunt`, `respond` — but it was
reachable only from the CLI, the Electron app, or the local HTTP API. **No AI
agent could drive it.** For a local-first product this is an unusually good fit:
the interesting security data is on the user's own machine, and an agent pointed
at it can answer "what happened on my box today, and what should I do?" without
anything leaving the host.

## Decision

Ship `valkyrie/mcp/` — an MCP server over **stdio**, wired to `--mcp`.

- **Protocol layer** (`server.py`): newline-delimited JSON-RPC 2.0 implementing
  `initialize` / `ping` / `tools/list` / `tools/call`, plus correct notification
  handling (no reply). Hand-rolled rather than taking the MCP SDK: Valkyrie ships
  as a frozen single exe and holds a stdlib-first line (same call as
  `etw/framework.py`), and this slice of the protocol is small and stable.
  `handle_message()` is pure, so the protocol is unit-tested without stdio.
- **Tool layer** (`tools.py`): a declarative registry of 9 tools named
  `valkyrie_<action>_<resource>`, mirroring falcon-mcp's `falcon_<action>_<resource>`.
  Handlers take a `ToolContext`, so the whole surface is testable without an agent.
- **`valkyrie_get_detection_coverage`** — a deliberate addition, not from
  falcon-mcp: it reports Valkyrie's detection layers *and its honest boundaries*
  (detection ≠ prevention; the ~2s poller can miss short-lived processes;
  memory tradecraft needs Sysmon or the unbuilt kernel driver). The server's
  `initialize` instructions tell the agent to call it before asserting what
  Valkyrie can do — so an agent summarising the product tells the truth rather
  than overselling it. This is the no-fake-claims discipline expressed as an API.

### Safety model (stricter than the obvious implementation)

An agent holding an EDR's response actions is a larger risk than most threats it
would investigate. So:

1. **Read-only by default.** Without `--allow-response`, `valkyrie_respond` is
   not advertised in `tools/list` at all (not merely refused on call).
2. **Dry-run by default even when enabled** — `dry_run` must be explicitly set
   to `false` to enforce, matching the SOAR playbooks' dry_run/enforce split.
   falcon-mcp makes the same judgement (its Real Time Response module is
   explicitly read-only triage).
3. **Actions validated** against the engine's real responder list.
4. **stdio only** — no socket, no bound port, unreachable from the network.
5. **Attributed** — `operator="mcp"` lands on the incident timeline, so
   agent-driven actions are auditable.

## Consequences

- Valkyrie becomes agent-drivable: incidents, investigation, hunting and
  telemetry search in natural language, locally.
- `tests/test_mcp.py` (40+ checks) covers the protocol (initialize/ping/unknown
  method/notifications), the tool surface, both safety guarantees (hidden **and**
  refused read-only; dry-run default when enabled), error handling (tool failures
  are `isError` results, never transport crashes), the read tools against a real
  engine + store, coverage introspection, and a full stdio session. Verified
  end-to-end against the real CLI (`python -m valkyrie --mcp`).
- No new dependencies; the module ships inside the frozen exe unchanged.

## Honest boundaries (what this is NOT)

- **This adds no detection capability.** It is an interface: it exposes what
  Valkyrie already sees. It does not make Valkyrie catch one extra threat.
- **Not the 25-module surface falcon-mcp offers.** Nine tools covering what
  Valkyrie genuinely has; there is no cloud, no fleet, no managed hunting, no
  identity/cloud-posture module to expose, and none are faked.
- **An agent can be wrong.** The tools return Valkyrie's data faithfully, but an
  agent's *interpretation* is not a verdict — which is exactly why the coverage
  tool ships the boundaries alongside the capabilities.
- **Response remains guarded on purpose.** Even with `--allow-response`, an
  enforcement action requires an explicit `dry_run: false`; that friction is a
  feature, not an oversight.
