# Valkyrie MCP server — talk to your own EDR

Valkyrie can run as a **Model Context Protocol (MCP) server**, so an AI agent
(Claude Desktop, Claude Code, or any MCP client) can search and investigate
incidents, run threat hunts, query telemetry, and ask what Valkyrie can honestly
detect — in natural language, against **your own machine's** security data.

Inspired by CrowdStrike's [`falcon-mcp`](https://github.com/CrowdStrike/falcon-mcp),
which does this for enterprise Falcon. The difference: Valkyrie is local-first,
so the transport is **stdio** (no listening port, nothing reachable from the
network) and the data never leaves the box.

## Start it

```powershell
valkyrie.exe --mcp                    # read-only (recommended)
valkyrie.exe --mcp --allow-response   # also exposes the guarded response tool
```

From source: `python -m valkyrie --mcp`

## Wire it to Claude Desktop

Add to `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "valkyrie": {
      "command": "C:\\Program Files (x86)\\Valkyrie\\engine\\valkyrie.exe",
      "args": ["--mcp"]
    }
  }
}
```

(For Claude Code: `claude mcp add valkyrie -- "C:\\path\\to\\valkyrie.exe" --mcp`)

Restart the client; the Valkyrie tools appear. Then just ask:

> *"What security incidents did Valkyrie see today, and which is worst?"*
> *"Investigate the critical incident and tell me what to do."*
> *"Run the beacon-candidates hunt — is anything talking to C2?"*
> *"Can Valkyrie detect process injection on this machine?"*

## Tools

| Tool | What it does |
|---|---|
| `valkyrie_get_status` | Engine health + incident posture. Start here. |
| `valkyrie_search_incidents` | Search incidents (filter by status/severity). |
| `valkyrie_get_incident` | Full detail: detections, ATT&CK techniques, timeline. |
| `valkyrie_investigate_incident` | Valkyrie's built-in analyst: meaning + recommended actions. |
| `valkyrie_list_hunts` | List saved threat hunts. |
| `valkyrie_run_hunt` | Run a saved hunt (beacons, rare domains, anomalies…). |
| `valkyrie_search_events` | Ad-hoc telemetry search (domain/process/decision/suspicion). |
| `valkyrie_get_detection_coverage` | **What Valkyrie can and cannot detect**, including real boundaries. |
| `valkyrie_respond` | Block domain / kill process / isolate host. **Gated — see below.** |

## Safety model (read this)

An AI agent with an EDR's response actions is a bigger risk than most threats it
would chase, so the defaults are deliberately strict:

1. **Read-only by default.** Without `--allow-response`, `valkyrie_respond` is
   not merely refused — it is **not advertised at all**, so an agent is never
   tempted by a capability it cannot use.
2. **Dry-run by default even when enabled.** With `--allow-response`, a response
   call still *simulates* unless the caller explicitly passes `dry_run: false`.
   Same dry-run/enforce discipline the SOAR playbooks use.
3. **Only real actions.** The tool validates against the engine's actual
   responder list; an invented action is refused.
4. **stdio only.** No socket, no port, nothing bound — an MCP session cannot be
   reached over the network.
5. **Attributed.** Response actions are recorded with `operator="mcp"` on the
   incident timeline, so agent-driven actions are auditable.

## Honest note on `valkyrie_get_detection_coverage`

The server's `initialize` instructions tell the agent to call this tool before
claiming Valkyrie detects (or prevents) anything. It reports the detection layers
**and** the boundaries — that Valkyrie is detection rather than prevention, that
the process collector is a ~2s poller which can miss short-lived processes, that
memory-level tradecraft needs Sysmon or the (unbuilt) kernel driver. This exists
so an agent summarising Valkyrie tells you the truth instead of overselling it.
