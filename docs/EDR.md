# Valkyrie -> EDR / Security-Operations Layer

**What it is:** a detection -> incident -> response layer built on top of
Valkyrie's existing sensors. Written in the same no-overclaiming spirit as the
other docs - it says plainly what is real and enforced, what is scaffolding,
and what is deliberately gated.

---

## The idea in one paragraph

Valkyrie already had excellent **sensors** - the DNS sinkhole, the firewall's
answer-IP screening against 12k+ threat-intel ranges, the behavioural
heuristics, and the self-learning intelligence engine. What it lacked was the
**SOC layer** that turns that signal into things a defender works with. The
`valkyrie/edr/` package adds exactly that, and **adds no new sensing** - it
*interprets* what Valkyrie already sees. It stays entirely local: all EDR state
lives in the same SQLite database, so zero-log RAM mode covers it automatically
and nothing new touches disk.

---

## What's real and running

| Capability | Status | Where |
|---|---|---|
| Plugin architecture (detection / responder / enrichment) | **Built + tested** | `edr/plugins.py` |
| Built-in detections (tracker, DGA, beacon, DoH-bypass, threat-intel IP, anomaly) | **Built + tested** | `edr/builtin.py` |
| Detection -> **incident** correlation with **timelines** | **Built + tested** | `edr/engine.py`, `edr/store.py` |
| **Threat hunting** - structured queries + 6 saved hunts | **Built + tested** | `edr/hunt.py` |
| **Response** - block domain, kill process, isolate host (dry-run-first, audited) | **Built + tested** | `edr/response.py` |
| **AI-assisted investigation** - offline analyst (default) | **Built + tested** | `edr/investigate.py` |
| AI-assisted investigation - LLM provider (opt-in, vendor-neutral) | **Built, off by default** | `edr/investigate.py`, `edr/ai_provider.py` |
| **Remote response** - signed operator->device commands over the fleet | **Built + tested** | `fleet/command.py`, `fleet/controller.py`, `fleet/agent.py` |
| Professional **EDR console** (incidents, timelines, hunt, response) | **Built** | `web/edr.html`, `web/server.py` |
| Live incident streaming over the dashboard WebSocket | **Built** | `web/server.py` |

Everything above is exercised by `tests/test_edr.py` (50 checks) and
`tests/test_fleet_response.py` (21 checks).

---

## How detections become incidents

The engine subscribes to the same live decision stream the dashboard uses. For
each event it runs the detection plugins; each detection is then **correlated**
into an incident by a deliberately simple, explainable rule:

> A detection joins the most-recent still-open incident that shares its
> **category** and either its **entity** (domain/IP) or its **process**, within
> a time window (default 10 minutes). Otherwise it opens a new incident.

This collapses "the same beacon blocked 400 times" into **one** incident with a
400-entry timeline and an escalating severity - not 400 alerts. Unrelated
activity stays in separate incidents.

---

## Response: dry-run first, always audited

Every response action is:

- **dry-run by default** - the API and the console both run a dry-run first and
  show you the exact effect (or the exact commands) before anything happens;
- **audited** - a row is written whether it ran, was simulated, or was refused,
  and it is attached to the incident's timeline;
- **honest about privileges** - an action that needs admin/root and doesn't have
  it reports `skipped` with the reason. It does not silently no-op.

`kill_process` refuses system/critical PIDs. `isolate_host` generates the exact
`iptables`/`netsh` commands and applies them only with privileges and an
explicit non-dry-run request - the same "verify-first, apply is gated"
philosophy as the signed updater.

---

## AI-assisted investigation - the privacy trade-off, stated plainly

Investigation has two modes:

- **Offline analyst (default, always available).** A deterministic, fully-local
  writeup built from the incident's own detections: severity rationale, observed
  MITRE ATT&CK techniques, affected process/entities, a timeline digest, and
  concrete recommended response actions. No network, no key.
- **LLM-assisted (opt-in, off by default).** If the operator explicitly asks
  *and* an AI provider is configured, the incident is summarised by an LLM for a
  richer narrative. The backend is **vendor-neutral** (`edr/ai_provider.py`):
  Anthropic, OpenAI, a local OpenAI-compatible server (Ollama/LM Studio/
  llama.cpp), or offline - the investigation engine depends only on the provider
  interface, never a single vendor. A **network** provider sends incident details
  (including domains) to the configured endpoint - so it is gated exactly like
  the roadmap requires of anything that leaves the machine: opt-in, off by
  default, clearly disclosed. The **local** provider keeps everything on-box. Any
  error (no provider, network blocked) silently falls back to the offline analyst.

Enable it per-investigation from the console ("AI investigate"). Configure via
`VALKYRIE_AI_PROVIDER` (`anthropic`|`openai`|`local`|`offline`),
`VALKYRIE_AI_KEY`, `VALKYRIE_AI_MODEL`, and `VALKYRIE_AI_BASE_URL`. Existing
`ANTHROPIC_API_KEY` / `OPENAI_API_KEY` are honored as fall-backs, so nothing
breaks. No AI-vendor SDK is required - providers speak plain HTTP over `httpx`.

---

## Remote response - control, not telemetry

The fleet already pushed **signed policy** (block/allow lists) to devices. The
remote-response channel extends that to **actions**: an operator signs a
response command with the fleet's Ed25519 key; agents pull pending commands,
verify the signature against the pinned public key, run the action through the
local responder, and acknowledge the result.

It reuses the exact security properties of the policy channel:

- **Authenticity** - a command runs only if Ed25519-verified (fail-closed).
- **Anti-replay** - every command has a unique id; the server tracks per-device
  acks, so a command runs at most once per device.
- **Bounded blast radius** - only an allow-list of actions can be encoded; a
  command targets one device or a whole org.

**Why this doesn't break the privacy invariant:** this is *control* flowing
server->device, not telemetry flowing device->server. The ack reports action
status for a target the operator *already chose and sent* - it never carries the
device's browsing history. The heartbeat (which does flow device->server) still
carries only counts/categories/component-health, proven by the privacy tests in
`tests/test_fleet.py`.

The channel is **inert unless** the device has the fleet policy public key
pinned (`$VALKYRIE_FLEET_POLICY_PUBKEY`) *and* a responder wired in - exactly
like signed-policy apply.

---

## Extending it - the plugin contract

Drop a `*.py` file into the plugin directory (`data/plugins/` by default, or
`--edr-plugin-dir DIR`) exposing `register(registry)`:

```python
from valkyrie.edr.plugins import DetectionPlugin
from valkyrie.edr.schema import Detection

class MyDetection(DetectionPlugin):
    name = "custom.suspicious_tld"
    description = "Flag lookups to a TLD I care about"

    def analyze(self, event, ctx):
        if event.get("domain", "").endswith(".zip"):
            return [Detection(source=self.name, severity="medium",
                              category="anomaly", title="'.zip' lookup",
                              entity=event["domain"],
                              process_name=event.get("process_name", ""))]
        return []

def register(registry):
    registry.register(MyDetection())
```

The same registry takes `ResponderPlugin` (new actions) and `EnrichmentPlugin`
(add context to detections). A broken plugin is isolated - its exception is
captured and counted, never allowed to take down the pipeline. Discovered
plugins run with Valkyrie's privileges, so point discovery only at a directory
you control; the loader says so plainly rather than pretending to sandbox.

---

## CLI

```
python -m valkyrie --web            # EDR active + console at /edr (default on)
python -m valkyrie --no-edr         # disable the EDR layer
python -m valkyrie --incidents      # print current incidents and exit
python -m valkyrie --hunt list      # list saved threat hunts
python -m valkyrie --hunt beacon_candidates   # run a saved hunt and exit
python -m valkyrie --edr-plugin-dir ./my-plugins --web
```

Web API (all under `/api/edr/`): `stats`, `incidents`, `incidents/{id}`,
`incidents/{id}/status`, `incidents/{id}/investigate`, `respond`, `hunt`,
`hunt/saved`, `plugins`. State-changing endpoints are loopback + control-token
gated (same defence-in-depth as the system-control buttons).

---

## Honest bottom line

The **detection/response engineering** is real, local-first, and tested. It
turns Valkyrie's existing signal into triable incidents with a genuine
response path, and it does so without weakening the privacy story: EDR data
never leaves the machine, and the fleet only ever carries control commands and
status metadata - never browsing history. The one place data can leave - the
optional LLM-assisted investigation, when pointed at a network provider - is off
by default and clearly disclosed, exactly where the trade-off belongs (and the
local provider avoids it entirely).
