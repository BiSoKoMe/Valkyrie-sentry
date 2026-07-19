# ADR 0018 — SOAR playbooks (declarative response automation)

Date: 2026-07-19 · Status: accepted

## Context

The EDR ships audited response actions (`block_domain`, `kill_process`,
`isolate_host`, plugin actions) that a human triggers. Enterprises expect
the SOAR layer: codified response to known-bad patterns at machine speed.
Automating response is the most dangerous feature in an EDR, so the design
is safety-first rather than capability-first.

## Decision

`valkyrie/edr/playbooks.py` — `PlaybookEngine` subscribes to the existing
EdrEngine incident bus and evaluates analyst-authored YAML
(`data/playbooks.yaml`): severity floor + optional category allowlist →
ordered actions with targets drawn from the incident
(`entity`/`process_name`/literal). Execution goes through the **same**
`ResponseManager` path a human uses — audited `ResponseAction` rows,
incident timeline entries, `operator: playbook:<id>`. No second response
system.

Safety model:
- **Dry-run by default**; a playbook must state `mode: enforce` to act.
- **Cooldown** per (playbook, action:target), default 300 s — no loops.
- **Fail-open to humans**: malformed playbooks are load errors in status;
  unknown actions audit as failed; nothing raises into correlation.
- **No file → idle**: engine only activates when playbooks exist.

Observability: `GET /api/edr/playbooks/status` (loaded books, load errors,
executed/suppressed counters). AppContext field `playbooks`.

## Rollback

Delete `data/playbooks.yaml` (engine idles) or the module (only `__main__`
references it).

## Honest boundary

Single-condition triggers (severity/category), sequential actions, no
cross-incident logic, no scheduled/enrichment steps, no approval workflow.
Each is an extension of `Playbook.matches`/`_run_playbook` when justified;
approval-gated enforce is the likely next increment.
