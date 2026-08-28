# ADR 0051 - Evidence-constructed remediation planning

Date: 2026-08-23 . Status: accepted . Follows: ADR 0049 (causality graph), ADR 0018 (SOAR playbooks)
Informed by: docs/VENDOR_ARCHITECTURE_2026.md

## Context

Vendor architecture research (docs/VENDOR_ARCHITECTURE_2026.md) surfaced one
design principle from CrowdStrike's agentic Falcon layer that Valkyrie could
adopt directly and cheaply, because it is a *design* commitment rather than a
scale commitment:

> Response logic should be constructed from evidence, not selected from
> templates.

Valkyrie had two response paths and both were selection, not construction:

- `decision.decide()` picks one action off a five-rung ladder for one signal.
- `playbooks.py` (ADR 0018) matches an incident against analyst-authored YAML
  and fires that playbook's fixed action list.

Both answer *"which of my prepared responses is closest to this?"* Neither
answers *"what did this intrusion actually do, and what is the minimum set of
actions that undoes it?"*

The consequence was concrete and asymmetric with what ADR 0049 had already
built. `causality.py` attributes every DNS query, network connection, file
write and registry change to the process that caused it, and `subgraph()`
returns the whole tree under the Causality Group Owner. So Valkyrie *knew* that
one document spawned three processes, wrote a run key and beaconed to a domain
— and then responded by killing the single process that happened to alert. The
attack was a graph; the response was a row.

This is also the gap that matters most for the four-gate authority model (ADR
0031 lineage / `authority.py`). Authority is computed per action. If the plan
only ever contains one action, per-action authority has nothing to discriminate
between.

## Decision

New `valkyrie/edr/remediation.py` — a **pure** planner that consumes a
causality subgraph and constructs a remediation `Plan`. It executes nothing.

**Actions are derived from observations.** A `block_domain` exists in a plan
because a specific DNS artifact was attributed to a specific process in the
tree; remove the observation and the action does not appear. Each
`PlannedAction` carries the `Evidence` tuple that produced it, so "why are you
about to block this?" has an answer that is not "a rule said so".

**Observed-but-unactionable evidence is surfaced, never dropped.** A bare IP
with no `block_ip` responder behind it, a file write, a persistence artifact
whose type the responder cannot parse — all land in `Plan.unactionable` rather
than being silently discarded *or* coerced into a malformed target. We never
synthesise an identity for `remove_persistence`: handing that responder a
guessed identity is how you delete the wrong autostart entry.

**Every action is authorised independently, on its own responder and target.**
This required one small additive change to `authority.authorize()`: a new
`responder=` keyword. The existing `Action -> responder` map assumes one action
means one responder, which stops being true the moment several distinct
remediations descend from a single BLOCK decision. Passing the responder
explicitly makes the consequence and invariant gates price *that* responder.
Empty (the default) preserves the old behaviour exactly — `test_authority.py`
passes unchanged.

The result is that a plan is routinely part-enforcing and part-alert-only: an
invariant may veto blocking one domain while permitting another in the same
tree, and `kill_process` (irreversible) is gated harder than `block_domain`
(leasable) on identical evidence.

**A hole in the graph caps irreversible action.** This is the load-bearing
safety property. `subgraph()` already reports its own honesty flags —
`truncated`, `inferred_nodes`, `evicted`. Any of them means the picture is
incomplete, and an incomplete picture may not authorise an irreversible
action: *you cannot know that ending this process tree is correct when you
cannot see all of it.* It **caps rather than abandons** — the reversible steps
still stand on a partial graph, because cutting C2 on incomplete evidence is
recoverable and killing on incomplete evidence is not.

This is the coverage gate's logic (ADR 0022/0023 — authority follows sensor
health) applied one level up: to the *graph* built from those sensors, not just
the sensors themselves.

**Ordering is operational, not cosmetic.**

1. `block_domain` — cut C2 first, so everything after happens to a process
   that can no longer phone home. Cheapest, fully reversible.
2. `remove_persistence` — close the return route BEFORE killing, so the
   termination is not undone by a task or run key firing minutes later.
3. `kill_process` — irreversible, so it happens once escape and return routes
   are already shut.
4. `isolate_host` — broadest blast radius, last, and only when the decision
   itself reached CONTAIN.

**Host isolation is reached by the decision, never by the size of the tree.**
A count of nodes must not be able to escalate to cutting the user's network.
Pinned by test.

## Consequences

Positive:

- Response now scales with the intrusion instead of with the alert. Three
  sibling processes, a run key and a beacon domain produce five planned
  actions, each individually gated.
- The per-action authority model finally has something to discriminate
  between, so its per-target invariant checks do real work.
- Fully offline-testable: 35 checks in `tests/test_remediation.py`, no host
  state touched.

Negative / accepted:

- The planner proposes kills for processes that may have already exited; the
  graph does not track exit. `responder.kill_process` returns "no such
  process", a benign no-op. Recorded here rather than papered over.
- `remove_persistence` candidates only appear when a collector attributes a
  persistence artifact carrying structured `asep_type` + `identity`. Today
  most do not, so that arm of the planner is largely dormant until the
  persistence collector is enriched. **This is a coverage gap, not a
  detection claim.**
- Nothing is wired into `engine.py` yet. This ADR lands the planner and its
  tests; adoption on the live incident path is a separate change, so that the
  first thing to run against real incidents is a plan an operator reads rather
  than a plan that acts.

## Honesty note

This changes what Valkyrie *does with* a detection. It does not detect
anything new and does not move the measured detection rate, which remains the
Tier A / Tier B position recorded in `valkyrie_redteam_evaluation`. No claim
here should be read as a detection improvement.
