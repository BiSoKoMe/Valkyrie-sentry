# ADR 0049 - Causality graph (Cortex XDR-style CGO / Falcon-style process tree)

Date: 2026-08-16 . Status: accepted . Follows: ADR 0025 (kill-chain), ADR 0032 (sequence IOAs)

## Context

Both major commercial EDR platforms are built on the same substrate, under two
different names. Palo Alto's Cortex XDR calls it the **causality chain** and
names its root the **Causality Group Owner (CGO)**; CrowdStrike Falcon calls it
the **process tree / threat graph**. In both, every process is a node, every
parent->child relationship an edge, and every non-process observation - a network
connection, a DNS query, a file write, an alert - is *attributed* to the process
that caused it. An alert is then not a row in a table but a point in a graph you
can walk.

Valkyrie had correlation but no structure. `killchain.py` (ADR 0025) already
folds a child into its parent's chain via the parent->child PID edge, and
`behavioral_sequences.py` (ADR 0032) matches ordered behaviours on a lineage -
but both do lineage work at *scoring* time and keep only a flat deque of steps.
The structure is computed and discarded. The consequences were concrete:

- No answer to "what started this?" - a bare `pid`/`ppid` pair on a detection
  cannot name the document, download or service that originated an intrusion.
- No answer to "what else did this do?" - sibling branches of the same attack
  were invisible; only the one process that happened to alert was reachable.
- Nothing to render. A process tree is the single most recognisable artifact of
  a serious EDR console, and there was no data structure to draw one from.

## Decision

New `valkyrie/edr/causality.py` - a thread-safe, bounded process-ancestry graph.

**Nodes and identity.** A `ProcessNode` is identified by `(pid, create_time)`,
not by pid, because pids are reused. Where a collector supplies no create_time
the key degrades to the bare pid and the node is flagged `inferred`, so the
weaker identity is always visible rather than silently assumed.

**Causality terminators are the whole trick.** Walking ppid links naively always
ends at `System`, and a chain rooted at `System` says nothing. The walk therefore
stops *below* OS infrastructure whose job is to launch unrelated work -
`explorer.exe`, `services.exe`, `svchost.exe`, `taskeng.exe`, `wmiprvse.exe` and
the boot chain. The first process below the terminator is the CGO: for
`explorer -> winword -> cmd -> powershell`, the CGO is `winword.exe` - the document
the user opened, not the shell that ran nor the desktop that launched it.

**Terminator status is path-aware, and that is a security property, not a
detail.** A process named `svchost.exe` running from `%TEMP%` is a masquerade,
and if its *name* alone terminated the walk the graph would hide precisely the
ancestry that exposes it. So a terminator name only terminates from a trusted OS
path (`trust.is_trusted_os_path`). An unknown path is treated as trusted, because
the processes whose paths a non-elevated userland poller cannot read are
overwhelmingly the real protected system processes; the opposite default would
root nearly every chain at `System` on an unprivileged install.

**Established edges are recorded once.** Each node holds a `parent_key` resolved
at link time. Re-deriving the parent from a pid->newest-node index on every walk
was a real bug found by the tests in this ADR's suite: a later, unrelated process
recycling the parent's pid tripped the reuse guard and silently severed a
correct chain. An edge resolved while the parent was still the live holder of
that pid cannot be made retroactively untrue.

**Wiring.** `EdrEngine._record_causality` feeds the graph from `ingest_telemetry`
**above** the severity gate. That placement is deliberate: the gate exists so a
routine process start never becomes an incident, but the ancestry that explains
an alert is entirely info-severity right up until the last hop isn't. Recording
structure is not the same act as raising an alert, so the gate governing alerting
does not govern this. `_enrich_causality` then stamps `details['causality']` onto
every detection - owner, chain, readable path - so the answer travels into the
incident record instead of having to be recomputed later against a graph that may
since have evicted it.

**Surface.** `GET /api/edr/incidents/{id}/causality` returns the subgraph;
`GET /api/edr/causality/stats` returns graph health.

## Honest boundaries

These are load-bearing and are carried on the API payload, not just in prose:

- `inferred_nodes` counts ancestry the graph **guessed at** rather than observed.
  Valkyrie's process collector is a userland psutil poller, so a process that
  starts and exits between polls is never seen; its children attach to a named
  placeholder built from the `parent_name` the collector carries. A chain reading
  `winword.exe -> powershell.exe` because of a guess must not be presented with
  the same confidence as one every hop of which was observed.
- `truncated` means the descendant walk hit its bound; `evicted` means nodes were
  dropped for memory before the query ran. A chain that looks short for either
  reason is a different claim from one that is genuinely short.
- An observation with no attributable pid is **dropped, not guessed** - the same
  limit ADR 0025 documents for DNS detections the resolver cannot map to a
  process. The graph does not paper over it.
- **This module raises no detections and changes no verdict.** It is structure,
  not judgment. Nothing here can make Valkyrie detect anything it did not already
  detect; it makes what was detected explicable. Closing the poller's blind spot
  requires a kernel/ETW process sensor, which is a separate piece of work.

## Consequences

- Detections now carry their causality owner into the incident record.
- The data needed for a Falcon-style process-tree render exists; the renderer
  itself is not part of this ADR.
- Memory is bounded (`max_nodes`, default 8192, LRU eviction) and artifacts are
  capped per node (200), so a beaconing implant emitting thousands of connections
  cannot grow the graph without limit.
- Existing correlation is untouched: `killchain.py` and `behavioral_sequences.py`
  score exactly as before, and a graph miss degrades enrichment to previous
  behaviour rather than breaking ingest.

## Validation

`tests/test_causality.py` - 76 structural checks: terminator rules including the
masquerade case, create_time identity, CGO/chain correctness and ordering, the
pid-reuse guard, inferred placeholders and their promotion (including the
name-mismatch case where promotion must *not* merge), artifact attribution and
caps, every honesty flag on the wire format, eviction bounds, cycle guards on
both walks, and an engine end-to-end test proving benign ancestry is recorded
below the alert gate.

**These are structural-correctness tests and are not a detection-rate
measurement.** Per the project's standing rule, detection efficacy is established
only by a live Atomic Red Team run on a VM. The only real Tier B figure on record
remains 1/40, and nothing in this ADR changes it - by design, since the causality
graph raises no detections at all.
