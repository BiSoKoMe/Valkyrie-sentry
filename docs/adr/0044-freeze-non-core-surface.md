# ADR 0044 — Freeze the non-core surface (Priority 0)

Date: 2026-08-04 · Status: accepted

## Context

Two independent adversarial architecture reviews, conducted separately, reached
the same conclusion in almost the same words: **months of engineering had gone
into enterprise features for customers who do not exist, while the core agent
still had no kernel visibility, no tamper resistance, and no validation against
a real attack.**

Stated bluntly: Valkyrie shipped a multi-device fleet control plane, a SOC 2
evidence report generator, an AI-agent MCP server, and a two-hop VPN — and the
agent itself could be stopped with `taskkill /f /im valkyrie.exe`.

`docs/GAP_ANALYSIS.md` and the `valkyrie_competitive_position` notes had already
named this ("enterprise cosplay"), but naming it had not changed where effort
went. A written diagnosis that does not alter the build is not a decision.

## Decision

Move — **not delete** — the non-core surface to `experimental/`:

| Moved | Why |
|---|---|
| `fleet/` | Zero devices enrolled, untested at any scale, assumes a backend that does not exist |
| `mcp/` | Zero users; solves no problem the product has |
| `compliance.py` | Generating audit evidence for a product with no customers and no certification is theatre |
| `wireguard.py` | Valkyrie is not a VPN product |
| `multihop.py` | Same; scope creep plus an unauditable security surface |

`git mv` was used throughout so history follows the code.

**Frozen in place (not moved):** `siem.py` (well built, off by default, costs
nothing wired — but do not extend), `edr/playbooks.py` (actively used by the
response path; all playbooks stay `dry_run` until field FP data justifies
arming any), `edr/ai_provider.py` (off by default, explain-only, correct as
built).

The product surface is now:

```
Valkyrie Core
 ├── Endpoint Protection   (sensors, kernel driver, response)
 ├── Detection Engine      (IOA rules, anomaly scorer, sequences, normalization)
 └── Privacy Engine        (DNS, MAC randomisation, telemetry control, zero-log)
```

### The boundary is mechanically enforced

A freeze that relies on discipline decays one convenience import at a time.
`tests/test_experimental_isolation.py` asserts:

1. no module under `valkyrie/` imports from `experimental/` (all 96 core
   modules scanned);
2. each frozen module is absent from `valkyrie/` **and** present in
   `experimental/` — deleted-by-accident fails the same as never-moved;
3. core still imports and exposes its entrypoint with `experimental/` absent;
4. no CLI flag (`--fleet-*`, `--mcp`, `--setup-wireguard`, `--setup-multihop`,
   `--multihop-status`) or API route (`/api/compliance/report`,
   `/api/vpn/status`) for a frozen feature survives.

The dependency arrow points one way. Core must remain shippable with
`experimental/` deleted entirely.

## What broke, and what that revealed

`tests/test_edr.py` failed after the move: it imported `valkyrie.fleet.agent`
for a privacy invariant asserting the fleet heartbeat never carries EDR
incident domains. That coupling was itself a symptom — a core test depending on
the enterprise surface.

Split rather than deleted: the core-relevant half (**the EDR engine has no
network transport of its own**; incidents reach the network only through the
explicitly wired, opt-in SIEM exporter) is now asserted directly against
`edr/engine.py`. The fleet-heartbeat half retired with the fleet code.

**Correction to this ADR's first draft:** `experimental/README.md` initially
claimed the moved tests "still exist and still pass." Verified — they do not.
All four fail at import because they still reference `valkyrie.fleet`,
`valkyrie.mcp`, etc. The README now states that plainly, and fixing those
imports is documented as part of the cost of unfreezing. Claiming a green
result without running it is exactly the failure mode this project's
no-silent-success standard exists to prevent.

## Consequences

- Core: 96 modules (was 101). Five subsystems and five test files out of the
  maintained surface.
- 26 core test modules verified green after the move, including
  `test_startup_smoke`, `test_web_route_auth`, `test_components`, and
  `test_context` — the ones that would catch broken wiring.
- `test_telemetry` remains an environmental SKIP (needs Administrator for
  registry edits); unrelated to this change and correctly reported as
  "SKIPPED — NOT a pass."
- Roughly a third of the maintenance burden removed, and none of the protection
  value: no detection, response, or privacy capability was touched.

## Unfreezing

Deliberate, not incremental: move the module back into `valkyrie/`, fix its
imports, wire it, restore its tests to the core gates, and write the ADR that
says which customer asked for it. Editing it in place inside `experimental/` is
explicitly not the path.
