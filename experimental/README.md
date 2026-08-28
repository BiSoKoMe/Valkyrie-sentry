# experimental/ - frozen, not deleted

Code in this directory is **not part of Valkyrie Core** and is not wired into
the running product. It is kept because it is real, working engineering that
may matter later - not because it is on the roadmap.

## Why these were frozen (2026-08-04)

Two independent adversarial architecture reviews reached the same conclusion:
months of effort had gone into enterprise features for customers who do not
exist, while the core agent still had **no kernel visibility, no tamper
resistance, and no validation against a real attack**. A security agent that
can be stopped with `taskkill` does not need a fleet management plane.

The product surface is now:

```
Valkyrie Core
 ├── Endpoint Protection   (sensors, kernel driver, response)
 ├── Detection Engine      (IOA rules, anomaly scorer, sequences, normalization)
 └── Privacy Engine        (DNS, MAC randomisation, telemetry control, zero-log)
```

## What is here

| Module | What it is | Why frozen | Unfreeze when |
|---|---|---|---|
| `fleet/` | Multi-device control plane - server, agent, policy, signed command channel | Zero devices enrolled. Untested at any scale. Assumes a backend that does not exist. | A paying customer needs >1 managed endpoint |
| `mcp/` | Model Context Protocol server - lets an AI agent query incidents and run hunts | Zero users. Solves no problem the product currently has. | Someone actually asks for agent-driven investigation |
| `compliance.py` | SOC 2 / ISO evidence report generator (MTTR, coverage, audit trail) | Generating compliance evidence for a product with no customers and no certification is theatre. | A real audit is scheduled |
| `wireguard.py` | WireGuard config generation | Valkyrie is not a VPN product. Scope creep, support burden, and a security surface that cannot be audited by one person. | Never, most likely - this belongs in a different product |
| `multihop.py` | Two-hop VPN chaining | Same as above. | Same as above |

## What was NOT moved, and why

- **`siem.py`** - stays in `valkyrie/`, but **frozen**: do not extend it. It is
  well built, off by default, and costs nothing to leave wired.
- **`edr/playbooks.py`** - stays and is actively used by the response path.
  Frozen in the sense that *no new automation* should be added until there is
  field false-positive data to justify arming any of it. All playbooks remain
  `dry_run`.
- **`edr/ai_provider.py`** - stays, off by default, explain-only. Correct as
  built; do not expand.

## Rules for this directory

1. **Nothing in `valkyrie/` may import from `experimental/`.** The dependency
   only ever points inward. A test enforces this
   (`tests/test_experimental_isolation.py`).
2. These modules are **not maintained**. They are not covered by the efficacy
   gate, the red-team evaluation, or the release checklist.
3. Do not add features here. If something here becomes worth having, the
   decision is to *unfreeze it deliberately* - move it back, wire it, test it,
   and write the ADR - not to keep editing it in place.
4. **Their tests moved here too (`experimental/tests/`) and do NOT run as-is.**
   They still `import valkyrie.fleet`, `valkyrie.mcp`, etc. - paths that no
   longer exist. Verified, not assumed: all four fail at import. Fixing those
   imports is part of the cost of unfreezing, and stating it here is cheaper
   than someone discovering it later and assuming the code is broken.
   `tests/test_edr.py` also carried one fleet-coupled privacy assertion; the
   core-relevant half (the EDR engine has no network transport of its own) was
   kept in `tests/test_edr.py`, and the fleet-heartbeat half retired with the
   fleet code.

See `docs/adr/0044-freeze-non-core-surface.md` for the full reasoning.
