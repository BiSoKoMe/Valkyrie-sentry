# ADR 0005 - README truth-in-labeling

- **Status:** Accepted
- **Phase:** 0 (trust / accuracy)
- **Date:** 2026-07-12

## Context

The architecture audit found the README describing capabilities the code does not
have, which is the fastest way to lose the trust of exactly the technical buyers
(researchers, enterprises, governments) Valkyrie wants. Three overclaims:

1. **"full endpoint detection & response layer"** - the EDR console correlates
   only Valkyrie's own DNS/network decision stream. There is no kernel/process/
   file/registry telemetry. It is network-layer D&R, not endpoint EDR.
2. **"behavioral detection catches it by how it acts"** - the behavioral engine
   scores the *domain string* (entropy, query rate, TLD), not process behavior.
3. **"AI-assisted investigation - a local analyst"** - the default analyst is a
   deterministic, rule-based template, not a machine-learning model. (The only
   real AI is the opt-in Claude path, which is already disclosed.)

A security product's documentation is part of its threat model: if the README
overstates coverage, an operator trusts protection they don't have.

## Decision

Make the claims precise without deleting the (genuinely useful) features:

- EDR section now leads with "**detection & response** console" and adds an
  explicit, framed **scope note** stating it reasons over DNS/network telemetry,
  is not a kernel EDR, and that ETW/eBPF endpoint telemetry is on the roadmap.
- Behavioral claim rewritten to describe what it actually inspects - the *shape*
  of the DNS request (entropy, burst rate, abuse-prone TLD).
- "AI-assisted investigation" -> "**Automated investigation**", explicitly labeled
  deterministic/rule-based and fully offline, with Claude called out as the only
  real-LLM (opt-in) path.
- Plugin bullet now warns that plugins run with Valkyrie's privileges (arbitrary
  code) - load only trusted plugins; sandboxing is on the roadmap.
- Documented the ADR-0003 secure-by-default change: dashboard is loopback-only by
  default, with `--web-host 0.0.0.0` + control token to expose it. Added
  `--web-host` to the flags table.

## Change report

- **What changed:** `README.md` only.
- **Why:** align public claims with implemented reality; document the new secure
  dashboard default so upgrading users aren't surprised.
- **Security impact:** positive (indirect) - operators now understand the real
  coverage boundary and the plugin trust model, and learn how to expose the
  dashboard safely.
- **Performance impact:** none.
- **Compatibility impact:** none (documentation).
- **Risks:** none technical. The honest scoping is less flashy, but credibility
  with technical evaluators is the whole point of Phase 0.
- **Tests added:** none (docs). Full suite unchanged: 22 passed, 0 failed, 2
  skipped.
- **Rollback plan:** `git revert` the README commit.

## Consequences

The README now under-promises relative to the roadmap and over-delivers on
honesty - the trust posture recommended as the single highest-impact change in the
audit. As Phase 2/3 add real endpoint telemetry, the scope notes get promoted to
features, in step with the code.
