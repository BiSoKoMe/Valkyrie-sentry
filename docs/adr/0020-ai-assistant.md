# ADR 0020 - AI assistant: explainable, evidence-grounded, never a detector

Date: 2026-07-19 . Status: accepted

## Context

The platform's AI philosophy (docs/ARCHITECTURE.md): AI correlates,
explains, and recommends - it is never the only detector, and every
conclusion must be explainable. `edr/investigate.py` already had the
right skeleton (offline heuristic analyst always; Claude opt-in,
key-gated, fail-open to offline) but its AI output was free text with no
verifiable structure, no tie to the response actions Valkyrie ships, and
zero test coverage of the fallback modes.

## Decision

Upgrade `_ai_narrative` -> `_ai_analysis` (structured, auditable):

- **Structured output** via `output_config.format` (json_schema, non-beta,
  Claude Opus 4.8 / adaptive thinking): `assessment`, `confidence`
  (low|medium|high), `likely_technique`, `recommended_action` constrained
  by enum to the actions Valkyrie actually ships
  (`block_domain|kill_process|isolate_host|monitor_only`), and `evidence`
  - lines quoted from the provided facts.
- **Defense in depth**: even a schema-conforming reply naming an unshipped
  action is rejected and the report falls back to offline (tested with a
  `wipe_disk` reply).
- **Explain-only contract in the system prompt**: the model is told it is
  not a detector and detections stand without it; it may only reference
  provided facts. Facts remain the compact derived set (title, severity,
  categories, techniques, top indicators, detection titles) - no raw
  event dump, no browsing history.
- **Compatibility**: `ai_narrative` remains (mirrors `assessment`);
  consumers gain `ai_analysis`.

## Privacy & security analysis

- Opt-in per request (`use_ai=True` + key present); default path never
  touches the network. Sending incident details to the Anthropic API is
  the operator's explicit choice, disclosed in the module docstring.
- The AI cannot trigger responses: it *recommends* one action with a
  rationale; execution still goes through the audited human/playbook
  paths. The enum + post-parse guard bound what it can even suggest.

## Testing

`tests/test_ai_assistant.py` (14 checks, fully offline via a fake
Anthropic client): offline-always, missing-key honesty, structured
round-trip, request-shape assertions (json_schema, adaptive thinking,
compact facts, explain-only prompt), unshipped-action rejection, and
network-failure fallback.

## Rollback

`use_ai` defaults to False everywhere; removing the method restores
offline-only investigation with no other changes.

## Honest boundary

Single-incident explanation only - no cross-incident AI correlation, no
AI-assisted hunting query generation, no FP-reduction feedback loop.
Each is an extension of the same facts->schema pattern when justified.

## Update (2026-07-19) - vendor-neutral provider layer

The original implementation called the Anthropic SDK directly and read
`ANTHROPIC_API_KEY`. To remove single-vendor lock-in, the transport is now
abstracted behind `edr/ai_provider.py` (`AIProvider`): **Anthropic, OpenAI, a
local OpenAI-compatible server, and Offline** providers, all over plain HTTP
(`httpx`) - **no AI-vendor SDK dependency**. `investigate.py` depends only on the
interface and reports the provider name as `analyst`. The structured-facts ->
JSON-schema -> enum-guard -> offline-fallback contract above is unchanged and still
enforced (now provider-independently). Selection: `VALKYRIE_AI_PROVIDER` /
`VALKYRIE_AI_KEY` / `VALKYRIE_AI_MODEL` / `VALKYRIE_AI_BASE_URL`, with
`ANTHROPIC_API_KEY` / `OPENAI_API_KEY` honored as fall-backs (backward
compatible). Tests: `tests/test_ai_provider.py` (real request/parse per dialect
via a stubbed `httpx.post`, selection, JSON extraction) + the rewritten
`tests/test_ai_assistant.py` (seam behavior via an injected fake provider).
