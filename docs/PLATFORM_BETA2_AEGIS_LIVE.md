# Platform Beta 2 -- Aegis Live-Fire Proof

**Evidence class:** real, in-process, live-host integration -- a real
Playwright Chromium process, real `ProcessCollector`/`NetworkCollector`
polling the real OS process/connection tables, a real `TLSInspector`/Nyx
addon, feeding a real `DetectionArchitectureV2` instance. Not a live
production deployment (this harness constructs its own collectors/engine
components in-process, the same shape `nyx_reliability.py` and
`nyx_live_test.py` already use), and not a sustained soak.
**Independent:** no.

## Qualification status

**OPEN.** This document is the predeclared spec. `redteam/evaluation/
platform_beta2_aegis_live.py` implements exactly what it says. Findings get
appended below only as real CI runs surface them.

## Research question

`docs/AEGIS_PLATFORM_BRIDGE.md` ("Platform Alpha") proved the
`CanonicalEvent -> ExposureObservation` translation boundary
(`valkyrie/aegis_bridge.py`) over ONE hand-built, fabricated-but-
structurally-real event chain. Its own closing line named what remained:
*"It does not prove browser-complete mediation, production network
enforcement, or live-host reliability -- those remain the next
environmental wall, named rather than simulated."*

This asks: does the identical pipeline (`DetectionArchitectureV2` ->
`aegis_bridge.translate_session` -> `aegis_exposure.evaluate_pair`) hold up
over a REAL causal chain -- a real browser process, a real network
connection, a real Nyx privacy observation, all attributed to the same
process instance by the real collectors and the real ADR-0057 causality
attribution -- instead of three hand-constructed `TelemetryEvent` objects?

This is a narrower question than a full live-engine deployment test: it
does not stand up the packaged `python -m valkyrie` engine subprocess (no
new introspection surface was added to it for this), and it is not a
sustained-load reliability soak the way Beta 0.5/Beta 1 are --
`DetectionArchitectureV2`/`aegis_bridge` are pure translation logic with no
long-running state (no proxy thread, no poll loop) to stress under
duration the way a mitmproxy addon or a periodic collector does.

## What this qualifies, and what it does not

Qualifies: the SAME properties `platform_alpha_evidence_story.py` already
checks over a fabricated chain, checked instead over a chain built from
real collector output --

- A real network-visible event (a real outbound connection, a real Nyx
  privacy disclosure) correctly produces a DESTINATION observation.
- A real non-network event (a bare process launch) produces ZERO Aegis
  observations, even though Valkyrie itself may reason about it.
- VOLUME, DIRECTION, IDENTITY, SESSION never appear in the real
  translation output (`aegis_bridge.UNAVAILABLE_CATEGORIES`).
- Aegis's own reasoning cannot alter Valkyrie/NYX's fused decision.
- Every Aegis observation's provenance traces back to a real event id.

Does not qualify: a working Aegis MITIGATION mechanism (Aegis 1A/1B were
both already tried and falsified; Aegis 2-4 are reasoning-only, by their
own stage descriptions -- there is no standing mechanism to reliability-
soak the way Nyx's observe/act pipeline was for Beta 1), browser-complete
mediation of a real production deployment, or anything about
`CanonicalEvent`'s schema itself (unchanged, per Platform Alpha's own
constraint).

## Scenario

One real causal chain, matching `build_shared_chain()`'s shape in
`platform_alpha_evidence_story.py` but built from real activity instead of
three hand-constructed events:

1. A real headless Chromium process launches (Playwright), proxied through
   a real `TLSInspector`/Nyx addon.
2. It navigates to a real HTTP page and sends a real beacon to a real
   third-party tracker host, through the real proxy -- generating a real,
   unauthorized Nyx privacy observation attributed to the browser's real
   pid via the real ADR-0057 `pid_for_local_port()` causality attribution.
3. The real `ProcessCollector`/`NetworkCollector` (both already polling in
   the background, matching production wiring) observe the same browser
   process launching and connecting.

All three real event sources are fed into one real `DetectionArchitectureV2`
instance, in timestamp order, then through `translate_session` and
`evaluate_pair` -- identical pipeline shape to the fabricated version,
different (real) inputs.

## Predeclared PASS criteria

- **`real_chain_captured`** -- at least 2 real events were captured for the
  one real subject (the browser process).
- **`chain_spans_process_and_network_or_privacy`** -- the real chain is not
  process-only; it includes a real network or privacy event too.
- **`destination_observation_derived`** -- the real network/privacy event(s)
  produced a real DESTINATION observation.
- **`unavailable_categories_never_fabricated`** -- VOLUME, DIRECTION,
  IDENTITY, SESSION never appear in the real output.
- **`non_network_events_produce_zero_observations`** -- a real process-only
  event never becomes Aegis evidence.
- **`provenance_survives`** -- every real Aegis observation traces back to
  a real canonical event id.
- **`no_observe_errors`** -- `DetectionArchitectureV2.observe()` never
  raised on any real event in the chain.

## Sequence

Platform Alpha (the fabricated-chain proof, locked) → Beta 0 → Beta 0.5
(QUALIFIED+audited) → Beta 1/NYX (QUALIFIED) → **Beta 2/Aegis (here)**.
