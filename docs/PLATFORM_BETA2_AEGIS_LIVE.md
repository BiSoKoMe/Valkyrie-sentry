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

**QUALIFIED — 2026-08-31.** The live-fire run passed every predeclared
check on real, live-captured data. See "Beta 2: QUALIFIED" near the end of
this document for the full evidence trail and the two harness bugs found
and fixed along the way (both in the harness, not in Aegis/Valkyrie/NYX
themselves).

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
(QUALIFIED+audited) → Beta 1/NYX (QUALIFIED) → **Beta 2/Aegis (here) ←
CLOSED**.

## Beta 2.1: two harness bugs, found and fixed - neither in Aegis/Valkyrie/NYX

**First attempt**: captured 9 real events (7 process, 2 privacy, 0
network) but built a process-only chain (`subject_event_count=1`).
`_find_subject_pid()` picked the first chrome-shaped `process` event by
name, but a real Chromium launch is multi-process on Linux (a main
browser process plus separate renderer/GPU/network-service child
processes) - the pid that actually owned the connection Nyx observed was a
different child than the one the name-match heuristic happened to find
first. Separately, `NetworkCollector` caught zero connections - expected,
not a bug: a userland snapshot poller can legitimately miss a connection
that opens and closes faster than its poll interval, which this harness's
sub-second beacon round-trip usually does (the same honest limitation this
project's own network_telemetry.py module docstring already states).
Fixed by treating the real Nyx privacy event's pid as ground truth (it was
genuinely resolved against the real OS connection table via ADR 0057's
`pid_for_local_port()` at the moment of the real beacon), falling back to
a network event's pid, then the name-match heuristic only if neither
exists.

**Second attempt**: crashed with `AttributeError: 'dict' object has no
attribute 'to_dict'` - `evaluate_pair()` (`aegis_exposure.py:269`) already
converts each hypothesis decision to a plain dict before returning, exactly
matching how `platform_alpha_evidence_story.py`'s own usage already
(correctly) never calls `.to_dict()` on them; my code added a redundant,
incorrect call. Fixed by removing it.

## Beta 2: QUALIFIED — 2026-08-31

**Third attempt: PASS**, on real, live-captured data (3 subject events: 1
process + 2 privacy - the network collector legitimately missed the
sub-second connection, and the two real Nyx privacy observations carried
the chain instead). All 7 predeclared checks green, zero `[!]` lines
anywhere in the log, the Platform Alpha frozen-baseline regression (15
tests) unaffected:

- `real_chain_captured`: 3 real events for one real subject pid.
- `chain_spans_process_and_network_or_privacy`: process + privacy.
- `destination_observation_derived`: **2x DESTINATION, plus TIMING,
  FREQUENCY, and SEQUENCE** - richer than the fabricated Platform Alpha
  scenario, because two real privacy observations for the same subject
  (>=2 network-visible events) triggered `translate_session`'s
  timing/frequency/sequence derivation that a single-event chain can't.
- `unavailable_categories_never_fabricated`: VOLUME/DIRECTION/IDENTITY/
  SESSION never appeared.
- `non_network_events_produce_zero_observations`: held.
- `provenance_survives`: every observation traced to a real event id
  (`evt:70bbc273...` from the real process collector,
  `nyx_d93be54d...`/`nyx_5ed73d96...` from Nyx's own real event ids).
- `no_observe_errors`: zero.

**Beta 2 is genuinely done, not declared done.** Both bugs found during
this stage were in the NEW harness itself, not in Aegis, Valkyrie, or NYX -
the translation boundary Platform Alpha already proved over a fabricated
chain held up over a real one on the very first run where the harness
correctly identified the real subject. This is a smaller, more contained
proof than Beta 0.5/Beta 1 (a one-shot integration check of pure
translation logic, not a sustained-load reliability soak - there is no
long-running mechanism here to stress under duration), matching the scope
`docs/AEGIS_PLATFORM_BRIDGE.md` itself asked for: proof over real events,
nothing more.
