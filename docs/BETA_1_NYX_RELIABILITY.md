# Platform Beta 1 — Nyx Reliability Soak

## Qualification status

**OPEN, not yet run.** This document is the predeclared spec, written
*before* the real soak runs, same discipline as
`docs/BETA_0_5_TELEMETRY_RELIABILITY.md`. `redteam/evaluation/nyx_reliability.py`
implements exactly what this document says; if they disagree, the code has
a bug. Findings sections ("Beta 1.N: ...") get appended below only as real
CI runs actually surface them — nothing below "## Sequence" is written yet.

## What this qualifies, and what it does not

Nyx (`valkyrie/nyx.py` + `nyx_graph.py` + `tls_addon.py`/`tls_inspector.py`,
ADR 0050) already has two kinds of proof:

- `docs/NYX_ENFORCEMENT_SCORECARD.md` — 24 synthetic scenarios scored
  offline in one pass: 91.7% deception, 0 false positives.
- `nyx_live/nyx_live_test.py` — a real headless Chromium driven through the
  real mitmproxy addon, proving the mechanism actually deceives a real
  tracker endpoint. **Once.** One browser, 2 origins, 1 beacon each,
  ~1 minute.

Neither proves the pipeline survives **repetition and time**: many page
loads, many trackers, a long real session. That is what this qualifies —
does `TLSInspector`'s in-process mitmproxy addon stay alive and keep
deceiving *correctly* under a sustained real browsing session, the same
"coverage vs. reliability" split Beta 0.5 drew for the EDR telemetry
pipeline.

This does **not** re-measure detection coverage (that's the scorecard's
job), does not test `TrackerGraph` correlation (not wired into the addon's
hot path — fed from stored events elsewhere), and does not change the
predeclared 91.7%/24-scenario evidence. A clean run here says Nyx's
observe/act pipeline does not degrade or go silently inert over time and
volume — nothing more, nothing less.

## Why CI, not the local machine

Same reasoning as Beta 0.5: a disposable, independently-reproducible
runner is the only environment whose result means anything beyond "worked
on this machine, this once." `nyx-live.yml` already runs on
`ubuntu-latest` (Nyx/farble/the proxy are cross-platform, no Sysmon
dependency) — this reuses the identical runner class and install steps
(mitmproxy + Playwright + Chromium).

## Workload

Runs entirely in-process (unlike the EDR soak, there is no subprocess to
boot and no HTTP API to poll — the harness holds the real `TLSInspector`
object directly, the same shape `nyx_live_test.py` already uses). One real
Playwright Chromium browser is launched once; the harness then opens a
fresh page per "visit" for the run's duration, cycling round-robin through
4 visit kinds — every one built from the *existing, already-proven*
`nyx_live/page.html` via query parameters only, so `nyx-live.yml` itself
stays provably unaffected:

1. **unauthorized-tracker-1** — beacons personal data to `tracker.test`
   (third party) → must be faked.
2. **unauthorized-tracker-2** — a *second*, distinct tracker domain
   (`tracker2.test`) → must also be faked. Covers "many trackers," not one.
3. **authorized-first-party** — beacons back to the page's *own* origin →
   must be left byte-identical (Nyx's "your login to the site you're on is
   yours" invariant).
4. **benign-no-personal-data** — a third party, but the beacon carries no
   personal data at all (`page.html`'s additive `nopersonal=1` flag) → must
   be left untouched, and must never be falsely flagged.

## What is sampled, continuously, for the whole run

Every ~2 seconds (background thread, streamed to JSONL immediately —
crash-proof, same convention as Beta 0.5): `TLSInspector.is_running()`,
this-process CPU/RSS/VMS/thread/handle counts (this harness's own process
*is* what needs watching — Nyx's mitmproxy addon runs same-process, ADR
0057), and `Store.queue_stats()` (depth + dropped-event count — a real,
previously-invisible fragility point this qualification's own prep work
found and instrumented: `Store.log()` silently drops on a full queue with
no counter). Every ~30 seconds, `nyx.self_test()` — a cheap, deterministic
5-case canary that exercises the real `inspect_outbound`/`fake_outbound`
pipeline directly, to catch the pipeline going silently inert the way ADR
0057 documented it already could (a wiring bug once fully disabled Nyx's
observe/act logic with no visible error, silently swallowed by the addon's
broad exception handling). Every visit's own outcome (which kind, was the
real value ever seen at the tracker endpoint, was it faked, was an
authorized/benign flow altered) is recorded as it happens, not just tallied
once at the end.

## Predeclared PASS criteria

- **`proxy_alive_throughout`** — `is_running()` true at every sample.
- **`zero_real_value_leaks`** — the real per-visit value is never observed
  at any tracker endpoint, across every unauthorized visit in the whole run.
- **`every_unauthorized_visit_deceived`** — every unauthorized visit was
  faked, not just some.
- **`authorized_benign_flows_unaltered`** — every authorized/benign visit's
  received body is byte-identical to what was sent.
- **`persona_consistent_throughout`** — the same fake value is used
  throughout (no drift/rotation mid-run).
- **`nyx_self_test_stable`** — every periodic `self_test()` call reports
  the same caught/faked/total counts as the first.
- **`no_process_crash`** — the harness completes the full run (a crash
  still scores whatever was collected before it, same crash-proof
  discipline as Beta 0.5).

Non-gating / exploratory on this first pass (no threshold exists yet — the
same honesty Beta 0.5 used for its own first CPU-trend measurement before
it had a real baseline to compare against): `resource_trend` (this-process
RSS/handle count, first vs. last vs. max) and `store_queue_trend` (queue
depth and drop count over the run).

## Independent runs

`soak` mode runs on **3 independent fresh GitHub Actions runners** (matrix),
never one — the same "a single clean run on shared CI is weak evidence
alone" principle behind every prior qualification in this project.

## Sequence

Platform Alpha (locked) → Beta 0 (startup deafness, resolved) → Beta 0.5
(telemetry reliability, QUALIFIED + audited) → **Beta 1 (Nyx reliability,
here)** → Beta 2 (Aegis). Do not start Beta 2 until this closes.
