# Platform Beta 1 — Nyx Reliability Soak

## Qualification status

**QUALIFIED — 2026-08-31.** The 3x15-minute soak passed 3/3 on independent
fresh GitHub Actions runners, every predeclared criterion green on all
three (~2,488 total visits combined, zero failures anywhere in any log).
See "Beta 1: QUALIFIED" near the end of this document for the full
evidence trail — two real product bugs were found and fixed along the way,
not smoothed over.

> **A THIRD bug of the same family surfaced later — 2026-09-03 — and this
> qualification did not catch it.** `nyx-live` leaked a real browser device
> id to the tracker, intermittently. Root cause: `fake_outbound()` applied
> its substitution map to the whole URL, so a beacon carrying `cores=8` put
> `"8" -> "4"` in the map and rewrote the tracker's **port**
> (`tracker.test:8111` → `:4111`). When the mangled port left 0-65535,
> mitmproxy's URL setter raised, the url/body/header rewrites shared one
> `try` block, and the body rewrite — where the real id was — never ran. The
> request went out RAW.
>
> Beta 1 fixed substitution-vs-*substitution*; this was
> substitution-vs-*URL structure*, which that fix never covered. **The soak
> could not have caught it**: it drives one origin on a fixed port and the
> collision needs a fingerprint value whose digits match the port's, so the
> bug is invisible unless the port happens to collide.
>
> The same single cause also produced what looked like unrelated CI
> flakiness — runs where 0 or 1 of 2 beacons "never arrived" were beacons
> sent to a valid-but-wrong port. Fixed in `_apply_repl_url()` plus
> independent per-part rewrites; verified 6/6 clean live runs with full
> delivery. See the commit for the full trail. Treat the 3/3 result below as
> real but **not** as evidence that this class of bug is exhausted.

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

## Beta 1.1: harness bugs (not Nyx) - a flawed test scenario, and CI contention

Before the harness was trustworthy, two non-Nyx issues had to be fixed:

1. The `benign-no-personal-data` visit's `nopersonal=1` body still carried
   screen/timezone/lang/cores fields. `nyx.py`'s fingerprint detector
   correctly treats each of those as an individually fake-able field
   (`_personal_values()`), independent of `inspect_outbound`'s own "3+
   signals" bundling threshold used only for the OBSERVE-side alert - so
   this was a real fingerprint disclosure by Nyx's own definition, not a
   benign one, and Nyx was correctly faking it. Fixed by sending a
   genuinely inert body (`event=pageview&ts=...`) for this visit kind.
2. Running the already-proven `nyx_live_test.py` immediately after this
   job's own resource-heavy dry-run/soak, on the same shared 2-vCPU
   runner, caused it to intermittently time out - reproduced 3/3 times in
   this job, then passed cleanly every time it was dispatched in
   isolation. Removed from this job; `nyx-live.yml` already runs
   independently on the same trigger paths.

## Beta 1.2: the card detector's Luhn-only gate

The first fully clean dry-run (2 min) still showed a small, reproducible
`authorized_benign_flows_unaltered` miss (2-4 of ~55 benign visits per
run). Traced to `nyx.py`'s payment-card detector: gated on a Luhn checksum
alone, on the documented assumption that Luhn was a precise-enough
boundary. It is not - Luhn's check digit is a mod-10 property, so an
arbitrary 13-19 digit number (here: a millisecond timestamp) has roughly a
1-in-10 chance of coincidentally passing it, and got faked into a card
number. Fixed by requiring Luhn AND (a card-shaped key name OR real
card-style grouping), matching the same contextual-gating philosophy every
other category already used. 4 new regression tests; all pre-existing
checks stayed green.

## Beta 1.3: the real finding - `_apply_repl` could corrupt a fake value

With the dry-run fully clean, the first real 3x15-minute soak failed
3/3 - EVERY unauthorized visit failed to be correctly deceived for the
whole run (some attempts showed 0% reaching the endpoint at all; others
showed 100% reaching but 0% carrying either the real or the fake value).
Root cause: `_apply_repl` applied each `(raw, fake)` substitution as its
own sequential `text.replace()` call. A real browser beacon normally fakes
MORE than one field per request (a device id AND a fingerprint bundle
together) - not an edge case. When it does, one substitution's OUTPUT can
contain a substring a LATER substitution's raw-value pattern matches,
corrupting an already-faked value: replacing `"16"->"8"` (cores) after a
screen field was already faked to `"3840x2160"` turned it into
`"3840x280"` (`"2160"` contains `"16"`). `self_test()` never caught this
because its 5 synthetic cases each exercise exactly one category in
isolation - never the multi-field shape a real request actually has.

Fixed by doing every substitution in ONE single regex pass (longest-raw-
value-first) instead of N sequential text passes, so an already-
substituted region can never be rescanned by a later pattern. Verified
0/3000 failures across random personas with a realistic multi-field body
(reproducible before the fix). A second, unrelated, already-latent ~8%
flake was found and fixed in the same pass: `test_nyx.py`'s own
fingerprint-bundle test hardcoded `"2560x1440"` as input, which happens to
be one of `persona.py`'s own weighted screen choices (weight 8 of ~100) -
a fresh CI persona seed matching it exactly would correctly skip the
now-redundant replacement, which the test wrongly read as a failure.

## Beta 1: QUALIFIED — 2026-08-31

**The real 3x15-minute soak, rerun with both fixes in place: 3/3 PASS.**
Every predeclared criterion green on all three independent runs:

| | Run 1 | Run 2 | Run 3 |
|---|---:|---:|---:|
| Total visits | 824 | 838 | 826 |
| Unauthorized visits deceived | 412/412 | 420/420 | 414/414 |
| Real-value leaks | 0 | 0 | 0 |
| Authorized/benign altered | 0/412 | 0/418 | 0/412 |
| Persona drift | 0/412 | 0/420 | 0/414 |
| self_test() drift | 0/31 | 0/31 | 0/31 |
| Proxy downtime samples | 0/452 | 0/452 | 0/452 |
| Process crashes | 0 | 0 | 0 |

Zero `[!]` (failing check) lines anywhere in any of the three full logs.
~2,488 total visits combined, zero real-value leaks, 100% deception rate,
zero false alterations of authorized or benign traffic.

**Beta 1 is genuinely done, not declared done.** The two real product
fixes that made this possible: the card detector's context-gating
(Beta 1.2) and `_apply_repl`'s single-pass substitution fix (Beta 1.3) -
the second one specifically a bug no prior test (scorecard, self_test(),
nyx_live_test.py) had ever caught, because none of them exercised a real
request faking more than one field at once, repeatedly, the way a
sustained real browsing session actually does. Per the sequence set at
the start of this work (Platform Alpha → Beta 0 → Beta 0.5 → **Beta 1 ←
closed here** → Beta 2/Aegis), development now proceeds to Platform
Beta 2.
