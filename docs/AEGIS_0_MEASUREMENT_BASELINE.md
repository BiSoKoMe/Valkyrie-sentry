# Aegis 0 -- Measurement Baseline

**Evidence class:** synthetic mechanism evaluation.
**Independent:** no.
**Stage:** Aegis 0 -- Measurement. No privacy transformation exists yet, on purpose.

## Research question

Aegis is a local network privacy authority, not another firewall and not
"spam fake packets until nobody can tell what's real." Its core question is:
for a legitimate connection, what information actually needs to be exposed,
and what can be removed, separated, or made harder to correlate? Before
answering that, Stage 0 asks the prerequisite question: **how much can an
untrusted network observer currently infer from controlled benign activity,
using only what is actually visible on the wire** -- destination, size,
timing, never process or app identity? If that isn't measured first, no
later claim that a mechanism "improves privacy" can mean anything.

## What this is, and is not

`redteam/evaluation/aegis_baseline.py` builds a deterministic synthetic
corpus of 240 sessions (40 each) across six controlled benign activities --
browsing, streaming, messaging, file sync, software update, background
telemetry -- and runs two measurements against a hand-built, auditable
nearest-centroid classifier (no ML library; every number can be traced by
hand, matching the "don't jump to AI" principle already applied to Detection
Architecture v2). This is not a live capture, and there is no mitigation to
evaluate yet -- it exists only to establish the number Aegis 1-3 must beat.

## Result

| Measurement | Value | Chance/floor |
|---|---:|---:|
| Activity classification accuracy | 91.7% (66/72 test sessions) | 16.7% (1/6 random) |
| Cross-session linkability, balanced accuracy | 78.4% | 50% (chance) |
| Cross-session linkability, raw accuracy | 69.6% | 93.8% (majority-class floor) |

The classifier clears random chance by a wide margin on activity
classification (5.5x), confirming it's a real adversary, not a strawman a
later mechanism could trivially "beat."

## The imbalance trap this harness had to guard against

Same-user session pairs are rare by construction next to different-user
pairs (94 vs 1,427 in this run), because a same-user pair requires the same
user AND the same activity. A naive "raw accuracy" reading would show ~94%
accuracy at a threshold that amounts to "always guess different-user" --
which is exactly the majority-class floor (93.8%), not evidence of real
linkability skill. The harness selects its threshold to maximize *balanced*
accuracy instead (mean of same-user recall and different-user recall) and
reports the majority-class floor alongside raw accuracy explicitly, so raw
accuracy can never be misread as skill. The honest comparison is balanced
accuracy (78.4%) against chance (50%) -- a real, moderate signal, not the
inflated-looking 69.6%/93.8% pair.

## Why this matters for what comes next

- **Aegis 1 (exposure minimization)** should move `mean_size`/`std_size`,
  destination diversity, and inter-arrival timing features closer between
  classes without breaking the connection -- re-running this exact harness
  after each change is the falsification test.
- **Aegis 2 (identity/activity separation)** should reduce
  `mean_same_user_overlap` toward `mean_different_user_overlap` by breaking
  the destination-set fingerprint a relay/split-trust route would hide.
- **Aegis 3 (traffic-analysis resistance)** is the only stage allowed to
  touch timing/size padding, and only after 0-2 are measured -- padding
  applied before a baseline exists is exactly the "add padding because
  privacy" mistake this project rejects.

## The step that matters most: retrain the observer knowing Aegis exists

A privacy mechanism that only beats a classifier that doesn't know the
mechanism exists is an illusion. Once any Aegis mechanism exists, this
harness's classifier must be retrained on POST-mechanism traffic (not just
re-run against pre-mechanism centroids) before any accuracy drop is credited
as real privacy gain. That retraining step does not exist yet, because there
is no mechanism yet to retrain against -- it is the required next step
before Aegis 1's own results doc can honestly claim anything.

## Limitations

- Synthetic corpus with a fixed generative model (`aegis_baseline._RECIPES`),
  not captured real traffic. This measures how classifiable this model of
  benign activity is, not a real machine's real traffic.
- The classifier is deliberately simple (nearest-centroid over 8 engineered
  features) so every number is auditable; a real network observer may use a
  stronger model, which would only raise these baseline numbers further.
- No mitigation exists yet -- there is nothing to credit or blame beyond the
  corpus's own inherent classifiability.
