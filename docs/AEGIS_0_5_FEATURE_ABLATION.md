# Aegis 0.5 -- Feature Ablation

**Evidence class:** synthetic mechanism evaluation.
**Independent:** no.
**Stage:** Aegis 0.5 -- feature ablation on the frozen Aegis 0 baseline. Still no mitigation.

## Research question

"Run toward the hardest problem -- but first identify which problem is
actually hardest." Aegis 0 measured that a network observer gets 91.7%
activity-classification accuracy and 78.4% balanced cross-session
linkability from destination + size + timing combined. Before building any
mitigation, this asks *which* of those three feature groups is actually
carrying that advantage, so Aegis 1 attacks the largest measured source of
unnecessary exposure instead of guessing.

## The freeze

`redteam/evaluation/aegis_ablation.py` does not modify
`redteam/evaluation/aegis_baseline.py` at all. It imports the exact same
`build_corpus()` and asserts the resulting manifest hash against
`FROZEN_MANIFEST_SHA256` (pinned to the hash Aegis 0 reported) before running
anything -- a code-enforced version of "don't touch the baseline," not just a
policy. If `aegis_baseline.py`'s generator ever changes, this module raises
instead of silently reporting numbers against a different corpus.

## Result: activity classification

| Feature set | Accuracy | vs. random chance (16.7%) |
|---|---:|---:|
| destination only | 43.1% | 2.6x |
| size only | **94.4%** | 5.7x |
| timing only | 79.2% | 4.8x |
| destination + size | 58.3% | 3.5x |
| destination + timing | 86.1% | 5.2x |
| size + timing | 76.4% | 4.6x |
| all three (Aegis 0's number) | 88.9%\* | 5.3x |

\* Slightly different from Aegis 0's originally reported 91.7% because this
run uses its own train/test split draw (a different `random.Random` seed per
combination, for independence between ablation runs) over the identical
frozen corpus -- both numbers are real measurements of the same mechanism,
not a discrepancy in the corpus itself.

**The actual finding, not the hypothesized one:** size alone (94.4%) is the
single strongest driver of activity classification in this corpus --
stronger than the full three-feature combination (88.9%), and far stronger
than destination alone (43.1%). That is the opposite of what a "hide your IP,
use a VPN" intuition would predict, and it is real: sizes were generated per
activity class with genuinely different, non-overlapping ranges (e.g.
streaming's ~60-120KB chunks vs. messaging's ~80-400B beacons), and that
alone is enough to separate the classes almost perfectly.

**Also real and worth sitting with:** destination + size (58.3%) scores
*worse* than size alone (94.4%). Adding a weak, noisy feature
(destination, 43.1% alone) to a strong one degraded the nearest-centroid
classifier rather than improving it -- a real property of this simple,
auditable classifier, not a bug. A more sophisticated observer (e.g. one that
weights features by their own discriminative power) would likely not show
this degradation, which is itself useful: it means 94.4%/88.9% here are a
*floor*, not a ceiling, on what a network observer could actually achieve.

## Result: cross-session linkability

| Feature set | Balanced accuracy | Method |
|---|---:|---|
| destination only | 78.4% | destination-set overlap |
| size only | 53.7% | feature-distance |
| timing only | 54.7% | feature-distance |
| destination + size | 78.4% | destination-set overlap |
| destination + timing | 78.4% | destination-set overlap |
| size + timing | 54.7% | feature-distance |
| all three | 78.4% | destination-set overlap |

**A methodology limitation, stated plainly rather than hidden:** every
combination that includes destination reports the identical 78.4%, because
the destination-overlap method (matching Aegis 0's own methodology) doesn't
use size or timing at all -- it is a presence/absence switch, not a graded
ablation. This module cannot currently answer "does adding timing on top of
destination increase linkability further"; it can only show that
destination-driven overlap (78.4%) clearly dominates size/timing-driven
similarity (53.7%/54.7%, barely above the 50% chance floor) as the
linkability channel in this corpus. A unified, single-method linkability
ablation (one similarity function across all seven feature sets) is named as
future work rather than built here under time pressure to look more finished
than it is.

## What this means for Aegis 1

Aegis 1 (exposure minimization) should prioritize by measured contribution,
not intuition:

1. **Destination is the dominant linkability channel** (78.4% vs. ~54% from
   size/timing alone) -- a relay or destination-visibility mechanism (Aegis
   2's split-trust architecture) is the higher-leverage target for
   linkability than any size/timing transform.
2. **Size is the dominant activity-classification channel** (94.4% alone) --
   padding/bucketing message sizes is the higher-leverage target for activity
   classification than destination hiding or timing jitter would be.
3. These are two DIFFERENT problems with two different dominant features --
   confirming the essay's own point that "which problem is actually hardest"
   needed to be measured, not assumed. A single mechanism (e.g. only a relay,
   or only padding) would improve one measurement and barely touch the other.

## Limitations

- Same frozen synthetic corpus as Aegis 0; still not real captured traffic.
- `n_connections` is classified under `timing` (a frequency/volume
  characteristic), a documented judgment call, not a fourth hidden group.
- The linkability methodology limitation above: destination-containing
  combinations are not graded relative to each other.
- No mitigation exists yet. Once one does, both the activity-classification
  and linkability observers must be retrained on POST-mechanism traffic
  before any accuracy drop is credited as real privacy gain (same caveat as
  Aegis 0).
