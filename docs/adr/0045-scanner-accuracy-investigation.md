# ADR 0045 — Scanner accuracy investigation: recall 0.333 → 0.933

Date: 2026-08-04 · Status: accepted

## The reported failure

`tests/test_scanner_accuracy.py` measured **recall 0.333** against a gate of
0.85, on 15 EasyPrivacy-confirmed trackers. Precision was 1.000 and false
positives 0. First step was to confirm it was not caused by recent work: the
entire working tree was stashed and the test re-run on the clean baseline —
**identical 0.333**. Pre-existing, not a regression.

## What failed

**The measurement, not the scanner.**

Scoring the ten "missed" domains directly through `SiteScanner._score`:

```
analytics.tiktok.com      block  0.70  tracker subdomain prefix: analytics
analytics.pinterest.com   block  0.70  tracker subdomain prefix: analytics
analytics.yahoo.com       block  0.70  tracker subdomain prefix: analytics
analytics.adobe.io        block  0.70  tracker subdomain prefix: analytics
beacon.dropbox.com        block  0.70  tracker subdomain prefix: beacon
pixel.byspotify.com       block  0.70  tracker subdomain prefix: pixel
segmentapis.com           block  0.70  tracker SLD prefix match
taboolasyndication.com    block  0.70  tracker SLD prefix match
events.reddit.com         allow  0.00  (nothing)
marketing.dropbox.com     allow  0.00  (nothing)
```

Eight of ten were **detected at full confidence**. Tracing the full pipeline
showed why they read as misses — `dns_interceptor._decide` stage 3:

```python
if should_deceive(result.category, _current_profile()):
    return "deceived", reason, result.confidence, result.category
```

A detected **tracker** in the Standard profile is **DECEIVED** — sinkholed to a
decoy dead-end so the calling application keeps working — rather than
hard-blocked. For a tracker that is the *preferred* outcome.

The test classified a positive as:

```python
def positive(dec: str) -> bool:
    return dec in ("blocked", "flagged")
```

`"deceived"` is neither. **Every successful deception was scored as a miss.**

## Why it failed

The test predates the DECEIVE mechanism. When a fourth verdict was added to the
pipeline, nothing failed loudly — an enumerated list in a test simply went
stale and the metric began under-reporting by 60 points.

That is the real defect, and it is structural: **a test enumerated a vocabulary
the product owns.** A detection-quality metric that silently under-reports is
worse than no metric, because it gets believed. It also invites the opposite
error — "fixing" a healthy detector to chase a broken number.

## Is the algorithm wrong?

**No.** The scanner scored 8/8 correctly at 0.70 with zero false positives
across 699 benign domains. `analytics`, `pixel` and `beacon` were already in
`TRACKER_PREFIXES`; the SLD-prefix signal correctly caught `segmentapis` and
`taboolasyndication`.

## Is the dataset wrong?

**No.** Ground truth is EasyPrivacy, independent of Valkyrie's own lists, and
every label checked out. Two genuine coverage gaps existed:

- **`marketing.dropbox.com`** — genuine miss. `marketing.<company>.com` is
  marketing-automation infrastructure in every observed case, and the prefix
  has zero hits across the 699-domain benign corpus. **Added.**
- **`events.reddit.com`** — genuine miss, **deliberately not fixed.**
  `events.reddit.com` is an event-collection endpoint, but `events` is
  ambiguous as a first label: `events.linuxfoundation.org`,
  `events.microsoft.com` and `events.google.com` are conference *websites*. As
  a +0.7 block-alone signal this would break real browsing — the exact
  false-positive class that produced ADR 0040. Precision over aggression: one
  documented miss beats a rule that kills conference sites. Revisit only as a
  weak combining signal requiring corroboration.

## The regression test

`tests/test_verdict_vocabulary.py` fixes the *class* of bug, not the instance.
It pins the product's verdict vocabulary and asserts every consumer covers it:

1. `_decide` emits only verdicts from a declared set;
2. the accuracy test's `POSITIVE_VERDICTS` covers every acted-on verdict;
3. `deceived` is genuinely a sinkhole path, not a pass-through.

**It found a second instance on its first run.** `"behavioral"` is a *fifth*
verdict — returned from the legacy fallback path when the scanner is not wired,
and treated as blocking by `dns_interceptor` (`decision in ("blocked",
"behavioral", "deceived")` gates the sinkhole). It would have caused the
identical under-reporting the moment that path was exercised. Now covered in
both the vocabulary set and `POSITIVE_VERDICTS`.

`store.py`'s `DnsEvent.decision` comment was also stale — it documented four
verdicts and never learned about `deceived`. Corrected.

## Result

| | Before | After |
|---|---:|---:|
| Recall | 0.333 | **0.933** |
| Precision | 1.000 | **1.000** |
| False positives (15 benign) | 0 | **0** |
| Benign corpus (699 domains) | 0 blocked | **0 blocked** |
| Genuine misses | — | **1** (`events.reddit.com`, documented above) |

Gate passes. No detection logic was weakened to achieve it: one prefix added
with measured FP cost, one measurement corrected, one latent instance of the
same bug found and closed.

## Lesson

Two of this session's findings share a root cause: **the sensor was fine and
the measurement was lying.** Here a stale verdict list under-reported recall by
60 points; in ADR 0043 a stale `delivery` label under-reported the red-team
score. Both were found by checking the measurement against the product rather
than trusting the number. Metrics need regression tests as much as detectors do.
