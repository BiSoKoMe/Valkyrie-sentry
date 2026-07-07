# Behavioural scanner — real-world accuracy measurement

**Date:** 2026-07-07
**Mode:** intelligence-only (`USE_EXTERNAL_LISTS = False` — seed blocklist +
behavioural scanner + intelligence layer, no downloaded lists)
**Harness:** `test_scanner_accuracy.py` (drives the real
`DNSInterceptor._decide` pipeline, one live DNS decision per domain)

## What was measured

The client-facing claim under test: *"Valkyrie catches novel trackers that no
list has."* To test it honestly, every tracker in the sample is:

- **independently confirmed** by EasyPrivacy
  (`github.com/easylist/easylist`, 5,926 host rules parsed), **and**
- **deliberately absent** from Valkyrie's own `seed_blocklist.py` (checked in
  code, including parent-domain coverage).

So each is genuinely novel to Valkyrie. The clean control set is 15 benign
domains (OS projects, CDNs, reference sites) absent from *both* EasyPrivacy and
the seed list. Ground truth never comes from Valkyrie's own data.

## Results (forward query order)

| | predicted TRACKER | predicted CLEAN |
|---|---|---|
| **actual TRACKER** | TP = 8 | FN = 7 |
| **actual CLEAN**   | FP = 0 | TN = 15 |

- **Precision = 1.000**
- **Recall = 0.533**
- **F1 = 0.696**
- False positives on benign sites: **0 / 15**
- Novel trackers missed: **7 / 15**

Of the 8 catches: **6 hard-blocked**, **2 flagged**.

## The honest caveats

**1. Recall is really 40–53%, and the top of that range is order-dependent.**
Only 6 of the 8 catches are order-independent. The other 2
(`ct.pinterest.com`, `marketing.dropbox.com`) were flagged by the
intelligence **threat-graph** *because a sibling on the same base domain
(`analytics.pinterest.com`, `beacon.dropbox.com`) was blocked earlier in the
same run*. Re-running with the tracker order reversed drops recall to **0.40
(6/15)** — the true order-independent floor. This is the self-learning layer
working as designed (related infrastructure caught after a first hit), but it
cannot catch a tracker on first contact.

**2. The scanner's novel-detection is a 9-word allowlist.** A never-before-seen
tracker is hard-blocked only when its *first DNS label* is exactly one of:
`analytics, beacon, pixel, telemetry, collect, tracker, tracking, adserver,
adtrack` (or its SLD is in a ~44-entry hardcoded set). That is why the six
`analytics.*` / `beacon.*` / `pixel.*` hosts were caught and everything else
was not.

**3. What it misses** — all EasyPrivacy-confirmed trackers, all allowed:

| domain | why missed |
|---|---|
| `tr.snapchat.com` | label `tr` not a tracker-prefix; SLD not listed |
| `cs.media.net` | label `cs` not a prefix; SLD not listed |
| `l.sharethis.com` | label `l` not a prefix; SLD not listed |
| `events.reddit.com` | label `events` not a prefix; SLD not listed |
| `browser-intake-datadoghq.com` | apex; SLD is `browser-intake-datadoghq`, not `datadoghq`; scored 0.289 (< 0.4) |
| `segmentapis.com` | SLD `segmentapis` ≠ listed `segment` |
| `taboolasyndication.com` | SLD `taboolasyndication` ≠ listed `taboola` |

## Bottom line for the claim

- **True:** zero false positives — the default-allow design does not break
  legitimate browsing, and every catch on this sample was correct.
- **Overstated:** "catches novel trackers no list has" holds only for
  conventionally-named tracker subdomains (and infra-siblings of an
  already-caught tracker). It **misses roughly half** of independently-confirmed
  novel trackers whose names don't match the small prefix/SLD sets.
- **Recommendation:** do not market this as general novel-tracker detection.
  Either soften the claim, or widen coverage (e.g. score short single-letter/
  ambiguous subdomains of high-traffic SLDs, expand the prefix set, or make the
  seed/list layer the primary guarantee and the behavioural scanner the bonus).

Re-run: `python3 test_scanner_accuracy.py`
