# Signal-level breakdown - why 7 known trackers were missed

**Date:** 2026-07-07
**Scope:** diagnosis only. No thresholds, classifier logic, or signals were
changed. This documents what each existing signal contributed, per domain.
**Harness:** `diag_signal_breakdown.py` - drives the real
`DNSInterceptor._decide` pipeline (intelligence-only, `USE_EXTERNAL_LISTS=False`,
live process name), decomposes every sub-signal using the **real** signal
functions, and asserts the recomposed totals equal the pipeline's own output.

> Cross-check result: recomposed totals matched `_decide` for all 7 domains,
> including the lone non-zero score (`browser-intake-datadoghq.com` = 0.289).
> The numbers below are the pipeline's actual behaviour, not a re-implementation.

Thresholds every domain had to clear: **flag >= 0.40, block >= 0.70.**

## Stage 1 - SiteScanner signals (the primary decision-maker)

| domain | parses as (sld / first / #labels) | S1a tracker-SLD | S1b analytics-SLD | S2 prefix | S3 entropy | S4 rate | S5 sysproc | **scanner total** |
|---|---|---|---|---|---|---|---|---|
| tr.snapchat.com | snapchat / tr / 3 | 0 | 0 | 0 | 0 | 0 | 0 | **0.0** |
| cs.media.net | media / cs / 3 | 0 | 0 | 0 | 0 | 0 | 0 | **0.0** |
| l.sharethis.com | sharethis / l / 3 | 0 | 0 | 0 | 0 | 0 | 0 | **0.0** |
| events.reddit.com | reddit / events / 3 | 0 | 0 | 0 | 0 | 0 | 0 | **0.0** |
| browser-intake-datadoghq.com | browser-intake-datadoghq / (same) / 2 | 0 | 0 | 0 | 0 | 0 | 0 | **0.0** |
| segmentapis.com | segmentapis / (same) / 2 | 0 | 0 | 0 | 0 | 0 | 0 | **0.0** |
| taboolasyndication.com | taboolasyndication / (same) / 2 | 0 | 0 | 0 | 0 | 0 | 0 | **0.0** |

## Stage 2 - ThreatClassifier signals (runs because scanner returned allow)

anomaly.py contributions (each gated as in code) . threat-graph . behavioral.py (entropy.0.5 + rate.0.35 + age.0.15)

| domain | bg | heartbeat | app-closed | never-seen | timing-dev | asym | **anomaly** | threat-graph | beh-entropy (raw->x0.5) | beh-rate | beh-age | **beh total** | **FINAL** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| tr.snapchat.com | 0 | 0 | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 (label "tr" H=1.0) | 0 | 0 | 0.0 | **0.0** |
| cs.media.net | 0 | 0 | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 (label "cs" H=1.0) | 0 | 0 | 0.0 | **0.0** |
| l.sharethis.com | 0 | 0 | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 (label "l" H=0.0) | 0 | 0 | 0.0 | **0.0** |
| events.reddit.com | 0 | 0 | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 (label "events" H=2.25) | 0 | 0 | 0.0 | **0.0** |
| browser-intake-datadoghq.com | 0 | 0 | 0 | 0 | 0 | 0 | 0.0 | 0.0 | **0.577->0.289** (label H=3.89) | 0 | 0 | **0.289** | **0.289** |
| segmentapis.com | 0 | 0 | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 (label H=3.10, < 3.5) | 0 | 0 | 0.0 | **0.0** |
| taboolasyndication.com | 0 | 0 | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 (label H=3.31, < 3.5) | 0 | 0 | 0.0 | **0.0** |

**Only one non-zero signal fired across all 7 domains** (behavioral entropy on
`browser-intake-datadoghq.com`, 0.289 - still below the 0.40 flag line). Every
other cell is a hard zero. Six of the seven domains are shut out completely:
nothing fired at all.

## Per-signal verdict: tuning problem, or structural?

For each signal, "did it fire on any of these 7, and could tuning ever make it
fire on this domain class?"

| signal | fired here? | verdict on this domain class |
|---|---|---|
| **S1a tracker-SLD keyword** | no | **Structural.** Exact-membership set of 28 SLDs. These SLDs (snapchat, media, reddit, sharethis, ...) are deliberately excluded because their apexes are mixed-use - you can't add them without blocking the real sites. Cannot fire by design. |
| **S1b analytics-SLD keyword** | no | **Structural.** Same exact-match set. `segmentapis` != listed `segment`; `taboolasyndication` != `taboola`. Substring-near-misses do not match. |
| **S2 subdomain-prefix keyword** | no | **Structural.** This is the main behavioural catch. It only fires when the *first label* is exactly one of 9 words {tracker, tracking, telemetry, analytics, pixel, beacon, collect, adserver, adtrack}. Real labels here (`tr`, `cs`, `l`, `events`) aren't in the set; the 3 apex domains have no subdomain at all (needs >=3 labels). No threshold change reaches these - the set would have to grow, and short/ambiguous labels can't be added without false positives. |
| **S3 scanner entropy** | no | **Structural.** Gated to >=3 labels, and measured on the leftmost label. For subdomain trackers that label is the short prefix (`tr`,`cs`,`l`) -> low entropy. For apex trackers it's disabled entirely (parts=2). Blind to this class. |
| **S4 scanner rate / behavioral rate** | no | **Structural for name-based detection.** Requires >30 queries in 10 s from one *process* (not one domain). A DNS decision keyed on the domain name never has this; it's a volume signal about the process, not the tracker. Zero in single-query evaluation and irrelevant to identifying *which* domain is a tracker. |
| **S5 system-process** | no | **Structural.** Requires S2 to fire *and* the process to be a Windows system binary. S2 never fired; the client is a browser, not svchost. |
| **anomaly: background-process** | no | **Structural.** Fires only for known service/background binaries. Browser-origin tracker traffic is never "background." |
| **anomaly: heartbeat (+0.4)** | no | **Structural for one-shot / name lookup.** Needs >=4 regular-interval gaps -> >=5 repeat queries of the same pair. A first-contact name decision can never have this. Only meaningful for long-lived beacons, not for deciding a domain on sight. |
| **anomaly: app-closed (+0.5)** | no | **Structural.** Fires only when the querying process is dead. Trackers loaded by a live browser never trip it. (Note: a *fake* test process name would wrongly fire this - a test artifact we avoided by using the live name.) |
| **anomaly: never-seen (+0.3)** | no | **Structurally gated OFF.** Disabled while `is_learning()` is true - the first `LEARNING_PERIOD_DAYS = 7` days. In intelligence-only mode from a fresh baseline it is always off. Even after learning it fires on *any* first-seen pair, so it isn't tracker-specific. |
| **anomaly: timing-deviation (+0.2)** | no | **Structurally gated OFF.** Same learning gate, plus requires prior timing history. Off here. |
| **anomaly: asymmetric small payloads (+0.3)** | no | **Structural for one-shot.** Needs >=4 payload samples for the pair. Never available on first contact. |
| **threat-graph** | no | **Context-dependent, silent here.** Returns >0 only if a *related* domain was already blocked (same base domain / subnet / seen prefix). None of these 7 had a blocked sibling in the run, so 0. Not a name signal - it's a propagation signal that needs a prior catch. |
| **behavioral: entropy** | **once (0.289)** | **Fired, but it's a length/charset proxy, not a tracker signal - and still short of 0.40.** It hit only on the longest hyphenated label; `segmentapis`/`taboolasyndication` landed just under 3.5 and short subdomain labels score ~0. Raising sensitivity here would flag long benign hostnames (CDN/build hostnames) far more than trackers. |
| **behavioral: domain-age (x0.15)** | no | **Dead weight in this mode.** `python-whois` is not installed, so `_domain_age_days` returns `None` and the signal is unconditionally 0. Even installed, it needs network WHOIS - unavailable in the offline/intelligence-only posture this mode exists for. Structurally 0 here regardless of the domain. |

## Bottom line

**This is an architecture problem, not a threshold-tuning problem.**

- Six of the seven domains scored a **flat zero from every signal**. There is
  nothing to "tune up" - no signal produced a small-but-real contribution that a
  lower threshold would rescue. The one exception (0.289) came from an entropy
  signal that is really measuring *label length/charset*, not tracking, and it
  fired on the one domain with an unusually long hyphenated label.

- The only signals in the stack that actually *discriminate a tracker by name*
  are the exact-match keyword sets (S1a/S1b/S2). All seven domains sit outside
  those sets **by construction**: their registrable domains are mixed-use
  (snapchat.com, reddit.com, media.net...) so their SLDs can't be listed, and
  their subdomain labels aren't among the 9 recognised prefixes.

- Every other signal is either (a) **gated off during the learning window**
  (never-seen, timing-deviation), (b) **dependent on repeat/temporal
  observations** a name-based decision doesn't have (heartbeat, asymmetric,
  rate), (c) **keyed on process traits** that don't hold for browser-origin
  tracking (background, app-closed, system-process), (d) **propagation-only**
  and needing a prior catch (threat-graph), or (e) **dead offline**
  (domain-age / WHOIS).

So the miss is not "signals fired but fell short." For 6/7 it is "no signal was
ever structurally able to fire on a domain of this shape." Any fix has to add a
*new* discriminating signal for mixed-use-parent tracker subdomains (or a wider
independent list), not re-tune the existing ones.

Re-run: `python3 diag_signal_breakdown.py`
