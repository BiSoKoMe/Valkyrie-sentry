# Bucket-B signal design — categorization + proposal (Phase 1)

**Date:** 2026-07-07 · **Status: STOP — awaiting design approval before any
Bucket-B detection code is written.**
**Harness:** `diag_bucket_categorize.py` (each domain confirmed in EasyPrivacy,
absent from seed, then run through the real `_decide` pipeline in isolation).

## Held-out set

40 EasyPrivacy-confirmed trackers, none in `seed_blocklist.py` (0 ground-truth
violations), including all 7 original accuracy-test misses. Split by the
decision rule:

> **Bucket A** — the registrable parent (eTLD+1) exists *only* to serve
> tracking/ads/analytics/telemetry. Safe to ship in the seed list.
> **Bucket B** — the tracker is a subdomain of a **mixed-use** parent people
> intentionally visit (snapchat.com, reddit.com…). Listing the parent SLD would
> break the real site.

15 Bucket A · 25 Bucket B.

## Result on the current pipeline (post Phase 0)

| | count | caught now | missed |
|---|---|---|---|
| Bucket A | 15 | 0 | **15** |
| Bucket B | 25 | 4 | **21** |
| **total** | **40** | **4** | **36** |

The only 4 caught are Bucket B whose subdomain label happens to be a listed
prefix (`analytics.yahoo.com`, `analytics.pointdrive.linkedin.com`,
`analytics.m7g.twitch.tv`, `beacon.dropbox.com`). Every Bucket A domain is
missed; 21/25 Bucket B are missed.

## Q1 — How many misses are Bucket A vs Bucket B?

**Of 36 misses: 15 Bucket A (42%) and 21 Bucket B (58%).**

**A wider *shipped* seed list closes the entire Bucket A column — 15/15 — with
no new architecture and zero FP risk** (these are dedicated tracker domains;
adding `media.net`, `sharethis.com`, `taboolasyndication.com`,
`segmentapis.com`, `browser-intake-datadoghq.com`, `posthog.com`,
`fingerprint.com`, … is exactly what the seed already does for `mixpanel.com` /
`segment.com` / `hotjar.com`). This is the higher-ROI move and should come
first.

Concretely on the **15-tracker accuracy test**, 5 of its 7 misses are Bucket A
(`cs.media.net`, `l.sharethis.com`, `browser-intake-datadoghq.com`,
`segmentapis.com`, `taboolasyndication.com`). Adding them to the seed lifts
that test from **recall 8/15 → 13/15 (0.53 → 0.87), FP still 0** — before any
Bucket-B work. The remaining 2 (`tr.snapchat.com`, `events.reddit.com`) are
Bucket B and are what actually needs a new signal.

> Note: Bucket B is *partially* list-addressable by shipping exact FQDNs
> (`tr.snapchat.com`), since seed matching blocks a host + its subdomains, not
> its parent. But exact-host lists don't generalize to rotating/novel subdomains
> — which is the whole point of behavioural detection — so Bucket B is where a
> context signal earns its keep.

## Q2 — What context does Valkyrie actually have at DNS decision time?

**It sees (DNS layer, `_decide` inputs):**
- the **hostname** (`qname`),
- the **process** via `process_watcher` (name, pid, path),
- **timing/history** via the baseline: per-`(process, domain)` timestamps,
  inter-query gaps, payload sizes, hit counts,
- the **DNS query payload size**.

**It does NOT see, at the DNS layer:** the referring page, the URL path, HTTP
headers, or whether a request is first- vs third-party. That distinction is an
HTTP/browser-layer fact — and it is exactly how EasyPrivacy itself classifies
(`$third-party` option). DNS sees a bare name with no page context.

**Could the TLS inspector supply real first/third-party context?** In principle
yes: `tls_inspector.py` runs mitmproxy in-process and `tls_addon.py` holds the
full `flow.request`, so it *could* read the `Referer`/`Origin` headers and
derive true first-party vs third-party (it does not read them today). But that
path is **not available in the mode this work targets**:
- it needs mitmproxy installed *and* the Valkyrie root CA installed and trusted
  on every device (a heavy manual opt-in the code itself flags), whereas the
  intelligence-only DNS sinkhole is the zero-config, offline default;
- the addon runs in a separate mitmproxy worker that talks to the rest of
  Valkyrie only through the `Store`, so it can't feed a per-query score into the
  DNS `_decide` path in real time.

So for the **DNS layer specifically, the only honest proxy for "third-party
tracker loaded by a page" is temporal co-occurrence**: tracker domains resolve
in a burst, from the same process, right after a main site is loaded.

## Q3 — Proposed Bucket-B signal (DNS-layer, given the real constraints)

**Signal: third-party co-occurrence + cross-anchor ubiquity (learned).**

1. **Anchor detection.** When a process resolves a domain the user navigated to
   (heuristic: a domain that scored *allow* and is itself the eTLD+1 the process
   is "sitting on"), treat it as the current first-party **anchor** for that
   process.
2. **Co-occurrence window.** Domains resolved by the **same process** within a
   short window (~1–3 s) after the anchor, whose **eTLD+1 differs** from the
   anchor's eTLD+1, are third-party candidates. (Same-eTLD+1 subdomains like
   `cdn.example.com` behind `example.com` are excluded — not third-party.)
3. **Cross-anchor ubiquity (the real discriminator).** The baseline learns, per
   candidate domain, the **set of distinct anchors** it has appeared behind.
   A domain that rides behind **many unrelated first-parties**, is never
   navigated to directly, and isn't infrastructure is behaving like a tracker —
   which is precisely the manual signal EasyList authors use.

### The FP problem, stated plainly, and the guards

A naive co-occurrence signal **would wrongly flag legit CDNs** (Fastly,
Cloudflare, jsDelivr, `fonts.gstatic.com`, Akamai) — they also load in a burst
behind every page and behind many anchors. The zero-FP result is preserved by
**all** of the following, not any one alone:

- **G1 — shipped infrastructure/CDN allowlist.** A static, offline set of
  CDN/first-party-infra suffixes is exempt: co-occurrence never scores an
  allowlisted domain. (Mirrors the existing `MS_TRUSTED_ROOTS` pattern.)
- **G2 — reuse the existing known-good promotion.** Domains promoted to
  known-good after `INTEL_GOOD_AFTER_ALLOWS` clean allows are exempt, so common
  benign infra self-clears.
- **G3 — never block on co-occurrence alone; flag-band only.** Co-occurrence
  contributes a partial score capped **below the block threshold**. It can reach
  *block* only in combination with a second independent positive signal (tracker-
  y label, small fixed-size beacon payload). Alone it is at most a flag.
- **G4 — ubiquity gate.** No contribution until a candidate has been seen behind
  **≥ N distinct anchors** (proposed N≈3). One co-occurrence is nothing; riding
  behind 3+ unrelated sites is the tracker signature. This also means the signal
  is **temporal/learned, not first-contact** — stated honestly below.

### Expected recall gain — and an honesty caveat about measuring it

- **Bucket A (seed widening):** measurable now. 15-tracker accuracy test
  **0.53 → 0.87, FP 0**. This is separate from the Bucket-B signal and worth
  landing first.
- **Bucket B (co-occurrence signal):** targets the 21 Bucket-B misses (incl.
  `tr.snapchat.com`, `events.reddit.com`). But because it is **temporal**, it
  **cannot register on the current single-shot `test_scanner_accuracy.py`** —
  that harness resolves each domain once, with no page-load burst, so a
  co-occurrence signal correctly contributes 0 there. Reporting "before/after"
  for Bucket B therefore requires **extending the test** with a co-occurrence
  scenario (simulate a benign anchor + a burst mixing real CDNs and the tracker,
  and assert the tracker flags while the CDNs do not). The existing 15+15
  single-shot test stays as the **FP guard** and must still show FP=0.
  Estimated reachable Bucket-B recall once ubiquity is learned: the ~21 misses
  that recur cross-site; genuinely single-site or first-visit trackers remain
  out of reach at the DNS layer without the TLS/Referer path.

### Honest limitations
- First-contact / low-traffic trackers won't be caught until ubiquity is learned
  (by design of G4). This is a latency/coverage tradeoff taken to protect FP.
- Anchor detection at the DNS layer is heuristic (no real navigation event); a
  process that legitimately talks to many unrelated APIs could resemble anchors.
  G1–G4 are what keep that from producing false positives.

## Recommendation

1. **Land Bucket A first** — widen the shipped seed with the 15 dedicated
   trackers here (+ a periodic curated top-up). Re-run 15+15: expect 0.53→0.87,
   FP 0. Highest ROI, no architecture.
2. **Then** build the co-occurrence + ubiquity signal for Bucket B with guards
   G1–G4, plus a new co-occurrence test alongside the preserved single-shot FP
   test.

**Stopping here for approval of the Bucket-B design before implementation.**
