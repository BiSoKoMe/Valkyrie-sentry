# ADR 0040 — Popular-domain false-positive floor

Date: 2026-07-28 · Status: accepted

## Context

A live DNS test on a real machine (Valkyrie installed, system DNS pointed at its
sinkhole) found it **blocking legitimate high-traffic domains**: microsoft.com,
bing.com, live.com, linkedin.com and paypal.com all resolved to `0.0.0.0`, while
trackers (doubleclick, google-analytics, criteo — 8/8) were correctly blocked.

Root cause, confirmed from the live `intel_memory` table: an older build's weak
**behavioural** heuristics — a per-process "query burst (N queries in 10s)" and
"domain never seen from this process" (fired by `WmiPrvSE.exe` and the like) —
scored these domains as suspicious. Because those signals reached the block
path, the domains were **persisted as `verdict='bad'`** in intelligence memory.
Memory is an O(1) fast path checked before the scanner/blocklist and *never
downgrades a bad verdict*, so every subsequent lookup was sinkholed — forever.
The `scan_cache` in the same DB correctly labelled all of them `legitimate`; the
learned-bad memory simply overrode it.

This is the worst failure mode for a single-user product: an EDR that blocks
paypal.com and Microsoft login gets turned off. Frequency and novelty are far
too weak to overrule the ground truth that paypal.com is PayPal.

## Decision

Add a curated **popular-domain floor** (`valkyrie/popular_domains.py`): a few
hundred registrable domains that are, by definition, not attacker infrastructure
(major OS/cloud, CDNs, banks, commerce, social, dev). `is_popular(host)` is a
boundary-safe suffix match (subdomains included; look-alikes excluded).

The floor is applied narrowly, at three points, and only to the *weak* paths:

- **`IntelligenceMemory.remember_bad`** refuses to store a popular domain as bad.
- **`IntelligenceMemory.check`** never serves 'bad' for a popular domain (defense
  in depth if an old verdict lingers).
- **`IntelligenceMemory.start`** SELF-HEALS: it purges any pre-existing popular
  'bad' rows from the DB on launch, so the fix takes effect the moment this build
  runs — the user's machine repairs itself on first start, no manual cleanup.
- **`ThreatClassifier`** downgrades a behavioural/anomaly BLOCK on a popular
  domain to a FLAG (still visible, never sinkholed).

Explicitly **out of scope of the floor** (still fully enforced): user
always-block rules, threat-intel IOC feeds, and the tracker/telemetry blocklist.
`telemetry.microsoft.com` stays blocked by the blocklist while `microsoft.com`
does not; trackers like doubleclick.net are deliberately absent from the floor.

## Consequences

- The entire class of "behavioural heuristic sinkholes a top legit domain" is
  closed, and existing damage self-heals on the next launch.
- `tests/test_popular_domains.py` pins it: matching + boundary safety, memory
  never learns/serves a popular domain bad, the start() purge (while a real C2
  verdict survives), and the classifier downgrade (while a non-popular domain
  with the same score still blocks). Efficacy gate holds 100% / 0%; trackers
  still block.

## Honest boundaries

- **It is a curated list, not a top-million.** A legit domain not on the list is
  still exposed to the same behavioural FP; the list grows as they surface. It is
  intentionally conservative — every entry must be one nobody could call
  malicious.
- **It masks, not fixes, the underlying weak signal.** The per-process
  "query burst" heuristic is a poor beacon detector (it counts a browser's
  page-load fan-out the same as C2 beaconing). The floor stops it from doing
  damage on known domains; a future change should make that signal count
  repeats of ONE domain (true beaconing) rather than per-process volume.
- **Running service must restart/reinstall to load the fix** — the guard lives in
  the engine; the currently-running older build keeps its cached verdicts until
  then.
