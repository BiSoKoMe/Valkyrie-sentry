# ADR 0034 - Site content analyzer (judge the page, not the name)

Date: 2026-07-28 . Status: accepted

## Context

The owner's north star is that Valkyrie "detects its own" - genuinely analyses a
site rather than matching its name against a list. The DNS layer already judges a
domain by NAME and BEHAVIOUR (tracker SLDs, DGA structure, query-stream shape,
CNAME uncloaking), which is real analysis - but it never looks at what the page
actually *contains*. A site can be malicious with a clean-looking name and reach
no list. The missing half is content analysis: fetch the page and score what it
loads and runs, the way an analyst decides "this site is sketchy."

## Decision

New `valkyrie/site_analyzer.py` - a genuine, list-free content analyzer.

- `analyze_content(html, url)` is a PURE scorer over the delivered HTML + inline
  JS. Signals, all content-based:
  - **Cryptomining** - in-browser miner signatures (0.9, block).
  - **Phishing / credential harvest** - a password field whose form posts
    cross-origin (0.8), or a big-brand impersonation on an unrelated domain with
    a login form (0.6).
  - **Browser fingerprinting** - canvas / WebGL / AudioContext / font-enum /
    hardware-probe techniques; one is normal, 3+ together is the signature of a
    fingerprinting library (0.7 block; 2 -> 0.45 flag).
  - **Obfuscated JS** - `eval(atob())` decode-execute (0.7), packer (0.55),
    `String.fromCharCode` spam / `document.write(unescape())` (0.45).
  - **Tracker density** - distinct third-party hosts, INFORMATIONAL: it
    annotates the category but never flags on its own (a site's own CDN domains
    count as third-party, so density alone is too noisy).
  - Hidden cross-origin iframes / immediate off-site meta-refresh (0.2 each).
- `SiteAnalyzer.analyze_url` is the isolated, opt-in fetch layer over httpx
  (tight timeout, size cap, cache). It fails OPEN - a fetch error yields a clean
  not-fetched verdict, so analysis can only ever add signal, never break
  browsing. It never runs on the DNS hot path.
- Exposed on-demand via `valkyrie --analyze <url>`.

## Consequences

- Valkyrie can now genuinely inspect a site's content and catch miners,
  phishing, fingerprinting and obfuscated-malware pages that no name list and no
  structural signal would flag - the "analyse the site itself" capability the
  owner asked for.
- `tests/test_site_analyzer.py` pins each malicious shape to its verdict AND the
  false-positive boundary (a clean bakery page and a same-origin login page both
  allow). Verified end-to-end against live sites: example/cnn/nytimes/github/
  wikipedia all ALLOW (tracker note), with the calibration that produced them
  driven by real output (e.g. cnn.com was mislabelled "malware" by an early
  high-entropy-blob heuristic that was removed because minified bundles look
  identical).

## Honest boundaries

- **Static, not dynamic.** It reads delivered HTML + inline JS; it does not
  execute JavaScript, so runtime-assembled or lazily-fetched payloads are missed.
- **Cloaking defeats it.** A site can serve benign content to Valkyrie's fetcher
  and malware to real browsers via bot detection.
- **Density is a weak proxy.** Without a CDN allowlist it counts a site's own
  asset domains as third parties, which is why it is informational-only.
- **On-demand, not inline.** Fetching is slow and makes Valkyrie's own requests;
  wiring it as async first-contact analysis with caching is a later step. It
  complements - never replaces - the name/behaviour layers.
