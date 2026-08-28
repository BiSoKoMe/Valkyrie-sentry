# ADR 0036 - Real-time content analysis, and farbling instead of constant lies

Date: 2026-07-30
Status: Accepted

## Context

Two capabilities that the product described itself as having were, on
inspection, not actually running.

**1. Content analysis was dormant.** `site_analyzer.py` genuinely scores a
page by what it loads and executes - cryptominers, fingerprinting scripts,
packed/obfuscated JS, phishing forms, hidden iframes, third-party density.
That is real analysis, and unlike a blocklist it produces a verdict for a
domain nobody has ever seen, because it judges the page rather than the
name. Its only caller was `python -m valkyrie --analyze <url>`: a manual
command that fetches one page, prints a verdict and exits. Nothing in the
running engine ever invoked it. The "own analysis engine" existed as a
CLI tool and had never been connected to the product.

**2. Fingerprint protection was actively counterproductive.** The TLS addon
injected the same constants into every page on every machine:

```
toDataURL           -> always 'data:image/png,v'
navigator.plugins   -> always []
navigator.languages -> always ['en-US','en']
screen.colorDepth   -> always 24
```

A *constant* lie is itself a fingerprint. No real browser returns
`data:image/png,v` for a canvas readback, so that value did not hide a
user - it uniquely identified them as a Valkyrie user, and it was
identical across every site and every session, which is the definition of
the durable cross-site identifier the feature exists to destroy. An empty
plugin list is rare in the wild and therefore *raises* entropy. Breaking
`toDataURL` outright also broke legitimate canvas use.

A third, smaller problem followed from the first two: the dashboard's
"Trackers Cleaned" counter reads `page_clean` rows, which only the TLS
addon writes, and TLS inspection is off by default. It therefore displayed
a hard `0` forever on a default install, which reads as "running, nothing
found" rather than "this layer is not on".

## Decision

**Farbling (`farble.py`).** Replace the constants with values derived from
`HMAC(session_seed, origin)`, so that values are:

* *stable* within one (origin, session) - the page works, and re-reading a
  canvas twice returns the same answer, since two different answers would
  itself be a tamper signal;
* *different across origins* - two trackers cannot correlate one user
  across two sites, which is the entire point;
* *different across sessions* - nothing becomes a durable identifier;
* *plausible* - drawn from distributions real hardware reports, so the
  user blends in rather than standing out as "the one lying".

Canvas and audio are **perturbed, not replaced**: a per-origin noise table
shifts readback samples by at most one least-significant bit, invisible to
a human and to legitimate use, but fatal to the byte-equality that canvas
fingerprinting depends on. Surfaces covered: canvas readback, WebGL
vendor/renderer, AudioContext, font metrics, hardware concurrency, device
memory, screen availWidth/Height, plugins. Patched functions carry a
native-looking `toString()`, because a detectable patch is itself an
identifying signal. The session seed is regenerated per engine start and
never persisted - persisting it would recreate the durable-identifier
problem this replaces.

**Content analysis (`content_watch.py`).** Run `site_analyzer` continuously
against domains as they are resolved. It is **asynchronous by requirement,
not as an optimisation**: `_decide` is synchronous with a live DNS query
waiting on it, so an inline HTTP fetch would add seconds of latency to
every first lookup of every new domain. `observe()` is O(1), cannot raise,
and drops rather than growing when its bounded queue is full; a worker
thread does the fetching, and the verdict informs *later* lookups.

No new decision stage was added: an auto-blocked page writes itself into
intelligence memory via `remember_bad()`, so the next lookup picks it up
through the stage-2b path that already existed.

**False-positive policy.** This project has shipped a false positive twice,
and content analysis is exactly the signal that could do it again. Only
categories where an FP is near-impossible may auto-block:

* `miner` - an in-page cryptominer is essentially never legitimate.

Everything else is recorded as evidence and surfaced, but never sinkholes a
site on its own. In particular **`fingerprinting` must never auto-block:
banks and payment processors fingerprint deliberately, for fraud
detection**, and blocking them would reproduce the original world-banks
incident exactly. Popular domains are never analysed at all - highest FP
cost, least benefit.

**Honest counters.** `/api/stats` reports `elements_cleaned` as `null`
when TLS inspection is not running, and the renderer displays "Off"
(muted, smaller) rather than `0`.

## Testing

`tests/test_farble.py` (34 checks) asserts the three invariants directly -
stable within an origin+session, different across origins (200 origins ->
200 distinct seeds), different across sessions - plus explicit regression
checks that each old constant is gone, and an **end-to-end** check that the
script actually reaches a page through *both* the lxml and regex cleaning
paths. The lxml path matters: its injection sits inside a bare `except:
pass`, so a rejected fragment would silently inject nothing while every
unit check still passed.

`tests/test_content_watch.py` (28 checks) covers both failure directions:
that a fingerprinting/obfuscation/phishing verdict is **not** auto-blocked
while a cryptominer is, and that the worker cannot silently die or grow
memory (5000 observes stay bounded and take ~100ms with no network on that
path).

Behavioural verification beyond unit tests: the generated script was
executed against a stubbed browser and confirmed to produce genuinely
different canvas and audio output for `facebook.com` vs `google.com`, with
noise bounded to <=1 LSB.

## Rollback

`content_watch` is an optional `AppContext`/`DNSInterceptor` field - pass
`None` and `_decide` behaves exactly as before. `FINGERPRINT_PROTECTION =
False` disables injection. Neither is on the DNS decision path in a way
that changes a verdict synchronously.

## Honest boundary

This is a real improvement and it is not a cloak of invisibility.

* Farbling only reaches pages Valkyrie can rewrite, which means HTML served
  through the TLS-inspection path. TLS inspection is **off by default** and
  requires installing a root CA, so on a default install this code does not
  run at all. Certificate-pinned apps cannot be intercepted even with the CA
  installed.
* It does nothing about server-side fingerprinting - IP address, TLS/JA3
  handshake shape, HTTP header order (see `fingerprint.py` for the
  network-layer half), or account-based identification. Being logged into
  Facebook identifies you perfectly regardless of canvas noise.
* Content analysis sees the page as fetched by Valkyrie, not as rendered in
  the user's browser: it does not execute JavaScript, so a tracker injected
  purely at runtime by another script is not visible to it.
* Auto-blocking is deliberately narrow, which means most real findings are
  evidence rather than enforcement. That is the correct trade for this
  product, but it should not be described as "blocks trackers automatically"
  beyond the one category that genuinely does.
