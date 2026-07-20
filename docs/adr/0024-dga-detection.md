# ADR 0024 — Corroborated DGA (domain-generation-algorithm) detection

Date: 2026-07-19 · Status: accepted · Follows: ADR 0023

## Context

ADR 0023 *measured* a genuine blind spot and refused to paper over it:
**algorithmically-generated C2 domains were not caught** — 0% recall. Malware
families (necurs, ramnit, gozi, murofet, qakbot) generate large numbers of
random domains and try them until one resolves to the live C2. Driving the real
pipeline confirmed the gap and its cause:

- The behavioral entropy signal caps at `0.5 × weight`, so entropy **alone can
  never reach the 0.70 block threshold**.
- A bare registered (2LD) DGA domain has no subdomain for the scanner's
  entropy/rate signals to corroborate.

The naive fix — "high entropy ⇒ block" — is unacceptable: legitimate CDN
hostnames have identical entropy (`d1anzknqnc1kmb.cloudfront.net` = 3.18) and
blocking them breaks real sites. Per the standing rule *precision > aggression;
a false positive breaks a real site*, the detector had to be corroborated and
precision-first, not aggressive.

## Decision

New pure classifier `valkyrie/dga.py` (`classify_dga`), wired into the live DNS
path via `SiteScanner` (signal **S7**) and surfaced as an EDR incident
(T1568.002) by broadening the existing `dns.dga` detection plugin — **extending
existing architecture, not adding a parallel pipeline.**

Two design decisions do the precision work:

1. **Score only the registrable (2LD) label.** A gibberish CDN *subdomain*
   under a real parent (`d1anzk….cloudfront.net` → label `cloudfront`) is
   structurally ignored. This eliminates the entire CDN false-positive class.
2. **Require three independent corroborators to agree** (all AND-ed):
   - length ≥ 12 (short brands like `netflix` can never qualify),
   - Shannon entropy ≥ 3.0 (repetitive/degenerate labels excluded),
   - **bigram-implausibility ≥ 0.55** — the linguistic discriminator: the
     fraction of adjacent character pairs absent from an embedded corpus of
     English + brand/domain words. DGA gibberish is ~all rare pairs; real words
     are mostly common ones. Hyphen-adjacent pairs are treated as a *negative*
     signal so hyphenated brands (`libjpeg-turbo`, `coca-cola`) stay clear.

Thresholds live in `config.py` (`DGA_MIN_LEN`, `DGA_MIN_ENTROPY`,
`DGA_MIN_RARE_BIGRAM`) and are tuned against a hard benign control set, not
guessed. The classifier is a stateless pure function (no network, no per-call
state) — deterministic and trivially testable.

## Result (measured, before → after)

Hard labeled set: 25 long-label DGA vs. 75 benign chosen to break a naive
detector (CDN hash hostnames, odd-spelled brands, long dictionary/foreign
domains, hyphenated brands).

| Detector | Recall | Precision | FPR |
|---|---|---|---|
| Baseline (`site_scanner` + `behavioral`) | **0%** | — | — |
| `classify_dga` | **76%** | **100%** | **0%** |

- Highest benign label sits at rare-bigram **0.40** — a comfortable margin
  below the 0.55 floor.
- On the representative PRNG-style corpus in `tests/test_dga.py`: **100% recall
  at 100% precision**, ~148k classifications/sec (a cheap pure function).
- Live pipeline verified: `xjkqvw92hd8skwlqz3ty.com` → **block, category `dga`,
  confidence 0.944**; `d1anzknqnc1kmb.cloudfront.net`, `chase.com`, `github.com`
  still **allow**.
- Efficacy harness: 3 DGA malicious cases + 4 hard benign controls added;
  overall **30/30 recall, 0/29 FPR**, gate green. Relevant unit suites
  (`test_dga`, `test_scanner`, `test_scanner_accuracy`, `test_edr`,
  `test_ai_assistant`, `test_intelligence`, telemetry) all pass.

## Honest boundary

Targets **long-label** DGA families. **Short-label** DGAs (some Conficker
variants, 8–11 chars) and clean keyboard-walk strings are out of scope — at that
length the signal cannot separate DGA from real short brands without an
internet-scale trained model, still marked "needs infra" in
docs/GAP_ANALYSIS.md. This is a strong *local* signal, corroborated further by
DNS timing, threat-intel, and process context in the pipeline — not a
standalone model, and it does not claim to be one.

## Security / privacy / performance

- **Security:** adds T1568.002 coverage; a confirmed DGA is a high-severity EDR
  incident with `block_domain`/`kill_process` recommended.
- **Privacy:** fully local, offline, deterministic; the bigram model is an
  auditable embedded word list, not an opaque blob or a phone-home lookup.
- **Performance:** O(label length) pure function, ~microseconds/call; negligible
  against the existing per-query scanner cost.

## Rollback

Delete `valkyrie/dga.py` and revert the S7 block in `site_scanner.py`, the
`dns.dga` plugin/technique-map edits, the `investigate.py` map entries, the
`config.py` thresholds, and the DGA corpus/harness cases. No schema or storage
change; the rest of the pipeline is unaffected.

## Next

Stand up the VM lab (Atomic Red Team + a lab beacon) to exercise real DGA family
traffic end-to-end (the sensor-capture dimension the in-repo harness structurally
cannot measure); revisit short-label DGA only if a low-FP corroboration path
(e.g. resolution-failure bursts + process context) proves out.
