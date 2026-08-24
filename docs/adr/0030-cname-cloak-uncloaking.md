# ADR 0030 — CNAME-cloak uncloaking (defeat first-party tracker disguise)

Date: 2026-07-25 · Status: accepted

## Context

The blocker pillar screened two things: the **queried domain** (`_decide`) and
the **answer IPs** (`_answer_blocked_ip`, against the firewall/intel CIDR sets).
Both miss the single most common way trackers evade DNS blocklists today —
**CNAME cloaking**:

    metrics.brand.com.        CNAME   brand.eulerian.net.
    brand.eulerian.net.       A       <tracker CDN IP>

The queried name (`metrics.brand.com`) looks first-party and is on no list. The
answer IP is the tracker's CDN — not in any IP blocklist. The tracker itself
(`eulerian.net`) rides in on the CNAME chain, which nothing inspected. Criteo,
Adobe (Experience Cloud / Audience Manager), AT Internet, Keyade, Commanders Act
and others sell this as a feature; it is why a plain blocklist quietly fails on
real sites. Top-tier blockers (uBlock Origin, NextDNS, AdGuard) counter it by
**uncloaking**: resolving the CNAME chain and deciding on the targets.

## Decision

New `valkyrie/cname_uncloak.py` — the pure, list-driven core — plus two methods
on the interceptor.

- `CNAME_TRACKERS` is a curated set of the apex domains of known cloaking
  providers. These almost never appear as a *queried* name (so they are absent
  from general adblock domain lists) — they exist only as CNAME targets, which
  is exactly why uncloaking is the only thing that catches them. `suffix_match`
  is boundary-safe (`noteulerian.net` does not match `eulerian.net`).
- The interceptor parses the CNAME chain from the upstream answer
  (`_cname_targets`) and, for each target, applies the SAME block criteria a
  queried name would get (`_uncloak_block`): curated tracker set → threat-intel
  → site scanner → blocklist. A CNAME that stays within the queried site's own
  registrable domain is skipped (not cloaking) unless the target is itself a
  known tracker apex. On a hit the reply is rewritten to the sinkhole and the
  event is labelled `cname_cloak`.
- It runs in `_handle` right after the response is built and before the answer-IP
  screen, and only for a real forwarded answer (never re-screens a reply already
  sinkholed). Parse failures fail **open** — a malformed answer is passed
  through, so uncloaking can only ever *add* a block, never break resolution.

## Consequences

- Trackers hiding behind first-party subdomains are now blocked on **apps and
  websites alike** — anything using the system resolver, over any link (Wi-Fi or
  wired), since the sinkhole sits below the application.
- `tests/test_cname_uncloak.py` proves both halves: real CNAME-chain answers to
  known trackers (single- and multi-hop) are uncloaked, non-curated trackers are
  caught via the scanner, and — the part that matters most — legitimate CDN
  CNAMEs (Akamai `edgekey.net`, CloudFront, Fastly, Azure) are **not** blocked.
  The efficacy corpus gains a `cname` detector (3 cloaked-tracker malicious + 3
  CDN benign controls); the gate holds at recall 100% / FPR 0%.

## Honest boundaries (what this is NOT)

- **Only as complete as the curated set + the scanner.** `CNAME_TRACKERS` is a
  seed of the well-documented cloaking providers; a brand-new cloaking domain
  not in the set and not scored by the scanner will pass until the set grows
  (blocklists have the same property). This raises the floor; it is not a claim
  of catching every cloak.
- **Needs the CNAME in the answer.** Uncloaking reads the CNAME chain the
  upstream returns. It cannot see a tracker reached by a hard-coded IP, by DoH
  inside an app (that path is `doh_detector.py`'s job), or by a resolver that
  strips the intermediate CNAME.
- **First-party analytics that a site self-hosts are unaffected** — by design.
  This targets third-party trackers *disguised* as first-party, not a site's own
  same-domain telemetry, which no list-based approach treats as a tracker.
