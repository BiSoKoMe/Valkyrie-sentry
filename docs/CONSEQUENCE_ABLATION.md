# Consequence ablation — privacy-only vs endpoint-only vs combined

**Evidence class:** synthetic mechanism evaluation (structural selectivity).
**Independent:** no.
**Stage:** first ablation of `valkyrie/edr/consequence.py`.
**Harness:** `redteam/evaluation/consequence_ablation.py`
**Corpus manifest:** `722161dbc0c7f001…` (frozen; the harness refuses to run against a changed corpus)

**This is not a detection rate.** It does not run the product, replay an attack, or touch a
live host. Per this project's standing rule, detection efficacy is established only by real
Atomic Red Team execution on a disposable host (`LIVE_FIRE_EVALUATION.md`). What is measured
here is narrower: given a population of causal structures, how selective is each decision
rule.

## Research question

The 2026-09-05 roadmap names the product hypothesis and asks for exactly this test:

> a local system can distinguish an intended disclosure from a suspicious consequence more
> accurately when it combines scoped user intent with endpoint provenance. **Test that against
> privacy-only and endpoint-only baselines.**

## Method

Three arms see an identical corpus and an identical learned baseline:

| arm | predicate |
|---|---|
| privacy-only | NYX's own observation: personal data crossed to a third party in this lineage |
| endpoint-only | a descendant process made an egress this host rarely makes |
| combined | `score_privacy_consequence()`, imported unmodified |

Arms A and B are written as the strongest honest version of each half, not strawmen. The
endpoint arm reuses the same rarity threshold (`≥ 0.90`), the same descendant rule, and the
same matured baseline the combined detector receives; only the other domain's evidence is
withheld.

The baseline is **learned**, not hand-set: ordinary-activity structures are replayed until the
real maturity gates pass (303 observations across 3 sessions, against gates of 300/3). Guard
probes and true positives are never learned from.

Corpus: 33 structures — 27 benign, 6 cross-layer. The benign population is dominated by two
shapes chosen because they are what actually fills a real desktop: ubiquitous third-party
tracking during ordinary browsing, and novel egress destinations during developer/updater work.

## Results

| arm | caught (of 6) | missed | false positives (of 27) | precision |
|---|---:|---:|---:|---:|
| privacy-only | 6 | 0 | 17 | 26% |
| endpoint-only | 5 | 1 | 3 | 62% |
| **combined** | **5** | **1** | **0** | **100%** |

Refusal reasons the combined arm gave on benign structures: `no_rare_descendant_egress` (14),
`non_interactive_owner` (11), `incomplete_provenance` (1), `ambiguous_privacy_destination` (1).

## Finding 1 — the hypothesis holds, but for precision, not detection

All three arms catch the standard cross-layer cases. The combination does **not** find anything
the halves miss. What it does is refuse: privacy-only fires on 17 benign structures, endpoint-only
on 3, the combination on none.

That is a real and specific effect, and the mechanism is legible. A privacy observation alone
cannot carry a security verdict because third-party disclosure happens on essentially every
page load — 10 of the 17 privacy-only false positives are nothing but ordinary tracked
browsing. Rarity alone cannot carry one either, because novel destinations are the normal
outcome of installing a package or taking an update. Each signal's dominant false-positive mode
is suppressed by the other's requirement.

So the honest claim is: **combining the domains buys selectivity, not reach.** That is worth
stating precisely, because "we combined two signals and caught more" would have been the
attractive claim and it is not what the measurement says.

## Finding 2 — a measured blind spot in the shipping detector

`CausalBaseline.artifact_rarity()` is keyed on `(process_name, artifact_kind)` and never
examines the destination. An egress to a never-before-seen host therefore scores rarity `0.0`
whenever it rides a process name the host runs routinely.

This was probed rather than assumed. The corpus contains `cross_layer_common_process_name`: the
same disclosure-then-consequence intent as the other true positives, differing only in that the
descendant egress is made by `node.exe` instead of an unfamiliar helper. Both the endpoint arm
and the shipping combined detector **miss it**. Privacy-only catches it, precisely because it
ignores process rarity.

Two consequences worth carrying forward:

1. The halves have **complementary** blind spots, which is a better argument for combining them
   than the precision result alone — but it also means the current combination inherits the
   endpoint half's blindness rather than covering it.
2. Any real technique that egresses through a common process name (a browser, a package manager,
   a living-off-the-land binary that routinely resolves names) is invisible to this rule today,
   regardless of how novel the destination is.

The obvious repair — make rarity destination-aware — is **not** applied here, because it trades
directly against the project's prime directive on false positives: on a developer machine, novel
destinations through common process names are constant, and a destination-aware rarity term
would likely fire on all of them. That tradeoff needs its own measurement before any sensitivity
change ships.

## Honest limitations

- **The corpus is authored, and authored with knowledge of how the detector works.** That is the
  single largest threat to this result's validity. The shape distribution is the load-bearing
  assumption; if a given machine does not look like this, the numbers do not transfer to it.
- **Precision numbers are relative to this population**, not to a real host's event mix. They say
  how the rules rank against each other on the same structures, not what any of them would do in
  production.
- **No live host, no real capture, no attack execution.** Every structure is constructed.
- The first run of this ablation was **wrong** and is recorded here rather than quietly fixed:
  guard probes were included in the learning population, which taught the baseline that
  `helper.exe` making DNS queries was routine and suppressed 4 of 5 true positives. The learning
  split was corrected to ordinary-activity structures only. The corpus hash is frozen so a
  future edit cannot silently move these numbers.

## Addendum — real-capture run (2026-09-06)

Follow-up #1 below was executed. `tools/capture_causal_corpus.py` performed a read-only
150-second observation of this Windows 11 desktop: 319 live processes seeded with their real
ancestry, the live socket table attributed to real pids, then the real `ProcessCollector` and
`NetworkCollector` running for the window. Result: **197 distinct causality-owner subgraphs,
325 nodes, 201 egress artifacts across 21 lineages.** Destinations are salted-hashed per run
and command lines and paths are dropped, so the capture is structure, not the machine's
browsing history. Evaluated with a held-out split (137 learn / 60 test, baseline matured to the
real 300/3 gates) so nothing is scored against a baseline that memorised it.

`redteam/evaluation/consequence_real_corpus.py` runs the arms against it. Two arms are **not
measurable** on this capture and are reported as such rather than as zeros: a real capture
contains no NYX observations, because TLS interception is opt-in and off, and injecting
synthetic leaks into real structures would restore the exact authorship problem this run exists
to remove.

### What it found

**The endpoint arm fired on 0 of 60 real structures**, and the combined rule's worst-case bound
— assuming *every* held-out lineage carried an unambiguous disclosure — is also **0 of 60**.

That number is real but it must not be read as "0% false positives on a real machine," because
the refusal breakdown says why:

| refusal reason on real structures | count |
|---|---:|
| `non_interactive_owner` | 56 |
| `incomplete_provenance` | 3 |
| `no_rare_descendant_egress` | 1 |

**56 of 60 were refused at the owner gate, before any privacy or rarity logic ran.** On this
machine 93 of 197 causality owners are `svchost.exe`, across 93 distinct owner names, and the
entire capture contained exactly **one** interactive owner (`msedge.exe`).

### Two corrections this forces to the authored result

1. **The combination is not what does the filtering on real data — the owner allowlist is.**
   The authored corpus refused 11 of 27 benign structures at the owner gate (41%); the real
   corpus refuses 93%. The authored population over-represented browser lineages because it was
   written to exercise the privacy/rarity interaction, and that made the combination look like
   it was carrying the selectivity. On a real desktop, most of the work is done by
   `_INTERACTIVE_OWNERS` — a hardcoded allowlist of nine process names — long before the
   cross-layer reasoning is consulted.

2. **The real-capture run cannot yet bound false positives in the regime that matters.** The
   only population the rule can ever act on is interactive-owner lineages, and this capture
   contained n=1 of them, because the machine was largely idle and not browsing. A 0/60 result
   over a population that is 93% system services says the rule is inert against ordinary service
   noise — genuinely worth knowing, and it is the first evidence of that — but it says nothing
   about its behaviour during actual browsing.

The honest status is therefore: the precision result in the main table stands as a statement
about decision logic on a constructed population, the real capture confirms inertness against
system/service activity, and the rule's false-positive behaviour under real browsing **remains
unmeasured**.

## Addendum 2 — measuring the Finding 2 repair (2026-09-06)

Finding 2 named the obvious repair for the blind spot (key rarity on the destination too) and
declined to apply it, predicting it "would likely fire on all of them" on a developer machine.
That was reasoning, not measurement. `redteam/evaluation/consequence_rarity_variant.py`
measures it. Nothing shipping was modified — the variant is implemented inside the experiment,
which is the whole point of measuring before changing a detector that runs on real machines.

| corpus | rarity keying | caught | false positives | closes blind spot |
|---|---|---:|---:|---|
| authored | name-keyed (shipping) | 5 / 6 | 3 | no |
| authored | destination-aware | **6 / 6** | 3 | **yes** |
| real capture | name-keyed (shipping) | — | 2 / 60 | — |
| real capture | destination-aware | — | 2 / 60 | — |

On the authored corpus the variant **strictly dominates**: it closes the blind spot at an
identical false-positive count. On the real capture it costs nothing measurable.

**That second row is much weaker than it looks, and should not be quoted on its own.** Only
**2 of the 60** held-out real structures contain a descendant egress at all — and both arms fire
on exactly those 2. The binding constraint in this sample is the descendant-egress requirement,
not the rarity keying, so the two arms had no room to differ. The predicted cost was therefore
neither observed nor actually tested; a 150-second capture of a mostly-idle desktop contains far
too little destination churn to exercise it. My original caution stands as untested, not
refuted.

What can honestly be said: destination-aware rarity closes a real blind spot at no cost on the
population measured so far, and the population measured so far is too thin to price it. It
should be measured again against a capture taken under real browsing and real package/update
activity — the regime where novel destinations are constant — before any sensitivity change
ships.

## Addendum 3 — the owner allowlist is a measured coverage gap (2026-09-06)

Addendum 1 found that `_INTERACTIVE_OWNERS` — a hardcoded list of nine process names — performs
93% of the real-world refusal work. Follow-up: check that list against the process names this
machine actually runs.

Of 93 distinct causality-owner names in the real capture, exactly one (`msedge.exe`) is on the
allowlist. And the capture contains **`brave.exe`** — a mainstream Chromium browser running on
the developer's own desktop, absent from the list.

**The consequence rule is therefore silently inert for Brave on this machine.** No Nyx
observation and no descendant egress, however novel, can make it fire, because the lineage is
refused at the owner gate before any of that is consulted. This is not hypothetical fragility;
it is a demonstrated coverage gap on the machine the product is being developed on.

The obvious repair — add the name — was measured before being applied, on the same principle as
Finding 2. Adding `brave.exe`, `vivaldi.exe` and `opera.exe` changes the worst-case bound on the
held-out real structures from 0/60 to 0/60, because **0 of the 60 held-out structures have an
interactive owner under either list**: the capture's single browser lineage fell in the training
split. So the cost of widening is not measurable on this capture either.

The allowlist was left unchanged. Adding names one at a time is whack-a-mole against the real
issue, which is structural: a short name list is the load-bearing filter, every unlisted
interactive application is a silent blind spot, and the project's own rule for the mirror case
already says not to reason this way — *"do not classify an installer as safe solely because of
its path, popularity or signature."*

### The bottleneck, stated once

Three separate open questions now block on the same missing input:

1. whether privacy-only and combined are measurable at all on real data (needs real Nyx observations),
2. what destination-aware rarity actually costs (needs real destination churn),
3. what widening the owner allowlist actually costs (needs real interactive-owner lineages).

All three are answered by one thing: **a capture taken during real browsing with TLS
interception enabled.** Until that exists, every conclusion about this rule's real-world
behaviour is bounded by a corpus that contains almost none of the regime it operates in.

## What would actually strengthen this

1. ~~Replay captured subgraphs from a real session~~ — **done, see addendum.** It removed one
   validity threat and exposed a larger one.
2. **Capture during real browsing, with TLS interception on.** This is now the critical gap:
   the rule can only act on interactive-owner lineages, and the idle capture contained one. A
   session with actual browsing produces both the population that matters and — with the proxy
   enabled — genuine NYX observations, which would make the privacy-only and combined arms
   directly measurable on real data instead of bounded. This needs the owner's involvement,
   since it means browsing on their machine through their own proxy.
3. **Re-examine `_INTERACTIVE_OWNERS` as the load-bearing filter it turned out to be.** A
   hardcoded nine-name allowlist is currently doing 93% of the real-world refusal work. Two
   consequences deserve measurement rather than assumption: a renamed or unlisted browser
   (or any interactive app not on the list) makes the rule silently inert, and adding names
   widens the population the cross-layer logic must then carry alone.
4. Measure the destination-aware rarity variant (Finding 2) against both corpora, to put a
   number on that tradeoff rather than reasoning about it.
5. Only after those: a live-fire path that produces a genuine disclosure-then-consequence chain
   on a disposable host, which is the only evidence class this project accepts as detection.
