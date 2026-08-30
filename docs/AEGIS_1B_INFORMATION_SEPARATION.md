# Aegis 1B -- Information Separation

**Evidence class:** synthetic mechanism evaluation.
**Independent:** no.
**Stage:** Aegis 1B -- testing a primitive (information separation), not building a proxy feature.

## Research question

Aegis 1A falsified single-feature hiding: an informed observer reconstructed
activity from untouched correlated features, and the size transform created
a *new* sequence fingerprint. The lesson is architectural, not "try harder at
padding." So 1B does not ask "destination leaked, build a relay." It asks:

> Can Aegis reduce linkability by separating pieces of information an
> observer currently gets to combine? Specifically: does reducing an
> observer's simultaneous access to client identity + destination
> materially lower cross-session linkability, even after the observer
> knows the mechanism and retrains?

## Three conditions

| Condition | What it sees |
|---|---|
| CONTROL | one observer: identity-context + destination + timing + size, all together |
| SINGLE_INTERMEDIARY | a relay sees the same two pieces together -- structurally identical to CONTROL by construction |
| SEPARATED_KNOWLEDGE | ENTRY sees client-context + timing + size, never destination. EXIT sees destination + timing + size, never a persistent identity signal |

## Result: the primitive fails, and it fails for two independent reasons

**1. EXIT alone keeps 100% of the destination-driven linkability (78.4%,
identical to CONTROL).** This is the sobering part: EXIT's ability to
correlate two sessions was *never* built on possessing an identity signal --
Aegis 0's original linkability measurement already inferred "same user" from
pure destination-set overlap, never from a true identity label. Hiding
identity from EXIT removes something EXIT never needed.

**2. Even where separation is real (ENTRY and EXIT genuinely don't share
identity or destination), a colluding/correlating observer re-links the two
views via timing+size with 99.6% accuracy** (vs. 0.4% random chance across
240 candidate sessions) -- despite realistic incidental relay noise (15ms
timing jitter, 3% size overhead from encapsulation, modeling real queueing
and protocol overhead, not a deliberate Aegis mechanism). Exactly the
plausible failure named in advance: "flow A at T, 43KB; flow B at T, 43KB;
observer correlates them anyway."

## Verdict

> FAILURE: knowledge separation alone does not lower end-to-end linkability.
> EXIT alone still achieves the same destination-driven linkability as
> CONTROL, and the two separated views can be re-linked via timing+size
> correlation (99.6% vs 0.4% chance), reconstructing the full
> identity-destination association anyway.

Per the pre-declared rule: this is reported as a failure of the primitive,
not patched with an ad-hoc timing fix mid-experiment.

## Does this generalize? No -- and that is the actual finding worth keeping

Both failure modes are properties of *this* exposure model, not yet shown to
be general:

- Destination-overlap linkability never needing identity is a fact about
  *this* corpus's linkability mechanism (favorite-destination reuse), not a
  universal law -- a system whose linkability came from, say, session tokens
  might behave differently under identity/destination separation.
- Timing+size correlation succeeding here is a fact about *this* experiment
  having no decorrelation mechanism at all -- it does not yet say whether a
  *combined* separation + light decorrelation approach would fail the same
  way.

Both are named as the next falsifiable questions rather than claimed as
proven impossibilities. That distinction is the entire point of not chasing
this failure with a reflexive "add jitter" patch.

## Why this matters more than a working mechanism would

This is the second Aegis mechanism killed in a row (after Aegis 1A's size
bucketing), and for a *different* structural reason each time -- Aegis 1A
failed because untouched correlated features compensated; Aegis 1B fails
because (a) the separated-away piece wasn't the piece providing the leak and
(b) the remaining piece re-links the separation anyway. That is exactly the
research loop the project committed to: measure leak, isolate the dominant
feature, change one thing, let an informed adversary adapt, keep only what
survives. Two mechanisms not surviving is not a wasted branch -- it is two
now-eliminated hypotheses, on the record, with the reason each one failed
named precisely enough to avoid retrying the same shape of fix.

## What's actually next

The architecture implied by both failures together is closer to what the
research plan called an exposure graph: reasoning about which combinations
of visible information enable an inference, not patching one field or one
observation point at a time.

```
NETWORK EVENT
      |
EXPOSURE GRAPH
      |
what information is visible, where?
      |
which visible pieces (across observation points) can be joined?
      |
what inference does that joining enable?
      |
what information is actually necessary for the connection to work?
      |
choose a transformation -- only once the above is answered
```

Aegis 1A and 1B together show why skipping straight to a transformation
(padding, or a relay) fails: neither addressed the *joining* step at all.

## Limitations

- Same frozen synthetic corpus as Aegis 0/0.5/1A (manifest pinned, checked
  at run time).
- `flow_failures` and the modeled latency/bandwidth overheads for the
  knowledge split are stated architectural assumptions (an extra hop's
  latency, protocol overhead), not measurements -- there is no real network
  in this harness.
- The relay timing jitter and size overhead applied before re-linking model
  incidental real-relay noise, explicitly not a deliberate Aegis privacy
  mechanism -- none was added during this experiment.
- `SINGLE_INTERMEDIARY` is reported as structurally identical to CONTROL by
  construction, not as an independently measured condition.

## Kept on the record, not smoothed over later

Aegis 1A: aggressive size normalization increased bandwidth ~24x and still
failed against an informed full-feature observer, so the mechanism was
abandoned. Aegis 1B: identity/destination separation removed a piece of
information an attacker never needed, and the genuinely separated
information re-linked via ordinary timing+size correlation with no
decorrelation mechanism in place, so the primitive was abandoned in this
form. Both failures, and the specific reason for each, stay in this
document rather than being quietly replaced by whatever mechanism (if any)
eventually works.
