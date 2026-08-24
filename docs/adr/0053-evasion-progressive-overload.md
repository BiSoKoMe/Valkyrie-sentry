# ADR 0053 - Progressive-overload loop for evasion resistance

Date: 2026-08-23 . Status: accepted . Follows: ADR 0042 (cmdline normalization), ADR 0047 (evasion tier)

## Context

2026-08-23 established, the hard way, that Valkyrie's offline scales had stopped
moving: Tier A 36/40 (the other 4 known-unreachable), live-safe 11/12 (the 1
by-design), and the evasion tier at **100% resistance on all four transforms -
0 evasions across 96 variants**. Writing more rules against a pinned scale
produces no measurable movement; that is not progress, it is motion.

The owner's framing was progressive overload from the gym: each session must be
slightly heavier, and you must never quietly slide back. A pinned scale cannot
deliver either. Two things were missing: **heavier plates** (obfuscations with
real headroom) and a **ratchet** (a record that only moves up, so a regression
stops the line instead of passing silently).

## Decision

### 1. Heavier plates - four new evasion transforms

Added to `redteam/evaluation/evasion_harness.py` (the `TRANSFORMS` dict is the
seam; everything downstream iterates it):

- `random_case` - the cheap plate that confirms case-insensitive matching.
- `comma_delimit` - replace the first inter-token space with a comma. cmd.exe
  accepts `,`/`;` as argument delimiters, but the normalizer only collapsed
  WHITESPACE. **This opened real headroom: 4 techniques evaded, 80.8%.**
- `compound_cmd` - caret-escape THEN quote-split, stacked. The single-transform
  tier never checked the normalizer's fixed-point loop unwinds more than one
  obfuscation from the same string.
- `compound_triple` - full-width + caret + quote-split, the heaviest plate;
  catches the loop stopping one round short.

### 2. The lift - generalize the fix in the normalizer

`comma_delimit`'s 4 evasions were closed by `_fold_delimiters` in
`cmdline_normalize.py`: fold unquoted, top-level `,`/`;` to a space. It is
**structure-aware** - commas inside quotes, inside `(...)` (a `[char[]]` array
or PowerShell arithmetic), and inside `%...%` (an env-substring spec like
`%COMSPEC:~0,1%`) are STRUCTURAL and left alone. The first draft skipped only
quotes and regressed char-arith and env-expand; the paren/percent guards are
the fix, verified against `tests/test_cmdline_normalize.py` (14/14, 0 FPs, 0
evasions across 300 randomized stacked variants). Result: comma_delimit 80.8% ->
96.2%, **0 techniques evadable across all 8 transforms.** The fix generalizes -
it folds the delimiter class, it does not list the four techniques.

### 3. The ratchet - `redteam/evaluation/ratchet.py`

A pure high-water-mark ledger. Per transform it stores the best resistance ever
seen and the exact set of techniques ever resisted. Each run is classified:

- **GAIN** - resistance rose, or a technique that used to evade now resists.
  The ledger ratchets up.
- **REGRESSION** - a technique that was ONCE resisted now evades, OR a rate
  fell below its recorded best. **Hard failure (non-zero exit).** Detected
  per-technique, so it fires even when the aggregate count is unchanged (a
  technique regressing while another newly resists). The ledger is left at the
  last good state.
- **HEADROOM** - evading now, never resisted. Not a failure - the next plate to
  lift, surfaced so the loop always has a target.

Asymmetric by design: gains absorbed automatically, losses stop the line. 25
checks in `test_ratchet.py`. The ledger `evasion_ratchet.json` is committed, so
the high-water mark persists across sessions and machines.

### 4. The automation - `redteam/evaluation/overload.py`

One command: run the harness, then the ratchet; exit 0 if the ratchet held, 1
if it broke (`--fail-on-headroom` also fails while any variant still evades).
Offline and host-pure - starts no service, touches no network/firewall/Sysmon -
so it is safe to drive from `/loop`, a pre-commit hook, or Task Scheduler on a
live machine.

## Consequences

- The evasion scale moves again, and gains are now one-way: a future change that
  weakens the normalizer against an obfuscation it once folded is a hard CI-able
  failure, not a silent slide.
- One real detection gap (comma/semicolon delimiters) was found and closed as a
  side effect of building the heavier plates - the loop's first rep already paid
  for itself.
- The loop is a template: the next heavier plates (env-var substring on real
  paths, base64 payload wrapping - both currently measured only in
  `test_cmdline_normalize.py`, and genuinely novel classes) drop into the same
  `TRANSFORMS` dict and the ratchet handles them with no further wiring.

## Honesty

The evasion tier is OFFLINE (Tier A class): obfuscated command lines scored
through the real classifiers on synthetic input. A rising ratchet is real
evidence the classifier's evasion resistance is improving and not regressing; it
is **not** a live end-to-end detection-rate claim. Live detection remains the
Tier B question (`RUN_PLAN_CLOUD.md`), unchanged by this ADR.
