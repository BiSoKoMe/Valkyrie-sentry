# ADR 0042 - Command-line normalization: defeat obfuscation before the rules run

Date: 2026-08-04 . Status: accepted

## Context

Two independent adversarial reviews converged on the same finding, and a
measurement confirmed it: **the entire 40-rule IOA engine was defeated by
trivial command-line obfuscation.**

`Rule.matches()` does lowercase substring matching on a raw command line. That
logic is correct and it is trivially evaded. Measured against the shipped
engine before this change - 8 variants of commands that every rule already
covers:

| Evasion | Detected before |
|---|---|
| `n^et us^er hacker /a^dd` (cmd caret) | **MISSED** |
| `n"e"t user hacker /add` (token-splitting quotes) | **MISSED** |
| `& ('ne'+'t') user hacker /add` (PS concat) | **MISSED** |
| ``vssa`dmin delete shadows`` (PS backtick) | **MISSED** |
| `[char]118+[char]115+...` (char arithmetic) | **MISSED** |
| extra whitespace / mixed case / `%COMSPEC%` | detected |

**3 of 8. Five trivial variants ran a backdoor-account creation or a
shadow-copy deletion past all 40 rules.**

The implication was worse than the number. Every detection figure this project
has published - the efficacy harness, the red-team Tier A score - was measured
against *unobfuscated* inputs. No adversary has typed a clean command line in a
decade. The honest reading was that real-world evasion resistance was
**unmeasured and materially lower than the published rate.**

Adding rules cannot fix this. The evasion happens upstream of matching, so a
500-rule engine fails identically to a 40-rule one.

## Decision

New `valkyrie/cmdline_normalize.py` - a pure, total, bounded de-obfuscation
pass that runs *in front of* the rule engine.

**Transforms:** unicode folding (full-width Latin, zero-width joiners), cmd
caret and PowerShell backtick escaping, token-splitting quotes, PowerShell
string concatenation, `[char]` arithmetic and `[char[]]` arrays, environment
variable expansion (including the `%VAR:~n,m%` substring form), base64
`-EncodedCommand` / `FromBase64String` payload recovery, 8.3 short paths,
whitespace collapse.

**Wiring - `match_process` matches the raw string AND the normalized string
and unions the hits.** Matching both is deliberate: normalization can then
only ever *add* detections, so no normalizer change can silently break a rule
that depends on raw syntax. Every call site (`process_telemetry`,
`etw/sysmon`, and therefore `native_process`/4688) inherits this with zero
changes.

**Obfuscation is treated as evidence in its own right.** Transforms are split
into `COSMETIC` (whitespace, env vars, short paths, benign string building) and
`EVASIVE` (caret, backtick, token-splitting quotes, char arithmetic,
keyword-fragmenting concat, base64, unicode substitution). Only EVASIVE
transforms set `obfuscated`, which:
- escalates a rule hit to at least HIGH (an administrator does not caret-escape), and
- on its own, with no rule match, still reports MEDIUM / T1027.

That last case is the one that matters most: it keeps "the attacker obfuscated
something we have no rule for" visible instead of silent.

## Two false positives this design caught before shipping

The benign-control corpus in `tests/test_cmdline_normalize.py` failed on the
first implementation. Both were real bugs, both would have shipped:

1. **`findstr /C:"net user" audit_policy.txt` -> T1136.001.** The
   token-splitting-quote heuristic required only non-whitespace on both sides
   of a quote, so `:` qualified and `/C:"net user"` was stripped into
   `/C:net user`. **Fix:** require *word characters* (`\w`) on both sides, not
   merely `\S`. Option-value quoting is now safe.
2. **`python -c "print('hello' + 'world')"` -> T1027.** Ordinary source-code
   string building was flagged as evasion. **Fix:** the join still happens
   (it can only help matching), but it counts as evasion only when some
   fragment is <=3 characters - a keyword chopped into meaningless pieces, as
   in `'ne'+'t'`. `'hello' + 'world'` is not.

A third bug - ordering - was caught by the transform tests: `split_quotes` ran
before `concat` and destroyed the quotes concat needed, so `('ne'+'t')` became
`(ne+t)` and the evasion survived. Quote-delimited transforms now run first.

## Consequences

**Measured:**

| Metric | Before | After |
|---|---:|---:|
| Evasion resistance (12-variant corpus) | 3/8 (38%) | **12/12 (100%)** |
| False positives on benign corpus | - | **0/10** |
| Efficacy gate (recall / FPR) | 100% / 0% | **100% / 0%** (held) |
| Red-team Tier A | 36/40 | **36/40** (unchanged - catalog is unobfuscated) |
| `normalize_cmdline`, clean input | - | **14.3 µs** |
| `classify_behavior` end-to-end, clean | ~30 µs | **44.6 µs** |
| `classify_behavior` end-to-end, obfuscated | - | **78.8 µs** |

15 test modules pass with no regression.

**Cost:** ~15 µs added to every process-creation classification. Acceptable
against a 2s poll interval and a 50 µs DNS hot-path budget; it would need
re-examination if the kernel driver raises event volume by orders of magnitude.

**Note on the Tier A score:** it did not move, and that is correct - the
red-team catalog replays *unobfuscated* command lines. This change improves
the number that catalog cannot measure. An obfuscated-variant evaluation tier
is the honest way to score it, and does not exist yet.

## Honest boundaries

- This handles **syntactic** obfuscation only. A payload assembled by runtime
  logic - a decryption loop, a string fetched from WMI, download-then-invoke -
  still reaches the engine opaque. Full coverage needs script emulation or
  AMSI's post-deobfuscation view (`amsi.py` already consumes the latter for
  4104 script blocks).
- Environment expansion uses **canonical default values, not this machine's
  environment**, to keep the function pure and deterministic. A non-standard
  `%TEMP%` will not resolve exactly.
- `normalize_cmdline` is total by contract - any unforeseen input returns the
  original text rather than raising into process-creation handling. Fifteen
  hostile inputs (5,000-character escape runs, 100 KB arguments, malformed
  base64, integer overflow in `[char]`) are pinned by test.

## Alternatives rejected

- **Normalize in place and match only the normalized string.** Rejected: a
  normalizer bug would then silently disable rules. Matching both makes the
  transform strictly additive.
- **More rules to cover obfuscated forms.** Rejected as combinatorially
  hopeless - each rule would need dozens of variants, and a new escape trick
  would defeat all of them at once.
- **Full PowerShell emulation.** Correct long-term answer, far out of scope,
  and largely redundant with AMSI where a provider is resident.
- **Treating any normalization as suspicious.** Rejected - it flagged
  `%TEMP%` and extra whitespace, which is the false-positive generator this
  project exists to avoid.
