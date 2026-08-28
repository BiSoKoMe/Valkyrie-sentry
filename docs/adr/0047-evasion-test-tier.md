# ADR 0047 - An evasion test tier for redteam/evaluation

Date: 2026-08-04 . Status: accepted

## Context

ADR 0042 (command-line normalization) measured evasion resistance against a
hand-built 12-variant corpus and said plainly what it had not done: "the
red-team catalog replays *unobfuscated* command lines... An
obfuscated-variant evaluation tier is the honest way to score it, and does
not exist yet." Tier A's 32/40 (later 39/40) score was therefore never
tested against anything an actual operator would type - every probe input in
`catalog.py` is a clean, textbook command line.

## Decision

`redteam/evaluation/evasion_harness.py`. For every in-scope Tier A technique
whose `probe_input` carries a `cmdline` (25 of 40 - the rest are DNS/network/
registry/entropy techniques with no command-line syntax to obfuscate), it
generates obfuscated variants of that exact command line and re-runs the
technique's own probe function - `replay_harness.run_technique`, unchanged -
against each variant. A variant is scored by the identical DETECT/
CONDITIONAL/MISS gate as unobfuscated Tier A; nothing is scored more
leniently.

Four transforms, chosen to mechanically apply to (almost) any command line:

  * `caret_escape` - cmd.exe caret escaping (`n^et`)
  * `quote_split` - token-splitting empty-around-one-char quote pairs (`u"s"er`)
  * `powershell_concat` - PowerShell string concatenation on the leading token
  * `unicode_fullwidth` - full-width Latin homoglyphs on the leading token

**Deliberately not attempted generically:** env-var expansion
(`%COMSPEC:~0,1%...`) only makes sense against a literal path substring most
catalog entries don't contain, and base64 `-EncodedCommand` only makes sense
wrapping an actual PowerShell payload. Forcing either onto an arbitrary
technique's cmdline would produce a syntactically bogus string that proves
nothing. Both are already measured directly by
`tests/test_cmdline_normalize.py`'s dedicated corpus (12/12, ADR 0042).

## A bug the harness caught in itself before it caught anything in the product

The first `quote_split` implementation inserted an *adjacent empty pair*
(`us""er`). Measured: 68% resistance, 7 techniques evaded. Before treating
that as a product finding, it was checked against `cmdline_normalize.py`
directly - `normalize_cmdline("net us\"\"er ...")` returned `changed=False`.
The real transform's regex, `(?<=\w)['"](?=\w)`, requires a *single* quote
character with a word character on both sides - the actual cmd.exe technique
(`n"e"t`) wraps one middle character in a quote pair, it does not place two
quotes back to back. Fixed to `u"s"er` and re-verified directly against
`normalize_cmdline` before re-running the harness. This is the same
discipline ADR 0045 and ADR 0046 both landed on: check the measurement
against the product before believing a number that makes the product look
bad, exactly as rigorously as one that makes it look good.

## Result

After the harness fix, on the corrected transforms:

| Transform | Applicable | Still detected | Evaded | Resistance |
|---|---:|---:|---:|---:|
| caret_escape | 25 | 23 | 2 | 92.0% |
| quote_split | 25 | 23 | 2 | 92.0% |
| powershell_concat | 21 | 20 | 1 | 95.2% |
| unicode_fullwidth | 25 | 23 | 2 | 92.0% |

Two techniques evaded at baseline-detected status, both via `caret_escape`,
both through the same root cause: `disc-net-view` (`net v^iew`) and
`disc-local-accounts` (`net u^ser`).

## The real finding, and the fix

`process_telemetry.classify_discovery` - the Discovery-tactic weak-labeling
function that feeds the `reconnaissance-burst` sequence IOA (ADR 0041) - does
exact substring checks (`"view" in cmdline`, `"net user" in cmdline`) against
the **raw** command line only. It was never wired into `cmdline_normalize`,
unlike `behavioral_rules.match_process`/`classify_behavior`, which match
raw AND normalized and union the hits. A caret defeats it trivially.

Fixed the same way ADR 0042 fixed the main rule engine: `classify_discovery`
now evaluates its keyword checks against both the raw and the de-obfuscated
command line. Doing this correctly required more than "also check the
normalized string" - the function has an EXCLUSION path too (`nltest
/dclist:...` is deliberately *not* labeled, because `behavioral_rules.py`'s
own `nltest-domain` rule already covers and alerts on it). An earlier draft
checked the positive match against both forms but the exclusion only against
whichever form first apparently matched, which would have let an obfuscated
*exclusion* flag slip a wrongly-labeled duplicate event past the exclusion
in the opposite direction. `_discovery_cmdline_technique` now takes a tuple
of candidate strings (raw, plus normalized when different) and checks both
the positive match and the exclusion against every candidate.

After the fix, re-running the harness: **100% resistance across all four
transforms, 0 evasions of anything detected at baseline.**

`tests/test_process_telemetry.py` gained regression cases: caret-escaped
`net view`/`net user` still label correctly, a token-split-quote variant
still labels correctly, and a caret-escaped `nltest /dcl^ist` still hits the
exclusion (proving the fix didn't just move the bug to the other direction).

## Consequences

- New permanent tier: `redteam/evaluation/evasion_harness.py`, runnable
  standalone (`PYTHONUTF8=1 python redteam/evaluation/evasion_harness.py`)
  and independent of Tier A's own run (it calls `run_technique` but does not
  modify or depend on Tier A's result files).
- `process_telemetry.classify_discovery` closed the one real gap this tier
  found; `tests/test_process_telemetry.py`, `tests/test_etw_sensors.py`, and
  `tests/test_behavioral_sequences.py` (the reconnaissance-burst pipeline
  test) all stay green.
- Efficacy gate held at 100% recall / 0% FPR throughout.

## Honest boundaries

- Still Tier A: classifier-input replay, not a live attack. It answers "does
  the code recognise this exact obfuscated shape," not "would this survive a
  live obfuscated Atomic Red Team run" - Tier B has still never been run.
- Four transforms, not an exhaustive obfuscation space. A determined
  attacker has more tricks than caret escaping, quote splitting, PowerShell
  concatenation, and Unicode homoglyphs - this raises the floor, it does not
  claim to be a ceiling.
- The two techniques already known to miss at baseline
  (`disc-local-accounts`, `lat-psexec-smb`) cannot regress further under
  obfuscation - they are reported as baseline misses, not evasion wins, and
  are excluded from the "evaded" count for exactly that reason.
