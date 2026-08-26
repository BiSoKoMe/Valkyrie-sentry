# ADR 0056 - Adaptive hardening: learning from a miss, safely

Date: 2026-08-24 . Status: accepted . Follows: ADR 0054 (evidence librarian), ADR 0053 (overload ratchet)

## Context

The owner asked for the thing that sounds most like magic: Valkyrie watching a
detection miss and *adapting* — learning to catch next time what it missed this
time. The naive implementation is genuinely dangerous: auto-write a rule from the
command that slipped and load it live. That does two unforgivable things for a
tool that sits in front of everything - it **memorises a literal** (a rule that
matches one exact string is trivially evaded and worthless), and it **creates
false positives** (an over-broad learned rule breaks legitimate programs, which
is a worse failure than the original miss).

## Decision

New `valkyrie/edr/adaptive.py` - a closed loop from a CONFIRMED miss to a GATED
rule *proposal*. It never activates anything.

**Only confirmed misses are eligible.** The input is a `Miss` the evidence
librarian (ADR 0054) certified: the attack executed, the engine was responsive,
and no detection fired. An infra failure or an unexecuted attack can never feed
the learner - you cannot learn from a measurement that did not happen.

**Generalise, never memorise.** `_generalise` extracts the *behaviour* - the
distinctive flag stems (`/format`, `-enc`) and a network-reach CATEGORY
(url/unc/ip) - and explicitly DROPS the literals (paths, IPs, hostnames,
base64/GUID blobs), recording what it dropped for audit. A candidate that can
only be built by memorising a literal is refused (`REJECTED_UNGENERALISABLE`) -
better no rule than a bad one.

**Three hard gates, in order:**
1. **Zero false positives** - the candidate is run against a benign corpus of
   18 legitimate commands (git, npm, pip, benign wmic/sc/reg/msbuild/msiexec,
   ...). One hit -> `REJECTED_FP`, with the offending command named. This gate
   is non-negotiable; catching the attack never justifies breaking a real
   program.
2. **Closes the miss + generalises** - it must detect the miss AND, when the
   progressive-overload transforms are supplied, at least one obfuscated
   variant. Catching only the exact literal is memorisation -> `REJECTED_NARROW`.
3. **No duplicate** - a candidate whose id already ships -> `REJECTED_DUPLICATE`.

**Propose, do not activate.** A candidate passing all gates is `APPROVED` and
*staged for review* - it is returned as data, never written into
`behavioral_rules.py` or loaded. A human (or a strict auto-promote that requires
all gates green and is itself audited) disposes. The asymmetry is the safety
model: the system can get smarter on its own, but cannot make itself more
dangerous on its own.

Pure; 16 checks in `test_adaptive.py`, the keystone proving an FP-prone
candidate is rejected even when it perfectly catches the attack.

## Demonstrated on the real Tier B misses (run 32778970884)

- **T1220 wmic-XSL: APPROVED** - generalised to `wmic.exe` + `/format` +
  any-URL-scheme, 0 FP across the benign corpus, catches the miss + 5 obfuscated
  variants.
- **MSBuild / double-extension / ntdsutil: REJECTED_UNGENERALISABLE** - the only
  distinguishing content was a literal path/name; the loop refused rather than
  memorise. 1 learned, 3 honestly declined.

## Honest scope (what this is NOT)

- It proposes; it does not auto-activate. Wiring an auto-promote for
  all-gates-green proposals is a deliberate, separate decision.
- Its value is genuine **rule-content gaps** (a behaviour no rule catches). It
  does NOT fix the "fires offline, misses live" class (e.g. several current Tier
  B misses where a rule already exists but the live capture path drops it) -
  those are a wiring/capture problem, and an adaptive rule would duplicate
  existing coverage without closing the live gap. Honest about which problem it
  solves.
- The benign corpus is 18 commands - a real deployment should widen it
  substantially before trusting auto-promotion; the gate is only as strong as
  the corpus behind it.

## Honesty

This adds a learning *mechanism*, not a detection number. Nothing here is claimed
to have raised coverage; it changes how a future gap can be closed - safely, with
a human still holding the activation switch by default.
