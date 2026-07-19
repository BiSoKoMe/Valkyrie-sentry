# Detection Efficacy — Measured Scorecard

`tests/efficacy/` · run: `PYTHONUTF8=1 python tests/efficacy/harness.py`

This is the answer to the question the project could not previously answer:
**does Valkyrie's detection logic actually discriminate attacker behavior
from normal activity?** The harness drives the *real* classifiers — no
mocks, no reimplementation — with a MITRE-ATT&CK-tagged corpus of
technique-representative malicious inputs and a benign control set, and
scores recall (true-positive rate) and false-positive rate.

## Result (2026-07-19)

| Metric | Value |
|---|---|
| Recall (malicious detected) | **16 / 16 = 100%** |
| False-positive rate (benign wrongly flagged) | **0 / 16 = 0%** |
| Precision | 100% |

Per-tactic recall: command-and-control 6/6 · credential-access 1/1 ·
defense-evasion 6/6 · impact 1/1 · persistence 2/2.

Detectors exercised (all real code): `process_telemetry.classify_cmdline`,
`etw/powershell.classify_powershell`,
`persistence_telemetry._persistence_severity`,
`ransomware_shield.shannon_entropy`, `threat_intel.match_domain/match_ip`,
`site_scanner.analyze`.

## What the first run found (measure → fix → re-measure)

The initial run scored **87.5% recall** and surfaced two misses. Both were
real and instructive:

1. **T1564.003 (WScript silent execution) — real detection gap, fixed.**
   `classify_cmdline`'s hidden-window heuristic covered PowerShell flags
   (`-w hidden`, `-nop`) but not WScript/CScript's `//b //nologo`
   silent-batch mode, which malware routinely uses to run VBScript with no
   window. Closed by adding `//b `/`//nologo` (trailing space keeps it off
   URLs like `//blah`). Verified FP-safe against benign https URLs.
2. **T1071 (C2 IP) — corpus artifact, not a detection failure.** The test
   used `203.0.113.66` (RFC 5737 TEST-NET-3), which Python's `ipaddress`
   classifies as private, so the threat-intel validator *correctly*
   dropped it. Real C2 IPs are routable; the corpus was fixed to use one.
   The detection code was behaving correctly.

That loop — a number that revealed a real gap, a fix, and a re-measured
number — is the entire point of the harness.

## A pre-existing finding this surfaced (not yet changed)

`curl https://…` currently flags **high** as a download cradle, because the
rule string `"curl http"` is a substring of `"curl https"`. On a developer
workstation that is noisy (curl-over-https is ubiquitous and benign); on a
locked-down server it is defensible. This is a **tuning decision with a real
FP/FN trade-off and an operator risk-appetite dimension**, so it is
documented here rather than silently retuned. It is deliberately kept out of
the benign corpus so it does not conflate a design choice with a regression.

## Honest boundary — read this before trusting the number

**100% recall here does NOT mean Valkyrie catches 100% of malware.** It
means the detection logic fired on every technique the author knew to write
and stayed silent on every benign case the author knew to write. Its
limits:

- **The corpus reflects the author's knowledge.** It cannot reveal a blind
  spot nobody thought to encode. A real adversary innovates; this corpus
  does not.
- **It exercises classifiers, not the whole kill chain.** It does not
  measure whether the *sensors* would have captured the event in the first
  place (the userland-visibility ceiling documented in
  docs/GAP_ANALYSIS.md), only whether the logic classifies it correctly
  once seen.
- **It is not live-sample testing.** Detonating real malware / running
  Atomic Red Team / a real C2 beacon in an isolated VM remains the gold
  standard. This harness is the in-repo instrument that complements that —
  fast, deterministic, and a regression gate — not a substitute for it.

## Regression gate

The harness exits non-zero if recall falls below **85%** or the
false-positive rate rises above **5%**, so a change that quietly degrades
detection fails visibly. Thresholds encode current honest capability, not
an aspiration — raise them only when detection genuinely improves. Grow the
corpus toward broader ATT&CK coverage as new detectors ship; each addition
makes the number mean more.
