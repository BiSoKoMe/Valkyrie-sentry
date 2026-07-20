# Detection Efficacy — Measured Scorecard

`tests/efficacy/` · run: `PYTHONUTF8=1 python tests/efficacy/harness.py`

This is the answer to the question the project could not previously answer:
**does Valkyrie's detection logic actually discriminate attacker behavior
from normal activity?** The harness drives the *real* classifiers — no
mocks, no reimplementation — with a MITRE-ATT&CK-tagged corpus of
technique-representative malicious inputs and a benign control set, and
scores recall (true-positive rate) and false-positive rate.

## Result (2026-07-19, corpus expanded to the ETW/sensor classifiers)

| Metric | Value |
|---|---|
| Recall (malicious detected) | **27 / 27 = 100%** |
| False-positive rate (benign wrongly flagged) | **0 / 25 = 0%** |
| Precision | 100% |

Per-tactic recall: command-and-control 7/7 · credential-access 2/2 ·
defense-evasion 10/10 · execution 1/1 · impact 1/1 · persistence 6/6.

Detectors exercised (all real code): `process_telemetry.classify_cmdline`
and `.classify_process`, `etw/powershell.classify_powershell`,
`etw/sysmon.classify_sysmon`, `etw/wmi.classify_wmi`,
`persistence_telemetry._persistence_severity`,
`network_telemetry.classify_connection` (reputation via the real
`ThreatIntelManager`), `ransomware_shield.shannon_entropy`,
`threat_intel.match_domain/match_ip`, `site_scanner.analyze`.

### 2026-07-19 expansion — measuring the ETW sensor classifiers (ADR 0023)

The first corpus measured 7 classifiers; four shipped classifier families
carried real MITRE techniques with **zero efficacy measurement**. Per the
Validation Philosophy ("if a detector cannot be measured, it is
incomplete"), the corpus was extended to drive them directly:

- **`classify_sysmon`** — CreateRemoteThread injection (T1055, EID 8), LSASS
  credential read (T1003.001, EID 10), process hollowing/tampering
  (T1055.012, EID 25), unsigned/DLL-hijack module load (T1574, EID 7), and
  registry/Startup-folder persistence (T1547.001, EID 13/11), each with a
  matching benign control (signed process/module, non-LSASS access,
  non-autorun key, ordinary outbound connection) that must stay silent.
- **`classify_wmi`** — permanent WMI event-subscription persistence via
  ActiveScript and CommandLine consumers (T1546.003), with a benign
  provider-activity control.
- **`classify_process`** — Office-document-spawns-shell (T1204.002) and
  LOLBin-from-temp (T1218), with signed-app benign controls.
- **`classify_connection`** — hard-coded-IP C2 (T1071) routed through the
  real `ThreatIntelManager`, the seam DNS filtering structurally misses,
  with a clean-public-IP control.

Every new malicious case fired and every new benign control stayed clean, so
recall/FPR held at 100% / 0% while measured technique coverage roughly
doubled (9 techniques added across 6 tactics). Unlike the first run this
expansion surfaced no classifier bug — the classifiers already discriminated
these representative inputs correctly; what changed is that we can now
**prove** it and a regression can no longer silently degrade them.

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

## A measured blind spot this expansion confirmed: DGA C2 domains

Probing the real pipeline surfaced a genuine, reproducible false-negative:
**algorithmically-generated (DGA) command-and-control domains are not
caught.** Driving `SiteScanner.analyze` and `BehavioralEngine.should_block`
directly:

| Domain | leftmost-label entropy | scanner | behavioral score (block @ 0.70) |
|---|---|---|---|
| `xjkqvw92hd8skwlqz3ty.com` | 4.02 | allow | 0.30 |
| `k2v9q3xw8pjh4m1tzr7f.top` | 4.32 | allow | 0.48 |
| `uqwxkcjznqvbhlpm.net` | 3.88 | allow | 0.29 |

Root cause: the behavioral entropy signal contributes at most `0.5 × weight`,
so entropy **alone can never reach the 0.70 block threshold**, and for a bare
registered (2LD) DGA domain there is no subdomain for the scanner's
entropy/rate signals to corroborate. This is a *deliberate* precision choice,
not an accidental bug — a pure high-entropy block would false-positive on
legitimate CDN hostnames with identical entropy (`d1anzknqnc1kmb.cloudfront.net`
is 3.18, `googleusercontent.com` 3.18), which per project policy ("precision >
aggression; a false positive breaks a real site") is unacceptable.

It is **not** added to the malicious corpus as a passing case, because it does
not pass — recording it as caught would game the scorecard. It is logged here
as the honest current state and queued as the next dedicated cycle: a
*corroborated* DGA detector (entropy **+** n-gram improbability **+** absence
of a known-good parent SLD **+** length/character-class gating), validated
against a large benign CDN/hostname control set before it ships. A
model-based DGA classifier trained on internet-scale domains is the
commercial approach and is explicitly marked "needs infra" in
docs/GAP_ANALYSIS.md — we will not fake it.

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
