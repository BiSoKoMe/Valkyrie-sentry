# Detection Efficacy — Measured Scorecard

`tests/efficacy/` · run: `PYTHONUTF8=1 python tests/efficacy/harness.py`

This is the answer to the question the project could not previously answer:
**does Valkyrie's detection logic actually discriminate attacker behavior
from normal activity?** The harness drives the *real* classifiers — no
mocks, no reimplementation — with a MITRE-ATT&CK-tagged corpus of
technique-representative malicious inputs and a benign control set, and
scores recall (true-positive rate) and false-positive rate.

## Result (2026-07-19, corpus expanded to the ETW/sensor classifiers + DGA)

| Metric | Value |
|---|---|
| Recall (malicious detected) | **30 / 30 = 100%** |
| False-positive rate (benign wrongly flagged) | **0 / 29 = 0%** |
| Precision | 100% |

Per-tactic recall: command-and-control 10/10 · credential-access 2/2 ·
defense-evasion 10/10 · execution 1/1 · impact 1/1 · persistence 6/6.

Detectors exercised (all real code): `process_telemetry.classify_cmdline`
and `.classify_process`, `etw/powershell.classify_powershell`,
`etw/sysmon.classify_sysmon`, `etw/wmi.classify_wmi`,
`persistence_telemetry._persistence_severity`,
`network_telemetry.classify_connection` (reputation via the real
`ThreatIntelManager`), `ransomware_shield.shannon_entropy`,
`threat_intel.match_domain/match_ip`, `site_scanner.analyze`,
`dga.classify_dga` (new — corroborated DGA C2 detection).

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

## Closed this cycle: DGA C2 domains (ADR 0024)

The previous expansion *measured* a genuine blind spot: **algorithmically-
generated (DGA) command-and-control domains were not caught** — 0% recall.
Driving the real pipeline confirmed entropy alone could never reach the block
threshold (`xjkqvw92hd8skwlqz3ty.com` scored 0.30 behavioral / scanner-allow),
and a naive high-entropy block would false-positive on CDN hostnames with
identical entropy (`d1anzknqnc1kmb.cloudfront.net` = 3.18). This cycle closed
it with a **corroborated** detector (`valkyrie/dga.py`, wired into
`SiteScanner`).

**The detector.** It scores only the **registrable (2LD) label** — so a
gibberish CDN *subdomain* under a real parent (`d1anzk….cloudfront.net`) is
structurally ignored, eliminating the entire CDN false-positive class — and
fires only when three independent signals agree: length ≥ 12, Shannon entropy
≥ 3.0, and a **bigram-implausibility fraction ≥ 0.55** from an embedded
English/brand bigram model (the linguistic discriminator). Hyphen-adjacent
pairs are treated as a negative signal so hyphenated brands (`libjpeg-turbo`,
`coca-cola`) stay clear.

**Measured, before → after**, on a hard labeled set (25 long-label DGA vs. 75
benign chosen to break a naive detector — CDN hash hostnames, odd-spelled
brands, long dictionary/foreign domains, hyphenated brands):

| Detector | Recall | Precision | FPR |
|---|---|---|---|
| Baseline (`site_scanner` + `behavioral`) | **0%** | — | — |
| `classify_dga` (this cycle) | **76%** | **100%** | **0%** |

The highest benign label sits at rare-bigram 0.40 — a comfortable margin below
the 0.55 floor. On the representative PRNG-style corpus in `tests/test_dga.py`
recall is 100% at 100% precision; the 76% figure reflects a deliberately harder
mixed set that also includes keyboard-walk strings.

**Honest boundary.** This targets **long-label** DGA families (necurs, ramnit,
gozi, murofet, qakbot). **Short-label** DGAs (some Conficker variants, 8–11
chars) and clean keyboard-walk strings remain out of scope — at that length the
signal cannot separate DGA from real short brands without the internet-scale
trained model still marked "needs infra" in docs/GAP_ANALYSIS.md. This is a
strong local signal corroborated by DNS timing, intel, and process context in
the pipeline — not a standalone model, and it does not claim to be one.

Three DGA cases (`dga-necurs`, `dga-ramnit`, `dga-digits`) and four hard benign
controls (CDN subdomain, long dictionary domain, hyphenated brand, consonant-
heavy brand) are now in the efficacy corpus, so a regression that reopens this
gap fails the gate.

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
