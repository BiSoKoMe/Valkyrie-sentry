# An Empirical Live-Fire Evaluation of Valkyrie's Endpoint Detection Engine, with a Case Study in Emergent Self-Interference

**Valkyrie Detection Assurance Program** · commit `89575c6`, branch `feat/efficacy-etw-coverage` · 26 August 2026

> A rendered, designed version of this paper (with figures) is also
> published as a Claude Artifact; this file is the canonical, versioned copy
> that lives with the code it describes.

## Abstract

Endpoint detection claims are conventionally reported as static rule or
technique counts, a metric that measures coverage intent rather than
realized capability. We instead report the results of a live-fire
evaluation in which Valkyrie, a Windows endpoint detection engine, was
subjected to a real Atomic Red Team battery — including destructive
techniques ordinarily excluded from safe testing — executed on a disposable,
single-use host and destroyed immediately afterward. Across two independent
executions of a 52-technique in-scope catalog, we establish a proven
detection floor of 38 techniques (73.1%), computed as a union across runs
rather than an average, on the grounds that infrastructure failure modes can
only suppress a true detection and can never fabricate one. The second
execution additionally surfaced an anomalous 50-fold increase in incident
volume (2,447 incidents versus a 49-incident baseline). We trace this
anomaly to a specific defect in the engine's DNS-resolution evidence model,
under which the engine's own network activity, and unrelated infrastructure
telemetry, were misclassified as attacker behavior. We present the
root-cause analysis, the corrective change, and a controlled before/after
re-measurement confirming the defect's elimination without any reduction in
genuine detection capability. We further report a subsequent
technique-by-technique remediation campaign in which two additional
previously-missed techniques — process injection (T1055) and local-group
discovery (T1069.001) — were independently root-caused, fixed, and
live-reconfirmed against the real engine. We conclude with an explicit
accounting of what remains unproven, rather than treating the evaluation as
closed.

**Index terms** — endpoint detection and response, Atomic Red Team,
live-fire validation, false-positive root-cause analysis, DNS resolution
telemetry, self-referential detection, sensor provisioning.

## 1. Introduction

The prevailing method by which endpoint detection products communicate
capability — an enumerated count of detection rules or claimed ATT&CK
technique coverage — measures what a system is designed to catch, not what
it demonstrably does catch when a real adversarial action is executed
against it. The distinction matters because the two figures are known to
diverge, sometimes substantially, once telemetry timing, sensor
availability, and correlation behavior are exercised under real conditions
rather than assumed.

This paper reports a live-fire evaluation of Valkyrie conducted against that
stricter standard. We pose a single question and decline to substitute an
easier one for it: *when a known attack technique is actually executed, does
the engine produce a correctly attributed detection, and does it do so
reliably across independent trials?* Section 2 describes the methodology.
Section 3 describes the experimental apparatus. Section 4 reports the
baseline outcome, with every miss named and reasoned. Section 5 presents an
extended case study in a false-positive amplification defect. Section 6
reports a subsequent, ongoing remediation campaign against the genuine
misses identified in Section 4, with two techniques independently fixed and
reconfirmed. Section 7 discusses threats to validity. Section 8 concludes.

## 2. Methodology

Detection engines are conventionally evaluated by two distinct means. A
*classifier replay* feeds synthetic, technique-representative inputs
directly to the engine's decision functions; it is inexpensive and
reproducible but cannot exercise telemetry timing, sensor delivery, or
correlation under real system load, and cannot produce a genuine
false-positive measurement. A *live-fire evaluation* instead executes the
real attacker procedure against a genuinely running instance of the engine,
and scores the result against the engine's own incident store. Only the
latter is reported here as authoritative.

A single live-fire run on shared infrastructure is not independently
trustworthy: sensor backpressure under a dense burst of near-simultaneous
atomics, transient runner unavailability, and job-level timeouts are known
failure modes of the execution environment itself, each of which can
suppress a detection that would otherwise occur — and none of which can
manufacture one that did not. The statistically defensible figure is
therefore a *union* across runs:

```
detected(T) = OR over every real run: was T observed in that run?
```

A detection was credited only when the resulting incident carried a
specific, technique-accurate label and severity assignment — never the
presence of process telemetry alone.

## 3. Experimental Setup

All executions ran on GitHub Actions' `windows-latest` hosted runner class:
a freshly provisioned, single-use Windows virtual machine destroyed
unconditionally at job completion. This property is what permits the
destructive subset of the technique catalog — credential dumping,
security-control tampering, shadow-copy deletion, event-log clearing — to be
executed at all. The evaluation catalog comprised 62 cataloged techniques,
of which 52 were in scope for live execution; the remaining 10 were excluded
a priori for stated structural reasons (e.g. a technique requiring a joined
Domain Controller) and are not counted in either the numerator or
denominator of the headline figure.

## 4. Baseline Results

Run 1 produced 42 of 58 detections; Run 2 produced 36 of 58. The union
across both runs yields 38 of the 52 in-scope techniques — a proven
detection floor of **73.1%**, including correctly attributed detections of
LSASS memory dumping via two independent tool implementations, Windows
Defender and firewall tampering, volume shadow copy deletion, and Windows
event log clearing.

| Run | Attempted | Detected |
|---|---:|---:|
| 1 | 58 | 42 |
| 2 | 58 | 36 |
| **Union (authoritative)** | **52** | **38 (73.1%)** |

Fourteen in-scope techniques were not proven detected in either run. None
were aggregated into an unexplained residual — each carries a specific,
individually verified reason (config exclusion, tool absence on the host,
single-runner topology limits, or a genuine open gap). The full
per-technique table is in `docs/LIVE_FIRE_EVALUATION.md`.

## 5. Case Study: An Emergent Self-Interference Defect

Run 2 produced 2,447 incidents against a 49-incident baseline — a fifty-fold
increase not attributable to any intended test condition.

**Observation.** The harness's own false-positive accounting attributed 789
spurious detections to Run 2, concentrated around techniques exhibiting
persistent, ongoing system state (a network port-forward, a background
file-transfer job, a script-proxy execution), as distinct from the remaining
techniques, which execute and terminate near-instantaneously.

**Root-cause analysis.** The engine's network-anomaly scorer weights a
signal termed *never-resolved* — the absence of any prior DNS lookup for a
connection's destination — at its single largest contribution, on the
rationale that a connection to a hardcoded, never-looked-up address
indicates hardcoded command-and-control infrastructure. The supporting
resolution-history component, however, returned an unqualified negative both
when DNS interception had genuinely observed no prior resolution for a given
address *and* when DNS interception had never been active at all — a
condition true of every continuous-integration execution, which disables DNS
interception by design. Under that condition, the never-resolved signal was,
in effect, unconditionally true for every connection on the host. Combined
with a second signal true of nearly every non-operating-system-signed binary
present on a CI runner — including the evaluated engine's own interpreter
process — the two signals alone exceeded the scorer's firing threshold for
entirely ordinary traffic. A second, compounding defect was identified in
the engine's self-recognition logic, which matched only a packaged,
installed binary by name or filesystem location, and had no means of
recognizing the engine when invoked as an interpreted module from a source
checkout — the shape every continuous-integration execution takes.

**Remediation.** The resolution-history component now returns an explicit
unknown state until it has processed at least one genuine resolution, rather
than conflating that state with a confirmed negative. Self-recognition was
extended to match the currently executing process by its own operating
system process identifier — an exact identity comparison incapable of
matching any other process, however similarly named, requiring no allowlist.

**Validation.** The isolated reproduction was re-executed, unmodified, on
the same runner class following the corrective change.

| | Before | After |
|---|---:|---:|
| Spurious network-category detections | 7 | **0** |
| Genuine, technique-driven detections | 40 | **40 (unchanged)** |

Eighteen new automated regression assertions and the complete pre-existing
test suite (135 files) passed following the change. A directly constructed
hardcoded-command-and-control scenario, evaluated under an *active*
resolution history, was confirmed to still produce a full detection verdict.

## 6. Remediation Campaign: Attacking the Baseline's Genuine Misses

Following the baseline, each miss classified as a genuine, Valkyrie-owned
gap in Section 4 was attacked individually — isolated, root-caused to a
specific layer, fixed at the smallest correct scope, regression-tested, and
re-verified live — rather than addressed with a blanket threshold change or
a name-based allowlist.

**T1069.001 (Permission Groups Discovery — `net localgroup`).** The live
atomic's exact command already matched existing classifier code, but under
the wrong ATT&CK identifier (T1087.001, Account Discovery) — MITRE's own
canonical example for T1069.001 is precisely this command. A scoring
discipline that never credits a technique under the wrong label therefore
never credited a detection that was, in a real sense, already happening.
Corrected the label split and a related sequence-engine whitelist gap.
*Live-reconfirmed: `[DETECT]`, 0 false positives, 2.1s latency.*

**T1055 (Process Injection — CreateRemoteThread).** Confirmed at the source
that Sysmon's stock configuration disables CreateRemoteThread logging (event
ID 8) by default for noise reasons, and the provisioning script had never
patched it on — a sensor/provisioning gap, not a detection-rule gap; the
engine's own EID8 handler was independently confirmed correct. A first
corrective patch applied without error but a live `Get-WinEvent` query
proved it silently captured zero events, tracing to an inverted
understanding of Sysmon's rule-matching semantics (an empty
`onmatch="include"` block matches nothing; the correct idiom for
"log everything of this type" is an empty `onmatch="exclude"` block). The
corrected patch was independently confirmed via a live `Get-WinEvent` query
capturing a real event during the actual atomic's execution.
*Live-reconfirmed: `[DETECT]`, 0 false positives, 4.9s latency.*

**Evaluation-harness honesty (four techniques).** Independently confirmed
that four techniques whose target binary does not exist on a stock
Windows/CI host (`wmic.exe`, `msbuild.exe`, `ntdsutil.exe`, `rar.exe`) were
uniformly, falsely recorded as `attack_executed=true` — a harness defect,
not a detection defect: the generic execution path launched every command
through a shell wrapper that only fails if the shell itself cannot start,
never if the wrapped command is absent. Corrected to check the actual target
binary first and classify a missing tool as "not executed," never as a
missed detection or (a materially different claim) an actively blocked one.

**A fifth harness gap (persistence probe).** A separate defect was found in
the same investigation: the harness's persistence-artifact probe implemented
only two of three documented activity types, silently performing no action
at all for the third (Windows service creation) while still reporting
successful execution. Implemented the missing case for real.

These findings are, in aggregate, as significant to the evaluation's
credibility as the headline percentage: a measurement apparatus that
silently overstates or understates what actually happened would corrupt
every number built on top of it, and each was found by refusing to accept an
unexplained result at face value.

## 7. Threats to Validity

We distinguish three tiers of confidence throughout this evaluation and its
remediation campaign, rather than presenting all claims uniformly:

- **Proven** — directly demonstrated by captured, inspectable data: an
  incident row, a `Get-WinEvent` query result, a before/after count, a live
  `[DETECT]` outcome against the real engine.
- **Strongly supported** — multiple independent observations agree, but the
  exact scale or a specific edge case was not independently re-measured
  (e.g. the self-interference mechanism's contribution to the *exact*
  2,447-incident figure, versus its confirmed elimination at the scale
  directly tested).
- **Unverified, named explicitly** — sensor behavior under sustained,
  high-volume production load beyond CI-battery scale; a false-positive rate
  measured against a real desktop's background activity rather than a CI
  runner's; multi-host lateral movement, structurally out of reach of a
  single disposable runner; and the exact union-coverage percentage once the
  two newly-fixed techniques are folded into a fresh full-battery run rather
  than verified individually.

## 8. Conclusion

A proven detection floor of 73.1% against a live, destructive Atomic Red
Team battery — inclusive of credential-access, defense-evasion, and impact
techniques — represents a materially stronger evidentiary basis than a
static coverage count. The discovery, root-cause analysis, and corrected,
re-measured elimination of a genuine self-interference defect, together with
an ongoing, individually-verified campaign against the baseline's remaining
genuine misses, is offered as evidence of the evaluation process's own
rigor, independent of the headline detection figure. Two techniques
(T1055, T1069.001) are, as of this writing, independently confirmed fixed
against the real engine; the coverage percentage above should be read as a
floor as of the commit it cites, pending a fresh full-battery run to fold
these fixes into the authoritative union number.

**GO** — credible for controlled technical due diligence. Not yet a claim of
comprehensive coverage; Section 7 should accompany any citation of the
headline figure.

## References & Artifacts

- Battery execution — `redteam/evaluation/run_live_evaluation.ps1`
- Cross-run scoring — `redteam/evaluation/union_coverage.py`
- Isolated self-interference reproduction — `redteam/evaluation/storm_repro.py`
- Regression assertions — `tests/test_incident_storm_fix.py`
- CI definitions — `.github/workflows/redteam-tierb.yml`, `storm-repro.yml`
- Full per-technique detail and the ongoing coverage log —
  [`docs/LIVE_FIRE_EVALUATION.md`](LIVE_FIRE_EVALUATION.md)
