# Application Engineering Narrative

I built Valkyrie because I was dissatisfied with security tools that present a
verdict without showing what caused it. My question became more specific over
time: can one local system connect security and privacy observations, explain
the causal chain, and refuse an unsafe response when its evidence is incomplete?

The difficult part was not writing another detection rule. It was learning when
the system did not know enough to act. User-mode process collection can miss
short-lived processes. Browser context does not provide an authoritative
Windows process identity. A privacy monitor can become a privacy risk if it
stores the values it is supposed to protect. An unsigned driver may compile but
cannot honestly be described as deployed protection. Those failures changed the
architecture.

I keyed process identity with creation time to reduce PID-reuse errors, marked
inferred graph nodes instead of presenting them as observed facts, bounded the
graph, and made response actions dry-run by default. I kept raw request values
out of the provenance graph. When I added browser context, I did not guess a
PID. I recorded the missing attribution explicitly.

The newest experiment tests causal authority. A trusted form gesture creates a
two-second, one-shot grant scoped to source, destination, tab, frame, action,
and coarse data labels. The matching consequence may proceed; a replay,
destination change, frame change, label escalation, expiry, or absent grant is
refused. The mechanism uses exact deterministic comparisons, not an AI model or
a cloud reputation service.

Several failure cases forced redesigns. Separate native messages could arrive
out of order, so I moved the extension to a persistent channel. A failed scope
probe could leave authority reusable, so failure now consumes the grant. Raw
values in telemetry would contradict the privacy goal, so I built a sentinel
test that fails if the value crosses the collector boundary. I also made the
evidence runner fail its process when a threshold is missed, because a report
that always generates a green result is not evidence.

In the fixed synthetic experiment, Valkyrie classified 500 authorized and 100
unauthorized consequences correctly on a clean GitHub Windows runner, with
zero false allows, zero false refusals, and zero retained raw sentinels. The
in-process p99 was 0.1206 ms. I do not present that as browser or enforcement
latency. The current extension records the decision but does not cancel the
request, and it still lacks authoritative Windows PID attribution.

This project taught me to separate code existence from evidence. A component
can be implemented, structurally tested, synthetically measured, or live
validated, and those are not interchangeable claims. The next step is a real
Chromium experiment in an isolated Windows VM that measures each stage and
tries to bypass the authority boundary. If the extension cannot provide
complete mediation, I will not hide that result. I will move the decision point
or narrow the claim.

Valkyrie is not a finished competitor to CrowdStrike or Palo Alto. Its value is
the engineering question it makes testable: whether local causal reasoning can
unify security and privacy decisions without exporting personal content. What
I want to continue studying is how to turn that idea into a system whose
correctness is measured under real workloads, not assumed from the size of its
codebase.
