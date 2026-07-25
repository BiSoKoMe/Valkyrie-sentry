# ADR 0027 — Behavioral IOA rule engine (endpoint detection breadth)

Date: 2026-07-25 · Status: accepted · Follows: ADR 0026

## Context

The gap between Valkyrie and a Falcon-class product on the endpoint was never
architecture — the EventBus → correlation → kill-chain pipeline is sound. It
was **detection content breadth**. Process/command-line detection lived in two
functions (`classify_process`, `classify_cmdline`) with a handful of hardcoded
`if` branches: a few PowerShell shapes (encoded, download cradle, hidden
window) and office-child-shell. Atomic Red Team exercises a far wider surface —
LOLBin proxy execution (rundll32/regsvr32/mshta), credential access (comsvcs
MiniDump, reg save SAM, ntdsutil), defense evasion (Defender/AMSI/firewall
tamper, event-log clearing), recovery inhibition (vssadmin/wbadmin/bcdedit),
persistence (run keys, services, scheduled tasks, WMI consumers), discovery,
and lateral movement — none of which had a detector, so none produced a
detection.

Adding those as more `if` branches doesn't scale and isn't reviewable. Real
EDRs treat detection as **content**: declarative Indicator-of-Attack (IOA)
rules, each mapped to an ATT&CK technique, extended by adding data.

## Decision

New `valkyrie/behavioral_rules.py` — a pure, declarative IOA engine:

- A `Rule` is a small pattern over a process start: `images` / `parents`
  (basename sets), `cmd_all` / `cmd_any` (substring AND/OR), `path_any`. All
  specified conditions must match; a rule with no conditions never fires.
- Each rule carries its **exact ATT&CK technique**, a severity tuned for
  precision, a short label, and a human reason.
- `RULES` ships **32 rules** spanning execution, defense-evasion, credential-
  access, persistence, discovery, lateral-movement and impact. Coverage grows
  by appending rules — no engine changes.

Integration reuses everything: `ProcInfo.to_event()` (the process collector)
runs `classify_behavior` alongside the existing classifiers, merges labels and
severity, and carries the top hit's technique on the event's `fields`.
`EdrEngine.ingest_telemetry` now prefers that explicit technique over inferring
one from a label, so the raised detection gets the **exact** ATT&CK id — which
the kill-chain correlator (ADR 0025) turns into the exact tactic. The
`TECHNIQUE_TACTIC` map was extended to cover the new techniques so every rule
is chain-ready.

## Consequences

- Endpoint detection breadth jumps from ~5 hardcoded shapes to 32 MITRE-mapped
  rules, and composes with correlation: e.g. `office → powershell` (execution)
  + `comsvcs MiniDump` (credential-access) + `vssadmin delete shadows` (impact)
  on one process lineage now scores as one critical multi-stage chain.
- Detection is now **content**: a new technique is a data addition with a test,
  not a code change.
- Validation: `tests/test_behavioral_rules.py` — every one of the 32 rules
  fires on a representative malicious command AND maps to a chain-ready tactic;
  11 benign controls (reg query, sc query, certutil hashing, net view, msbuild,
  …) confirm the false-positive boundary; a pipeline test proves a rule hit
  becomes a detection carrying the exact technique. The efficacy corpus gained
  5 malicious behavior cases + 4 benign controls; the gate holds at recall
  100% / FPR 0%. Full unit suite 49/0/2.

## Honest boundaries (what this is NOT)

- **Content is finite and static.** 32 rules is broad, not complete — it covers
  common ATT&CK command shapes, not every technique or every obfuscation. A
  determined attacker who avoids these exact shapes (heavy obfuscation, custom
  tooling, direct syscalls, in-memory-only tradecraft) will not trip a rule.
  This raises the floor; it is not a claim of full ATT&CK coverage.
- **It needs the command line.** Rules match on process image/parent/cmdline,
  which requires the process collector (or Sysmon/ETW) to actually capture the
  command line. Where the OS doesn't provide it, cmdline rules can't fire.
- **Detection, not prevention.** A rule hit raises an incident (and can drive an
  opt-in response playbook); it does not by itself stop the process. Prevention
  remains the kernel driver's job (ADR 0026), unbuilt/unvalidated here.
- **Not measured against live Atomic Red Team.** The corpus proves the rules
  discriminate representative inputs; it does not substitute for running the
  real ART tests in a VM, which remains the gold-standard measurement.
