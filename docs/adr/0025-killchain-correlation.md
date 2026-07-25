# ADR 0025 — Multi-stage kill-chain correlation

Date: 2026-07-24 · Status: accepted · Follows: ADR 0024

## Context

A live Atomic Red Team run surfaced a real complaint: Valkyrie *detected*
individual attacker actions but each one landed as its own low-signal
incident, and nothing rose to the confidence needed to act. Root cause, found
in the code (not guessed):

`store.find_open_incident` — the only correlation Valkyrie had — groups
detections by **the same `category`** within a window. So one intrusion driven
by a single process fragmented into several disconnected incidents:

```
powershell.exe  encoded command   (category: process)       → incident A
powershell.exe  DNS C2 beacon      (category: intelligence)  → incident B
powershell.exe  registry Run key   (category: persistence)   → incident C
```

None of A/B/C alone is confident enough to justify a response, and the analyst
sees three unrelated blips instead of one attack. This is the difference
between "collects telemetry" and "detects intrusions": the signal is in the
*sequence across ATT&CK tactics on one actor*, which same-category grouping
structurally cannot see.

## Decision

Add a second, additive correlation layer — `valkyrie/edr/killchain.py`
(`KillChainCorrelator`) — that scores the sequence, **extending** the ingest
pipeline rather than replacing the base correlator:

- A static, honest `TECHNIQUE_TACTIC` map covering **only** the 30 techniques
  Valkyrie actually emits (grepped from the tree), so it never implies
  coverage that doesn't exist. Each detection's `technique` → its ATT&CK
  tactic.
- Per **actor** (process name), a sliding window of the *distinct* tactics
  seen. When one actor crosses ≥ 2 distinct tactics, the engine raises a
  single `attack_chain` incident that **grows** as new stages appear (it
  re-emits only when a genuinely new tactic joins — no alert storm).
- Confidence is a **pure, explainable** function: `0.25 × distinct_tactics`,
  `+0.15` if the chain reaches a high-impact tactic (credential-access /
  exfiltration / impact). Severity: ≥0.9 critical, ≥0.7 high, else medium.
  No learned weights, no opaque thresholds — every number is reproduced in a
  unit test, and each incident carries a plain-English `explanation`.

Integration is deliberately minimal and safe: `_ingest_detection` feeds the
correlator **after** releasing `_corr_lock` (a plain `Lock`; re-entering to
raise the chain incident under it would deadlock), and the raised detection
carries `category="attack_chain"`, which is never fed back — so there is no
recursion and no new primary signal is invented. The correlator only escalates
confidence when **independent detectors already agree**.

## Consequences

- The three-incident example above now also produces **one** high/critical
  `attack_chain` incident naming `powershell.exe`, listing the tactics in
  order, with a confidence that rose at each stage. The base incidents remain
  (full evidence is preserved); the chain is the correlated view on top.
- New `attack_chain` category is wired through the MITRE map (builtin), the
  explainability gate (`investigate.py` — meaning + recommended response,
  enforced by `test_explainability.py`), so it is never an unexplained score.
- Validation: `tests/test_killchain.py` (33 checks — pure mapping/scoring,
  correlator windowing/growth/eviction, engine end-to-end) and two efficacy
  corpus cases (a full execution→C2→persistence→cred-access intrusion and a
  ransomware execution→evasion→impact chain) with two benign controls
  (single-tactic C2 fan-out; repeated admin PowerShell). Efficacy gate holds
  at recall 100% / FPR 0%.

## Honest boundaries (what this is NOT)

- **Actor = process name, not true lineage.** A real chain often spans
  `powershell → rundll32 → …`; correlating across a parent→child process tree
  needs a consistent PID/parent map at the detection layer that the user-mode
  sensors don't yet guarantee. Naming is the pragmatic key today; PID-level
  lineage is future work (and is one of the things a kernel driver would make
  reliable — see below).
- **Correlation, not clairvoyance.** This raises confidence when independent
  detectors agree; it cannot manufacture a stage the sensors never observed.
  If a technique isn't detected upstream, it isn't in the chain.
- **No kernel visibility.** Tamper-proof, pre-execution telemetry (image
  loads, handle opens to LSASS, remote-thread creation observed in-kernel)
  remains out of reach without a signed minifilter/ETW-consumer driver, which
  Valkyrie deliberately does not ship. That is the architectural ceiling; this
  ADR raises the ceiling of *correlation* under it, honestly.
