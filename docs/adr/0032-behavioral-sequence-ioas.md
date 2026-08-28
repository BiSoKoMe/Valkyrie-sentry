# ADR 0032 - Behavioural sequence IOAs (CrowdStrike-style Event Stream Processing)

Date: 2026-07-27 . Status: accepted . Follows: ADR 0025 (kill-chain), ADR 0027 (IOA rules)

## Context

Research into CrowdStrike Falcon's detection model (their public IOA / Event
Stream Processing material) highlighted a capability Valkyrie was missing. Its
signature approach is **Event Stream Processing (ESP)**: statefully hold only
the *relevant* prior behaviours in memory and, when a later behaviour completes
a **known ordered sequence** on the same process lineage, fire ONE named,
high-confidence indicator - "credential theft from a reflectively-injected
module in PowerShell" - *regardless of the tools used*. Their worked example:
store each `iexplore.exe` pid; when `cmd.exe` appears, check whether its parent
pid is a stored Internet Explorer - a single-pass, lineage-aware correlation.

Valkyrie had two adjacent layers but not this one:
- `behavioral_rules.py` (ADR 0027): single-event IOAs - one process start matches
  one rule. No memory of what came before.
- `killchain.py` (ADR 0025): correlation, but **generic** - it counts *distinct
  ATT&CK tactics* on a lineage ("a lot is happening here"). It cannot say *which*
  attack pattern; two intrusions with very different tradecraft look identical to
  a tactic counter.

The gap was **specific, named, ordered behavioural sequences** - the exact thing
ESP names.

## Decision

New `valkyrie/behavioral_sequences.py` - a stateful ESP-style engine:

- A `SequenceRule` is an ORDERED tuple of `Step` behaviour-predicates plus a time
  `window`. A `Step` matches a behaviour by ATT&CK technique (prefix, so a base
  id matches its sub-techniques), by label, or by activity - **never by tool
  name**, so a brand-new tool performing the same behaviour still advances the
  sequence (tool-agnostic by construction).
- `SequenceEngine.observe()` is the ESP core: it holds partial matches per
  process-lineage root, advances them in order as matching behaviours arrive
  within the window, evicts expired partials (holds only relevant state), and
  emits a named IOA the instant a sequence completes. Lineage-aware exactly like
  the ESP example - a child process's behaviour advances its parent's sequence
  via the ppid edge.
- Five shipped sequences, each a *specific* attack pattern the generic chain
  can't name: `inject-then-creds` (the CrowdStrike worked example), `creds-then-
  exfil`, `macro-dropper-c2`, `ransomware-detonation`, `download-then-persist`.
- Wired into `EdrEngine` beside the kill-chain: `_correlate_sequence` runs after
  the correlation lock releases; a completed sequence raises ONE
  `attack_sequence` incident (never re-fed, so no recursion). It complements -
  does not replace - the kill-chain: the sequence says "this IS injection->cred-
  theft," the chain says "many tactics, probably an intrusion."

## Consequences

- Endpoint detection gains named, high-confidence, ordered attack patterns on top
  of single-event rules and generic tactic correlation - the ESP layer.
- `attack_sequence` is fully wired for explainability (`edr/investigate.py`
  meaning + recommended actions + `KNOWN_INCIDENT_CATEGORIES`) and MITRE mapping
  (`edr/builtin.py`), so it passes `tests/test_explainability.py`.
- Validation: `tests/test_behavioral_sequences.py` proves each sequence fires in
  order, order matters (reversed does not fire), the window matters (too slow
  does not fire), lineage works (a child advances the parent), isolation holds
  (unrelated actors do not fire), it is tool-agnostic (novel tooling still
  fires), and the end-to-end pipeline raises one `attack_sequence` incident. The
  efficacy corpus gains 3 sequence malicious + 2 FP controls (wrong-order /
  incomplete); the gate holds at recall 100% / FPR 0%.

## Honest boundaries (what this is NOT)

- **Content is finite.** Five named sequences is a seed, not the "over 1,000
  event types" and cloud-trained pattern library CrowdStrike runs. It names the
  common high-value patterns; it does not claim to name every attack. Coverage
  grows by appending `SequenceRule`s.
- **It only sees what the sensors emit.** A sequence step advances only when a
  prior layer (rule engine, nose, ETW/kernel sensor) actually produced a
  detection with the matching technique/label. Where a behaviour isn't sensed,
  the sequence can't advance - this correlates existing signal, it doesn't
  conjure it (same honest limit as the kill-chain).
- **Lineage is user-mode-attributed.** Parent-linking uses the ppid the collector
  captured; where a detection carries no pid (e.g. a DNS event), the actor name
  is the identity, so a name-only and a pid-based behaviour won't fold together.
- **Not measured against live malware.** The corpus proves the engine
  discriminates ordered inputs; it is not a substitute for detonating real
  tooling in a VM.

## Sources

- CrowdStrike - [Understanding Indicators of Attack (IOAs): the power of event
  stream processing](https://www.crowdstrike.com/en-us/blog/understanding-indicators-attack-ioas-power-event-stream-processing-crowdstrike-falcon/)
- CrowdStrike - [What are Indicators of Attack (IOAs)?](https://www.crowdstrike.com/en-us/cybersecurity-101/threat-intelligence/indicators-of-attack-ioa/)
- Repo researched: `github.com/krewkrewkrew/crowdstrike-falcon-knowledge-center`
