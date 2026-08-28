# ADR 0028 - Behavioral anomaly scorer (the generalizing "nose")

Date: 2026-07-25 . Status: accepted . Follows: ADR 0027

## Context

ADR 0027 shipped a Falcon-style IOA rule engine: 32 declarative rules, each an
exact ATT&CK-mapped command shape. That is real detection breadth, but it is a
**list of known smells**. A rule is a photograph of one attack; it cannot see a
threat nobody photographed. An attacker who renames a binary, obfuscates a
command in a way no rule string matches, or uses a parent->child lineage the
rules don't enumerate slips straight through. Every list-based detector has this
ceiling, and adding more rules never removes it - it only moves it.

The project's own detection philosophy (memory: *behavioral is the real path;
lists are a supplement*) points the other way. What was missing was the
complementary half: a detector that **generalizes** - that scores the intrinsic
*wrongness* of a process the way a drug dog scores a scent, keying on the shape
of hiding rather than on specific strings, so it fires on malware it has never
been shown.

## Decision

New `valkyrie/behavior_score.py` - a pure weak-signal anomaly ensemble.

- Every signal is **intrinsic and generalizing**, never a known-bad literal:
  - `masquerade_system_image` - a core system-process name (svchost, lsass, ...)
    running from outside System32 (weight 0.75).
  - `system_name_lookalike` - an edit-distance-1 typosquat of a system name
    (svch0st, scvhost) (0.5).
  - `double_extension` - a document-looking name with an executable tail
    (invoice.pdf.exe) (0.6); `bidi_filename_trick` - RTL/bidi control chars (0.7).
  - `server_spawned_shell` - an internet-facing service (w3wp, sqlservr, ...)
    spawning a shell, the web-shell pattern (0.6); `document_spawned_interpreter`
    - a browser/Office/mail app spawning an interpreter (0.5).
  - `interpreter_from_lowtrust` - a real interpreter running from Temp/Downloads
    (a relocated binary dodging path allowlists) (0.5).
  - `obfuscated_command` - obfuscation measured by **shape** (encoded blobs,
    char-code reassembly, caret/backtick escape spam, env-var splicing,
    format-operator string building), 0..0.6, so novel obfuscation still smells.
  - `script_proxy_remote` (0.55) / `lolbin_network_fetch` (0.35) - a LOLBin
    reaching the network; script-proxy binaries (mshta/regsvr32/rundll32) fire
    alone, general interpreters only compound (developers legitimately fetch URLs).
  - `machine_generated_name` (0.35), `rare_ancestry_for_host` (0.15, opt-in
    per-host baseline - "trained on your house").
- A process's **score is the capped sum** of its signals. `.fired()` is true only
  above a 0.45 threshold, and weights are tuned so **no single weak signal fires**
  - a plain exe from Downloads (0.3), a lone LOLBin-URL (0.35), a random name
  (0.35) all stay quiet. Only a strong intrinsic tell or a *compounding
  combination* crosses. This is the precision discipline that keeps the
  false-positive rate at zero while still generalizing.

Integration mirrors ADR 0027: `ProcInfo.to_event()` runs `classify_anomaly`
after the rule engine. The nose can raise severity and add labels; it supplies
the ATT&CK technique only when no rule already set a more specific one, and it
surfaces **only when it fires**, so a below-bar scent never raises a detection.
The technique flows into the kill-chain correlator exactly like a rule's does -
so a masquerading binary that then dumps LSASS chains into one incident.

## Consequences

- Valkyrie now has both halves of real endpoint detection: **content** (the rule
  list, ADR 0027) *and* a **generalizing detector** that catches shapes no rule
  covers. The efficacy corpus proves the second half on six malicious shapes the
  rule engine returns zero hits for (svchost masquerade, double-extension lure,
  IIS web-shell, browser-spawned PowerShell, char-code-obfuscated command,
  system-name typosquat) with four benign look-alike controls (real svchost,
  Downloads installer, AppData updater, msbuild-under-devenv). Gate holds:
  recall 46/46 (100%), FPR 0/43 (0%).
- `tests/test_behavior_score.py` pins the behavior directly: 12 malicious shapes
  fire, 12 benign look-alikes stay quiet, weak signals demonstrably compound
  (one alone does not fire), and the baseline lift only tips a near-bar case.

## Honest boundaries (what this is NOT)

- **A score is not a proof.** The nose raises *suspicion* from weak signals; it
  will occasionally rank an unusual-but-benign program above the bar in the
  wild, and a careful attacker who avoids every intrinsic tell (signed binary,
  clean name, normal location, unobfuscated command, plausible parent) scores
  low. It raises the floor and generalizes; it does not claim to be unbeatable.
- **It is calibrated, not learned.** The weights are hand-tuned and explainable,
  not fit to a labelled dataset. That is a deliberate trade for auditability
  over a black-box model - but it means the thresholds encode the author's
  judgement, and real-world FP tuning will move them.
- **It needs the command line / path / lineage** the collector captures; where
  the OS withholds those (short-lived process, denied access), the signals it
  keys on aren't there to score.
- **Detection, not prevention**, and **not a substitute for a live Atomic Red
  Team run.** The corpus proves the scorer discriminates representative inputs;
  detonating real samples in a VM remains the gold standard this complements.
