# Detection v2 Behavioral-Vocabulary Canonicalization

**What this closes:** the vocabulary gap found in
`docs/TIER_A_V2_PIPELINE_TRACE.md` -- 39 of 50 real Tier A technique
classifier fires produced zero Detection Architecture v2 evidence, not
because telemetry or normalization failed, but because
`detection_v2.BehaviorEngine` and the codebase's actual detector modules
spoke two different label vocabularies.

## The architectural fix, not 39 one-off mappings

The objective was never "make 90/90 green." It was: prove that
independently implemented detection subsystems can share one semantic
language, and that one reusable canonical primitive can support multiple
techniques -- the actual thesis behind Detection Architecture v2.

`valkyrie/edr/behavior_ontology.py` is the new translation boundary:

```
behavioral_rules.py, process_telemetry.py, behavior_score.py,
persistence_telemetry.py, network_telemetry.py, etw/powershell.py,
etw/sysmon.py (190+ raw, detector-specific labels)
        |
        v
 behavior_ontology.canonicalize()
        |
        v
 12 canonical behaviors (CANONICAL_BEHAVIORS)
        |
        v
 BehaviorEngine.extract()  (unchanged hypothesis thresholds)
        |
        v
 hypothesis engine / decision  (untouched)
```

`BehaviorEngine` no longer checks raw labels against a hand-picked
8-label set (`_EXECUTION_LABELS`). It canonicalizes first, then emits one
`EvidenceFact` per canonical behavior actually present, carrying the
original raw label(s) as provenance (`EvidenceFact.provenance`) so every
canonical fact still points back to the exact rule/event that produced it.

## The canonical vocabulary (12 behaviors)

| Canonical behavior | What it groups | Example raw labels |
|---|---|---|
| `unexpected_process_relationship` | anomalous execution origin/ancestry | `office_child_shell`, `masquerade_syspath`, `wrong_parent_system_proc` |
| `sensitive_configuration_modified` | durable security-relevant state change | `persistence_runkey`, `account_created`, `uac_bypass` |
| `external_communication` | a process reached an external destination | `threat_intel_ip`, `c2_tunnel`, `download` |
| `security_control_tampering` | defense evasion against the security stack | `defender_tamper`, `impair_etw`, `eventlog_cleared`, `byovd` |
| `credential_access_attempt` | credential theft/dumping/enumeration | `lsass_access`, `ntds_dump`, `kerberoasting` |
| `discovery_activity` | host/domain/account reconnaissance | `domain_discovery`, `user_discovery` |
| `lateral_movement` | remote-execution/lateral tooling | `lateral_psexec`, `lateral_wmic`, `psexec_system` |
| `code_injection` | process/memory injection primitives | `dll_injection`, `remote_thread_injection`, `reflective_load` |
| `obfuscated_execution` | encoding/obfuscation of what is executing | `encoded_powershell`, `dynamic_exec`, `certutil_decode` |
| `lolbin_proxy_execution` | a trusted OS binary proxying execution/fetch | `mshta_exec`, `regsvr32_scriptlet`, 13 `lolbin_*` labels |
| `destructive_impact` | data destruction / recovery inhibition | `destroy_files`, `shadow_delete`, `secure_wipe` |
| `collection_staging` | staging/archiving data ahead of exfiltration | `collection_archive`, `capture_pktmon` |

`unexpected_process_relationship`, `sensitive_configuration_modified`, and
`external_communication` already existed; the other 9 are new. Weights
(0.45-0.85) are judgment calls grounded in the source rules' own typical
severity, documented inline in `detection_v2.BehaviorEngine._CANONICAL_FACTS`
-- `discovery_activity` is deliberately weak (0.45) because a single recon
command is common and mostly benign; the project already has a dedicated
sequence engine (`behavioral_sequences.py`) for recon *bursts*, and this
canonical behavior only covers the single-event case.

No new hypotheses were added, and no existing threshold or
`minimum_support` value changed. All 9 new categories feed evidence into the
two existing alert hypotheses (`suspicious_execution_chain`,
`possible_data_theft`) exactly like the original three did.

## Methodology: grouped by real technique data, not by label-name guessing

Every one of `behavioral_rules.py`'s 173 rules (144 distinct labels) was
pulled programmatically with its actual MITRE ATT&CK technique field, then
grouped by tactic shape -- not by eyeballing what a label string "sounds
like." `process_telemetry.py`, `behavior_score.py`,
`persistence_telemetry.py`, `network_telemetry.py`, `etw/powershell.py`, and
`etw/sysmon.py` were each inspected at their actual label-emitting call
sites (`labels.append(...)`, `Signal(...)`, literal `"labels": [...]`
returns), not guessed from documentation.

`tests/test_behavior_ontology.py` asserts this against the **real**
vocabulary at test time -- it imports `behavioral_rules.RULES` and calls the
real classifier functions, so a new rule added later with an unmapped label
fails the suite immediately, instead of silently reopening the gap.

## Documented judgment calls (ambiguous, not unmappable)

- **`byovd`** (bring-your-own-vulnerable-driver) -> `security_control_tampering`,
  reflecting its typical real-world purpose (loading a vulnerable signed
  driver to disable EDR/AV). Its sibling `unsigned_driver`/`unsigned_module`/
  `driver_load` -> `unexpected_process_relationship` instead, a more neutral
  "unusual execution origin" reading when there's no evidence of
  tamper-specific intent.
- **`hidden_exec`/`hide_file`** (T1564 Hide Artifacts) -> `obfuscated_execution`
  rather than `unexpected_process_relationship`; both readings are
  defensible, this one groups it with other "conceal what's running" signals.
- **`psexec_system`** -> `lateral_movement` (a SYSTEM shell obtained via
  PsExec is lateral-movement tooling in intent) rather than
  `unexpected_process_relationship`.

## Genuinely non-canonical (documented in `UNMAPPED_KNOWN_LABELS`, not a gap)

- `trusted`, `trusted_os_path`, `signed`, `trusted_os` -- benign
  counter-evidence (`TRUST_LABELS`), never an attack behavior.
- `known_admin`, `expected_maintenance` -- declared in the trust vocabulary
  with **no current producer anywhere in this codebase** (checked directly).
  An honest existing gap, left named rather than invented a source for.
- `trusted_gesture`, `user_initiated` -- handled directly by
  `BehaviorEngine` as `active_user_context`, outside this table by design.
- `sigma_import` -- an import-provenance marker on Sigma-derived rule hits
  (verified: zero rules in `behavioral_rules.RULES` have this as their own
  label; it only ever accompanies a real semantic label at match time), not
  a behavior signal. Excluding it never loses evidence.

## Rerun result: real Tier A catalog, before and after

| Stage | Before | After |
|---|---:|---:|
| Real rules fired | 50 | 50 |
| Source behaviors emitted | -- | 62 |
| Successfully canonicalized | -- | 55 |
| Unmapped | -- | 0 |
| Canonical evidence reaching v2 (behavior stage) | 11 (17.5%) | 53 (84.1%) |
| Hypothesis formed | 11 (17.5%) | 53 (84.1%) |
| Final verdict (alert) | 1 (1.6%) | 3 (4.8%) |
| Vocabulary gap | 39 | **0** |

Full detail in `docs/TIER_A_V2_PIPELINE_TRACE.md` (updated in place) and
`redteam/evaluation/tier_a_pipeline_trace.py`.

## The current wall, now visible for the first time

Before this fix, the failure was invisible: an integration gap wearing the
costume of "v2 doesn't detect anything." After it, the failure has moved
downstream to exactly one place -- `first_failures.decision = 50`. Every one
of those 50 techniques now reaches canonical evidence but falls short of
`detection_v2._HYPOTHESES`' `minimum_support=2` requirement, because
`replay_harness.py`'s Tier A methodology replays each technique as ONE
isolated event with no causal chain (its own documented limitation). 3
techniques (e.g. `exec-mshta-remote`, whose real classifier returns both
`mshta_exec` and `clickfix_paste_exec` for one command line) clear the bar
anyway, because their single event genuinely canonicalizes into two distinct
behaviors -- exactly the "independently weak signals combine" property
Detection Architecture v2 exists to capture, with no threshold touched to
produce it.

That is the actual next question: does the real world supply the
corroborating second fact (a causal chain, a second collector's evidence)
that Tier A's single-event replay cannot? Answering that is a causal-graph
and telemetry-realism question, not a vocabulary question -- and it is only
askable now that the vocabulary question is closed.

## Benign regression coverage

`tests/test_behavior_ontology_benign_regression.py` checks the risk this
whole change introduces: widening `BehaviorEngine` from 3 categories to 12
could have made a single common, often-legitimate signal enough to convict.
It confirms, per new category, that one isolated fact never alerts alone
(`minimum_support=2` holds), that a trusted-maintenance signal contradicts
even a two-fact combination from the same benign action, and -- the honest
complement -- that two genuinely untrusted new-category facts together still
do alert, so the widened vocabulary demonstrably contributes real detection
power rather than being inert.
