# ADR 0023 - Efficacy coverage for the ETW/sensor classifiers + CI gate

Date: 2026-07-19 . Status: accepted . Follows: ADR 0022

## Context

ADR 0022 stood up `tests/efficacy/` and measured **7** classifiers at 100% /
0% on a technique-representative corpus. But four shipped classifier families
each carried real MITRE ATT&CK techniques with **zero efficacy measurement**:

- `etw/sysmon.classify_sysmon` - injection (T1055), LSASS access (T1003.001),
  process tampering (T1055.012), unsigned module load (T1574), registry/
  Startup persistence (T1547.001).
- `etw/wmi.classify_wmi` - WMI event-subscription persistence (T1546.003).
- `process_telemetry.classify_process` - Office-spawns-shell (T1204.002),
  LOLBin-from-temp (T1218). (Only `classify_cmdline` was previously measured.)
- `network_telemetry.classify_connection` - hard-coded-IP C2 (T1071), the seam
  DNS filtering structurally cannot see.

Per the Validation Philosophy - *if a detector cannot be measured, it is
incomplete* - an unmeasured detector is a liability regardless of how good its
code looks. This was the highest-value measurable improvement available and
the explicit "Next" of ADR 0022.

## Decision

1. **Extend the corpus and harness** (`tests/efficacy/`) to drive all four
   families directly through their real pure classifiers - no mocks. Added 12
   malicious cases (9 new techniques across 6 tactics) and 9 benign controls,
   each malicious technique paired with a benign control that must stay silent
   (signed process/module, non-LSASS access, non-autorun registry key,
   ordinary outbound connection, benign WMI provider activity, signed apps,
   clean public IP). Sysmon cases carry the exact `(EventID, EventData)` shape
   the live sensor parses; the network case derives reputation from the real
   `ThreatIntelManager`, measuring the end-to-end collector->intel path.
2. **Wire the gate into CI** as a dedicated `efficacy` job in
   `.github/workflows/tests.yml`: `python tests/efficacy/harness.py` fails the
   build if recall < 85% or FPR > 5%. Detection degradation is now a red build,
   not a silent ship.

## Result

Corpus 15->27 malicious, 16->25 benign. Recall/FPR held at **100% / 0%**;
measured technique coverage roughly doubled. All 42 unit tests remain green.
Unlike ADR 0022, this expansion surfaced no classifier bug - the classifiers
already discriminated these representative inputs; the change is that we can
now prove it and guard it.

## Honest findings recorded, not papered over

- **DGA C2 domains are a measured blind spot.** High-entropy registered
  domains (`xjkqvw92hd8skwlqz3ty.com`, entropy 4.02) are allowed: the
  behavioral entropy signal caps below the 0.70 block threshold and a bare
  2LD has nothing to corroborate. This is a deliberate precision choice (a
  pure entropy block false-positives on CDN hostnames of identical entropy),
  **not** added to the corpus as passing - recording an uncaught technique as
  caught would game the scorecard. Queued as the next cycle: a corroborated
  DGA detector validated against a large benign control set, or the
  infra-bound model approach we will not fake. See
  docs/DETECTION_EFFICACY_REPORT.md.
- The boundary from ADR 0022 still holds: this measures classifier
  *discrimination on author-known inputs*, not sensor capture or novel
  adversary behavior, and does not replace live-sample VM testing.

## Rollback

Additive test tooling and one CI job. Revert the `corpus.py`/`harness.py`
additions and drop the `efficacy` job to remove; no product code changed.

## Next

Build the corroborated DGA detector (its own design -> threat-model -> FP-
validation -> ADR cycle); grow the corpus as detectors ship; and stand up the
VM lab (Atomic Red Team + lab beacon) for the sensor-capture dimension this
harness structurally cannot measure.
