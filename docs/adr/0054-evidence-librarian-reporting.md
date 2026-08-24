# ADR 0054 - The evidence librarian: testing results as a forensic chain

Date: 2026-08-23 . Status: accepted . Follows: ADR 0022 (efficacy harness), ADR 0047 (evasion tier), ADR 0053 (overload loop)

## Context

On 2026-08-23 a live-EDR report went: "5 techniques detected end-to-end" ->
"that was wrong" -> "the battery never ran." The engine had gone deaf 15s into
startup; incident-store rows left by the engine's own activity were read as
attack detections; and a run that measured *nothing* nearly became a "0%
detection rate." The DNS interceptor separately stranded the host's Wi-Fi the
same day. Every one of those is one failure: **interpretation was allowed to run
ahead of evidence, and infrastructure failure was allowed to wear the costume of
a security result.**

A longer, more careful narrative does not fix this - the fix is to make the
reporting system structurally incapable of the lie.

## Decision

New `redteam/evaluation/evidence.py` - a forensic evidence librarian. It stores
every result in four separated layers that are never blended:

- **L1 Raw evidence** (`Evidence`): what literally happened. A detection-shaped
  event carries `linked_attack` - the tie to the attack it belongs to, whose
  ABSENCE is what made stray rows look like hits.
- **L2 Test state**: tri-state facts - `attack_executed`, `engine_responsive`,
  `telemetry_available`. Tri-state, not bool, so "unknown" is a first-class
  answer and is never silently read as "no".
- **L3 Detection result**: DETECTED / NOT_DETECTED / INCONCLUSIVE / NOT_TESTED -
  **derived**, never asserted.
- **L4 Validity**: VALID / INCONCLUSIVE / INFRASTRUCTURE_FAILURE / ... - whether
  the measurement is even allowed to count.

**The adjudicator is the anti-lie core.** `adjudicate(record)` gates the evidence
chain in order, infrastructure gates FIRST:

    attack executed? -> engine responsive? -> telemetry present?
    -> detection event LINKED to the attack? -> conclusion

A `DETECTED` verdict requires *every* link. Miss one and the verdict is
`NOT_TESTED` or `INCONCLUSIVE` with the broken link named - never a detection,
and never a `NOT_DETECTED` that would score as a miss. Detection evidence not
linked to an executed attack is explicitly excluded and named. Replayed against
the real 2026-08-23 run (attack never executed, engine deaf, 5 stray rows), it
returns `NOT_TESTED / INFRASTRUCTURE_FAILURE` and lists the 5 rows as EXCLUDED -
it is structurally unable to emit "5 detected".

**Honest scoring** (`score`): the detection rate is `detected / VALID
measurements`, never over scheduled or executed. Zero valid measurements yields
`N/A` (None), not a misleading `0%`. 34 unexecuted tests -> N/A; 30 valid of 34
-> "90% of valid", with the 4 infra failures shown, not hidden in the
denominator.

**The consistency audit** (`audit`) scans for contradictions - detected without
execution, not-detected with a linked detection, a detection linked to an
unexecuted attack, duplicate ids, stray detection rows. If any exist, `score`
refuses to produce a number and returns REPORT VALIDATION FAILED. (On the real
run this is what fires: the stray rows are contradictory input, so no score is
produced at all - stronger than merely reporting N/A.)

**Corrections are preserved** (`Correction`, `TestLibrary`): a wrong conclusion
is never overwritten - it is superseded with a reason and its evidence, so
"5 detected -> retracted -> unmeasured" stays an auditable history. The library
is append-only; re-adding a run id is refused.

**The dashboard** (`dashboard`) renders the 10-second read (Campaign / Status /
Valid / Result) and then, immediately, WHY anything is N/A or UNMEASURED or
VALIDATION FAILED.

45 checks in `test_evidence.py`, including the keystone that replays the exact
2026-08-23 trap.

## Consequences

- The specific lie that happened cannot happen: a stray DB row cannot become a
  detection, an infra failure cannot become a 0%, and a contradictory set cannot
  produce a score.
- Ingestion (`from_tierb_record`) is conservative: a harness "detected" with no
  execution proof ingests as UNKNOWN and adjudicates to NOT_TESTED, so old
  result files cannot be inflated.
- This is the reporting layer ABOVE the existing `score.py` / `union_coverage.py`;
  those still compute raw coverage, this decides what may honestly be claimed
  from it. Wiring the live harness to emit `Evidence`/`TestRecord` directly is a
  follow-up.

## Honesty

This changes how results are REPORTED, not what Valkyrie detects. It does not
raise any number. Its entire purpose is to make every number - and every
"unmeasured" - true.
