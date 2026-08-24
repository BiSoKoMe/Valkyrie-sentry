#!/usr/bin/env python3
"""Sensor-dependency registry + confidence degradation (edr/sensor_deps.py).

The bug being defended against: assess_confidence() scores a signal with no
knowledge of whether the sensors that produced it -- or could REFUTE it -- are
running. On this machine right now Sysmon is stopped and 45 of 57 controls are
unconfirmed, and the engine still returns HIGH. Absence of refutation is being
read as confirmation, so the agent gets more aggressive as it goes blind.

These checks pin the three relationships (requires / corroborates_with /
refuted_by) and, critically, the referential integrity of the registry: a
dependency naming a sensor that is not a real control id fails the build,
rather than silently disabling the downgrade it was supposed to apply.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402


def main() -> int:
    c = Checks("sensor dependencies -> confidence degradation", expect_min=18)

    from valkyrie.edr import sensor_deps as SD
    from valkyrie.control_taxonomy import CONTROLS
    from valkyrie.decision import (Signal, Confidence, assess_confidence,
                                   apply_sensor_state)

    real = {getattr(ctl, "name", None) for ctl in CONTROLS}
    real.discard(None)

    # ------------------------------------------------------------------ [1]
    print("\n[1] referential integrity — every sensor named must be a REAL control")
    bad: list[str] = []
    for det, dep in SD.all_registered().items():
        for s in dep.all_sensors():
            if s not in real:
                bad.append(f"{det} -> {s}")
    c.check(f"all sensors in the registry exist in control_taxonomy.CONTROLS "
            f"(a typo here would silently disable a downgrade; offenders: {bad or 'none'})",
            not bad)
    c.check("registry is non-empty", len(SD.all_registered()) >= 5)

    # ------------------------------------------------------------------ [2]
    print("\n[2] a REQUIRED sensor being dark floors confidence")
    all_live = lambda s: SD.STATE_EFFECTIVE            # noqa: E731
    proc_dark = lambda s: (SD.STATE_ABSENT if s == "process_telemetry"  # noqa: E731
                           else SD.STATE_EFFECTIVE)

    adj = SD.assess("attack_sequence", all_live)
    c.check("clean when every sensor is effective", adj.clean)

    adj = SD.assess("attack_sequence", proc_dark)
    c.check("not clean when process_telemetry is absent", not adj.clean)
    c.check("floors to 'low' — missing INPUT is not weaker input", adj.cap == "low")
    c.check("reason names the sensor and its state",
            any("process_telemetry" in r and "absent" in r for r in adj.reasons))

    # ------------------------------------------------------------------ [3]
    print("\n[3] 'degraded' counts as dark — unconfirmed is never 'fine'")
    proc_degraded = lambda s: (SD.STATE_DEGRADED if s == "process_telemetry"  # noqa: E731
                               else SD.STATE_EFFECTIVE)
    adj = SD.assess("attack_sequence", proc_degraded)
    c.check("degraded required sensor still floors confidence — coverage.py's "
            "own wording is 'cannot confirm it is actually running'",
            adj.cap == "low")
    unknown = lambda s: SD.STATE_UNKNOWN               # noqa: E731
    c.check("unknown state also counts as dark", not SD.assess("attack_sequence", unknown).clean)

    # ------------------------------------------------------------------ [4]
    print("\n[4] the subtle one: a dark REFUTER weakens, it must never strengthen")
    ref_dark = lambda s: (SD.STATE_ABSENT if s in ("dns_tunnel_detector",  # noqa: E731
                                                   "cname_uncloak")
                          else SD.STATE_EFFECTIVE)
    adj = SD.assess("network_score", ref_dark)
    c.check("a dark refuting sensor costs a notch", adj.notches_down >= 1)
    c.check("required sensor still live, so it is NOT floored to low",
            adj.cap != "low")
    c.check("reason explains unfalsifiability",
            any("refuted" in r or "unfalsifiable" in r for r in adj.reasons))

    # ------------------------------------------------------------------ [5]
    print("\n[5] a dark CORROBORATOR caps but does not floor")
    corr_dark = lambda s: (SD.STATE_ABSENT if s in ("persistence_telemetry",  # noqa: E731
                                                    "network_telemetry",
                                                    "killchain_correlator")
                           else SD.STATE_EFFECTIVE)
    adj = SD.assess("attack_sequence", corr_dark)
    c.check("caps at medium", adj.cap == "medium")
    c.check("does not floor to low (the detection still stands on its own)",
            adj.cap != "low")

    # ------------------------------------------------------------------ [6]
    print("\n[6] deliberate exemptions and safe defaults")
    nothing_live = lambda s: SD.STATE_ABSENT           # noqa: E731
    c.check("decoy_trigger stays clean even with every sensor dark — touching "
            "a decoy is self-contained evidence, declared ON PURPOSE",
            SD.assess("decoy_trigger", nothing_live).clean)
    c.check("an UNREGISTERED detector is clean — a missing entry must never "
            "silently blunt detection; the enumerating test applies the "
            "pressure to add one instead",
            SD.assess("no_such_detector", nothing_live).clean)

    # ------------------------------------------------------------------ [7]
    print("\n[7] wiring into decision.py — additive, pure, off by default")
    sig = Signal(category="attack_sequence", severity="critical",
                 source="attack_sequence", process_name="evil.exe")
    base = assess_confidence(sig)
    c.check("a completed sequence is HIGH confidence before adjustment",
            base == Confidence.HIGH)

    same, reasons = apply_sensor_state(base, sig, None)
    c.check("sensor_state=None is a no-op — existing callers are unchanged "
            "until the engine wires coverage in",
            same == base and reasons == ())

    adjusted, reasons = apply_sensor_state(base, sig, proc_dark)
    c.check("with process_telemetry dark, HIGH degrades to LOW — this is the "
            "live bug: today it would stay HIGH and could reach CONTAIN on "
            "input that is not confirmed to exist",
            adjusted == Confidence.LOW)
    c.check("degradation carries machine-readable reasons", len(reasons) >= 1)

    adjusted2, _ = apply_sensor_state(base, sig, corr_dark)
    c.check("corroborators dark caps HIGH at MEDIUM (not floored)",
            adjusted2 == Confidence.MEDIUM)

    clean, _ = apply_sensor_state(base, sig, all_live)
    c.check("fully live sensors leave confidence untouched", clean == base)

    # purity
    c.check("apply_sensor_state does not mutate the Signal",
            sig.source == "attack_sequence" and sig.severity == "critical")

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
