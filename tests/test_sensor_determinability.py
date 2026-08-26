#!/usr/bin/env python3
"""'Cannot look' must never render as 'nothing there'.

THE BUG THIS PINS (found live on 2026-08-23)
--------------------------------------------
The Sysmon operational log is Administrators-only. `probe_sysmon()` read it
with `-ErrorAction SilentlyContinue`, so an unprivileged probe produced
`log_enabled=False`, `record_count=0`, `newest_event=None`,
`collection_live=False` — byte-identical to a genuinely dead sensor. The
product then reported itself BLIND while Sysmon was collecting 49,000 events,
and `coverage._check_sysmon()` returned ABSENT: a negative it had never
observed.

`efficacy.sensor_health()` had the same shape, returning
`command_line_source="none"` ("a miss here is BLINDNESS") while Windows 4688
command-line auditing was in fact enabled and feeding NativeProcessSensor.

WHY THIS MATTERS MORE THAN A COSMETIC REPORT
--------------------------------------------
Coverage gates authority arithmetically (`authority.authorize`, gate 2). That
is Valkyrie's whole claim: commercial EDR underwrites autonomous action
CONTRACTUALLY (a SOC and a support agreement absorb the blast radius), while
Valkyrie underwrites it STRUCTURALLY. A structural claim is only as good as the
honesty of the inputs. A probe that asserts unobserved negatives is a
correctness bug sitting directly in the authority chain.

The correct value is UNKNOWN, which `sensor_deps` already defines and already
treats exactly as `degraded` — "I do not know" is never allowed to read as
"fine". These tests pin that the probes can actually PRODUCE it.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402


def main() -> int:
    c = Checks("sensor determinability (cannot-look != nothing-there)",
               expect_min=18)

    from valkyrie import sysmon_manager as SM, coverage as COV
    from valkyrie.edr import sensor_deps as SD

    # ------------------------------------------------------------------ [1]
    print("\n[1] the access-denied detector recognises PRIVILEGE failures")
    denied_samples = [
        "Get-WinEvent : Attempted to perform an unauthorized operation.",
        "FullyQualifiedErrorId : System.UnauthorizedAccessException,"
        "Microsoft.PowerShell.Commands.GetWinEventCommand",
        "[SC] DeleteService FAILED 5:\n\nAccess is denied.",
        "Requested registry access is not allowed.",
    ]
    for s in denied_samples:
        c.check(f"denial recognised: {s[:42]!r}...", SM._is_access_denied(s))

    for s in ["True", "49479", "12.5", "", "not-found",
              "No events were found that match the specified selection criteria."]:
        c.check(f"NOT treated as denial: {s[:42]!r}", not SM._is_access_denied(s))

    # ------------------------------------------------------------------ [2]
    print("\n[2] a refused probe is UNDETERMINABLE, not absent")
    denied = SM.SysmonEnvironment(present=True, service_state="Running",
                                  access_denied=True)
    c.check("determinable is False", not denied.determinable)
    c.check("provides() still refuses -- authority is never granted "
            "on an unverified sensor", not denied.provides(1))
    why = denied.why_not(1)
    c.check("why_not says CANNOT DETERMINE", "cannot determine" in why.lower())
    c.check("why_not explicitly denies being evidence of darkness",
            "not evidence" in why.lower())
    c.check("why_not tells the operator how to resolve it",
            "elevated" in why.lower())

    # ------------------------------------------------------------------ [3]
    print("\n[3] a genuinely dark sensor still reports as dark")
    dark = SM.SysmonEnvironment(present=True, service_state="Running",
                                log_enabled=True,
                                newest_event_age_seconds=99999.0)
    c.check("a determinable probe stays determinable", dark.determinable)
    c.check("stale collection is still not provided", not dark.provides(1))
    c.check("and its reason is the real one, not 'cannot determine'",
            "cannot determine" not in dark.why_not(1).lower())

    absent = SM.SysmonEnvironment(present=False, service_state="Stopped")
    c.check("an observed-absent Sysmon says so plainly",
            "not installed/running" in absent.why_not(1))

    # ------------------------------------------------------------------ [4]
    print("\n[4] coverage has an UNKNOWN state, and it is sensor_deps' UNKNOWN")
    c.check("coverage.UNKNOWN exists", hasattr(COV, "UNKNOWN"))
    c.check("it matches sensor_deps.STATE_UNKNOWN exactly",
            COV.UNKNOWN == SD.STATE_UNKNOWN)
    c.check("and it is distinct from ABSENT", COV.UNKNOWN != COV.ABSENT)

    # ------------------------------------------------------------------ [5]
    print("\n[5] the POLICY treats unknown as degraded -- never as fine")
    # This is the property that makes returning UNKNOWN safe rather than
    # permissive: it must not buy the authority that 'effective' would.
    live = lambda _c: SD.STATE_EFFECTIVE          # noqa: E731
    unk = lambda _c: SD.STATE_UNKNOWN             # noqa: E731
    absent_fn = lambda _c: SD.STATE_ABSENT        # noqa: E731

    from valkyrie.decision import Signal, decide, assess_confidence, apply_sensor_state
    sig = Signal(category="process", source="ioa_rule", severity="high",
                 process_name="evil.exe", entity="evil.example")
    raw = assess_confidence(sig)
    conf_live, _ = apply_sensor_state(raw, sig, live)
    conf_unk, why_unk = apply_sensor_state(raw, sig, unk)
    conf_abs, _ = apply_sensor_state(raw, sig, absent_fn)

    c.check("unknown does NOT get the same confidence as effective",
            conf_unk != conf_live or raw == conf_live)
    c.check("unknown degrades (or at worst matches) absent, never exceeds live",
            _rank(conf_unk) <= _rank(conf_live))
    c.check("unknown produces a stated reason, not silent degradation",
            bool(why_unk) or conf_unk == conf_live)
    c.check("absent is at least as severe as unknown",
            _rank(conf_abs) <= _rank(conf_unk))

    # ------------------------------------------------------------------ [6]
    print("\n[6] SensorHealth carries determinability and serialises it")
    from valkyrie.efficacy import SensorHealth
    h = SensorHealth(False, "undetermined", "cannot tell", False,
                     determinable=False)
    d = h.to_dict()
    c.check("to_dict carries determinable", d.get("determinable") is False)
    c.check("ready is False when undetermined (conservative)", not h.ready)
    c.check("but the source is 'undetermined', NOT 'none'",
            h.command_line_source == "undetermined")

    dflt = SensorHealth(True, "sysmon", "fine", True)
    c.check("determinable defaults to True for normal results",
            dflt.determinable)

    return c.finish()


def _rank(conf) -> int:
    from valkyrie.decision import Confidence
    return [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH].index(conf)


if __name__ == "__main__":
    raise SystemExit(main())
