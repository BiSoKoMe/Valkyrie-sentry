#!/usr/bin/env python3
"""Registry-backed coverage probes (valkyrie/coverage.py).

Before these, 50 of 57 controls reported the same sentence:

    "module present and importable, but no independent liveness probe is
     wired -- cannot confirm it is actually running"

That is not a measurement of the defense. It is a measurement of how many
probes someone has written. The coverage fraction was reporting the state of
coverage.py while being consumed as though it meant the state of the host --
including by authority.py, as a gate on autonomous action. A gate that says
"no" because of unwritten measurement code is worse than no gate.

Two live health surfaces already existed in a running engine and were simply
not consulted: the ComponentRegistry (19 subsystems, each with real health)
and the responder registry (which actions are dispatchable right now).

The property that matters most here is that these probes can LOWER the score.
Converting an "unknown" into a truthful "absent" is an improvement even though
the number goes down. A probe that can only confirm good news is not a probe,
and every check below that asserts a downgrade is deliberate.

Pure fakes. No engine, no host state, no network.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402


class _FakeComponentRegistry:
    def __init__(self, health: dict, raises: bool = False) -> None:
        self._health = health
        self._raises = raises

    def health(self) -> dict:
        if self._raises:
            raise RuntimeError("registry exploded")
        return self._health


class _FakeResponderRegistry:
    def __init__(self, actions, raises: bool = False) -> None:
        self._actions = list(actions)
        self._raises = raises

    def available_actions(self):
        if self._raises:
            raise RuntimeError("responder registry exploded")
        return list(self._actions)


def _result(results, name):
    for r in results:
        if r.name == name:
            return r
    return None


def main() -> int:
    c = Checks("registry-backed coverage probes", expect_min=18)

    from valkyrie import coverage as CV

    # ------------------------------------------------------------------ [1]
    print("\n[1] with NO registries supplied, behaviour is unchanged")
    base = CV.check_all(CV.CoverageContext())
    r = _result(base, "blocklist")
    c.check("a component-backed control falls back to the generic verdict "
            "instead of inventing one from a registry it does not have",
            r is not None and "no independent liveness probe" in r.detail)
    r = _result(base, "kill_process")
    c.check("so does a responder-backed control",
            r is not None and "no independent liveness probe" in r.detail)

    # ------------------------------------------------------------------ [2]
    print("\n[2] a HEALTHY component resolves to effective, with real detail")
    ctx = CV.CoverageContext(component_registry=_FakeComponentRegistry({
        "blocklist": {"state": "up", "detail": ""},
        "amsi": {"state": "up", "detail": ""},
    }))
    res = CV.check_all(ctx)
    r = _result(res, "blocklist")
    c.check("blocklist is now EFFECTIVE on live evidence",
            r is not None and r.state == CV.EFFECTIVE)
    c.check("and says what it measured, not that it gave up",
            r is not None and "reports up" in r.detail)

    # ------------------------------------------------------------------ [3]
    print("\n[3] THE POINT: a probe must be able to LOWER the score")
    ctx = CV.CoverageContext(component_registry=_FakeComponentRegistry({
        "blocklist": {"state": "down", "detail": "not wired"},
        "amsi": {"state": "degraded", "detail": "self-reported unhealthy"},
        "playbooks": {"state": "disabled", "detail": "not available on this host"},
        "cred_watch": {"state": "error", "detail": "probe raised"},
    }))
    res = CV.check_all(ctx)
    c.check("'down' becomes ABSENT — not 'unknown', the engine booted and did "
            "not wire it",
            _result(res, "blocklist").state == CV.ABSENT)
    c.check("'degraded' stays DEGRADED",
            _result(res, "amsi_scan").state == CV.DEGRADED)
    c.check("'disabled' becomes ABSENT — a control that does not apply here is "
            "not protecting this host, whatever the reason",
            _result(res, "playbook_automation").state == CV.ABSENT)
    c.check("'error' becomes DEGRADED — the probe failed, so the state is "
            "genuinely unknown and must not be reported as either extreme",
            _result(res, "browser_cred_watch").state == CV.DEGRADED)

    # ------------------------------------------------------------------ [4]
    print("\n[4] a component the engine never registered is ABSENT, not unknown")
    ctx = CV.CoverageContext(component_registry=_FakeComponentRegistry({}))
    r = _result(CV.check_all(ctx), "threat_intel")
    c.check("an unregistered component reports absent", r.state == CV.ABSENT)
    c.check("and names what was missing",
            "not wired at startup" in r.detail)

    # ------------------------------------------------------------------ [5]
    print("\n[5] responder controls are real only if DISPATCHABLE")
    ctx = CV.CoverageContext(responder_registry=_FakeResponderRegistry(
        ["block_domain", "kill_process"]))
    res = CV.check_all(ctx)
    c.check("a registered action is effective",
            _result(res, "block_domain").state == CV.EFFECTIVE)
    c.check("and says it is dispatchable",
            "dispatchable" in _result(res, "block_domain").detail)
    r = _result(res, "isolate_host")
    c.check("an action nothing will dispatch is ABSENT — a responder whose "
            "module imports but which no registry will call is not a control, "
            "it is dead code", r.state == CV.ABSENT)
    c.check("and the reason distinguishes 'exists' from 'will run'",
            "nothing will dispatch it" in r.detail)

    # ------------------------------------------------------------------ [6]
    print("\n[6] a registry that RAISES yields degraded, never a crash and "
          "never a silent pass")
    ctx = CV.CoverageContext(
        component_registry=_FakeComponentRegistry({}, raises=True),
        responder_registry=_FakeResponderRegistry([], raises=True))
    res = CV.check_all(ctx)
    c.check("check_all still returns a full report",
            len(res) == len(CV.CONTROLS) if hasattr(CV, "CONTROLS") else len(res) > 0)
    c.check("the component probe degrades and names the failure",
            _result(res, "blocklist").state == CV.DEGRADED
            and "raised" in _result(res, "blocklist").detail)
    c.check("so does the responder probe",
            _result(res, "kill_process").state == CV.DEGRADED
            and "raised" in _result(res, "kill_process").detail)

    # ------------------------------------------------------------------ [7]
    print("\n[7] the probes measurably move the number, in both directions")
    healthy = {name: {"state": "up", "detail": ""}
               for name in set(CV._COMPONENT_BACKED.values())}
    up_ctx = CV.CoverageContext(
        component_registry=_FakeComponentRegistry(healthy),
        responder_registry=_FakeResponderRegistry(
            list(CV._RESPONDER_BACKED.values())))
    down_ctx = CV.CoverageContext(
        component_registry=_FakeComponentRegistry(
            {name: {"state": "down", "detail": "not wired"}
             for name in set(CV._COMPONENT_BACKED.values())}),
        responder_registry=_FakeResponderRegistry([]))

    base_sum = CV.summarize(base)
    up_sum = CV.summarize(CV.check_all(up_ctx))
    down_sum = CV.summarize(CV.check_all(down_ctx))
    base_f, up_f, down_f = (base_sum.fraction_effective,
                            up_sum.fraction_effective,
                            down_sum.fraction_effective)
    print(f"      unmeasured={base_f:.3f} {base_sum.counts}")
    print(f"      all-healthy={up_f:.3f} {up_sum.counts}")
    print(f"      all-down={down_f:.3f} {down_sum.counts}")

    c.check(f"a healthy engine now scores materially higher "
            f"({base_f:.3f} -> {up_f:.3f})", up_f > base_f)
    c.check("the two extremes are far apart — the metric now discriminates, "
            "which one identical 'no probe wired' verdict could not",
            (up_f - down_f) > 0.25)

    # fraction_effective deliberately does NOT drop for the all-down case, and
    # asserting that it would was my error: these controls were DEGRADED before
    # and are ABSENT now, and neither counts as effective. The real improvement
    # is in which bucket they land in -- "we cannot tell" becoming "it is off".
    base_absent = base_sum.counts.get("absent", 0)
    down_absent = down_sum.counts.get("absent", 0)
    base_degraded = base_sum.counts.get("degraded", 0)
    down_degraded = down_sum.counts.get("degraded", 0)
    c.check(f"a broken engine reports far more ABSENT than the unmeasured "
            f"baseline ({base_absent} -> {down_absent}) — the old report could "
            f"not say a subsystem was OFF, only that it had not looked",
            down_absent > base_absent + 5)
    c.check(f"and correspondingly fewer unknown-DEGRADED "
            f"({base_degraded} -> {down_degraded})",
            down_degraded < base_degraded)

    # ------------------------------------------------------------------ [8]
    print("\n[8] a hand-written specific probe still wins over the generic map")
    ctx = CV.CoverageContext(component_registry=_FakeComponentRegistry(
        {"firewall": {"state": "up", "detail": ""}}))
    r = _result(CV.check_all(ctx), "firewall")
    c.check("firewall keeps its dedicated probe's verdict, not a registry "
            "lookup — the specific check is the more precise measurement",
            r is not None and "component 'firewall' reports" not in r.detail)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
