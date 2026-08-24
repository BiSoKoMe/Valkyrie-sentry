#!/usr/bin/env python3
"""Coverage metric tests (valkyrie/coverage.py, IIBA §4.8.3 + Clinton ch. 9).

Pins the exact case that motivated this module: Sysmon INSTALLED but
STOPPED must report ABSENT, never EFFECTIVE — a binary
installed/not-installed check would get this wrong; the three-state model
(effective/degraded/absent) is what makes it possible to get it right.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from harness import Checks   # noqa: E402

from valkyrie.control_taxonomy import CONTROLS               # noqa: E402
from valkyrie.coverage import (                               # noqa: E402
    ABSENT, DEGRADED, EFFECTIVE, STATES, CoverageContext, check_all,
    summarize,
)

c = Checks("coverage metric", expect_min=15)


class _FakeSysmonEnv:
    def __init__(self, present, collection_live, configured_eids, detail=""):
        self.present = present
        self.collection_live = collection_live
        self.configured_eids = configured_eids
        self.detail = detail


def test_sysmon_three_states() -> None:
    print("\n[1] Sysmon coverage: the exact three-state case this module exists for")
    from valkyrie import sysmon_manager

    # 1a. Not present at all -> ABSENT
    with patch.object(sysmon_manager, "probe_sysmon",
                      return_value=_FakeSysmonEnv(False, False, set(), "not installed")):
        results = check_all()
    sysmon = next(r for r in results if r.name == "etw_sysmon")
    c.check("Sysmon not installed -> ABSENT", sysmon.state == ABSENT)

    # 1b. THE case: installed, service present, but NOT delivering events
    # (e.g. stopped). Must NOT be EFFECTIVE.
    with patch.object(sysmon_manager, "probe_sysmon",
                      return_value=_FakeSysmonEnv(True, False, set(),
                                                  "Sysmon service state is 'Stopped'")):
        results = check_all()
    sysmon = next(r for r in results if r.name == "etw_sysmon")
    c.check("Sysmon installed but STOPPED -> ABSENT, not EFFECTIVE",
            sysmon.state == ABSENT)
    c.check("detail says it's not collecting, not a generic message",
            "not collecting" in sysmon.detail.lower()
            or "stopped" in sysmon.detail.lower())

    # 1c. Running and collecting, but missing some of the EIDs Valkyrie needs
    # -> DEGRADED (partial value), distinct from fully absent.
    from valkyrie.sysmon_manager import _EID_RULE_SECTION
    have_all = set(_EID_RULE_SECTION)
    missing_one = have_all - {next(iter(have_all))}
    with patch.object(sysmon_manager, "probe_sysmon",
                      return_value=_FakeSysmonEnv(True, True, missing_one,
                                                  "running")):
        results = check_all()
    sysmon = next(r for r in results if r.name == "etw_sysmon")
    c.check("Sysmon running but missing an EID -> DEGRADED, not EFFECTIVE or ABSENT",
            sysmon.state == DEGRADED)

    # 1d. Fully healthy -> EFFECTIVE
    with patch.object(sysmon_manager, "probe_sysmon",
                      return_value=_FakeSysmonEnv(True, True, have_all,
                                                  "collecting everything")):
        results = check_all()
    sysmon = next(r for r in results if r.name == "etw_sysmon")
    c.check("Sysmon fully healthy -> EFFECTIVE", sysmon.state == EFFECTIVE)


def test_every_control_gets_exactly_one_verdict() -> None:
    print("\n[2] every control_taxonomy entry gets exactly one coverage result")
    results = check_all()
    c.check("one CoverageResult per Control",
            len(results) == len(CONTROLS))
    c.check("every result's state is one of the 3 declared STATES",
            all(r.state in STATES for r in results))
    c.check("STATES is exactly 3 (not binary, per the task)", len(STATES) == 3)


def test_directive_controls_default_effective_if_importable() -> None:
    print("\n[3] directive (policy/config) controls: importable == effective")
    results = check_all()
    risk_profiles = next(r for r in results if r.name == "risk_profiles")
    c.check("risk_profiles (directive, no runtime state) is EFFECTIVE",
            risk_profiles.state == EFFECTIVE)


def test_stateful_controls_never_silently_claim_effective() -> None:
    print("\n[4] stateful controls with no live probe are DEGRADED, never a "
          "false EFFECTIVE (this module refuses to claim what it can't prove)")
    results = check_all()   # no CoverageContext -> nothing live is wired
    dns_sinkhole = next(r for r in results if r.name == "dns_sinkhole")
    c.check("dns_sinkhole with no live context is DEGRADED (unverified), not EFFECTIVE",
            dns_sinkhole.state == DEGRADED)


def test_broken_module_is_absent() -> None:
    print("\n[5] a control whose module cannot import is ABSENT, not silently skipped")
    from valkyrie import coverage as cov
    from valkyrie.control_taxonomy import PREVENTIVE, Control
    fake = Control("_fake_broken", "valkyrie.this_module_does_not_exist_xyz",
                   PREVENTIVE, note="test fixture")
    with patch.object(cov, "CONTROLS", CONTROLS + [fake]):
        results = check_all()
    broken = next(r for r in results if r.name == "_fake_broken")
    c.check("nonexistent module -> ABSENT", broken.state == ABSENT)
    c.check("nothing was silently dropped from the report (len matches)",
            len(results) == len(CONTROLS) + 1)


def test_broken_probe_does_not_crash_the_pass() -> None:
    print("\n[6] a raising coverage probe reports DEGRADED, not a crash")
    with patch("valkyrie.coverage._check_sysmon", side_effect=RuntimeError("boom")):
        results = check_all()
    sysmon = next(r for r in results if r.name == "etw_sysmon")
    c.check("a raising probe yields DEGRADED with the error visible",
            sysmon.state == DEGRADED and "boom" in sysmon.detail)
    c.check("every OTHER control still got a verdict (one bad probe doesn't "
            "take the whole pass down)",
            len(results) == len(CONTROLS))


def test_live_context_upgrades_firewall_and_sensor_tamper() -> None:
    print("\n[7] a live CoverageContext produces a real verdict, not the generic fallback")
    fw = MagicMock()
    fw._active = True
    fw.count.return_value = 12345
    st = MagicMock()
    st.is_running.return_value = True

    ctx = CoverageContext(firewall=fw, sensor_tamper=st)
    results = check_all(ctx)
    fw_result = next(r for r in results if r.name == "firewall")
    st_result = next(r for r in results if r.name == "sensor_tamper")
    c.check("live firewall reference -> EFFECTIVE with a real count",
            fw_result.state == EFFECTIVE and "12,345" in fw_result.detail)
    c.check("live sensor_tamper reference -> EFFECTIVE, not the generic fallback",
            st_result.state == EFFECTIVE)

    fw.count.return_value = 0
    ctx2 = CoverageContext(firewall=fw)
    results2 = check_all(ctx2)
    fw_result2 = next(r for r in results2 if r.name == "firewall")
    c.check("live firewall active but zero ranges -> DEGRADED, not EFFECTIVE",
            fw_result2.state == DEGRADED)


def test_summarize_fraction_and_gaps() -> None:
    print("\n[8] summarize() reports the fraction + names every non-effective control")
    results = check_all()
    s = summarize(results)
    c.check("total matches control count", s.total == len(CONTROLS))
    c.check("counts sum to total",
            sum(s.counts.values()) == s.total)
    c.check("fraction_effective matches counts[EFFECTIVE]/total",
            abs(s.fraction_effective - s.counts[EFFECTIVE] / s.total) < 1e-9)
    c.check("gaps contains every non-effective result, nothing more",
            len(s.gaps) == s.total - s.counts[EFFECTIVE]
            and all(g.state != EFFECTIVE for g in s.gaps))


def test_api_endpoint() -> None:
    print("\n[9] GET /api/controls/coverage")
    try:
        from starlette.testclient import TestClient   # noqa: F401
    except Exception as exc:                          # noqa: BLE001
        c.skip("API endpoint checks", f"test client unavailable: {exc}")
        return
    try:
        from valkyrie.web.server import create_app, state
    except ImportError as exc:
        c.skip("API endpoint checks", f"fastapi/web stack unavailable: {exc}")
        return

    from testclient_compat import make_client   # noqa: E402

    state.firewall = None
    state.sensor_tamper = None
    state.playbooks = None
    state.sensor_manager = None
    app = create_app()
    client = make_client(app, "127.0.0.1")

    resp = client.get("/api/controls/coverage")
    c.check("GET /api/controls/coverage -> 200 even with nothing live wired",
            resp.status_code == 200)
    body = resp.json()
    c.check("response has fraction_effective/counts/total/gaps",
            {"fraction_effective", "counts", "total", "gaps"} <= set(body.keys()))
    c.check("total matches the taxonomy size", body["total"] == len(CONTROLS))
    c.check("gaps are structured with name/category/state/detail",
            bool(body["gaps"]) and
            {"name", "category", "state", "detail"} <= set(body["gaps"][0].keys()))
    c.check("no POST route exists (read-only monitoring surface)",
            client.post("/api/controls/coverage").status_code == 405)

    resp2 = client.get("/api/controls/taxonomy")
    c.check("GET /api/controls/taxonomy (item 2) -> 200",
            resp2.status_code == 200)
    body2 = resp2.json()
    c.check("taxonomy response has categories/gaps",
            {"categories", "gaps"} <= set(body2.keys()))


def main() -> int:
    print("=" * 60)
    print("Coverage metric (IIBA §4.8.3 + Clinton ch. 9)")
    print("=" * 60)
    test_sysmon_three_states()
    test_every_control_gets_exactly_one_verdict()
    test_directive_controls_default_effective_if_importable()
    test_stateful_controls_never_silently_claim_effective()
    test_broken_module_is_absent()
    test_broken_probe_does_not_crash_the_pass()
    test_live_context_upgrades_firewall_and_sensor_tamper()
    test_summarize_fraction_and_gaps()
    test_api_endpoint()
    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
