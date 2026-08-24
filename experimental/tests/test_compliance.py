#!/usr/bin/env python3
"""Compliance evidence reports — offline generation + honesty tests.

  [1] Full report from live services (EDR incidents, MTTR, audit trail)
  [2] Honesty: absent subsystems reported as unavailable, never invented
  [3] Threat-intel section reflects real cache state incl. staleness
  [4] Markdown rendering carries the disclaimer and key figures
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def main() -> int:
    from valkyrie.compliance import ComplianceReporter, render_markdown
    from valkyrie.context import AppContext
    from valkyrie.store import Store
    from valkyrie.edr import EdrEngine
    from valkyrie.edr.schema import Detection
    from valkyrie.threat_intel import IntelFeed, ThreatIntelManager

    print("\n=== compliance evidence reports ===\n")

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        store = Store(db_path=tdp / "c.db")
        store.start()
        engine = EdrEngine(store)
        engine.start()

        # Two incidents: one high resolved (for MTTR), one critical open.
        a = engine.report_detection(Detection(
            source="t", severity="high", category="c2",
            title="beacon", entity="a.example", process_name="x.exe"))
        time.sleep(0.05)
        engine.update_incident(a, status="resolved")
        engine.report_detection(Detection(
            source="t", severity="critical", category="ransomware",
            title="canary", entity="C:/u", process_name="y.exe"))
        engine.respond("block_domain", "a.example", dry_run=True,
                       operator="playbook:auto", incident_id=a)

        # Threat intel with one fresh cache file.
        icache = tdp / "intel"; icache.mkdir()
        (icache / "urlhaus.txt").write_text("evil.example\n", encoding="utf-8")
        ti = ThreatIntelManager(
            feeds=[IntelFeed("urlhaus", "domain", "malware_distribution", "https://x.invalid/u"),
                   IntelFeed("feodo_c2", "ip", "botnet_c2", "https://x.invalid/f")],
            cache_dir=icache)
        ti.load(allow_download=False)

        ctx = AppContext(store=store, edr=engine, threat_intel=ti)

        print("[1] Full report")
        rep = ComplianceReporter(ctx).generate(period_hours=24)
        dr = rep["sections"]["detection_response"]
        _check("both incidents counted", dr["incidents_in_period"] == 2)
        _check("open high/critical tracked", dr["open_high_or_critical"] == 1)
        _check("MTTR computed from resolved incident",
               dr.get("resolved_count") == 1
               and "mean_time_to_resolve_minutes" in dr)
        au = rep["sections"]["audit_trail"]
        _check("audited response actions counted",
               au.get("response_actions_recorded", 0) >= 1)
        _check("playbook vs human attribution",
               au.get("by_operator_kind", {}).get("playbook", 0) >= 1)
        mon = rep["sections"]["monitoring"]
        _check("monitoring reflects wired components",
               mon["components_wired"].get("edr") is True
               and mon["components_wired"].get("firewall") is False)
        _check("disclaimer present (evidence, not certification)",
               "not a compliance certification" in rep["disclaimer"])

        print("\n[2] Honesty on absent subsystems")
        empty = ComplianceReporter(AppContext()).generate(period_hours=24)
        _check("EDR absent -> available: False",
               empty["sections"]["detection_response"] == {
                   "available": False,
                   "framework_refs": empty["sections"]["detection_response"]["framework_refs"]}
               or empty["sections"]["detection_response"]["available"] is False)
        _check("intel absent -> available: False",
               empty["sections"]["threat_intel"]["available"] is False)

        print("\n[3] Threat-intel staleness surfaced")
        tis = rep["sections"]["threat_intel"]
        _check("loaded IOCs reported", tis.get("total") == 1)
        _check("missing feodo cache reported stale",
               "feodo_c2" in tis.get("stale_feeds", []))

        print("\n[4] Markdown rendering")
        md = render_markdown(rep)
        _check("carries disclaimer", "not a compliance certification" in md)
        _check("carries incident count", "Incidents in period: **2**" in md)
        _check("carries framework refs", "ISO27001" in md and "SOC2" in md)

        engine.stop()
        store.stop()

    print("\n" + "=" * 48)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
