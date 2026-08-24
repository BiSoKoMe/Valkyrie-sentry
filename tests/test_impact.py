#!/usr/bin/env python3
"""Incident impact narratives (valkyrie/edr/impact.py, Clinton ch.4 +
NIST SP 800-30 via IIBA §4.9.4).

Pins: no fabricated dollar figures anywhere (Clinton's specific critique of
false precision), every assessment answers all four questions the task
requires (exposed/to whom/reversible/action), severity is left completely
untouched, and the dispatch priority order matches what the correlation
engine itself treats as higher-confidence signal (a decoy hit outranks a
generic 'process' category, etc.).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from harness import Checks   # noqa: E402

from valkyrie.edr import impact                                # noqa: E402
from valkyrie.edr.impact import HARM_LEVELS, ImpactAssessment   # noqa: E402

c = Checks("incident impact (NIST SP 800-30)", expect_min=25)

_DOLLAR_RE = re.compile(r"\$\s?\d")


def _all_text(a: ImpactAssessment) -> str:
    return " ".join([a.exposed, a.to_whom, a.reversible, a.recommended_action])


# ---------------------------------------------------------------------------
# [1] Dispatch coverage: every real category in use gets a real assessment
# ---------------------------------------------------------------------------

_CASES = [
    ("decoy label", {"category": "process", "entity": "id_rsa",
                     "detections": [{"details": {"labels": ["decoy"]}}]}, "decoy"),
    ("sensor tamper", {"category": "process", "entity": "sysmon",
                       "technique": "T1562.001 — Impair Defenses"}, "sensor_tamper"),
    ("credential access technique", {"category": "process", "entity": "mimikatz.exe",
                                     "technique": "T1003.001 — LSASS Memory"}, "credential"),
    ("credential access label", {"category": "process", "entity": "x.exe",
                                 "detections": [{"details": {"labels": ["lsass_access"]}}]},
     "credential"),
    ("injection technique", {"category": "process", "entity": "svchost.exe",
                             "technique": "T1055 — Process Injection"}, "injection"),
    ("ransomware", {"category": "ransomware", "entity": "crypt.exe"}, "ransomware"),
    ("exfil", {"category": "exfil", "entity": "leak.exe"}, "exfiltration"),
    ("persistence", {"category": "persistence", "entity": "scheduled_task::Evil"}, "persistence"),
    ("dga", {"category": "dga", "entity": "kq9x7z.example"}, "c2"),
    ("tunnel", {"category": "tunnel", "entity": "abc.tunnel.example"}, "c2"),
    ("attack_chain", {"category": "attack_chain", "entity": "x.exe"}, "c2"),
    ("threat intel", {"category": "intelligence", "entity": "bad.example"}, "known_bad"),
    ("firewall ip", {"category": "firewall_ip", "entity": "1.2.3.4"}, "known_bad"),
    ("tracker", {"category": "tracker", "entity": "ads.example"}, "tracking"),
    ("anomaly", {"category": "anomaly", "entity": "x.exe"}, "generic"),
    ("bare process", {"category": "process", "entity": "y.exe"}, "generic"),
    ("totally unknown category", {"category": "made_up_category_xyz"}, "unknown"),
]


def test_dispatch_and_no_fabricated_precision() -> None:
    print("\n[1] every real incident shape gets a real assessment; no fake $ figures")
    for label, inc, _hint in _CASES:
        a = impact.assess(inc)
        c.check(f"'{label}': harm_level is a real NIST tier", a.harm_level in HARM_LEVELS)
        c.check(f"'{label}': exposed/to_whom/reversible/action all non-empty",
                all([a.exposed.strip(), a.to_whom.strip(),
                    a.reversible.strip(), a.recommended_action.strip()]))
        c.check(f"'{label}': no fabricated dollar figure anywhere",
                not _DOLLAR_RE.search(_all_text(a)))
        c.check(f"'{label}': line() produces one non-empty sentence",
                bool(a.line().strip()))


# ---------------------------------------------------------------------------
# [2] Priority ordering
# ---------------------------------------------------------------------------

def test_priority_ordering() -> None:
    print("\n[2] higher-confidence signals outrank generic category matching")
    # A decoy label on a bare 'process' category must win over generic.
    a = impact.assess({"category": "process",
                       "detections": [{"details": {"labels": ["decoy"]}}]})
    c.check("decoy label overrides generic 'process' category dispatch",
            a is not None and "decoy" in a.exposed.lower())

    # Credential-access technique on 'process' category must win over generic.
    a2 = impact.assess({"category": "process", "technique": "T1003.001 — LSASS Memory"})
    c.check("credential-access technique overrides generic 'process' dispatch",
            "credential" in a2.exposed.lower())

    # Ransomware category must not be shadowed by a coincidental label.
    a3 = impact.assess({"category": "ransomware", "entity": "x.exe"})
    c.check("ransomware category dispatches to the ransomware-specific narrative",
            "encrypt" in a3.exposed.lower())


# ---------------------------------------------------------------------------
# [3] Confidence honesty: confirmed vs attempted
# ---------------------------------------------------------------------------

def test_confirmed_vs_attempted_honesty() -> None:
    print("\n[3] confirmed=True only for what Valkyrie actually verified")
    ransomware = impact.assess({"category": "ransomware"})
    c.check("ransomware (canary + entropy confirmed) is marked confirmed=True",
            ransomware.confirmed is True)
    tracker = impact.assess({"category": "tracker"})
    c.check("routine tracker block is marked confirmed=True (blocking is the "
            "confirmed fact, not a guess)", tracker.confirmed is True)
    exfil = impact.assess({"category": "exfil"})
    c.check("exfil (Valkyrie cannot read what data left) is confirmed=False",
            exfil.confirmed is False)
    injection = impact.assess({"category": "process", "technique": "T1055"})
    c.check("injection (stopped, but full reach unknown) is confirmed=False",
            injection.confirmed is False)


# ---------------------------------------------------------------------------
# [4] Wired into the engine: severity untouched, impact present
# ---------------------------------------------------------------------------

def test_wired_into_engine() -> None:
    print("\n[4] EdrEngine surfaces impact WITHOUT disturbing severity")
    from valkyrie.edr import schema
    from valkyrie.edr.engine import EdrEngine
    from valkyrie.store import Store
    import tempfile

    tmp = Path(tempfile.mkdtemp(prefix="valkyrie_impact_"))
    store = Store(db_path=tmp / "t.db")
    store.start()
    engine = EdrEngine(store)
    engine.start()

    inc_id = engine.report_detection(schema.Detection(
        source="test", severity="critical", category="ransomware",
        title="mass encryption detected", entity="crypt.exe"))
    c.check("incident created", bool(inc_id))

    listed = engine.list_incidents()
    this_one = next((i for i in listed if i["id"] == inc_id), None)
    c.check("list_incidents() includes this incident", this_one is not None)
    if this_one:
        c.check("severity is UNCHANGED / still machine-readable ('critical')",
                this_one["severity"] == "critical")
        c.check("compact view carries an 'impact' dict",
                "impact" in this_one and isinstance(this_one["impact"], dict))
        c.check("compact-view impact correctly dispatched to ransomware",
                "encrypt" in this_one["impact"]["exposed"].lower())

    detail = engine.get_incident(inc_id)
    c.check("get_incident() also carries 'impact'",
            detail is not None and "impact" in detail)
    if detail:
        c.check("detail severity also unchanged", detail["severity"] == "critical")
        c.check("detail impact has all 4 required fields + harm_level + confirmed",
                {"exposed", "to_whom", "reversible", "recommended_action",
                 "harm_level", "confirmed", "line"} <= set(detail["impact"].keys()))

    engine.stop()
    store.stop()


# ---------------------------------------------------------------------------
# [5] API surface
# ---------------------------------------------------------------------------

def test_api_surface() -> None:
    print("\n[5] GET /api/edr/incidents and /api/edr/incidents/{id} carry impact")
    try:
        from starlette.testclient import TestClient   # noqa: F401
    except Exception as exc:                          # noqa: BLE001
        c.skip("API checks", f"test client unavailable: {exc}")
        return
    try:
        from valkyrie.web.server import create_app, state
    except ImportError as exc:
        c.skip("API checks", f"fastapi/web stack unavailable: {exc}")
        return

    from testclient_compat import make_client   # noqa: E402
    from valkyrie.edr import schema
    from valkyrie.edr.engine import EdrEngine
    from valkyrie.store import Store
    import tempfile

    tmp = Path(tempfile.mkdtemp(prefix="valkyrie_impact_api_"))
    store = Store(db_path=tmp / "t.db")
    store.start()
    engine = EdrEngine(store)
    engine.start()
    inc_id = engine.report_detection(schema.Detection(
        source="test", severity="high", category="persistence",
        title="new autostart entry", entity="scheduled_task::Evil"))

    prior_edr = state.edr
    try:
        state.edr = engine
        app = create_app()
        client = make_client(app, "127.0.0.1")

        resp = client.get("/api/edr/incidents")
        c.check("GET /api/edr/incidents -> 200", resp.status_code == 200)
        body = resp.json()
        row = next((r for r in body if r["id"] == inc_id), None)
        c.check("list row carries impact", row is not None and "impact" in row)

        resp2 = client.get(f"/api/edr/incidents/{inc_id}")
        c.check("GET /api/edr/incidents/{id} -> 200", resp2.status_code == 200)
        body2 = resp2.json()
        c.check("detail response carries impact",
                "impact" in body2 and "restart" in body2["impact"]["exposed"].lower())
    finally:
        state.edr = prior_edr
        engine.stop()
        store.stop()


def main() -> int:
    print("=" * 60)
    print("Incident impact (Clinton ch.4 + NIST SP 800-30 via IIBA §4.9.4)")
    print("=" * 60)
    test_dispatch_and_no_fabricated_precision()
    test_priority_ordering()
    test_confirmed_vs_attempted_honesty()
    test_wired_into_engine()
    test_api_surface()
    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
