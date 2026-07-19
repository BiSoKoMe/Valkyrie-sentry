#!/usr/bin/env python3
"""SOAR playbooks — offline evaluation, safety, and audit tests.

  [1] YAML parsing: valid playbooks load; malformed ones become load
      errors without killing the engine
  [2] Matching: severity floor + category allowlist
  [3] End to end: detection -> incident -> playbook -> audited dry-run
      response with operator playbook:<id> in the incident timeline
  [4] Enforce mode sets dry_run=False on the audited action
  [5] Cooldown suppresses immediate re-fire per (playbook, target)
  [6] A playbook naming an unknown action audits a failure, never raises
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


PLAYBOOK_YAML = """\
playbooks:
  - id: block-c2
    min_severity: high
    categories: [c2]
    actions:
      - action: block_domain
        target_from: entity
  - id: contain-ransomware
    min_severity: critical
    categories: [ransomware]
    mode: enforce
    cooldown_seconds: 600
    actions:
      - action: nonexistent_action
        target_from: process_name
  - id: broken-no-actions
    min_severity: low
"""


def main() -> int:
    from valkyrie.store import Store
    from valkyrie.edr import EdrEngine
    from valkyrie.edr.schema import Detection
    from valkyrie.edr.playbooks import Playbook, PlaybookAction, PlaybookEngine

    print("\n=== SOAR playbooks ===\n")

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        pb_file = tdp / "playbooks.yaml"
        pb_file.write_text(PLAYBOOK_YAML, encoding="utf-8")

        store = Store(db_path=tdp / "pb.db")
        store.start()
        engine = EdrEngine(store)
        engine.start()

        print("[1] Loading")
        pbe = PlaybookEngine(engine, path=pb_file)
        n = pbe.load()
        st = pbe.status()
        _check("two valid playbooks loaded", n == 2)
        _check("malformed playbook recorded as load error",
               any("broken-no-actions" in e for e in st["load_errors"]))
        pbe.start()

        print("\n[2] Matching")
        pb = Playbook(id="x", min_severity="high", categories=("c2",),
                      actions=[PlaybookAction("block_domain")])
        _check("below severity floor rejected",
               not pb.matches({"severity": "medium", "category": "c2"}))
        _check("wrong category rejected",
               not pb.matches({"severity": "critical", "category": "dns"}))
        _check("critical c2 accepted",
               pb.matches({"severity": "critical", "category": "c2"}))

        print("\n[3] End to end: incident -> dry-run response, audited")
        inc_id = engine.report_detection(Detection(
            source="test", severity="high", category="c2",
            title="beacon", entity="evil.example", process_name="mal.exe"))
        deadline = time.monotonic() + 3
        inc = engine.get_incident(inc_id)
        while time.monotonic() < deadline and not (inc and inc.get("responses")):
            time.sleep(0.05)
            inc = engine.get_incident(inc_id)
        resp = (inc or {}).get("responses") or []
        _check("response recorded on the incident", len(resp) == 1)
        if resp:
            r = resp[0]
            _check("operator is playbook:block-c2",
                   r.get("operator") == "playbook:block-c2")
            _check("dry-run by default", r.get("dry_run") is True)
            _check("targeted the incident entity",
                   r.get("target") == "evil.example")
        _check("timeline carries the response entry",
               any(t.get("kind") == "response"
                   for t in (inc or {}).get("timeline", [])))

        print("\n[4] Enforce mode + unknown action -> audited failure")
        rid = engine.report_detection(Detection(
            source="test", severity="critical", category="ransomware",
            title="canary tripped", entity="C:/u", process_name="crypt.exe"))
        deadline = time.monotonic() + 3
        rinc = engine.get_incident(rid)
        while time.monotonic() < deadline and not (rinc and rinc.get("responses")):
            time.sleep(0.05)
            rinc = engine.get_incident(rid)
        rr = (rinc or {}).get("responses") or []
        _check("enforce playbook executed (audited)", len(rr) == 1)
        if rr:
            _check("enforce sets dry_run=False", rr[0].get("dry_run") is False)
            _check("unknown action audits as failed, engine alive",
                   rr[0].get("status") == "failed")

        print("\n[5] Cooldown suppression")
        before = pbe.status()["executed"]
        engine.report_detection(Detection(
            source="test", severity="high", category="c2",
            title="beacon again", entity="evil.example", process_name="mal.exe"))
        # Same (playbook, block_domain:evil.example) inside cooldown: suppressed.
        # New incident correlates into the SAME incident (same entity/category),
        # which still notifies — give the bus a moment.
        time.sleep(0.3)
        st5 = pbe.status()
        _check("cooldown suppressed the re-fire",
               st5["executed"] == before and st5["suppressed_by_cooldown"] >= 1)

        print("\n[6] Engine survives everything")
        _check("playbook engine still active", pbe.status()["active"])
        _check("EDR still correlating", len(engine.list_incidents()) >= 2)

        pbe.stop()
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
