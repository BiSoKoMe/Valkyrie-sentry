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

# How long to wait for an async playbook response to land on an incident.
# The work itself completes in ~0.00s; this is purely slack for a loaded CI box.
# It was 3s, and this file has been observed failing 8 runs in a row and then
# passing 18 in a row on the same commit — a nondeterministic result is as
# useless as a vacuous one, so the slack is generous on purpose. If a response
# genuinely never arrives, 10s fails just as surely as 3s did.
_WAIT = 10.0

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
    from valkyrie.edr.playbooks import (
        Playbook, PlaybookAction, PlaybookEngine, _parse_playbook)

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
        deadline = time.monotonic() + _WAIT
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
        deadline = time.monotonic() + _WAIT
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

        print("\n[7] kill_process resolves the incident PID (not the name)")
        pb_kill = _parse_playbook({
            "id": "kill", "min_severity": "critical", "categories": ["process"],
            "actions": [{"action": "kill_process", "target_from": "process_pid"}],
        })
        _check("process_pid is a valid target_from", pb_kill.actions[0].target_from == "process_pid")
        pbe._playbooks = [pb_kill]                      # dry-run (default mode)
        pk = engine.report_detection(Detection(
            source="etw", severity="critical", category="process",
            title="injection", entity="C:/x.exe", process_name="mal.exe",
            process_pid=2147480000))                   # unused high PID → no such process
        deadline = time.monotonic() + _WAIT
        pinc = engine.get_incident(pk)
        while time.monotonic() < deadline and not (pinc and pinc.get("responses")):
            time.sleep(0.05); pinc = engine.get_incident(pk)
        presp = (pinc or {}).get("responses") or []
        _check("kill fired on the process incident", len(presp) == 1)
        if presp:
            # The point: the target parsed as a PID. Whatever the outcome
            # (dry_run "would terminate", or "no such process"), it must NOT be
            # the old "invalid pid: 'mal.exe'" — that was the name-not-PID bug.
            _check("target resolved as a PID, not the process name",
                   "invalid pid" not in presp[0].get("result", ""))

        pbe.stop()
        engine.stop()
        store.stop()

    print("\n[8] Shipped default playbook set")
    _default_playbooks_checks()

    print("\n" + "=" * 48)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


def _default_playbooks_checks() -> None:
    """The shipped default (valkyrie/defaults/playbooks.default.yaml) must ship
    enabled, safe, and parseable — it's what makes auto-response ON out of the
    box instead of the old zero-playbook observe-only posture."""
    import yaml
    from valkyrie.config import DEFAULT_PLAYBOOKS_PATH
    from valkyrie.edr.playbooks import _parse_playbook

    _check("default playbook file is bundled", DEFAULT_PLAYBOOKS_PATH.exists())
    raw = yaml.safe_load(DEFAULT_PLAYBOOKS_PATH.read_text(encoding="utf-8")) or {}
    books = [_parse_playbook(e) for e in raw.get("playbooks") or []]
    by_id = {b.id: b for b in books}

    _check("default set parses without error", len(books) >= 3)
    # Domain blocks are reversible → ship enforce; process kill is destructive
    # → must ship dry_run so it only simulates until consciously armed.
    domain_blockers = [b for b in books
                       if any(a.action == "block_domain" for a in b.actions)]
    _check("domain-block playbooks present", len(domain_blockers) >= 1)
    _check("every domain-block ships in ENFORCE",
           all(b.mode == "enforce" for b in domain_blockers))
    _check("dga C2 is auto-blocked", "dga" in by_id.get("block-dga-c2").categories
           if "block-dga-c2" in by_id else False)
    _check("dns tunnelling is auto-blocked",
           "tunnel" in by_id.get("block-dns-tunnel").categories
           if "block-dns-tunnel" in by_id else False)
    killers = [b for b in books
               if any(a.action == "kill_process" for a in b.actions)]
    _check("any process-kill playbook ships DRY_RUN (never auto-kills by default)",
           all(b.mode == "dry_run" for b in killers))
    _check("no domain-block targets a bare TLD or wildcard root (would over-block)",
           all(a.target_from == "entity" for b in domain_blockers for a in b.actions))


if __name__ == "__main__":
    raise SystemExit(main())
