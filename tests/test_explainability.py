#!/usr/bin/env python3
"""Explainability coverage gate for incident investigation.

The engineering doctrine requires every incident to answer, for an analyst:
*what happened, why, what evidence, which MITRE, how confident, what next.*
`edr/investigate.py` supplies "what/why" (`_MEANING`) and "what next"
(`_RECOMMEND`) by looking up each incident's **category**. If a category is
missing from those maps the analyst gets a generic sentence and — worse — **zero
recommended actions**. That silently happened for the endpoint categories
(`process`, `persistence`, `network`), which carry the most severe detections
(LSASS access, injection, ransomware, persistence, hard-coded-IP C2).

This test is the regression gate that keeps coverage at 100%:
  1. every category an incident can carry has a non-empty meaning + at least one
     recommended action;
  2. every recommended action is a REAL shipped responder (derived live from the
     response registry — never an aspirational action);
  3. the endpoint telemetry categories are actually in the canonical set (so a
     new emitter category cannot escape the gate);
  4. an end-to-end investigate() of an endpoint incident yields a specific
     meaning (not the generic fallback) and valid recommended actions.

Exit 0 on success, non-zero on failure (standalone-script contract).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.edr.investigate import (
    KNOWN_INCIDENT_CATEGORIES, Investigator, _MEANING, _RECOMMEND,
)
from valkyrie.edr.plugins import PluginRegistry
from valkyrie.edr.response import register_responders
from valkyrie.edr.schema import Incident
from valkyrie.telemetry import CAT_NETWORK, CAT_PERSISTENCE, CAT_PROCESS

_FAILS: list = []


def _check(cond: bool, msg: str) -> None:
    print(("  [+] " if cond else "  [!] FAIL ") + msg)
    if not cond:
        _FAILS.append(msg)


def _valid_actions() -> set:
    """The set of response actions that actually ship — derived live so the
    gate can never drift from response.py."""
    reg = PluginRegistry()
    register_responders(reg)
    return set(reg.available_actions())


def main() -> int:
    print("Valkyrie explainability coverage gate")
    print("=" * 60)
    valid = _valid_actions()
    print(f"\nShipped response actions (live from registry): {sorted(valid)}")

    # 1 + 2 — every known category has meaning + recommendation of real actions.
    print("\n-- coverage: meaning + recommended actions per category --")
    for cat in sorted(KNOWN_INCIDENT_CATEGORIES):
        meaning = (_MEANING.get(cat) or "").strip()
        recs = _RECOMMEND.get(cat) or []
        _check(bool(meaning), f"{cat}: has a plain-English meaning")
        _check(bool(recs), f"{cat}: has >=1 recommended action")
        bad = [a for a in recs if a not in valid]
        _check(not bad, f"{cat}: all recommended actions are real responders"
                        + (f" (invalid: {bad})" if bad else ""))

    coverage = sum(
        1 for c in KNOWN_INCIDENT_CATEGORIES
        if (_MEANING.get(c) or "").strip() and (_RECOMMEND.get(c) or [])
    )
    total = len(KNOWN_INCIDENT_CATEGORIES)
    print(f"\n  coverage = {coverage}/{total} categories "
          f"= {coverage/total*100:.0f}%")
    _check(coverage == total, "explainability coverage is 100%")

    # 3 — endpoint telemetry categories cannot escape the canonical set.
    print("\n-- endpoint telemetry categories are in the canonical set --")
    for cat in (CAT_PROCESS, CAT_PERSISTENCE, CAT_NETWORK):
        _check(cat in KNOWN_INCIDENT_CATEGORIES,
               f"telemetry category '{cat}' is a known incident category")

    # 4 — end-to-end: an endpoint incident explains itself (no generic fallback,
    #     real recommended actions).
    print("\n-- end-to-end investigate() of an endpoint incident --")
    inc = Incident(
        id="INC-TEST-1", title="LSASS credential access from an unsigned binary",
        severity="critical", status="open", category=CAT_PROCESS,
        entity="mimikatz.exe", process_name="mimikatz.exe",
    )
    report = Investigator(edr_store=None).investigate(inc, use_ai=False)
    generic = "Correlated security detections were grouped into this incident."
    _check(report.get("meaning") and report["meaning"] != generic,
           "endpoint incident gets a specific meaning (not the generic fallback)")
    acts = [a.get("action") for a in report.get("recommended_actions", [])]
    _check(bool(acts), "endpoint incident yields recommended actions")
    _check(all(a in valid for a in acts),
           f"end-to-end recommended actions are all real responders ({acts})")

    print("\n" + "=" * 60)
    if _FAILS:
        print(f"  RESULT: {len(_FAILS)} FAILURE(S)")
        return 1
    print("  RESULT: ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
