#!/usr/bin/env python3
"""Causality-aware investigation - regression gate.

Verifies edr/investigate.py actually consumes the causality data
edr/engine.py's _enrich_causality() already attaches to every detection
(det.details["causality"]), rather than the two modules sitting next to each
other unconnected. Covers exactly the cases the milestone specified:

  A. causality present  -> story contains the actual process chain
  B. causality absent    -> existing investigation behavior is unchanged
  C. inferred causality  -> output explicitly marks inference, never silently
                            upgrades a guess to a stated fact
  D. multiple detections, one shared chain -> story does not repeat itself
  E. malformed/missing causality fields -> investigation does not crash
  F. run alongside test_explainability.py to confirm no regression there

No network, no Windows APIs, no live engine - pure construction of
Detection/Incident objects plus a minimal fake store, matching the pattern
tests/test_explainability.py already uses for this module.

Exit 0 on success, non-zero on failure (standalone-script contract, matching
tests/run_safe.py's discovery of test_*.py).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.edr.investigate import Investigator, _causality_story, _chain_sentence
from valkyrie.edr.schema import Detection, Incident

_FAILS: list = []


def _check(cond: bool, msg: str) -> None:
    print(("  [+] " if cond else "  [!] FAIL ") + msg)
    if not cond:
        _FAILS.append(msg)


class _FakeStore:
    """Minimal stand-in for the real event store - only what Investigator uses."""

    def __init__(self, detections: list) -> None:
        self._detections = detections

    def list_detections(self, incident_id: str = "", limit: int = 200) -> list:
        return self._detections


def _causality_stamp(chain: list, *, cgo_pid: int = 100, inferred: bool = False) -> dict:
    """Build the exact shape edr/engine.py's _enrich_causality() produces."""
    return {
        "cgo": chain[0], "cgo_pid": cgo_pid, "cgo_path": "",
        "chain": list(chain),
        "path": " -> ".join(chain),
        "depth": len(chain),
        "inferred": inferred,
    }


def main() -> int:
    print("Causality-aware investigation - regression gate")
    print("=" * 60)

    # -- A: causality present -> story contains the actual process chain ----
    print("\n-- A: causality present --")
    chain = ["explorer.exe", "winword.exe", "cmd.exe", "powershell.exe"]
    det = Detection(
        source="edr.behavioral", severity="high", category="process",
        title="Suspicious PowerShell command line",
        process_name="powershell.exe", process_pid=4242,
        details={"causality": _causality_stamp(chain)},
    )
    inc = Incident(title="Suspicious PowerShell activity", severity="high",
                   category="process", process_name="powershell.exe")
    report = Investigator(edr_store=_FakeStore([det])).investigate(inc, use_ai=False)
    story = report.get("story", "")
    causality = report.get("causality", {})
    _check(causality.get("available") is True, "causality.available is True")
    for name in chain:
        _check(name in story, f"story mentions {name}")
    _check(causality.get("chain") == chain, "causality.chain matches the real chain, in order")
    _check(causality.get("cgo") == "explorer.exe", "causality.cgo is the actual root, not the alerted process")
    _check(causality.get("inferred") is False, "causality.inferred is False for a fully-observed chain")
    _check("inferred" not in story.lower(), "story does NOT claim inference for an observed chain")
    # Structured data present so the UI never has to parse the sentence.
    _check(isinstance(report.get("causality"), dict) and "sentence" in report["causality"],
           "structured causality block exposes 'sentence' directly (UI need not reverse-engineer prose)")

    # -- B: causality absent -> existing behavior unchanged ------------------
    print("\n-- B: causality absent (fallback to pre-existing behavior) --")
    det_no_causality = Detection(
        source="dns.blocklist", severity="medium", category="firewall_ip",
        title="Blocked connection to threat-intel IP", entity="1.2.3.4",
    )
    inc2 = Incident(title="Blocked C2 IP", severity="medium", category="firewall_ip",
                    entity="1.2.3.4")
    report2 = Investigator(edr_store=_FakeStore([det_no_causality])).investigate(inc2, use_ai=False)
    _check(report2["causality"]["available"] is False, "causality.available is False with no causality data")
    # UPDATED CONTRACT (Human Decision Layer audit, PHASE 1): "story" no
    # longer falls back to "summary" verbatim. A PHASE 1 audit against 500
    # real incidents found that contract meant the interpretive/technical
    # _MEANING paragraph (summary always includes it) was ALSO the primary
    # "what happened" text, then repeated again verbatim in "technical
    # detail" - the same paragraph shown twice in one report. "story" is now
    # a purely factual sentence (title + detection count); "summary" keeps
    # its original, more technical shape unchanged for any existing consumer
    # that reads it directly.
    _check(report2["story"] != report2["summary"],
           "story is now its own factual sentence, not a verbatim copy of the technical summary")
    _check(report2["meaning"] not in report2["story"],
           "the technical _MEANING paragraph no longer leaks into the human-facing story")
    _check(bool(report2["summary"]) and bool(report2["meaning"]),
           "pre-existing summary/meaning fields are still populated normally")
    _check(bool(report2["recommended_actions"]),
           "pre-existing recommended_actions still populated normally")

    # An incident with truly nothing (no detections, no category) - the
    # original pre-causality generic-fallback path - must still produce a
    # non-empty, honest story with no fabricated causality.
    inc3 = Incident(title="Untitled incident", severity="low")
    report3 = Investigator(edr_store=None).investigate(inc3, use_ai=False)
    _check(report3["causality"]["available"] is False, "no-store incident: causality unavailable")
    _check(bool(report3["story"]), "no-store incident: story is still non-empty and honest")

    # -- C: inferred causality -> output explicitly marks it -----------------
    print("\n-- C: causality with an inferred hop --")
    det_inferred = Detection(
        source="edr.behavioral", severity="high", category="persistence",
        title="Registry Run key persistence",
        process_name="powershell.exe", process_pid=4242,
        details={"causality": _causality_stamp(chain, inferred=True)},
    )
    inc4 = Incident(title="Persistence via PowerShell", severity="high",
                    category="persistence", process_name="powershell.exe")
    report4 = Investigator(edr_store=_FakeStore([det_inferred])).investigate(inc4, use_ai=False)
    _check(report4["causality"]["inferred"] is True, "causality.inferred is True")
    _check("inferred" in report4["story"].lower(),
           "story text explicitly says 'inferred' - never silently upgraded to stated fact")
    facts_report = Investigator(edr_store=_FakeStore([det_inferred]))._offline_report(inc4, [det_inferred])
    _ai_facts_ok = True
    try:
        # Exercise the same helper _ai_analysis uses to build its facts, without
        # a network call, to prove the LLM path would receive the distinction.
        cz = facts_report["causality"]
        _ai_facts_ok = cz.get("inferred") is True
    except Exception:
        _ai_facts_ok = False
    _check(_ai_facts_ok, "offline report's causality block (source for the LLM facts payload) marks inferred=True")

    # -- D: multiple detections, one shared chain -> no repetition -----------
    print("\n-- D: multiple detections sharing one causal chain --")
    det_a = Detection(source="edr.behavioral", severity="high", category="process",
                      title="Process injection", process_name="powershell.exe",
                      process_pid=4242, details={"causality": _causality_stamp(chain)})
    det_b = Detection(source="dns.dga", severity="high", category="dga",
                      title="DGA-looking domain contacted", entity="xj29fk.example",
                      process_name="powershell.exe", process_pid=4242,
                      details={"causality": _causality_stamp(chain)})
    det_c = Detection(source="edr.behavioral", severity="high", category="persistence",
                      title="Registry Run key persistence", process_name="powershell.exe",
                      process_pid=4242, details={"causality": _causality_stamp(chain)})
    inc5 = Incident(title="Multi-stage attack", severity="critical", category="attack_chain",
                    process_name="powershell.exe")
    report5 = Investigator(edr_store=_FakeStore([det_a, det_b, det_c])).investigate(inc5, use_ai=False)
    story5 = report5["story"]
    occurrences = story5.count("explorer.exe started winword.exe")
    _check(occurrences == 1, f"identical chain repeated across 3 detections appears exactly once in the story (found {occurrences})")
    _check(report5["causality"]["supporting_detections"] == 3,
           f"supporting_detections counts all 3 detections sharing the chain (got {report5['causality']['supporting_detections']})")
    _check(report5["causality"]["chain_count"] == 1,
           "chain_count is 1 distinct chain, not 3 (dedup by path)")

    # Two genuinely DIFFERENT chains in one incident - both should be
    # acknowledged, still without duplicating either chain's own sentence.
    other_chain = ["services.exe", "svchost.exe", "malware.exe"]
    det_d = Detection(source="edr.behavioral", severity="high", category="process",
                      title="Unrelated malicious process", process_name="malware.exe",
                      process_pid=9999, details={"causality": _causality_stamp(other_chain, cgo_pid=200)})
    report6 = Investigator(edr_store=_FakeStore([det_a, det_d])).investigate(inc5, use_ai=False)
    _check(report6["causality"]["chain_count"] == 2, "two genuinely distinct chains are both counted")

    # -- E: malformed/missing causality fields -> never crashes --------------
    print("\n-- E: malformed causality data does not crash the investigation --")
    malformed_cases = [
        {"details": {"causality": "not-a-dict"}},
        {"details": {"causality": {}}},
        {"details": {"causality": {"chain": None, "path": None}}},
        {"details": {"causality": {"chain": ["only-one"], "path": "only-one"}}},
        {"details": {"causality": {"chain": [None, None], "path": "x -> y"}}},
        {"details": None},
        {"details": {}},
    ]
    all_survived = True
    for i, case in enumerate(malformed_cases):
        try:
            d = Detection(source="s", severity="low", category="anomaly",
                         title=f"malformed case {i}", **case)
            r = Investigator(edr_store=_FakeStore([d])).investigate(
                Incident(title="malformed", severity="low", category="anomaly"), use_ai=False)
            assert isinstance(r.get("story"), str)
            assert isinstance(r.get("causality"), dict)
        except Exception as exc:  # noqa: BLE001
            all_survived = False
            print(f"      case {i} raised: {exc!r}")
    _check(all_survived, "every malformed-causality case returns a valid report, none raise")

    # Also exercise the helpers directly with adversarial input.
    try:
        _check(_chain_sentence({}) == "", "_chain_sentence({}) returns '' rather than raising")
        _check(_chain_sentence({"chain": []}) == "", "_chain_sentence with empty chain returns ''")
        _check(_causality_story([]) == {"available": False}, "_causality_story([]) is cleanly unavailable")
        _check(_causality_story([Detection(source="s", severity="low", category="anomaly", title="t")])
               == {"available": False}, "_causality_story with a causality-less detection is unavailable")
    except Exception as exc:  # noqa: BLE001
        _check(False, f"helper functions raised on adversarial input: {exc!r}")

    print("\n" + "=" * 60)
    if _FAILS:
        print(f"  RESULT: {len(_FAILS)} FAILURE(S)")
        return 1
    print("  RESULT: ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
