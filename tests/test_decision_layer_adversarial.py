#!/usr/bin/env python3
"""Adversarial trust review regression gate for the human decision layer.

Each test here corresponds to a GENUINE weakness found by hostile testing of
edr/investigate.py, not a restatement of test_decision_layer.py's own
milestone coverage. Every test either (a) proves a real bug found in this
review was fixed, or (b) locks in a real behavior that was specifically
adversarially probed and found correct - never padding for count.

Bugs found and fixed this review:
  1. CRASH: a causality stamp with a non-list `chain` (e.g. `chain: 12345`)
     crashed _causality_story() - `(x.get("chain") or [])` lets a truthy
     non-iterable straight through to `for n in ...`.
  2. OVERCONFIDENCE: an incident tagged with a category string (e.g.
     "malware") but with ZERO backing Detection records reached "high"
     confidence off the category label alone - a tag is not evidence.
  3. FALSE CORROBORATION (temporal): detection count alone was read as
     mutual corroboration even when detections were years apart.
  4. FALSE CORROBORATION (actor): detection count alone was read as mutual
     corroboration even when the detections' own causality chains showed
     DIFFERENT, unrelated process lineages.
  5. INCONSISTENT STRUCTURED OUTPUT: at "low" confidence the plain-language
     text said "no immediate action is recommended", but the structured
     `recommended_action` field still named a specific responder action -
     a consumer reading only the JSON would see a concrete recommendation
     the prose right next to it was disclaiming.
  6. PROMPT WORDING: the LLM system prompt called offline_confidence "a
     floor" while describing ceiling semantics ("you may report LOWER... but
     never HIGHER") - self-contradictory instruction to the model.

No network, no Windows APIs. Exit 0 on success, non-zero on failure
(standalone-script contract, matching tests/run_safe.py's test_*.py glob).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.edr.ai_provider import AIProvider
from valkyrie.edr.investigate import Investigator, _assess_confidence, _causality_story
from valkyrie.edr.schema import Detection, Incident

_FAILS: list = []


def _check(cond: bool, msg: str) -> None:
    print(("  [+] " if cond else "  [!] FAIL ") + msg)
    if not cond:
        _FAILS.append(msg)


class _FakeStore:
    def __init__(self, detections: list) -> None:
        self._detections = detections

    def list_detections(self, incident_id: str = "", limit: int = 200) -> list:
        return self._detections


def _stamp(chain: list, *, cgo_pid: int = 100, inferred: bool = False) -> dict:
    return {"cgo": chain[0], "cgo_pid": cgo_pid, "cgo_path": "", "chain": list(chain),
            "path": " -> ".join(chain), "depth": len(chain), "inferred": inferred}


def main() -> int:
    print("Adversarial trust review - regression gate")
    print("=" * 60)

    # -- Bug 1: malformed causality `chain` field must not crash -----------
    print("\n-- Bug 1: malformed causality chain (non-list) does not crash --")
    for bad_chain in (12345, True, 3.14, {"a": 1}, "a-string-not-a-list"):
        det = Detection(source="s", severity="high", category="process", title="t",
                        details={"causality": {"chain": bad_chain, "path": "x -> y",
                                               "inferred": False, "cgo": "x", "depth": 2}})
        try:
            result = _causality_story([det])
            _check(result == {"available": False},
                   f"chain={bad_chain!r} ({type(bad_chain).__name__}) degrades to unavailable, not a crash")
        except Exception as exc:  # noqa: BLE001
            _check(False, f"chain={bad_chain!r} raised {exc!r} instead of degrading gracefully")

    rep = Investigator(edr_store=_FakeStore([
        Detection(source="s", severity="high", category="process", title="t",
                 details={"causality": {"chain": 999, "path": "x -> y"}})
    ])).investigate(Incident(title="x", severity="high", category="process"), use_ai=False)
    _check(rep["decision"]["how"] == "", "end-to-end investigate() with malformed chain: 'how' degrades to '' not a crash")

    # -- Bug 2: bare category label with zero detections is NOT evidence ---
    print("\n-- Bug 2: category label alone (no detections) cannot reach high/medium --")
    for cat in ("malware", "attack_chain", "attack_sequence", "firewall_ip"):
        inc = Incident(title="label only", severity="critical", category=cat)
        rep = Investigator(edr_store=_FakeStore([])).investigate(inc, use_ai=False)
        dec = rep["decision"]
        _check(dec["confidence"] == "insufficient",
               f"category='{cat}' with zero detections -> insufficient (got {dec['confidence']})")
        _check(dec["recommended_action"] is None,
               f"category='{cat}' with zero detections recommends no specific action")
        _check(cat in dec["confidence_reasons"][0],
               f"category='{cat}': the reason names the actual tag, not a generic excuse")

    # -- Bug 3: temporal spread demotes count-based corroboration ----------
    print("\n-- Bug 3: detections far apart in time are not treated as corroborating --")
    close = [
        Detection(source="s", severity="high", category="process", title="a",
                 timestamp="2026-08-25T10:00:00+00:00", process_pid=1,
                 details={"causality": _stamp(["x.exe", "y.exe"])}),
        Detection(source="s", severity="high", category="process", title="b",
                 timestamp="2026-08-25T10:02:00+00:00", process_pid=1,
                 details={"causality": _stamp(["x.exe", "y.exe"])}),
    ]
    far = [
        Detection(source="s", severity="high", category="process", title="a",
                 timestamp="2020-01-01T00:00:00+00:00", process_pid=1,
                 details={"causality": _stamp(["x.exe", "y.exe"])}),
        Detection(source="s", severity="high", category="process", title="b",
                 timestamp="2026-08-25T00:00:00+00:00", process_pid=1,
                 details={"causality": _stamp(["x.exe", "y.exe"])}),
    ]
    inc_t = Incident(title="t", severity="high", category="process")
    tier_close, _ = _assess_confidence(inc_t, close, ["process"], _causality_story(close))
    tier_far, reasons_far = _assess_confidence(inc_t, far, ["process"], _causality_story(far))
    _check(tier_close == "medium", f"2 detections 2 minutes apart -> medium (got {tier_close})")
    _check(tier_far in ("low", "medium") and tier_far != tier_close or "spread across" in " ".join(reasons_far),
           f"2 detections years apart are NOT treated identically to 2 minutes apart (close={tier_close}, far={tier_far}, reasons={reasons_far})")
    _check(any("h" in r and ("spread" in r or "connected event" in r) for r in reasons_far),
           "the far-apart reason explicitly names the time spread, not a silent demotion")

    # -- Bug 4: unrelated process lineages are not mutual corroboration ----
    print("\n-- Bug 4: detections from DIFFERENT process lineages are not treated as corroborating --")
    same_actor = [
        Detection(source="s", severity="high", category="process", title="a", process_pid=1,
                 details={"causality": _stamp(["x.exe", "y.exe"], cgo_pid=1)}),
        Detection(source="s", severity="high", category="process", title="b", process_pid=1,
                 details={"causality": _stamp(["x.exe", "y.exe"], cgo_pid=1)}),
    ]
    diff_actor = [
        Detection(source="s", severity="high", category="process", title="a", process_pid=1,
                 details={"causality": _stamp(["x.exe", "y.exe"], cgo_pid=1)}),
        Detection(source="s", severity="high", category="process", title="b", process_pid=2,
                 details={"causality": _stamp(["p.exe", "q.exe"], cgo_pid=2)}),
    ]
    tier_same, _ = _assess_confidence(inc_t, same_actor, ["process"], _causality_story(same_actor))
    tier_diff, reasons_diff = _assess_confidence(inc_t, diff_actor, ["process"], _causality_story(diff_actor))
    _check(tier_same == "medium", f"2 detections, same process lineage -> medium (got {tier_same})")
    _check(tier_diff == "low", f"2 detections, DIFFERENT process lineages -> demoted to low (got {tier_diff})")
    _check(any("lineage" in r for r in reasons_diff), "the demotion reason explicitly names the multiple lineages")

    # -- Bug 5: structured recommended_action never contradicts the prose --
    print("\n-- Bug 5: structured recommended_action matches what the prose says --")
    rep_low = Investigator(edr_store=_FakeStore([
        Detection(source="s", severity="medium", category="network", title="weak", entity="1.2.3.4")
    ])).investigate(Incident(title="x", severity="medium", category="network"), use_ai=False)
    dec_low = rep_low["decision"]
    _check(dec_low["confidence"] == "low", f"sanity: single weak detection is low (got {dec_low['confidence']})")
    _check(dec_low["recommended_action"] is None,
           "at low confidence, structured recommended_action is None (matches 'no immediate action' prose)")
    _check("no immediate action" in dec_low["recommended_action_plain"].lower(),
           "the prose the structured field must match does say 'no immediate action'")

    # -- Bug 6: LLM system prompt is not self-contradictory, and stays bounded --
    print("\n-- Bug 6: LLM prompt/facts boundary (no network call) --")

    class _CapturingProvider(AIProvider):
        name = "capturing-test-double"

        def __init__(self):
            self.captured = {}

        def available(self) -> bool:
            return True

        def analyze(self, system: str, user: str, schema: dict):
            self.captured = {"system": system, "user": user, "schema": schema}
            # Deliberately return None - this is a captor, not a real model;
            # no fabricated LLM answer is invented or asserted on.
            return None

    provider = _CapturingProvider()
    inc_llm = Incident(title="malware", severity="critical", category="malware", process_name="evil.exe")
    dets_llm = [Detection(source="amsi", severity="critical", category="malware",
                          title="AMSI conviction", process_name="evil.exe", process_pid=1,
                          details={"causality": _stamp(["explorer.exe", "evil.exe"], inferred=True)})]
    rep_llm = Investigator(edr_store=_FakeStore(dets_llm))
    offline = rep_llm._offline_report(inc_llm, dets_llm)
    analysis = rep_llm._ai_analysis(provider, inc_llm, dets_llm, offline)
    _check(analysis is None, "capturing test-double returns None (no fabricated model answer used or asserted on)")
    sys_prompt = provider.captured.get("system", "")
    user_prompt = provider.captured.get("user", "")
    _check(bool(sys_prompt) and bool(user_prompt), "the real _ai_analysis code path actually ran and captured real prompts")
    _check("offline_confidence" in user_prompt, "offline_confidence is present in the facts sent to the model")
    _check('"tier": "high"' in user_prompt, "the real offline confidence tier (high, from AMSI) is in the facts")
    _check("as a floor:" not in sys_prompt and "as a CEILING" in sys_prompt,
           "the prompt calls offline_confidence a ceiling (matches the 'may go lower, never higher' "
           "semantics it actually describes), not the old self-contradictory 'a floor: you may go lower'")
    _check("never" in sys_prompt.lower() and ("higher" in sys_prompt.lower() or "HIGHER" in sys_prompt),
           "the prompt still clearly forbids reporting HIGHER confidence than the evidence supports")
    _check("inferred" in sys_prompt.lower(), "the prompt still instructs the model to preserve observed/inferred distinctions")
    import json as _json
    facts = _json.loads(user_prompt.split("Incident facts:\n", 1)[1])
    _check(facts["causality"]["chain_observed_or_inferred"] == "inferred",
           "the facts payload correctly marks this incident's chain as inferred, not observed")
    _check(len(facts["detections"]) <= 25, "detections sent to the model stay capped, no unbounded raw dump")
    _check(set(facts["detections"][0].keys()) == {"title", "severity", "entity", "reason"},
           "each detection fact is limited to title/severity/entity/reason - no raw command lines, file paths, or PII fields")

    print("\n" + "=" * 60)
    if _FAILS:
        print(f"  RESULT: {len(_FAILS)} FAILURE(S)")
        return 1
    print("  RESULT: ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
