#!/usr/bin/env python3
"""Human decision layer - regression gate.

Verifies edr/investigate.py's "what happened / how / why it matters / what
should I do" layer added on top of the existing causality-aware investigation.
Covers exactly what the milestone specified:

  A. high-confidence incident   -> confident-but-conditional action language,
                                    a real evidence-grounded reason
  B. low-confidence incident    -> hedged language, no false certainty
  C. benign/false-positive      -> tracker/anomaly-only never exceeds "low",
                                    why_it_matters says so plainly
  D. insufficient evidence      -> no action guessed at; says so explicitly
  E. traceability               -> confidence_reasons cite real fields, not
                                    invented ones
  F. no false certainty         -> medium/low/insufficient tiers never use
                                    unconditional/certain phrasing
  G. existing behavior intact   -> causality, offline/LLM boundary, fallback

No network, no Windows APIs - pure construction of Detection/Incident objects
plus the same minimal fake store test_causality_investigation.py already uses.

Exit 0 on success, non-zero on failure (standalone-script contract, matching
tests/run_safe.py's discovery of test_*.py).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.edr.investigate import (
    Investigator, _assess_confidence, _decision_layer, _how_chain,
)
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


def _causality_stamp(chain: list, *, cgo_pid: int = 100, inferred: bool = False) -> dict:
    return {
        "cgo": chain[0], "cgo_pid": cgo_pid, "cgo_path": "",
        "chain": list(chain), "path": " -> ".join(chain),
        "depth": len(chain), "inferred": inferred,
    }


# Phrases that assert certainty a hedged tier must never use unconditionally.
_UNCONDITIONAL_CERTAINTY = ("this is definitely", "you must", "confirmed malicious",
                            "will happen again", "guaranteed")


def main() -> int:
    print("Human decision layer - regression gate")
    print("=" * 60)

    # -- A: high confidence ---------------------------------------------
    print("\n-- A: high-confidence incident (malware conviction) --")
    det_malware = Detection(source="amsi", severity="critical", category="malware",
                            title="AMSI convicted content", process_name="powershell.exe",
                            process_pid=4242, entity="script.ps1",
                            details={"causality": _causality_stamp(["WINWORD.EXE", "powershell.exe"])})
    inc_a = Incident(title="AMSI conviction", severity="critical", category="malware",
                     process_name="powershell.exe")
    rep_a = Investigator(edr_store=_FakeStore([det_malware])).investigate(inc_a, use_ai=False)
    dec_a = rep_a["decision"]
    _check(dec_a["confidence"] == "high", f"malware conviction -> high confidence (got {dec_a['confidence']})")
    _check(bool(dec_a["confidence_reasons"]), "high-confidence tier still carries a reason")
    _check("amsi" in dec_a["confidence_reasons"][0].lower() or "antimalware" in dec_a["confidence_reasons"][0].lower(),
           "the reason actually names the real evidence (AMSI/antimalware), not a generic phrase")
    _check(dec_a["recommended_action"] is not None, "high-confidence incident gets a concrete recommended action")
    _check("if you did not" in dec_a["recommended_action_plain"].lower(),
           "even high-confidence guidance is conditional ('if you did not...'), never a bare imperative")
    _check("WINWORD.EXE" in dec_a["how"] and "powershell.exe" in dec_a["how"],
           "the 'how' chain names the real processes involved")
    _check(dec_a["what_happened"] == rep_a["story"], "what_happened reuses the existing story field verbatim")

    # -- B: low confidence ------------------------------------------------
    print("\n-- B: low-confidence incident (single weak detection) --")
    det_weak = Detection(source="dns.anomaly", severity="low", category="anomaly",
                         title="Unusual destination", entity="odd-but-not-alarming.example")
    inc_b = Incident(title="Baseline deviation", severity="low", category="anomaly")
    rep_b = Investigator(edr_store=_FakeStore([det_weak])).investigate(inc_b, use_ai=False)
    dec_b = rep_b["decision"]
    _check(dec_b["confidence"] == "low", f"single low-severity anomaly -> low confidence (got {dec_b['confidence']})")
    _check("isn't strong enough" in dec_b["recommended_action_plain"] or "no immediate action" in dec_b["recommended_action_plain"].lower(),
           "low-confidence guidance explicitly says it isn't strong enough to act on")

    # -- C: benign / false-positive-leaning -------------------------------
    print("\n-- C: benign/false-positive-leaning incident (tracker only) --")
    det_tracker = Detection(source="dns.tracker", severity="low", category="tracker",
                            title="Tracker blocked", entity="adnetwork.example")
    det_tracker2 = Detection(source="dns.tracker", severity="low", category="tracker",
                             title="Tracker blocked again", entity="adnetwork2.example")
    inc_c = Incident(title="Trackers blocked", severity="low", category="tracker")
    rep_c = Investigator(edr_store=_FakeStore([det_tracker, det_tracker2])).investigate(inc_c, use_ai=False)
    dec_c = rep_c["decision"]
    _check(dec_c["confidence"] == "low",
           f"tracker-only incident stays capped at low confidence even with 2 detections (got {dec_c['confidence']})")
    _check("privacy" in dec_c["why_it_matters"].lower() or "not" in dec_c["why_it_matters"].lower(),
           "why_it_matters for a tracker incident explicitly frames it as not a compromise")
    _check("tracker" in dec_c["confidence_reasons"][0].lower(),
           "the confidence reason names the actual category, not a generic hedge")

    # -- D: insufficient evidence ------------------------------------------
    print("\n-- D: insufficient evidence (nothing to go on) --")
    inc_d = Incident(title="Untitled", severity="low")  # no category, no detections
    rep_d = Investigator(edr_store=_FakeStore([])).investigate(inc_d, use_ai=False)
    dec_d = rep_d["decision"]
    _check(dec_d["confidence"] == "insufficient", f"empty incident -> insufficient (got {dec_d['confidence']})")
    _check(dec_d["insufficient_evidence"] is True, "insufficient_evidence flag is set")
    _check(dec_d["recommended_action"] is None, "no specific action is guessed at when evidence is insufficient")
    _check("isn't enough evidence" in dec_d["recommended_action_plain"].lower(),
           "the system says plainly it cannot safely recommend an action")

    # No-store variant (real production path when a store isn't wired) must
    # behave identically - this is the exact case the previous milestone's
    # test suite already exercises for causality; decision must not regress it.
    rep_d2 = Investigator(edr_store=None).investigate(Incident(title="x", severity="low"), use_ai=False)
    _check(rep_d2["decision"]["confidence"] == "insufficient", "edr_store=None with no category also reads as insufficient")

    # -- E: traceability - reasons cite REAL fields, not invented ones -----
    print("\n-- E: confidence reasons are traceable to real evidence --")
    dets_3 = [
        Detection(source="edr.behavioral", severity="high", category="process", title="Injection", process_pid=1),
        Detection(source="dns.dga", severity="high", category="dga", title="DGA domain", process_pid=1),
        Detection(source="edr.behavioral", severity="high", category="persistence", title="Run key", process_pid=1),
    ]
    inc_e = Incident(title="Multi-stage", severity="high", category="process")
    tier_e, reasons_e = _assess_confidence(inc_e, dets_3, ["process", "dga", "persistence"],
                                           {"available": False})
    _check(tier_e in ("high", "medium"), f"3 corroborating high-severity detections rate at least medium (got {tier_e})")
    _check(any(str(len(dets_3)) in r for r in reasons_e), "the reason cites the ACTUAL detection count (3), not a made-up number")

    # -- F: no false certainty on hedged tiers ------------------------------
    print("\n-- F: no unconditional certainty language on non-high tiers --")
    for label, dec in (("low", dec_b), ("low-benign", dec_c), ("insufficient", dec_d)):
        text = dec["recommended_action_plain"].lower()
        hit = [p for p in _UNCONDITIONAL_CERTAINTY if p in text]
        _check(not hit, f"{label}-tier guidance contains no unconditional-certainty phrasing (found: {hit})")
    # Reasons must never claim MORE detections than were actually supplied.
    _check("0 separate" not in " ".join(dec_d["confidence_reasons"]),
           "insufficient-tier reasoning doesn't invent a detection count")

    # -- G: existing behavior intact ----------------------------------------
    print("\n-- G: existing fields untouched by this addition --")
    for rep in (rep_a, rep_b, rep_c, rep_d):
        for key in ("summary", "story", "meaning", "categories", "techniques",
                   "entities", "recommended_actions", "causality"):
            _check(key in rep, f"pre-existing field '{key}' still present")
    # decision.how degrades cleanly when there's no causality at all.
    _check(_how_chain({"available": False}, ["anomaly"]) == "", "_how_chain with no causality returns ''")
    _check(_how_chain({"available": True, "chain": []}, ["anomaly"]) == "", "_how_chain with an empty chain returns ''")

    print("\n" + "=" * 60)
    if _FAILS:
        print(f"  RESULT: {len(_FAILS)} FAILURE(S)")
        return 1
    print("  RESULT: ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
