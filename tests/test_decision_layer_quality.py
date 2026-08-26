#!/usr/bin/env python3
"""Human Decision Layer quality audit - regression gate.

Covers the SPECIFIC improvements made in this audit pass (PHASE 1-10 of the
"make it genuinely excellent" review), each one found against real, live
incident data, not invented. Does not re-test what test_decision_layer.py
and test_decision_layer_adversarial.py already cover.

  1. No duplication between "what happened" and "technical detail" - a real
     defect found in 100% of a real-incident sample before this pass.
  2. Label-based specificity replaces the generic 3-in-1 "process" catch-all
     when the real detection carries a specific finding (details["labels"]).
  3. Consecutive duplicate process names in a chain are collapsed.
  4. The "how" chain names a real persistence outcome, not just network.
  5. A fragmented incident (many unrelated process lineages) says so plainly
     in "what happened", not only in the confidence caveat.
  6. Overly technical "primary indicator" strings (SIDs, GUIDs) are withheld
     from the plain narrative but stay available in `summary`/`entities`.
  7. Benign developer activity (Cursor/Claude/PowerShell/Python) never gets
     narrated as if malicious - confidence and wording both stay honest.
  8. No fabricated claims (attacker identity, data theft, breach, malware
     name) appear anywhere the evidence doesn't establish them.

No network, no Windows APIs. Exit 0 on success, non-zero on failure
(standalone-script contract, matching tests/run_safe.py's test_*.py glob).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.edr.investigate import Investigator, _dedupe_consecutive, _is_readable_indicator
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


# Fabrication words that must never appear unless the evidence actually
# establishes them - none of the fixtures below carry attribution, breach
# confirmation, or a named malware family, so none of these words are earned.
_FABRICATION_WORDS = ("attacker", "hacker", "stolen", "breach", "compromised",
                      "ransomware", "trojan", "the malware is")


def _no_fabrication(rep: dict) -> list:
    dec = rep["decision"]
    text = " ".join([rep.get("story", ""), dec.get("why_it_matters", ""),
                     dec.get("recommended_action_plain", "")]).lower()
    return [w for w in _FABRICATION_WORDS if w in text]


def main() -> int:
    print("Human Decision Layer quality audit - regression gate")
    print("=" * 60)

    # -- 1: no duplication between what_happened and technical detail ------
    print("\n-- 1: what_happened and technical detail never repeat the same paragraph --")
    det = Detection(source="edr.behavioral", severity="high", category="process",
                    title="masquerade finding", process_name="svchost.exe", process_pid=1,
                    details={"causality": _stamp(["system idle process", "svchost.exe"])})
    rep = Investigator(edr_store=_FakeStore([det])).investigate(
        Incident(title="masquerade", severity="high", category="process", process_name="svchost.exe"),
        use_ai=False)
    _check(rep["meaning"] not in rep["decision"]["what_happened"],
           "the technical _MEANING text does not appear inside what_happened")
    _check(rep["decision"]["what_happened"] != rep["meaning"],
           "what_happened and technical detail (meaning) are not identical")

    det_no_causality = Detection(source="s", severity="medium", category="process",
                                 title="living-off-the-land binary (wscript.exe)")
    rep2 = Investigator(edr_store=_FakeStore([det_no_causality])).investigate(
        Incident(title="living-off-the-land binary (wscript.exe)", severity="medium", category="process"),
        use_ai=False)
    _check(rep2["meaning"] not in rep2["decision"]["what_happened"],
           "no-causality path: technical meaning also does not leak into what_happened")

    # -- 2: label-based specificity beats the generic category catch-all ---
    print("\n-- 2: real detection labels produce a SPECIFIC why, not the generic 3-in-1 --")
    det_masq = Detection(source="s", severity="high", category="process", title="masquerade",
                         details={"labels": ["wrong_parent_system_proc"]})
    rep3 = Investigator(edr_store=_FakeStore([det_masq])).investigate(
        Incident(title="masquerade", severity="high", category="process"), use_ai=False)
    why3 = rep3["decision"]["why_it_matters"]
    _check("wrong parent" in why3.lower(), "a real 'wrong_parent_system_proc' label produces the specific masquerade explanation")
    _check("LSASS" not in why3 and "lsass" not in why3.lower(),
           "the generic 'process' category's LSASS/injection catch-all is NOT used when a specific label exists")

    det_hidden = Detection(source="s", severity="medium", category="process", title="hidden window",
                           details={"labels": ["hidden_window"]})
    rep4 = Investigator(edr_store=_FakeStore([det_hidden])).investigate(
        Incident(title="hidden window", severity="medium", category="process"), use_ai=False)
    _check("hidden" in rep4["decision"]["why_it_matters"].lower(),
           "a 'hidden_window' label produces the specific hidden-window explanation, not the generic one")

    # Co-occurring labels (real data: lolbin+hidden_window+execpolicy_bypass
    # always travel together) must produce ONE sentence, not three restatements.
    det_multi = Detection(source="s", severity="medium", category="process", title="lolbin combo",
                          details={"labels": ["lolbin", "hidden_window", "execpolicy_bypass"]})
    rep5 = Investigator(edr_store=_FakeStore([det_multi])).investigate(
        Incident(title="lolbin combo", severity="medium", category="process"), use_ai=False)
    why5 = rep5["decision"]["why_it_matters"]
    _check(why5.count(".") <= 2, f"co-occurring labels produce ONE crisp sentence, not a run-on of all three (got: {why5!r})")

    # Credential-access-flavored label (a genuinely serious, specific real label).
    det_cred = Detection(source="s", severity="critical", category="process", title="cred theft",
                         details={"labels": ["cred_browser"]})
    rep6 = Investigator(edr_store=_FakeStore([det_cred])).investigate(
        Incident(title="cred theft", severity="critical", category="process"), use_ai=False)
    _check("password" in rep6["decision"]["why_it_matters"].lower() or "cookie" in rep6["decision"]["why_it_matters"].lower(),
           "a 'cred_browser' label names the real, specific finding (saved password/cookie theft)")

    # No label at all -> must still fall back to the existing category text (unchanged behavior).
    det_plain = Detection(source="s", severity="high", category="process", title="generic")
    rep7 = Investigator(edr_store=_FakeStore([det_plain])).investigate(
        Incident(title="generic", severity="high", category="process"), use_ai=False)
    _check("LSASS" in rep7["decision"]["why_it_matters"] or "lsass" in rep7["decision"]["why_it_matters"].lower()
           or "private memory" in rep7["decision"]["why_it_matters"].lower(),
           "with NO specific label, the existing category-level plain text is still used (no regression)")

    # -- 3: consecutive duplicate names in a chain are collapsed -----------
    print("\n-- 3: consecutive duplicate process names are collapsed in the chain --")
    _check(_dedupe_consecutive(["a", "a", "a", "b", "b", "c"]) == ["a", "b", "c"],
           "_dedupe_consecutive collapses consecutive repeats but keeps distinct names")
    _check(_dedupe_consecutive(["a", "b", "a"]) == ["a", "b", "a"],
           "_dedupe_consecutive does NOT collapse non-consecutive repeats (a real re-visit is real data)")

    det_repeat = Detection(source="s", severity="high", category="process", title="repeat",
                           process_pid=1,
                           details={"causality": _stamp(["Cursor.exe", "python.exe", "python.exe", "python.exe", "powershell.exe"])})
    rep8 = Investigator(edr_store=_FakeStore([det_repeat])).investigate(
        Incident(title="repeat", severity="high", category="process", process_name="powershell.exe"), use_ai=False)
    how8 = rep8["decision"]["how"]
    _check(how8.count("python.exe") == 1, f"the 'how' chain shows python.exe once, not three times in a row (got: {how8!r})")
    _check("python.exe, which started python.exe" not in rep8["decision"]["what_happened"],
           "the prose sentence also does not repeat the same immediate name")

    # -- 4: persistence outcome is named in the chain, not just network ----
    print("\n-- 4: the 'how' chain names a real persistence outcome --")
    det_persist = Detection(source="s", severity="high", category="persistence", title="autostart",
                            process_pid=1,
                            details={"causality": _stamp(["WINWORD.EXE", "powershell.exe", "python.exe"])})
    rep9 = Investigator(edr_store=_FakeStore([det_persist])).investigate(
        Incident(title="autostart", severity="high", category="persistence", process_name="python.exe"), use_ai=False)
    _check("persistence attempt" in rep9["decision"]["how"],
           f"a persistence-category incident's 'how' chain names the persistence outcome (got: {rep9['decision']['how']!r})")
    _check("attempt was made to set up automatic startup" in rep9["decision"]["what_happened"],
           "the prose 'what happened' also names the persistence outcome factually, without asserting success")

    # -- 5: fragmented (many-unrelated-lineage) incidents say so plainly ---
    print("\n-- 5: a heavily-fragmented incident says so in what_happened, not just confidence --")
    lineages = []
    for i in range(8):
        lineages.append(Detection(source="s", severity="high", category="process", title=f"d{i}",
                                  process_pid=i,
                                  details={"causality": _stamp([f"root{i}.exe", f"child{i}.exe"], cgo_pid=i)}))
    rep10 = Investigator(edr_store=_FakeStore(lineages)).investigate(
        Incident(title="grab bag", severity="high", category="process"), use_ai=False)
    _check("groups" in rep10["decision"]["what_happened"] and "not one connected chain" in rep10["decision"]["what_happened"],
           "8 unrelated lineages -> what_happened explicitly says this is a grouped, not connected, incident")

    # -- 6: unreadable technical indicators are withheld from the narrative -
    print("\n-- 6: SID/GUID-shaped indicators are withheld from the plain narrative --")
    _check(_is_readable_indicator("example.com") is True, "a plain domain is readable")
    _check(_is_readable_indicator("1.2.3.4") is True, "a plain IP is readable")
    ugly = r"scheduled_task::SoftLanding\S-1-5-21-1348178330-531555113-1032912420-1001\Task-{bd8a9e72-9c6b-4ee6-a6f9-ee450a7ef2cf}"
    _check(_is_readable_indicator(ugly) is False, "a raw SID+GUID scheduled-task path is NOT readable")
    det_ugly = Detection(source="s", severity="medium", category="persistence", title="autostart",
                         entity=ugly)
    rep11 = Investigator(edr_store=_FakeStore([det_ugly])).investigate(
        Incident(title="autostart", severity="medium", category="persistence"), use_ai=False)
    _check(ugly not in rep11["decision"]["what_happened"], "the raw SID/GUID string does not appear in what_happened")
    _check(ugly in rep11["summary"] or ugly in rep11["entities"],
           "the raw value is still available in summary/entities for an analyst who wants it")

    # -- 7: benign developer activity is never narrated as if malicious ----
    print("\n-- 7: real dev-tool activity (Cursor/Claude/PowerShell/Python) stays honest --")
    dev_det = Detection(source="edr.behavioral", severity="medium", category="process",
                        title="child process", process_name="python.exe", process_pid=1,
                        details={"causality": _stamp(["Cursor.exe", "claude.exe", "powershell.exe", "python.exe"])})
    rep12 = Investigator(edr_store=_FakeStore([dev_det])).investigate(
        Incident(title="dev chain", severity="medium", category="process", process_name="python.exe"), use_ai=False)
    _check(rep12["decision"]["confidence"] in ("low", "medium"),
           f"a single medium-severity dev-tool detection does not reach 'high' confidence (got {rep12['decision']['confidence']})")
    _check(not _no_fabrication(rep12), f"no fabricated attack language in a benign-looking dev chain (found: {_no_fabrication(rep12)})")
    action_plain12 = rep12["decision"]["recommended_action_plain"].lower()
    _check("if you" in action_plain12 or "no immediate action" in action_plain12,
           f"the recommendation stays conditional or explicitly says no action is warranted, never asserting this IS an attack (got: {action_plain12!r})")

    # -- 8: no fabricated claims anywhere across a spread of real shapes ----
    print("\n-- 8: no fabricated attacker/breach/malware-name language --")
    fixtures = [
        (Incident(title="malware", severity="critical", category="malware"),
         [Detection(source="amsi", severity="critical", category="malware", title="AMSI conviction")]),
        (Incident(title="net", severity="high", category="network"),
         [Detection(source="s", severity="high", category="network", title="net", entity="1.2.3.4")]),
        (Incident(title="chain", severity="high", category="attack_chain"),
         [Detection(source="s", severity="high", category="attack_chain", title=f"t{i}") for i in range(3)]),
    ]
    for inc, dets in fixtures:
        rep = Investigator(edr_store=_FakeStore(dets)).investigate(inc, use_ai=False)
        bad = _no_fabrication(rep)
        _check(not bad, f"'{inc.title}': no fabricated claims (found: {bad})")

    print("\n" + "=" * 60)
    if _FAILS:
        print(f"  RESULT: {len(_FAILS)} FAILURE(S)")
        return 1
    print("  RESULT: ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
