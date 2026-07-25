#!/usr/bin/env python3
"""Detection-efficacy harness — drives Valkyrie's REAL classifiers and scores.

Runs every corpus case (tests/efficacy/corpus.py) through the actual
detection code — no mocks, no reimplementation — and reports:

  * Recall (true-positive rate): of the malicious cases, how many fired.
  * False-positive rate: of the benign cases, how many wrongly fired.
  * Precision, and a per-technique / per-detector breakdown.

Exit code is a REGRESSION GATE: non-zero if recall drops below RECALL_FLOOR
or the false-positive rate rises above FP_CEILING, so this doubles as a
guard against a change that quietly degrades detection.

Run:  PYTHONUTF8=1 python tests/efficacy/harness.py
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from corpus import BENIGN, MALICIOUS, Case   # noqa: E402

# Regression gate thresholds. These encode the CURRENT honest capability, not
# an aspiration — raise them only when detection genuinely improves.
RECALL_FLOOR = 0.85     # must catch >= 85% of represented malicious techniques
FP_CEILING = 0.05       # must wrongly flag <= 5% of benign controls


def _fires(case: Case, ctx: dict) -> bool:
    """Return True if the REAL detector fires on this case's input."""
    from valkyrie.telemetry import severity_rank, SEV_MEDIUM, SEV_HIGH
    d = case.detector

    if d == "cmdline":
        from valkyrie.process_telemetry import classify_cmdline
        name, cmd = case.inp
        sev, labels, _ = classify_cmdline(name, cmd)
        return severity_rank(sev) >= severity_rank(SEV_MEDIUM)

    if d == "powershell":
        from valkyrie.etw.powershell import classify_powershell
        sev, labels, _tech, _ = classify_powershell(case.inp)
        return severity_rank(sev) >= severity_rank(SEV_MEDIUM)

    if d == "persistence":
        # Every new auto-start is inherently "medium" (notable); a MALICIOUS
        # one must escalate to HIGH. So "fired as a threat" = severity high.
        from valkyrie.persistence_telemetry import _persistence_severity
        activity, command = case.inp
        sev, _labels, _ = _persistence_severity(activity, command)
        return severity_rank(sev) >= severity_rank(SEV_HIGH)

    if d == "entropy":
        from valkyrie.ransomware_shield import shannon_entropy, _ENTROPY_ENCRYPTED
        data = case.inp if case.inp else os.urandom(4096)  # encrypted-like
        return shannon_entropy(data) >= _ENTROPY_ENCRYPTED

    if d == "sysmon":
        # inp = (Sysmon EventID, EventData dict). A None result = no emit; an
        # emit at >= medium severity is "fired as a threat" (same bar as above).
        from valkyrie.etw.sysmon import classify_sysmon
        eid, data = case.inp
        res = classify_sysmon(eid, data)
        return res is not None and severity_rank(res["severity"]) >= severity_rank(SEV_MEDIUM)

    if d == "wmi":
        from valkyrie.etw.wmi import classify_wmi
        sev, _labels, _tech, _reason = classify_wmi(case.inp, "")
        return severity_rank(sev) >= severity_rank(SEV_MEDIUM)

    if d == "process":
        # inp = (name, path, parent_name) — process-relationship heuristics.
        from valkyrie.process_telemetry import classify_process
        name, path, parent = case.inp
        sev, _labels, _ = classify_process(name, path, parent)
        return severity_rank(sev) >= severity_rank(SEV_MEDIUM)

    if d == "network":
        # inp = (ip, port). Reputation comes from the REAL threat-intel manager,
        # measuring the end-to-end network-collector → intel path DNS can't see.
        from valkyrie.network_telemetry import classify_connection
        ip, port = case.inp
        blocked = ctx["intel"].match_ip(ip) is not None
        sev, _labels, _ = classify_connection(ip, port, blocked)
        return severity_rank(sev) >= severity_rank(SEV_MEDIUM)

    if d == "dga":
        # Corroborated DGA classifier (length + entropy + bigram implausibility).
        from valkyrie.dga import classify_dga
        return classify_dga(case.inp).is_dga

    if d in ("intel_domain", "intel_ip"):
        mgr = ctx["intel"]
        if d == "intel_domain":
            return mgr.match_domain(case.inp) is not None
        return mgr.match_ip(case.inp) is not None

    if d == "scanner":
        scanner = ctx["scanner"]
        res = scanner.analyze(case.inp, "chrome.exe")
        return res.decision in ("block", "flag")

    if d == "tunnel":
        # inp = tuple of hostnames — a query STREAM, because tunnelling is an
        # aggregate shape no single query shows. Fresh scanner per case so the
        # flood window is isolated and cases stay order-independent. Fires
        # only if the stream produced an outright BLOCK (flag is not enough
        # for a malicious tunnel case to count as caught).
        from valkyrie.site_scanner import SiteScanner
        scanner = SiteScanner(store=None)
        return any(scanner.analyze(dm, "powershell.exe").decision == "block"
                   for dm in case.inp)

    if d == "killchain":
        # inp = (actor, [(technique, title), ...]) — a sequence of detections
        # on ONE actor. "Fires" = the correlator raised a multi-stage chain,
        # which is exactly the escalation the base same-category correlator
        # could not produce. Deterministic ts, fresh correlator per case.
        from valkyrie.edr.killchain import KillChainCorrelator
        kc = KillChainCorrelator()
        actor, steps = case.inp
        fired = False
        for i, (tech, title) in enumerate(steps):
            if kc.observe(actor, tech, title, ts=1000.0 + i) is not None:
                fired = True
        return fired

    raise ValueError(f"unknown detector: {case.detector}")


def _build_ctx() -> dict:
    """Stand up the real stateful detectors (threat-intel cache, scanner)."""
    from valkyrie.threat_intel import IntelFeed, ThreatIntelManager
    from valkyrie.site_scanner import SiteScanner

    tmp = Path(tempfile.mkdtemp(prefix="efficacy_"))
    icache = tmp / "intel"
    icache.mkdir()
    # Seed the real cache with the indicators the malicious corpus references.
    (icache / "urlhaus.txt").write_text("evil-c2.example\n", encoding="utf-8")
    (icache / "feodo_c2.txt").write_text("45.9.148.99\n", encoding="utf-8")
    intel = ThreatIntelManager(
        feeds=[IntelFeed("urlhaus", "domain", "malware_distribution", "https://x.invalid/u"),
               IntelFeed("feodo_c2", "ip", "botnet_c2", "https://x.invalid/f")],
        cache_dir=icache)
    intel.load(allow_download=False)

    scanner = SiteScanner(store=None)
    return {"intel": intel, "scanner": scanner, "_tmp": tmp}


def main() -> int:
    ctx = _build_ctx()

    print("\n" + "=" * 70)
    print("  VALKYRIE DETECTION-EFFICACY SCORECARD")
    print("  (real classifiers, technique-representative corpus — NOT live")
    print("   malware; see corpus.py honest boundary)")
    print("=" * 70)

    # ── Malicious: recall ──────────────────────────────────────────────
    tp = fn = 0
    missed: list[Case] = []
    by_tactic: dict[str, list[int]] = {}
    print("\n[ Malicious techniques — should FIRE ]\n")
    print(f"  {'technique':<12} {'detector':<13} {'result':<7} case")
    print(f"  {'-'*12} {'-'*13} {'-'*7} {'-'*30}")
    for c in MALICIOUS:
        fired = _fires(c, ctx)
        tp += fired
        fn += (not fired)
        by_tactic.setdefault(c.tactic, [0, 0])
        by_tactic[c.tactic][0] += fired
        by_tactic[c.tactic][1] += 1
        if not fired:
            missed.append(c)
        mark = "DETECT" if fired else "MISS  "
        print(f"  {c.technique:<12} {c.detector:<13} {mark:<7} {c.id} — {c.note}")

    # ── Benign: false positives ────────────────────────────────────────
    fp = tn = 0
    false_hits: list[Case] = []
    print("\n[ Benign controls — must NOT fire ]\n")
    print(f"  {'detector':<13} {'result':<7} case")
    print(f"  {'-'*13} {'-'*7} {'-'*40}")
    for c in BENIGN:
        fired = _fires(c, ctx)
        fp += fired
        tn += (not fired)
        if fired:
            false_hits.append(c)
        mark = "FP!   " if fired else "clean "
        print(f"  {c.detector:<13} {mark:<7} {c.id} — {c.note}")

    # ── Scorecard ──────────────────────────────────────────────────────
    n_mal = tp + fn
    n_ben = fp + tn
    recall = tp / n_mal if n_mal else 0.0
    fp_rate = fp / n_ben if n_ben else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0

    print("\n" + "=" * 70)
    print("  SCORECARD")
    print("=" * 70)
    print(f"  Malicious detected (recall):  {tp}/{n_mal}  = {recall*100:5.1f}%")
    print(f"  Benign wrongly flagged (FPR): {fp}/{n_ben}  = {fp_rate*100:5.1f}%")
    print(f"  Precision:                    {precision*100:5.1f}%")
    print("\n  By tactic (detected / total):")
    for tac, (hit, tot) in sorted(by_tactic.items()):
        print(f"    {tac:<22} {hit}/{tot}")
    if missed:
        print("\n  MISSED techniques (false negatives):")
        for c in missed:
            print(f"    - {c.technique} {c.id}: {c.note}")
    if false_hits:
        print("\n  FALSE POSITIVES:")
        for c in false_hits:
            print(f"    - {c.id}: {c.note}")

    # ── Regression gate ────────────────────────────────────────────────
    print("\n" + "=" * 70)
    ok = True
    if recall < RECALL_FLOOR:
        print(f"  GATE FAIL: recall {recall*100:.1f}% < floor {RECALL_FLOOR*100:.0f}%")
        ok = False
    if fp_rate > FP_CEILING:
        print(f"  GATE FAIL: FPR {fp_rate*100:.1f}% > ceiling {FP_CEILING*100:.0f}%")
        ok = False
    if ok:
        print(f"  GATE PASS: recall {recall*100:.1f}% >= {RECALL_FLOOR*100:.0f}%, "
              f"FPR {fp_rate*100:.1f}% <= {FP_CEILING*100:.0f}%")
    print("=" * 70 + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
