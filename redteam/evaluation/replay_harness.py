"""Tier A -- classifier-input replay. Executes TODAY, on this host, safely.

## What this is, precisely

For every in-scope technique in catalog.py, this drives Valkyrie's REAL
detection functions (no mocks, no reimplementation -- the same functions the
running product calls) with the exact command line / registry artifact / DNS
name / Sysmon event fields a real Atomic Red Team execution of that technique
would produce. It records whether the real code fires, at what severity, and
with what confidence.

## What this is NOT, and why that distinction is enforced in code, not prose

This is NOT a live attack. No process actually runs, no registry key is
actually written, no LSASS handle is actually opened. It cannot execute
successfully or unsuccessfully -- there is no attack to execute. It cannot
measure detection LATENCY -- there is no real clock between "attack happened"
and "Valkyrie noticed" when the "attack" is a Python function call. It cannot
produce false positives in the aggregate sense the live tier measures, because
each test is one isolated synthetic input, not a running system under load.

Every one of those fields is still emitted per the requested schema, but as
`null` with an explanation -- never fabricated to look like a measurement.

## The one thing this tier CANNOT be allowed to do: inflate the score

catalog.py records a `predicted_tier_b` for each technique, arrived at by
tracing the actual delivery mechanism (is the classifier reachable in real
time, via a reliable 15s artifact-at-rest poll, or only via a racy 2-second
process poll that most one-shot attacker commands will outrun?). That
judgment -- not "did the function return truthy when I called it directly" --
is what determines whether a technique counts as DETECTED in this report.

Calling classify_behavior() directly with a hand-built cmdline string will
happily return a hit for `regsvr32 /i:http://.../evil.sct` -- the RULE LOGIC
is correct. But real regsvr32 exits in milliseconds, and the only path to that
rule is a poller that ticks every two seconds. Reporting that as "DETECTED"
because the Python call succeeded would be exactly the kind of inflated score
this evaluation was commissioned to prevent. So this harness reports BOTH:

  * `classifier_logic_fires` -- ground truth about the code: did the real
    function match this exact input? (a genuine, executed-today fact)
  * `counted_as_detected`    -- the scored outcome, gated by catalog.py's
    delivery-mechanism judgment. CONDITIONAL and MISS both score as NOT
    detected in the headline number, per the instruction that a miss is a
    miss. `classifier_logic_fires=True` alongside `counted_as_detected=False`
    is the single most actionable row in this report: the logic is right, the
    plumbing to reach it live is what needs fixing.

Run:  PYTHONUTF8=1 python redteam/evaluation/replay_harness.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from catalog import (Technique, all_in_scope, CATALOG_VERSION,   # noqa: E402
                     DELIVERY_PROCESS_POLL_RACY, DELIVERY_NONE)
from environment import check_requirements, probe_sysmon        # noqa: E402
from valkyrie.telemetry import (SEV_INFO, SEV_LOW, SEV_MEDIUM,   # noqa: E402
                                SEV_HIGH, SEV_CRITICAL, severity_rank)

TIER = "A_replay"

# Severity -> approximate confidence, used ONLY where the real function does
# not itself expose a float. Documented here so the report can show its work
# rather than presenting a borrowed number as if it were precise.
_SEV_CONFIDENCE = {
    SEV_INFO: 0.10, SEV_LOW: 0.30, SEV_MEDIUM: 0.55,
    SEV_HIGH: 0.80, SEV_CRITICAL: 0.95,
}


def _confidence_for(sev: str) -> float:
    return _SEV_CONFIDENCE.get(sev, 0.0)


# --- Shared context (built once) ---

def _build_ctx() -> dict:
    from valkyrie.threat_intel import IntelFeed, ThreatIntelManager
    from valkyrie.site_scanner import SiteScanner

    tmp = Path(tempfile.mkdtemp(prefix="valkyrie_redteam_replay_"))
    icache = tmp / "intel"
    icache.mkdir()
    (icache / "urlhaus.txt").write_text("evil-c2.example\n", encoding="utf-8")
    (icache / "feodo_c2.txt").write_text("45.9.148.99\n", encoding="utf-8")
    intel = ThreatIntelManager(
        feeds=[IntelFeed("urlhaus", "domain", "malware_distribution",
                         "https://x.invalid/u"),
               IntelFeed("feodo_c2", "ip", "botnet_c2", "https://x.invalid/f")],
        cache_dir=icache)
    intel.load(allow_download=False)
    # Probed ONCE per run, not per technique: it shells out to PowerShell and
    # the answer cannot change mid-run in any way we'd want to act on. Also
    # means every record in a run is scored against one consistent snapshot.
    return {"intel": intel, "scanner": SiteScanner(store=None), "_tmp": tmp,
            "sysmon_env": probe_sysmon()}


# --- Probe functions. One per catalog `probe` key. ---
# Each returns (logic_fires: bool, severity: str, confidence: float,
#               technique_tag: str, reason: str, evidence: dict)

def _probe_powershell(inp: dict, ctx: dict):
    from valkyrie.etw.powershell import classify_powershell
    sev, labels, tech, reason = classify_powershell(inp["script_block"])
    fires = severity_rank(sev) >= severity_rank(SEV_MEDIUM)
    return fires, sev, _confidence_for(sev), tech or "", reason or "; ".join(labels), \
        {"processes": [{"note": "no live process -- synthetic PS Script "
                                "Block Logging event replayed"}],
         "registry": [], "network": [], "dns": [], "files": [],
         "script_block": inp["script_block"]}


def _probe_process_relationship(inp: dict, ctx: dict):
    from valkyrie.process_telemetry import classify_process
    sev, labels, reason = classify_process(inp["name"], inp["path"], inp["parent"])
    fires = severity_rank(sev) >= severity_rank(SEV_MEDIUM)
    return fires, sev, _confidence_for(sev), "", reason or "; ".join(labels), \
        {"processes": [{"name": inp["name"], "path": inp["path"],
                        "parent": inp["parent"], "note": "synthetic"}],
         "registry": [], "network": [], "dns": [], "files": []}


def _probe_ioa_rule(inp: dict, ctx: dict):
    from valkyrie.behavioral_rules import classify_behavior
    result = classify_behavior(inp["image"], inp["parent"], inp["cmdline"],
                               inp.get("path", ""))
    if result is None:
        return False, SEV_INFO, 0.0, "", "no IOA rule matched", \
            {"processes": [{"image": inp["image"], "cmdline": inp["cmdline"],
                            "parent": inp["parent"], "note": "synthetic"}],
             "registry": [], "network": [], "dns": [], "files": []}
    sev = result["severity"]
    fires = severity_rank(sev) >= severity_rank(SEV_MEDIUM)
    return fires, sev, _confidence_for(sev), result["technique"], result["reason"], \
        {"processes": [{"image": inp["image"], "cmdline": inp["cmdline"],
                        "parent": inp["parent"], "labels": result["labels"],
                        "note": "synthetic"}],
         "registry": [], "network": [], "dns": [], "files": []}


def _probe_behavior_score(inp: dict, ctx: dict):
    from valkyrie.behavior_score import score_process
    r = score_process(inp["image"], inp["parent"], inp["cmdline"], inp.get("path", ""))
    return r.fired(), r.severity, r.score, r.technique, r.reason, \
        {"processes": [{"image": inp["image"], "cmdline": inp["cmdline"],
                        "parent": inp["parent"],
                        "signals": [s.name for s in r.signals],
                        "note": "synthetic"}],
         "registry": [], "network": [], "dns": [], "files": []}


def _probe_persistence(inp: dict, ctx: dict):
    from valkyrie.persistence_telemetry import _persistence_severity
    sev, labels, reason = _persistence_severity(inp["activity"], inp["command"])
    fires = severity_rank(sev) >= severity_rank(SEV_MEDIUM)
    return fires, sev, _confidence_for(sev), "", reason or "; ".join(labels), \
        {"processes": [],
         "registry": [{"activity": inp["activity"], "command": inp["command"],
                       "note": "synthetic artifact -- represents what a "
                               "15s-interval scan of the real location would read"}],
         "network": [], "dns": [], "files": []}


def _probe_cmdline(inp: dict, ctx: dict):
    from valkyrie.process_telemetry import classify_cmdline
    sev, labels, reason = classify_cmdline(inp["name"], inp["cmdline"])
    fires = severity_rank(sev) >= severity_rank(SEV_MEDIUM)
    return fires, sev, _confidence_for(sev), "", reason or "; ".join(labels), \
        {"processes": [{"name": inp["name"], "cmdline": inp["cmdline"],
                        "note": "synthetic"}],
         "registry": [], "network": [], "dns": [], "files": []}


def _probe_sysmon_eid8(inp: dict, ctx: dict):
    from valkyrie.etw.sysmon import classify_sysmon
    r = classify_sysmon(8, inp)
    if r is None:
        return False, SEV_INFO, 0.0, "", "EID 8 handler returned None", \
            {"processes": [], "registry": [], "network": [], "dns": [], "files": []}
    fires = severity_rank(r["severity"]) >= severity_rank(SEV_MEDIUM)
    return fires, r["severity"], _confidence_for(r["severity"]), \
        r.get("technique", ""), r.get("reason", ""), \
        {"processes": [{"source": inp.get("SourceImage", ""),
                        "target": inp.get("TargetImage", ""),
                        "note": "synthetic Sysmon EID 8 event"}],
         "registry": [], "network": [], "dns": [], "files": []}


def _probe_sysmon_eid10(inp: dict, ctx: dict):
    from valkyrie.etw.sysmon import classify_sysmon
    r = classify_sysmon(10, inp)
    if r is None:
        return False, SEV_INFO, 0.0, "", "EID 10 handler returned None " \
                                          "(target was not lsass.exe, or filtered)", \
            {"processes": [], "registry": [], "network": [], "dns": [], "files": []}
    fires = severity_rank(r["severity"]) >= severity_rank(SEV_MEDIUM)
    return fires, r["severity"], _confidence_for(r["severity"]), \
        r.get("technique", ""), r.get("reason", ""), \
        {"processes": [{"source": inp.get("SourceImage", ""),
                        "target": inp.get("TargetImage", ""),
                        "note": "synthetic Sysmon EID 10 event"}],
         "registry": [], "network": [], "dns": [], "files": []}


def _probe_dns(inp: dict, ctx: dict):
    scanner = ctx["scanner"]
    result = scanner.analyze(inp["domain"], inp["process"])
    fires = result.decision in ("block", "flag")
    sev = SEV_HIGH if result.decision == "block" else \
        (SEV_MEDIUM if result.decision == "flag" else SEV_INFO)
    return fires, sev, float(getattr(result, "confidence", _confidence_for(sev))), \
        "T1071.004", "; ".join(getattr(result, "reasons", []) or [result.decision]), \
        {"processes": [{"name": inp["process"]}], "registry": [], "network": [],
         "dns": [{"domain": inp["domain"], "decision": result.decision,
                  "category": getattr(result, "category", "")}],
         "files": []}


def _probe_dga(inp: dict, ctx: dict):
    from valkyrie.dga import classify_dga
    r = classify_dga(inp["domain"])
    sev = SEV_HIGH if r.is_dga else SEV_INFO
    return r.is_dga, sev, float(getattr(r, "score", _confidence_for(sev))), \
        "T1071.004", f"DGA score {getattr(r, 'score', 0):.3f}", \
        {"processes": [], "registry": [], "network": [],
         "dns": [{"domain": inp["domain"], "is_dga": r.is_dga}], "files": []}


def _probe_network(inp: dict, ctx: dict):
    from valkyrie.network_telemetry import classify_connection
    sev, labels, reason = classify_connection(inp["ip"], inp["port"], inp["blocked"])
    fires = severity_rank(sev) >= severity_rank(SEV_MEDIUM)
    return fires, sev, _confidence_for(sev), "T1071", reason or "; ".join(labels), \
        {"processes": [], "registry": [],
         "network": [{"ip": inp["ip"], "port": inp["port"],
                      "threat_intel_match": inp["blocked"]}],
         "dns": [], "files": []}


def _probe_dns_tunnel(inp: dict, ctx: dict):
    from valkyrie.dns_tunnel import SubdomainFloodDetector
    det = SubdomainFloodDetector()
    now = 1_000_000.0
    best_score, best_reason = 0.0, ""
    queries = []
    for i in range(inp["n_labels"]):
        label = f"{i:08x}{os.urandom(3).hex()}"
        domain = f"{label}.{inp['base']}"
        queries.append(domain)
        score, reason = det.record_and_score(domain, now=now)
        if score > best_score:
            best_score, best_reason = score, reason
    fires = best_score >= 0.75
    sev = SEV_HIGH if fires else (SEV_MEDIUM if best_score > 0 else SEV_INFO)
    return fires, sev, best_score, "T1071.004", best_reason or "no tunnelling signal", \
        {"processes": [], "registry": [], "network": [],
         "dns": [{"domain": d} for d in queries[:5]] + (
             [{"note": f"... and {len(queries) - 5} more"}] if len(queries) > 5 else []),
         "files": []}


def _probe_recon_burst(inp: dict, ctx: dict):
    """Discovery techniques, scored the ONLY way this project is willing to
    score them: as a contributor to the reconnaissance-burst sequence IOA.

    A lone discovery command deliberately raises NOTHING (process_telemetry.
    classify_discovery returns INFO severity, and the engine's severity gate
    drops it) - firing on a single `whoami` would be a guaranteed
    false-positive generator, which is the trade this codebase explicitly
    refuses. So this probe replays what a real recon sweep produces: THIS
    technique's command plus the co-occurring commands named in
    ``probe_input['co_occurring']``, through the REAL classify_discovery and
    the REAL SequenceEngine, and reports whether the named burst IOA fires.

    The honest reading of a DETECT here is therefore precise: "this technique
    is recognised as part of a recon burst," NOT "running this one command
    alone raises an alert." Every record's reason says exactly that.
    """
    from valkyrie.process_telemetry import classify_discovery
    from valkyrie.behavioral_sequences import SequenceEngine

    _, labels, _, technique = classify_discovery(inp["image"], inp["cmdline"])
    if not labels:
        return False, SEV_INFO, 0.0, "", \
            "classify_discovery did not label this command at all", \
            {"processes": [{"image": inp["image"], "cmdline": inp["cmdline"],
                            "note": "synthetic"}],
             "registry": [], "network": [], "dns": [], "files": []}

    # Replay the burst on ONE lineage: this technique first, then the
    # co-occurring recon commands an operator/script runs alongside it.
    eng = SequenceEngine()
    fired = None
    replayed = [{"image": inp["image"], "cmdline": inp["cmdline"],
                 "technique": technique, "note": "the technique under test"}]
    fired = eng.observe("cmd.exe", technique, labels, "exec",
                        ts=100.0, pid=4242, ppid=1) or fired
    for i, (img, cmd) in enumerate(inp.get("co_occurring", []), start=1):
        _, co_labels, _, co_tech = classify_discovery(img, cmd)
        replayed.append({"image": img, "cmdline": cmd, "technique": co_tech,
                         "note": "co-occurring recon command in the same burst"})
        fired = eng.observe("cmd.exe", co_tech, co_labels, "exec",
                            ts=100.0 + i, pid=4242, ppid=1) or fired

    if fired is None:
        return False, SEV_INFO, 0.0, technique, \
            "labeled as a discovery command, but the burst sequence did not complete", \
            {"processes": replayed, "registry": [], "network": [], "dns": [],
             "files": []}
    sev = fired["severity"]
    return True, sev, float(fired.get("score", _confidence_for(sev))), technique, \
        (f"{fired['name']}: {fired['reason']} "
         f"(NOTE: this technique ALONE raises nothing by design — it is "
         f"detected as a contributor to the burst, not standalone)"), \
        {"processes": replayed, "registry": [], "network": [], "dns": [],
         "files": [], "sequence": {"rule_id": fired["rule_id"],
                                   "span_seconds": fired["span_seconds"]}}


def _probe_cred_store_watch(inp: dict, ctx: dict):
    """Browser credential-store access - drives the REAL CredentialStoreWatch
    emit path with a synthetic open-handle observation (a non-browser process
    holding a known credential-store file open), which is exactly what its
    poll would see during a live T1555.003 execution."""
    from valkyrie.browser_cred_watch import CredentialStoreWatch

    emitted: list = []
    watch = CredentialStoreWatch(emit=emitted.append, cooldown=0.0)
    watch._paths_lower = {inp["path"].lower()}
    watch._scan = lambda: [{"pid": 4242, "name": inp["image"],
                            "path": inp["path"]}]
    watch.poll_once()
    if not emitted:
        return False, SEV_INFO, 0.0, "", "credential-store watch emitted nothing", \
            {"processes": [], "registry": [], "network": [], "dns": [], "files": []}
    ev = emitted[0]
    fires = severity_rank(ev.severity) >= severity_rank(SEV_MEDIUM)
    return fires, ev.severity, _confidence_for(ev.severity), \
        ev.fields.get("technique", ""), ev.reason, \
        {"processes": [{"name": inp["image"], "pid": 4242,
                        "note": "synthetic open-handle observation"}],
         "registry": [], "network": [], "dns": [],
         "files": [{"path": inp["path"],
                    "note": "browser credential store held open by a "
                            "non-browser process"}]}


def _probe_ransomware(inp: dict, ctx: dict):
    from valkyrie.ransomware_shield import shannon_entropy, _ENTROPY_ENCRYPTED
    data = os.urandom(4096)
    e = shannon_entropy(data)
    fires = e >= _ENTROPY_ENCRYPTED
    sev = SEV_CRITICAL if fires else SEV_INFO
    return fires, sev, min(1.0, e / 8.0), "T1486", \
        f"entropy {e:.2f} bits/byte (threshold {_ENTROPY_ENCRYPTED})", \
        {"processes": [], "registry": [], "network": [], "dns": [],
         "files": [{"note": "synthetic canary-directory write, "
                            f"{len(data)} bytes, entropy {e:.2f}"}]}


PROBES = {
    "powershell": _probe_powershell,
    "process_relationship": _probe_process_relationship,
    "ioa_rule": _probe_ioa_rule,
    "behavior_score": _probe_behavior_score,
    "persistence": _probe_persistence,
    "cmdline": _probe_cmdline,
    "sysmon_eid8": _probe_sysmon_eid8,
    "sysmon_eid10": _probe_sysmon_eid10,
    "dns": _probe_dns,
    "dga": _probe_dga,
    "network": _probe_network,
    "dns_tunnel": _probe_dns_tunnel,
    "ransomware": _probe_ransomware,
    "recon_burst": _probe_recon_burst,
    "cred_store_watch": _probe_cred_store_watch,
}


def run_technique(t: Technique, ctx: dict) -> dict:
    fn = PROBES.get(t.probe)
    if fn is None:
        raise ValueError(f"{t.id}: no probe registered for '{t.probe}'")

    error = None
    try:
        logic_fires, sev, confidence, tech_tag, reason, evidence = fn(t.probe_input, ctx)
    except Exception as exc:                       # noqa: BLE001
        logic_fires, sev, confidence, tech_tag, reason, evidence = \
            False, SEV_INFO, 0.0, "", "", {"processes": [], "registry": [],
                                           "network": [], "dns": [], "files": []}
        error = f"{type(exc).__name__}: {exc}"

    # HOST preconditions (Technique.requires) -- checked against the real
    # machine, never assumed. A technique whose classifier is correct but whose
    # delivering event source is absent on this host is NOT detected here, and
    # the reason is recorded rather than the credit being quietly taken. This
    # is what lets the three Sysmon-dependent techniques carry an honest
    # predicted_tier_b="DETECT": the label describes Valkyrie's code, and the
    # precondition describes what the host must supply for that code to ever
    # see the event.
    preconditions_met, precondition_reason = check_requirements(
        tuple(t.requires), ctx["sysmon_env"])

    # The scoring gate this whole harness exists to enforce: a miss is a miss,
    # and CONDITIONAL does not get to borrow DETECT's credit. Only a technique
    # BOTH judged reliably-delivered (predicted_tier_b == DETECT) AND whose
    # real code actually fires on the input counts as detected. A known
    # mismatch (the real rule fires, but for a DIFFERENT technique than the
    # one under test -- e.g. net-user-add firing on bare account-listing)
    # never counts either: an incident under the wrong label is not evidence
    # the system recognised the behaviour actually being tested.
    counted_as_detected = (t.predicted_tier_b == "DETECT" and logic_fires
                           and not error and not t.known_mismatch
                           and preconditions_met)

    is_user_rule = False   # no probe here ever exercises a user-authored rule;
                           # kept explicit so the field exists uniformly and the
                           # live (Tier B) scorer's exclusion logic has a
                           # same-shaped field to check on every record.

    return {
        "schema": "valkyrie-redteam-evaluation/1",
        "tier": TIER,
        "catalog_version": CATALOG_VERSION,
        "id": t.id,
        "technique_id": t.technique_id,
        "technique_name": t.technique_name,
        "test_number": t.art_test_ref,
        "tactic": t.tactic,
        "mitre": {"tactic": t.tactic, "technique_id": t.technique_id,
                  "technique_name": t.technique_name},
        "destructive": t.destructive,

        "attack_executed": None,      # N/A: Tier A replays inputs, runs no attack
        "attack_executed_note": "not applicable in Tier A (classifier-input "
                                "replay) -- no real attack ran; see Tier B "
                                "(run_live_evaluation.ps1) for a real answer",

        "classifier_logic_fires": logic_fires,
        "predicted_tier_b": t.predicted_tier_b,
        "counted_as_detected": counted_as_detected,
        "known_mismatch": t.known_mismatch or None,
        "host_requirements": list(t.requires),
        "host_requirements_met": preconditions_met,
        "host_requirements_note": precondition_reason or (
            "all host preconditions verified on this machine at run time"
            if t.requires else "none required"),
        "detection_category": ("blocklist" if t.id == "c2-dns-tracker-domain"
                               else ("behavioral" if counted_as_detected else "none")),
        "is_user_defined_rule": is_user_rule,

        "detection_latency_seconds": None,
        "theoretical_latency_bound_seconds": (
            2.0 if t.delivery == DELIVERY_PROCESS_POLL_RACY else
            15.0 if t.delivery == "artifact_poll_15s" else
            0.0 if t.delivery in ("realtime_etw", "inline_request_path") else None),
        "latency_note": "not measurable in Tier A (no live clock between "
                        "attack and detection); theoretical_latency_bound_"
                        "seconds is the poll interval that path depends on, "
                        "not an observed value",

        "severity_assigned": sev,
        "confidence_score": round(confidence, 3),
        "confidence_note": "from the classifier's own float score where one "
                           "exists (behavior_score, dga, scanner); otherwise "
                           "a documented severity->confidence mapping "
                           "(see _SEV_CONFIDENCE), not a measured probability",

        "false_positives_generated": None,
        "false_positives_note": "not measurable in Tier A (one isolated "
                                "synthetic input per test, not a system "
                                "under load); see tests/test_benign_corpus.py "
                                "(699 real domains, 0 blocked) and "
                                "tests/efficacy/harness.py (FP-rate gate) "
                                "for this project's real aggregate FP evidence",

        "reason": reason,
        "evidence": evidence,
        "delivery_mechanism": t.delivery,
        "detector_path": t.detector_path,
        "source_confidence": t.source_confidence,
        "error": error,
        "notes": t.notes,
    }


def main() -> int:
    ctx = _build_ctx()
    techniques = all_in_scope()
    records = [run_technique(t, ctx) for t in techniques]

    out_dir = Path(__file__).resolve().parent / "results"
    out_dir.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = out_dir / f"{ts}__tierA.json"
    # The host snapshot travels WITH the score. A result file that says
    # "39/40" without saying which event sources the machine had is not
    # reproducible and not auditable -- the same catalog legitimately scores
    # differently on a host without Sysmon, and the file must show that.
    env = ctx["sysmon_env"]
    out_path.write_text(json.dumps({
        "tier": TIER, "catalog_version": CATALOG_VERSION,
        "generated_at": ts,
        "host_environment": {"sysmon": env.as_dict()},
        "records": records,
    }, indent=2), encoding="utf-8")

    gated = [r for r in records if r["host_requirements"]]
    unmet = [r for r in gated if not r["host_requirements_met"]]

    print(f"Tier A replay: {len(records)} techniques run against real "
          f"Valkyrie code.")
    print(f"Host: Sysmon present={env.present} collection_live="
          f"{env.collection_live} configured_eids={list(env.configured_eids)}")
    print(f"Host-gated techniques: {len(gated)} "
          f"({len(gated) - len(unmet)} preconditions met, {len(unmet)} not)")
    for r in unmet:
        print(f"  NOT CREDITED  {r['id']}: {r['host_requirements_note']}")
    print(f"Results written to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
