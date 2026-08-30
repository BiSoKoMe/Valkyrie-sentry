"""Run the REAL Tier A catalog through Detection Architecture v2, stage by
stage -- not through a committed synthetic corpus (see generalization.py),
through the actual 90-technique catalog replay_harness.py already drives
against Valkyrie's real classifiers today.

## What this answers

generalization.py proves the v2 MECHANISM against 30 scenarios written to
exercise it. This module asks a different, harder question: when the real
per-technique inputs replay_harness.py already builds from catalog.py are
turned into the canonical events v2 actually consumes, how far does the real
pipeline get -- telemetry, normalization, behavior recognition, hypothesis,
decision -- using the SAME stage vocabulary as pipeline_trace.py, so one
aggregate number can never hide which stage broke (per the "next plan"
essay's central complaint about Atomic-by-Atomic scoring).

## Scope, honestly

Only techniques whose probe type maps cleanly onto one canonical event are
covered here: ioa_rule, process_relationship, cmdline, persistence,
behavior_score, network, dns. That is the majority of the catalog (roughly
70%), but NOT recon_burst (a multi-event sequence IOA), sysmon_eid8/eid10,
powershell, dga, dns_tunnel, cred_store_watch, or ransomware -- those need
either multi-event sequencing or a different canonical shape this module
does not yet build. Uncovered techniques are reported as `probe_unsupported`,
never silently dropped from the denominator.

## The one thing this is NOT allowed to do: quietly inflate v2

Each technique's real classifier is called exactly once here, with the exact
`probe_input` catalog.py already declares, and its OWN returned labels are
carried into the canonical event verbatim -- never translated, widened, or
invented to make detection_v2's vocabulary line up. If v2's BehaviorEngine
does not recognise a label the real classifier returned, that is reported as
a real vocabulary gap, not patched over.

## Why "hypothesis formed" is expected to be rare here, and that is not a bug

Every technique here is replayed as ONE isolated canonical event with no
causal chain and no co-occurring evidence -- replay_harness.py's own
documented limitation ("one isolated synthetic input, not a running system").
detection_v2's hypothesis specs require >=2 supporting facts before an attack
hypothesis can even be considered (see detection_v2._HYPOTHESES). A single
technique run in isolation is therefore expected to reach `behavior=YES` far
more often than `hypothesis`/`decision=YES` -- that is v2 correctly refusing
to convict on one weak signal, exactly the property the essay argues for, not
a regression to explain away.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from catalog import Technique, all_in_scope                     # noqa: E402
from valkyrie.edr.detection_v2 import DetectionArchitectureV2    # noqa: E402
from valkyrie.telemetry import TelemetryEvent, severity_rank     # noqa: E402

from .pipeline_trace import PipelineTrace, Stage, quality_matrix  # noqa: E402

SUPPORTED_PROBES = frozenset({
    "ioa_rule", "process_relationship", "cmdline", "persistence",
    "behavior_score", "network", "dns",
})


@dataclass(frozen=True)
class TechniqueTrace:
    technique_id: str
    catalog_id: str
    probe: str
    legacy_fires: bool
    real_labels: tuple[str, ...]
    v2_facts: tuple[str, ...]
    v2_selected: str
    v2_alerts: bool
    trace: PipelineTrace


def _event(category: str, activity: str, pid: int, actor: str,
          labels: tuple, fields: dict, target: Optional[dict] = None) -> TelemetryEvent:
    return TelemetryEvent(
        category=category, activity=activity, ts=float(pid),
        actor_pid=pid, actor_name=actor, source="tier_a_replay",
        target=target or {}, labels=list(labels),
        fields={**fields, "event_id": f"tiera-{pid}", "create_time": float(pid)},
    )


def _build(tech: Technique, pid: int):
    """Return (TelemetryEvent, real_labels, legacy_fires) using the SAME real
    classifier call replay_harness.py's matching probe makes -- called fresh
    here (not reusing replay_harness's return value) because most probes
    don't surface their labels in the tuple they hand back to that harness."""
    inp = tech.probe_input

    if tech.probe == "ioa_rule":
        from valkyrie.behavioral_rules import classify_behavior
        result = classify_behavior(inp["image"], inp["parent"], inp["cmdline"],
                                   inp.get("path", ""))
        labels = tuple(result["labels"]) if result else ()
        fires = bool(result) and severity_rank(result["severity"]) >= severity_rank("medium")
        return _event("process", "exec", pid, inp["image"], labels,
                      {"parent": inp["parent"], "cmdline": inp["cmdline"]}), labels, fires

    if tech.probe == "process_relationship":
        from valkyrie.process_telemetry import classify_process
        sev, labels, _reason = classify_process(inp["name"], inp["path"], inp["parent"])
        fires = severity_rank(sev) >= severity_rank("medium")
        return _event("process", "exec", pid, inp["name"], tuple(labels),
                      {"parent": inp["parent"], "path": inp["path"]}), tuple(labels), fires

    if tech.probe == "cmdline":
        from valkyrie.process_telemetry import classify_cmdline
        sev, labels, _reason = classify_cmdline(inp["name"], inp["cmdline"])
        fires = severity_rank(sev) >= severity_rank("medium")
        return _event("process", "exec", pid, inp["name"], tuple(labels),
                      {"cmdline": inp["cmdline"]}), tuple(labels), fires

    if tech.probe == "behavior_score":
        from valkyrie.behavior_score import score_process
        r = score_process(inp["image"], inp["parent"], inp["cmdline"], inp.get("path", ""))
        labels = tuple(s.name for s in r.signals)
        return _event("process", "exec", pid, inp["image"], labels,
                      {"parent": inp["parent"], "cmdline": inp["cmdline"]}), labels, r.fired()

    if tech.probe == "persistence":
        from valkyrie.persistence_telemetry import _persistence_severity
        sev, labels, _reason = _persistence_severity(inp["activity"], inp["command"])
        fires = severity_rank(sev) >= severity_rank("medium")
        return _event("persistence", inp["activity"], pid, "persistence-actor.exe",
                      tuple(labels), {"command": inp["command"]},
                      target={"location": inp["command"][:80]}), tuple(labels), fires

    if tech.probe == "network":
        from valkyrie.network_telemetry import classify_connection
        sev, labels, _reason = classify_connection(inp["ip"], inp["port"], inp["blocked"])
        fires = severity_rank(sev) >= severity_rank("medium")
        return _event("network", "connect", pid, "network-actor.exe", tuple(labels),
                      {"port": inp["port"]}, target={"ip": inp["ip"]}), tuple(labels), fires

    if tech.probe == "dns":
        from valkyrie.site_scanner import SiteScanner
        result = SiteScanner(store=None).analyze(inp["domain"], inp["process"])
        fires = result.decision in ("block", "flag")
        # SiteScanner reasons about a decision/category, not detection_v2's
        # label vocabulary -- there is no comparable label to carry through
        # here, and inventing one would be exactly the kind of translation
        # this module refuses to do. Left empty on purpose.
        return _event("dns", "resolve", pid, inp["process"], (),
                      {"decision": result.decision},
                      target={"domain": inp["domain"]}), (), fires

    raise ValueError(f"unsupported probe: {tech.probe}")


def trace_technique(tech: Technique, pid: int) -> TechniqueTrace:
    event, labels, legacy_fires = _build(tech, pid)
    arch = DetectionArchitectureV2()
    result = arch.observe(event)

    facts = tuple(fact.behavior for fact in result.facts)
    trace = PipelineTrace(
        test_id=tech.id, cohort="tier_a_catalog",
        execution=Stage.NOT_APPLICABLE,   # replay_harness: no live process runs
        telemetry=Stage.YES,              # the real classifier's own input shape
        normalization=Stage.YES,          # EventNormalizer always normalizes
        causal_link=Stage.NOT_APPLICABLE, # single isolated event, no chain built
        behavior=Stage.YES if facts else Stage.NO,
        hypothesis=Stage.YES if result.hypothesis.confidence > 0 else Stage.NO,
        decision=Stage.YES if result.hypothesis.alerts else Stage.NO,
        prevention=Stage.NOT_APPLICABLE,  # shadow mode; no enforcement authority
        benign_control=Stage.NOT_APPLICABLE,  # catalog is malicious-only
        evidence_ids=tuple(f"{tech.id}:{b}" for b in facts),
    )
    return TechniqueTrace(
        technique_id=tech.technique_id, catalog_id=tech.id, probe=tech.probe,
        legacy_fires=legacy_fires, real_labels=labels, v2_facts=facts,
        v2_selected=result.hypothesis.selected, v2_alerts=result.hypothesis.alerts,
        trace=trace,
    )


def run() -> dict:
    all_techniques = all_in_scope()
    supported = [t for t in all_techniques if t.probe in SUPPORTED_PROBES]
    unsupported = [t for t in all_techniques if t.probe not in SUPPORTED_PROBES]

    traces = [trace_technique(tech, 10_000 + i) for i, tech in enumerate(supported)]
    matrix = quality_matrix(t.trace for t in traces)

    behavior_seen = sum(t.trace.behavior == Stage.YES for t in traces)
    legacy_fired = sum(t.legacy_fires for t in traces)
    vocab_gap = [t.catalog_id for t in traces if t.legacy_fires and not t.v2_facts]

    return {
        "evidence_class": "safe replay against the real catalog (Tier A), "
                          "not a live attack and not a committed synthetic corpus",
        "independent": False,
        "total_catalog": len(all_techniques),
        "covered": len(supported),
        "probe_unsupported": [
            {"catalog_id": t.id, "technique_id": t.technique_id, "probe": t.probe}
            for t in unsupported
        ],
        "legacy_classifier_fired": legacy_fired,
        "v2_behavior_fact_extracted": behavior_seen,
        "v2_hypothesis_alerted": sum(t.v2_alerts for t in traces),
        "vocabulary_gap": {
            "count": len(vocab_gap),
            "meaning": "legacy classifier fired with real labels, but none of "
                      "those labels are in detection_v2.BehaviorEngine's "
                      "recognised vocabulary, so no evidence fact was extracted",
            "catalog_ids": vocab_gap,
        },
        "quality_matrix": matrix,
        "traces": [
            {**t.trace.to_dict(), "technique_id": t.technique_id,
             "catalog_id": t.catalog_id, "probe": t.probe,
             "legacy_fires": t.legacy_fires, "real_labels": list(t.real_labels),
             "v2_facts": list(t.v2_facts), "v2_selected": t.v2_selected,
             "v2_alerts": t.v2_alerts}
            for t in traces
        ],
        "limitations": [
            "Covers ioa_rule/process_relationship/cmdline/persistence/"
            "behavior_score/network/dns probes only; recon_burst (multi-event "
            "sequence), sysmon_eid8/eid10, powershell, dga, dns_tunnel, "
            "cred_store_watch, and ransomware are listed under "
            "probe_unsupported, not silently excluded from the denominator.",
            "Each technique is one isolated canonical event with no causal "
            "chain -- detection_v2's hypothesis specs require >=2 supporting "
            "facts, so hypothesis/decision=YES is expected to be rare here by "
            "design, not evidence the mechanism is broken (see module "
            "docstring).",
            "This is not a live attack (no process runs, no registry key "
            "changes, no clock between attack and detection) and not the "
            "committed synthetic corpus in generalization.py -- it is the "
            "real catalog's real probe inputs through the real v2 pipeline.",
        ],
    }


if __name__ == "__main__":
    import json
    report = run()
    print(json.dumps({k: v for k, v in report.items() if k != "traces"},
                     indent=2, default=str))
