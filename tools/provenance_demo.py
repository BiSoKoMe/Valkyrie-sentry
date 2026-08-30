#!/usr/bin/env python3
"""Run Valkyrie's safe, synthetic privacy/security provenance demonstration.

This tool creates an in-memory EDR session only.  It never reads browser
traffic, starts a proxy, changes DNS, alters firewall rules, or loads a driver.
Its purpose is to make the experiment's decision path and guardrails easy to
show in a short screen recording.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# A directly executed repository tool has ``tools/`` as sys.path[0], not the
# repository root. Keep its import behavior identical to the other tools.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.decision import Profile, Signal, decide
from valkyrie.edr.causal_detect import MIN_OBSERVATIONS, MIN_SESSIONS, CausalBaseline
from valkyrie.edr.consequence import score_privacy_consequence
from valkyrie.edr.engine import EdrEngine
from valkyrie.store import Store
from valkyrie.telemetry import CAT_DNS, CAT_PRIVACY, CAT_PROCESS, TelemetryEvent


def _mature_baseline() -> CausalBaseline:
    """Create the minimum mature baseline required by the guarded experiment."""
    return CausalBaseline(observations=MIN_OBSERVATIONS, sessions=MIN_SESSIONS)


def _content_bearing_subgraph() -> dict:
    """A deliberately invalid input used only to show a privacy-boundary refusal."""
    owner = {"key": "7000/1", "pid": 7000, "name": "chrome.exe", "parent_key": ""}
    child = {"key": "7001/1", "pid": 7001, "name": "helper.exe", "parent_key": "7000/1"}
    return {
        "found": True,
        "cgo": owner,
        "chain": [owner],
        "tree": [child],
        "truncated": False,
        "evicted": 0,
        "inferred_nodes": 0,
        "artifacts": [
            {
                "kind": "nyx_leak",
                "process": "chrome.exe",
                # This value is not surfaced or persisted. It exists solely to
                # prove that the scorer refuses content-bearing metadata.
                "data": {
                    "privacy_category": "identifier",
                    "destination_host": "tracker.example",
                    "body": "synthetic-content-is-refused",
                },
            },
            {"kind": "dns", "process": "helper.exe", "data": {"subject": "rare.example"}},
        ],
    }


def run_demo() -> dict:
    """Exercise the actual local EDR path and return presentation-safe evidence."""
    store = Store(ram_uri="file:valkyrie-provenance-demo?mode=memory&cache=shared")
    store.start()
    engine = EdrEngine(store)
    engine.start()
    try:
        engine._causal_baseline = _mature_baseline()
        events = [
            TelemetryEvent(
                category=CAT_PROCESS,
                activity="exec",
                ts=1.0,
                actor_pid=7000,
                actor_name="chrome.exe",
                source="process_collector",
            ),
            TelemetryEvent(
                category=CAT_PROCESS,
                activity="exec",
                ts=2.0,
                actor_pid=7001,
                actor_name="helper.exe",
                source="process_collector",
                fields={"ppid": 7000},
            ),
            TelemetryEvent(
                category=CAT_DNS,
                activity="query",
                ts=3.0,
                actor_pid=7001,
                actor_name="helper.exe",
                target={"domain": "rare.example"},
                source="provenance_demo",
            ),
            TelemetryEvent(
                category=CAT_PRIVACY,
                activity="outbound_observation",
                ts=4.0,
                actor_pid=7000,
                actor_name="chrome.exe",
                target={"domain": "tracker.example"},
                severity="low",
                source="nyx.tls",
                labels=["nyx_leak"],
                reason="Nyx observed a privacy category crossing a boundary",
                fields={
                    "artifact_kind": "nyx_leak",
                    "event_id": "provenance-demo-nyx-1",
                    "privacy_category": "identifier",
                    "destination_host": "tracker.example",
                    "first_party_origin": "publisher.example",
                    # The engine deliberately excludes this from graph and
                    # incident evidence. It verifies retention boundaries.
                    "masked_sample": "id***42",
                    "body": "must-not-retain",
                },
            ),
        ]
        for event in events:
            engine.ingest_telemetry(event)

        graph = engine.causality_subgraph(7000)
        incidents = [
            incident for incident in engine.list_incidents()
            if incident.get("category") == "privacy_consequence"
        ]
        if len(incidents) != 1:
            raise RuntimeError("The synthetic consequence scenario did not yield one incident")

        incident = incidents[0]
        detail = engine.get_incident(incident["id"])
        policy = decide(
            Signal(
                category="privacy_consequence",
                severity="medium",
                labels=("metadata_leakage",),
                entity="tracker.example",
            ),
            Profile.STANDARD,
        )
        refusal = score_privacy_consequence(_content_bearing_subgraph(), _mature_baseline())
        serialized_graph = repr(graph)
        if "id***42" in serialized_graph or "must-not-retain" in serialized_graph:
            raise RuntimeError("The demo's privacy-retention boundary failed")

        return {
            "mode": "synthetic, in-memory, local-only",
            "causal_chain": ["chrome.exe", "helper.exe", "DNS rare.example"],
            "observed": {
                "privacy_artifact": "identifier category to tracker.example",
                "raw_content_retained": False,
                "provenance_complete": graph.get("inferred_nodes", 0) == 0
                and not graph.get("truncated")
                and not graph.get("evicted"),
            },
            "decision": {
                "incident_category": incident["category"],
                "reason": incident["explanation"],
                "standard_profile_action": policy.action.value,
                "playbook_execution": "not executed; no DNS or network setting changed",
            },
            "refusal": {
                "condition": "content-bearing privacy metadata",
                "result": refusal.suppressed_by,
                "content_printed_or_persisted": False,
            },
            "claims_not_made": [
                "No live browser traffic was observed.",
                "No live DNS query was blocked or redirected.",
                "The original privacy request was observed, not prevented.",
                "This does not prove browser-to-Windows PID attribution, kernel enforcement, or real-world efficacy.",
            ],
            "evidence": {
                "artifact_count": len(graph.get("artifacts", [])),
                "timeline_kinds": [entry.get("kind") for entry in detail.get("timeline", [])],
            },
        }
    finally:
        engine.stop()
        store.stop()


def _print_walkthrough(result: dict) -> None:
    print("VALKYRIE - SAFE PROVENANCE DEMO")
    print("Scope: synthetic events in an in-memory local session. No host controls change.\n")
    print("1. CAUSAL CHAIN")
    print("   " + " -> ".join(result["causal_chain"]))
    print("\n2. WHAT VALKYRIE OBSERVED")
    print("   Privacy evidence: " + result["observed"]["privacy_artifact"])
    print("   Provenance complete: " + str(result["observed"]["provenance_complete"]))
    print("   Raw content retained: " + str(result["observed"]["raw_content_retained"]))
    print("\n3. WHY IT CHOSE A RESPONSE")
    print("   Incident: " + result["decision"]["incident_category"])
    print("   Standard policy: " + result["decision"]["standard_profile_action"])
    print("   " + result["decision"]["reason"])
    print("   Enforcement: " + result["decision"]["playbook_execution"])
    print("\n4. WHAT IT REFUSED")
    print("   Content-bearing metadata: " + result["refusal"]["result"])
    print("\n5. WHAT THIS DOES NOT CLAIM")
    for claim in result["claims_not_made"]:
        print("   - " + claim)
    print("\nEvidence: " + ", ".join(result["evidence"]["timeline_kinds"]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print presentation-safe evidence as JSON")
    args = parser.parse_args()
    result = run_demo()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        _print_walkthrough(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
