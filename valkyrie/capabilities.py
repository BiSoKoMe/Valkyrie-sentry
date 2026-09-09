"""Versioned product boundaries for the local Valkyrie suite.

This is a capability contract, not a runtime health report. Runtime status stays
on each component endpoint so an unavailable sensor cannot be mistaken for an
absent product capability.
"""
from __future__ import annotations

from copy import deepcopy


_CONTRACT = {
    "schema_version": 1,
    "deployment": {
        "platform": "windows",
        "management": "single-endpoint-local",
        "data_boundary": "on-device",
    },
    "shared_foundation": {
        "evidence_store": "local-sqlite",
        "event_delivery": "in-process-eventbus",
        "response_authority": "valkyrie-audited-response-manager",
    },
    "components": [
        {
            "id": "valkyrie",
            "name": "Valkyrie",
            "role": "endpoint-detection-response",
            "owns": [
                "endpoint-and-network-observation",
                "deterministic-detection",
                "response-policy-and-authority",
                "bounded-host-enforcement",
            ],
            "independent_enforcement": True,
            "implementation_status": "user-mode-beta",
            "evidence": [
                "tests/test_edr.py",
                "tests/test_response_contract.py",
                "tests/test_process_response_identity.py",
            ],
        },
        {
            "id": "nyx",
            "name": "NYX",
            "role": "outbound-privacy-defense",
            "owns": [
                "outbound-data-shape-inspection",
                "tracker-correlation",
                "privacy-exposure-inference",
                "policy-gated-request-rewrite",
            ],
            "independent_host_enforcement": False,
            "implementation_status": "experimental-opt-in",
            "evidence": [
                "tests/test_nyx_rewrite_contract.py",
                "tests/test_nyx_reliability.py",
                "tests/test_aegis_facade.py",
            ],
        },
        {
            "id": "aegis",
            "name": "Aegis",
            "role": "local-investigation-correlation",
            "owns": [
                "durable-case-view",
                "evidence-correlation",
                "incident-timeline",
                "investigation-workflow",
            ],
            "independent_enforcement": False,
            "implementation_status": "foundation",
            "evidence": [
                "tests/test_aegis_facade.py",
                "tests/test_eventbus.py",
                "tests/test_edr.py",
            ],
        },
    ],
    "excluded_from_release_claims": [
        "unsigned-kernel-driver",
        "fleet-cloud-management",
        "cross-endpoint-correlation",
    ],
    "reviewed_at": "2026-09-07",
}


def component_contract() -> dict:
    """Return a caller-owned copy of the product capability contract."""
    return deepcopy(_CONTRACT)
