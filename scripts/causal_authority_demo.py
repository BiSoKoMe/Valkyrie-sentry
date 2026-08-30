#!/usr/bin/env python3
"""Safe, synthetic demonstration of Valkyrie's causal-authority reflex."""
from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.causal_authority import CausalAuthorityEngine, EgressRequest


def request(interaction_id: str) -> EgressRequest:
    return EgressRequest(
        request_id=str(uuid.uuid4()),
        interaction_id=interaction_id,
        source_origin="https://shop.example",
        destination_origin="https://payments.example",
        tab_id=7,
        frame_id=0,
        action="form_submit",
        data_labels=frozenset({"email", "payment"}),
    )


def main() -> int:
    engine = CausalAuthorityEngine()

    trusted_interaction = str(uuid.uuid4())
    engine.issue(
        interaction_id=trusted_interaction,
        source_origin="https://shop.example",
        destination_origin="https://payments.example",
        tab_id=7,
        frame_id=0,
        action="form_submit",
        data_labels=("email", "payment"),
    )
    trusted = engine.verify_and_consume(request(trusted_interaction))
    background = engine.verify_and_consume(request(str(uuid.uuid4())))

    print(json.dumps({
        "trusted_submit": trusted.to_dict(),
        "background_submit": background.to_dict(),
        "retained_data": {
            "source_origin": "https://shop.example",
            "destination_origin": "https://payments.example",
            "labels": ["email", "payment"],
            "raw_values": "transiently classified at capture point; not retained",
        },
        "refused_claims": [
            "no browser request was blocked",
            "no end-to-end latency was measured",
            "no Windows PID attribution was inferred",
        ],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
