#!/usr/bin/env python3
"""Run Valkyrie's fixed causal-authority evidence corpus."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.authority_experiment import (DEFAULT_AUTHORIZED,
                                            DEFAULT_UNAUTHORIZED, MAX_P99_MS,
                                            run_experiment, write_evidence)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the fixed synthetic causal-authority experiment.")
    parser.add_argument("--authorized", type=int, default=DEFAULT_AUTHORIZED)
    parser.add_argument("--unauthorized", type=int, default=DEFAULT_UNAUTHORIZED)
    parser.add_argument("--max-p99-ms", type=float, default=MAX_P99_MS)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    evidence = run_experiment(
        authorized=args.authorized,
        unauthorized=args.unauthorized,
        max_p99_ms=args.max_p99_ms,
    )
    if args.output:
        write_evidence(evidence, json_path=args.output, report_path=args.report)
    elif args.report:
        parser.error("--report requires --output")
    print(json.dumps({
        "passed": evidence["passed"],
        "corpus": evidence["corpus"],
        "metrics": evidence["metrics"],
        "criteria": evidence["criteria"],
        "refused_claims": evidence["refused_claims"],
    }, indent=2, sort_keys=True))
    return 0 if evidence["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
