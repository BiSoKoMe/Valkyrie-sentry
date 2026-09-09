#!/usr/bin/env python3
"""Run the consequence ablation's arms against REAL captured structures.

Evidence class: real-structure selectivity measurement.
Independent: no.
Input: `tools/capture_causal_corpus.py` output (read-only capture of this host).

`docs/CONSEQUENCE_ABLATION.md` measured three decision rules on an AUTHORED
corpus and named that authorship as the largest threat to the result. This
removes that threat for the half it can: the structures here were produced by a
real Windows desktop, not written by hand.

## What this can and cannot measure

A real capture contains no NYX observations, because TLS interception is opt-in
and off. That is not worked around by inventing leaks - injecting synthetic
privacy artifacts into real structures would quietly restore the exact
authorship problem this file exists to remove.

So two of the three arms are simply not measurable here, and are reported as
such rather than as zeros:

  * privacy-only  - unmeasurable on this capture (no NYX data present).
  * combined      - unmeasurable directly, for the same reason.
  * endpoint-only - FULLY measurable, and it is the arm whose false-positive
                    behaviour the authored corpus was least able to model,
                    because "how often does a real machine make a rare
                    descendant egress" was previously a guess.

For the combined rule, what IS rigorously measurable without NYX data is a
WORST-CASE BOUND. For each real structure, assume the most pessimistic privacy
input possible - that this lineage did carry exactly one unambiguous personal
data disclosure - and then ask whether every OTHER guard would have passed. The
count of structures that survive is an upper bound on the combined rule's
false-positive rate on this machine. It cannot fire more often than that, no
matter what NYX would have observed.

## Held-out split

The baseline learns from a fraction of the captured structures and is evaluated
on the remainder, so no structure is scored against a baseline that already
memorised it. A rule that only looks selective because the baseline saw the
exact structure is not selective.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from valkyrie.edr.causal_detect import (           # noqa: E402
    MIN_OBSERVATIONS, MIN_SESSIONS, CausalBaseline,
)
from valkyrie.edr.consequence import (             # noqa: E402
    _EGRESS_KINDS, _INTERACTIVE_OWNERS, score_privacy_consequence,
)
from consequence_ablation import arm_endpoint_only     # noqa: E402


def load(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not payload.get("subgraphs"):
        raise SystemExit(f"{path} contains no subgraphs")
    return payload


def split(subs: list[dict], holdout: float, seed: int) -> tuple[list, list]:
    rng = random.Random(seed)
    shuffled = list(subs)
    rng.shuffle(shuffled)
    cut = int(len(shuffled) * (1.0 - holdout))
    return shuffled[:cut], shuffled[cut:]


def learn(train: list[dict]) -> CausalBaseline:
    """Mature the baseline on the training split only.

    Replay is how a real host accumulates observations of the same recurring
    shapes over days; the gates (300 structures / 3 sessions) are the real
    ones, not lowered for convenience.
    """
    baseline = CausalBaseline()
    if not train:
        return baseline
    per_session = -(-MIN_OBSERVATIONS // MIN_SESSIONS) + 1
    for _ in range(MIN_SESSIONS):
        baseline.start_session()
        for i in range(per_session):
            baseline.observe_subgraph(train[i % len(train)])
    return baseline


def worst_case_combined(sub: dict, baseline: CausalBaseline) -> tuple[bool, str]:
    """Would the combined rule fire on this real structure IF this lineage had
    carried one unambiguous personal-data disclosure?

    Every guard other than the privacy artifact itself is evaluated by the real
    shipping function: a synthetic, metadata-only NYX artifact is attached to
    the owner and `score_privacy_consequence` is called unmodified. The
    synthetic artifact is the assumption being bounded, and it is the most
    generous one available to the rule - a single, well-formed, unambiguous
    disclosure. Anything the rule still refuses, it would refuse in reality.
    """
    owner = str((sub.get("cgo") or {}).get("name") or "")
    probe = dict(sub)
    probe["artifacts"] = list(sub.get("artifacts") or []) + [{
        "kind": "nyx_leak", "process": owner,
        "data": {"category": "identifier", "destination_host": "assumed.example"},
    }]
    finding = score_privacy_consequence(probe, baseline)
    return finding.fires, (finding.suppressed_by or "fired")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", default="redteam/evaluation/real_causal_corpus.json")
    ap.add_argument("--holdout", type=float, default=0.3)
    ap.add_argument("--seed", type=int, default=1729)
    args = ap.parse_args(argv)

    payload = load(Path(args.corpus))
    subs = payload["subgraphs"]
    cap = payload.get("capture", {})
    train, test = split(subs, args.holdout, args.seed)
    baseline = learn(train)

    print("\n=== consequence arms vs REAL captured structures ===")
    print("EVIDENCE CLASS: real-structure selectivity. NOT a detection rate.")
    print(f"\ncapture: {cap.get('host_os','?')}, {cap.get('seconds','?')}s, "
          f"{cap.get('seeded_processes','?')} processes seeded, "
          f"{cap.get('network_artifacts','?')} network artifacts")
    print(f"structures: {len(subs)} total -> {len(train)} learn / {len(test)} held-out")
    print(f"baseline: {baseline.observations} observations across "
          f"{baseline.sessions} sessions, mature={baseline.mature} "
          f"(gates {MIN_OBSERVATIONS}/{MIN_SESSIONS})")

    if not baseline.mature:
        print("\nbaseline did not mature - every arm is gated off and the run is void")
        return 1

    # -- what is present at all ---------------------------------------------
    leaks = sum(1 for s in test for a in (s.get("artifacts") or [])
                if str(a.get("kind") or "").lower() == "nyx_leak")
    interactive = sum(1 for s in test
                      if str((s.get("cgo") or {}).get("name") or "").lower()
                      in _INTERACTIVE_OWNERS)
    with_egress = sum(1 for s in test for a in (s.get("artifacts") or [])
                      if str(a.get("kind") or "").lower() in _EGRESS_KINDS)
    print(f"\nheld-out composition: {interactive} interactive-owner lineages, "
          f"{with_egress} egress artifacts, {leaks} NYX observations")

    # -- endpoint-only: fully measurable ------------------------------------
    ep_fires = [s for s in test if arm_endpoint_only(s, baseline)]
    print(f"\nendpoint-only  fired on {len(ep_fires)}/{len(test)} real structures "
          f"({100.0*len(ep_fires)/max(1,len(test)):.1f}%)")
    for s in ep_fires[:5]:
        print(f"    - owner {(s.get('cgo') or {}).get('name','?')}")

    # -- privacy-only / combined: honestly unmeasurable ---------------------
    print("\nprivacy-only   NOT MEASURABLE on this capture (no NYX data present)")
    print("combined       NOT MEASURABLE directly, same reason")

    # -- combined: worst-case upper bound -----------------------------------
    fired, reasons = 0, {}
    for s in test:
        hit, why = worst_case_combined(s, baseline)
        if hit:
            fired += 1
        reasons[why] = reasons.get(why, 0) + 1
    pct = 100.0 * fired / max(1, len(test))
    print(f"\ncombined WORST-CASE bound: assuming EVERY held-out lineage carried")
    print(f"an unambiguous disclosure, the rule could fire on at most "
          f"{fired}/{len(test)} ({pct:.1f}%)")
    print("\n  refusal reason on real structures (worst-case probe):")
    for why, n in sorted(reasons.items(), key=lambda kv: -kv[1]):
        print(f"    {n:>4}x  {why}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
