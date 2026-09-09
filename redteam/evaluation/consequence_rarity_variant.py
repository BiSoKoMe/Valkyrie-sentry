#!/usr/bin/env python3
"""Does making rarity destination-aware close the blind spot, and what does it cost?

Evidence class: mechanism comparison on one authored and one real corpus.
Independent: no.

`docs/CONSEQUENCE_ABLATION.md` Finding 2 measured a blind spot: because
`CausalBaseline.artifact_rarity()` is keyed on `(process_name, artifact_kind)`
and never examines the destination, an egress to a never-before-seen host
scores rarity 0.0 whenever it rides a routinely-seen process name. The report
named the obvious repair - key rarity on the destination too - and explicitly
declined to apply it, on the grounds that it would trade against the project's
false-positive directive.

That was reasoning, not measurement. This file measures it.

NOTHING SHIPPING IS MODIFIED. The variant is implemented here, in the
experiment, precisely so the tradeoff can be quantified before anyone changes
a detector that runs on real machines.

Two questions, two corpora:

  1. On the authored corpus: does destination-aware rarity actually close the
     `cross_layer_common_process_name` blind spot?
  2. On the real 150s capture of this desktop: how many additional structures
     would it fire on? That is the cost, in the only units that matter.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from valkyrie.edr.causal_detect import (           # noqa: E402
    MIN_OBSERVATIONS, MIN_SESSIONS, CausalBaseline,
)
from valkyrie.edr.consequence import _EGRESS_KINDS  # noqa: E402
from consequence_ablation import (                  # noqa: E402
    arm_endpoint_only, build_corpus, learn_baseline,
)

RARITY_FIRE = 0.90


class DestinationAwareBaseline(CausalBaseline):
    """CausalBaseline plus a `(process, kind, destination)` counter.

    Deliberately additive: every inherited behaviour is untouched, so the two
    arms differ in exactly one thing - whether the destination participates in
    the rarity judgement.
    """

    def __init__(self) -> None:
        super().__init__()
        self.triples: dict = {}

    def observe_subgraph(self, sub: dict) -> None:
        super().observe_subgraph(sub)
        for a in (sub.get("artifacts") or []):
            proc = str(a.get("process") or "").lower()
            kind = str(a.get("kind") or "").lower()
            data = a.get("data") or {}
            subject = str(data.get("subject") or "").lower() if isinstance(data, dict) else ""
            if proc and kind and subject:
                k = f"{proc}>{kind}>{subject}"
                self.triples[k] = self.triples.get(k, 0) + 1

    def destination_rarity(self, proc: str, kind: str, subject: str) -> float:
        c = self.triples.get(f"{(proc or '').lower()}>{(kind or '').lower()}"
                             f">{(subject or '').lower()}", 0)
        if c >= 20:
            return 0.0
        if c == 0:
            return 1.0
        return max(0.0, 1.0 - (c / 20.0))


def arm_endpoint_destination_aware(sub: dict, baseline) -> bool:
    """Identical to `arm_endpoint_only` except the rarity term also considers
    where the egress went."""
    if not baseline.mature:
        return False
    owner = str((sub.get("cgo") or {}).get("name") or "").lower()
    for a in sub.get("artifacts") or []:
        if str(a.get("kind") or "").lower() not in _EGRESS_KINDS:
            continue
        proc = str(a.get("process") or "").lower()
        if proc == owner:
            continue
        data = a.get("data") or {}
        subject = str(data.get("subject") or "") if isinstance(data, dict) else ""
        kind = str(a.get("kind") or "").lower()
        if subject and baseline.destination_rarity(proc, kind, subject) >= RARITY_FIRE:
            return True
    return False


def _learn_destination_aware(structures: list[dict]) -> DestinationAwareBaseline:
    b = DestinationAwareBaseline()
    if not structures:
        return b
    per_session = -(-MIN_OBSERVATIONS // MIN_SESSIONS) + 1
    for _ in range(MIN_SESSIONS):
        b.start_session()
        for i in range(per_session):
            b.observe_subgraph(structures[i % len(structures)])
    return b


def authored() -> dict:
    corpus = build_corpus()
    name_baseline = learn_baseline(corpus)
    ordinary = [c["sub"] for c in corpus
                if not c["cross_layer"] and c["label"].startswith("benign_")]
    dest_baseline = _learn_destination_aware(ordinary)

    out = {"name_keyed": {"caught": 0, "fp": 0, "blind_spot": False},
           "destination_keyed": {"caught": 0, "fp": 0, "blind_spot": False}}
    for case in corpus:
        for label, fn, base in (
                ("name_keyed", arm_endpoint_only, name_baseline),
                ("destination_keyed", arm_endpoint_destination_aware, dest_baseline)):
            fired = bool(fn(case["sub"], base))
            if case["cross_layer"]:
                if fired:
                    out[label]["caught"] += 1
                if case["label"] == "cross_layer_common_process_name" and fired:
                    out[label]["blind_spot"] = True
            elif fired:
                out[label]["fp"] += 1
    return out


def real(path: Path) -> dict | None:
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    subs = payload.get("subgraphs") or []
    if not subs:
        return None
    cut = int(len(subs) * 0.7)
    train, test = subs[:cut], subs[cut:]

    name_baseline = CausalBaseline()
    per_session = -(-MIN_OBSERVATIONS // MIN_SESSIONS) + 1
    for _ in range(MIN_SESSIONS):
        name_baseline.start_session()
        for i in range(per_session):
            name_baseline.observe_subgraph(train[i % len(train)])
    dest_baseline = _learn_destination_aware(train)

    return {
        "structures": len(test),
        "name_keyed_fires": sum(1 for s in test if arm_endpoint_only(s, name_baseline)),
        "destination_keyed_fires": sum(
            1 for s in test if arm_endpoint_destination_aware(s, dest_baseline)),
        "capture": payload.get("capture", {}),
    }


def main() -> int:
    print("\n=== rarity variant: name-keyed vs destination-aware ===")
    print("Nothing shipping is modified; the variant lives in this experiment.\n")

    a = authored()
    print("AUTHORED corpus (6 cross-layer cases, 27 benign):")
    print(f"{'rarity keying':<22}{'caught':>8}{'false pos':>11}{'closes blind spot':>20}")
    print("-" * 61)
    for label in ("name_keyed", "destination_keyed"):
        r = a[label]
        print(f"{label:<22}{r['caught']:>8}{r['fp']:>11}"
              f"{('YES' if r['blind_spot'] else 'no'):>20}")

    r = real(Path(__file__).resolve().parent / "real_causal_corpus.json")
    print("\nREAL capture (held-out structures from this desktop):")
    if r is None:
        print("  no real corpus present - run tools/capture_causal_corpus.py first")
        return 0
    cap = r["capture"]
    print(f"  {cap.get('host_os','?')}, {cap.get('seconds','?')}s, "
          f"{cap.get('network_artifacts','?')} network artifacts")
    n = r["structures"]
    nk, dk = r["name_keyed_fires"], r["destination_keyed_fires"]
    print(f"  name-keyed        fires on {nk:>3}/{n} ({100.0*nk/max(1,n):5.1f}%)")
    print(f"  destination-aware fires on {dk:>3}/{n} ({100.0*dk/max(1,n):5.1f}%)")
    if dk > nk:
        print(f"\n  cost of closing the blind spot on this machine: "
              f"+{dk - nk} structures ({100.0*(dk-nk)/max(1,n):.1f} points)")
    elif dk == nk:
        print("\n  no measured false-positive cost on this capture")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
