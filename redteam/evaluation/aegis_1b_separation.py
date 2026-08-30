"""Aegis 1B -- information separation, not "build a proxy."

Aegis 1A falsified single-feature hiding: an informed observer reconstructed
activity from untouched correlated features, and the transform created a
new sequence fingerprint. The lesson carried forward is architectural, not
"try harder at padding": Aegis should reason about which pieces of
correlation-enabling information an observation point receives TOGETHER,
not about hiding one field at a time.

## The hypothesis under test

    Reducing an observer's simultaneous access to client identity +
    destination materially lowers cross-session linkability, even after
    the observer knows the mechanism and retrains.

## Three conditions

  CONTROL              one observer sees identity-context + destination
                        together for every connection (today's baseline;
                        reuses Aegis 0's destination-overlap linkability).
  SINGLE_INTERMEDIARY   a relay sees the SAME two pieces together, just
                        physically relayed -- structurally identical to
                        CONTROL. Included to make the "obvious weakness"
                        (Cloudflare's own words: "proxy knows who you are +
                        where you're going") an empirical fact, not an
                        assertion.
  SEPARATED_KNOWLEDGE   two observation points. ENTRY sees a stable
                        per-session client-context signal plus timing/size,
                        but never destination. EXIT sees destination plus
                        timing/size, but never a client-identity signal
                        that persists across sessions. Neither alone
                        receives the full identity+destination association.

## The test that actually matters: can the separated views be re-linked?

Knowledge separation is worthless if a correlating observer can just match
ENTRY's view of a session to EXIT's view of the same session using timing
and size -- the exact failure this module was told to test for rather than
assume. `relink_accuracy` measures exactly that: nearest-neighbor matching
between the two views' timing+size signatures, across realistic incidental
relay jitter/overhead (NOT a deliberate Aegis mechanism -- see below). If
relinking succeeds, the report says so as a failure of the primitive, not a
reason to bolt on ad-hoc timing protection mid-experiment.

## What is and is not being tested

No mitigation is added here beyond the knowledge split itself and the
already-frozen corpus -- no jitter/padding as a PRIVACY mechanism. The
"relay jitter" applied before re-linking is a small, explicitly-labeled
model of INCIDENTAL real-relay noise (queueing delay, protocol
encapsulation overhead) that exists whether or not anyone is trying to
protect privacy -- included so the re-linking test isn't a tautological
zero-distance match, not included as an Aegis defense. Its magnitude is
declared, not tuned to produce a particular result.
"""

from __future__ import annotations

import random
import statistics
from dataclasses import dataclass

from .aegis_ablation import FROZEN_MANIFEST_SHA256
from .aegis_baseline import (
    ACTIVITIES,
    Session,
    Standardizer,
    _destination_set,
    _distance,
    _jaccard,
    build_corpus,
    manifest_hash,
)

# Declared, not tuned: a small amount of incidental relay noise (queueing
# jitter and protocol/encapsulation size overhead) that exists on any real
# two-hop path whether or not anyone is trying to protect privacy. Without
# ANY noise, ENTRY's and EXIT's views of the same session are numerically
# identical and re-linking would be a tautological zero-distance match --
# this exists so the re-linking test is a real empirical question, not a
# guaranteed answer, while remaining clearly distinct from a deliberate
# Aegis privacy mechanism (no mitigation is being tested this stage).
_RELAY_TIMING_JITTER_MS = 15.0
_RELAY_SIZE_OVERHEAD_FRACTION = 0.03

# Structural, not measured: an extra network hop's typical latency, for a
# knowledge-separated two-hop path versus a single-hop CONTROL/intermediary.
_MODELED_EXTRA_HOP_LATENCY_MS = 20.0


@dataclass(frozen=True)
class ViewFeatures:
    n_connections: int
    mean_ipi: float
    std_ipi: float
    duration: float
    mean_size: float
    std_size: float


def _timing_size_features(session: Session, rng: random.Random | None = None) -> ViewFeatures:
    """Timing+size only -- the fields both ENTRY and EXIT can see, since
    neither view depends on identity or destination. `rng`, when given,
    applies the declared incidental relay noise (see module docstring)."""
    times = [c.t for c in session.connections]
    sizes = [c.size_bytes for c in session.connections]
    if rng is not None:
        times = [t + rng.gauss(0, _RELAY_TIMING_JITTER_MS / 1000.0) for t in times]
        sizes = [s * (1.0 + rng.uniform(0, _RELAY_SIZE_OVERHEAD_FRACTION)) for s in sizes]
    ipis = [b - a for a, b in zip(times, times[1:])] or [0.0]
    return ViewFeatures(
        n_connections=len(session.connections),
        mean_ipi=statistics.fmean(ipis),
        std_ipi=statistics.pstdev(ipis) if len(ipis) > 1 else 0.0,
        duration=(times[-1] - times[0]) if times else 0.0,
        mean_size=statistics.fmean(sizes) if sizes else 0.0,
        std_size=statistics.pstdev(sizes) if len(sizes) > 1 else 0.0,
    )


def _vector(features: ViewFeatures) -> tuple[float, ...]:
    return (features.n_connections, features.mean_ipi, features.std_ipi,
           features.duration, features.mean_size, features.std_size)


def _destination_linkability(sessions: list[Session]) -> dict:
    """Same balanced-accuracy methodology as Aegis 0: EXIT (or CONTROL/
    SINGLE_INTERMEDIARY, which see the same destinations) always has
    destination information, so this is unaffected by whether identity is
    also present -- that is itself a finding, not a null result to skip."""
    candidates = [s for s in sessions if any(
        d.startswith("fav-") for d in _destination_set(s))]
    if len(candidates) < 4:
        return {"pairs": 0, "note": "not enough sessions with personal destinations"}

    same_scores: list[float] = []
    diff_scores: list[float] = []
    for i, a in enumerate(candidates):
        for b in candidates[i + 1:]:
            if a.activity != b.activity:
                continue
            score = _jaccard(_destination_set(a), _destination_set(b))
            (same_scores if a.user_id == b.user_id else diff_scores).append(score)

    if not same_scores or not diff_scores:
        return {"pairs": 0, "note": "no comparable same/different-user pairs"}

    all_scores = sorted(set(same_scores + diff_scores))
    best_balanced = 0.0
    for threshold in all_scores:
        tpr = sum(s >= threshold for s in same_scores) / len(same_scores)
        tnr = sum(s < threshold for s in diff_scores) / len(diff_scores)
        balanced = 0.5 * (tpr + tnr)
        best_balanced = max(best_balanced, balanced)

    return {"pairs": len(same_scores) + len(diff_scores),
           "balanced_accuracy": round(best_balanced, 4),
           "balanced_random_chance": 0.5}


def _relink_accuracy(sessions: list[Session], seed: int) -> dict:
    """The critical test: can a correlating observer match each ENTRY view
    to its true EXIT view using ONLY timing+size, under realistic incidental
    relay noise? Nearest-neighbor, top-1, across the WHOLE candidate pool
    (a real adversary doesn't get to restrict the search to one activity)."""
    entry_rng = random.Random(seed)
    exit_rng = random.Random(seed + 1)   # independent noise draw per view

    entry_vectors = {s.session_id: _vector(_timing_size_features(s, entry_rng))
                     for s in sessions}
    exit_vectors = {s.session_id: _vector(_timing_size_features(s, exit_rng))
                    for s in sessions}

    standardizer = Standardizer(list(entry_vectors.values()) + list(exit_vectors.values()))
    entry_std = {sid: standardizer.apply(v) for sid, v in entry_vectors.items()}
    exit_std = {sid: standardizer.apply(v) for sid, v in exit_vectors.items()}

    correct = 0
    for sid, entry_v in entry_std.items():
        best_match = min(exit_std, key=lambda other: _distance(entry_v, exit_std[other]))
        correct += int(best_match == sid)
    accuracy = correct / len(entry_std) if entry_std else 0.0
    return {
        "matched": len(entry_std),
        "relink_accuracy": round(accuracy, 4),
        "relink_random_chance": round(1.0 / len(entry_std), 4) if entry_std else 0.0,
        "relay_timing_jitter_ms": _RELAY_TIMING_JITTER_MS,
        "relay_size_overhead_fraction": _RELAY_SIZE_OVERHEAD_FRACTION,
    }


def run(seed: int = 20260830) -> dict:
    sessions = list(build_corpus(seed=seed))
    current_hash = manifest_hash(tuple(sessions))
    if current_hash != FROZEN_MANIFEST_SHA256:
        raise RuntimeError(
            "aegis_baseline's corpus generator changed since the Aegis 0/0.5/1A "
            f"baselines were measured (expected {FROZEN_MANIFEST_SHA256}, got "
            f"{current_hash}). Aegis 1B numbers would not be comparable.")

    control_linkability = _destination_linkability(sessions)
    relink = _relink_accuracy(sessions, seed)

    conditions = {
        "CONTROL": {
            "description": "one observer sees identity-context + destination together",
            "entry_information": "identity + destination + timing + size (all combined)",
            "exit_information": "n/a -- single observation point",
            "destination_linkability": control_linkability,
            "latency_overhead_ms": {"modeled": 0.0, "assumption": "single hop, no separation"},
            "bandwidth_overhead_pct": 0.0,
            "flow_failures": "not applicable -- no real flows execute in this harness",
        },
        "SINGLE_INTERMEDIARY": {
            "description": "a relay sees the SAME two pieces together -- structurally "
                           "identical to CONTROL by construction, not a separate "
                           "measurement (this is the 'obvious weakness': a proxy that "
                           "can see both ends provides no separation benefit)",
            "entry_information": "identity + destination + timing + size (relayed, not split)",
            "exit_information": "n/a -- one relay holds both pieces",
            "destination_linkability": control_linkability,
            "latency_overhead_ms": {"modeled": _MODELED_EXTRA_HOP_LATENCY_MS,
                                    "assumption": "one relay hop, no knowledge split"},
            "bandwidth_overhead_pct": 0.0,
            "flow_failures": "not applicable -- no real flows execute in this harness",
        },
        "SEPARATED_KNOWLEDGE": {
            "description": "ENTRY and EXIT each see only part of the association",
            "entry_information": "stable per-session client context + timing + size "
                                 "-- NEVER destination",
            "exit_information": "destination + timing + size -- NEVER a client-identity "
                                "signal that persists across sessions",
            "destination_linkability_at_exit": control_linkability,
            "entry_alone_has_no_destination_signal": True,
            "relink_via_timing_size_correlation": relink,
            "latency_overhead_ms": {"modeled": _MODELED_EXTRA_HOP_LATENCY_MS,
                                    "assumption": "two-hop path, entry + exit"},
            "bandwidth_overhead_pct": round(100 * _RELAY_SIZE_OVERHEAD_FRACTION, 2),
            "flow_failures": "not applicable -- no real flows execute in this harness",
        },
    }

    relink_succeeds = relink["relink_accuracy"] > 3 * relink["relink_random_chance"]
    verdict = (
        "FAILURE: knowledge separation alone does not lower end-to-end linkability. "
        "EXIT alone still achieves the same destination-driven linkability as CONTROL "
        "(destination was never the piece that got separated from an attacker who "
        "only ever needed destination overlap, not identity, to correlate sessions). "
        "And the two separated views can be re-linked via timing+size correlation "
        f"({relink['relink_accuracy']:.1%} vs {relink['relink_random_chance']:.1%} chance), "
        "reconstructing the full identity-destination association anyway."
        if relink_succeeds else
        "Knowledge separation held against timing/size re-linking in this experiment, "
        "but EXIT alone still retains full destination-driven linkability -- separation "
        "did not address the dominant Aegis 0.5 linkability channel either way."
    )

    return {
        "evidence_class": "synthetic mechanism evaluation",
        "independent": False,
        "stage": "Aegis 1B -- information separation (identity vs. destination), "
                "not a proxy feature",
        "hypothesis": "Reducing an observer's simultaneous access to client identity "
                     "+ destination materially lowers cross-session linkability, even "
                     "after the observer knows the mechanism and retrains.",
        "frozen_baseline_manifest_sha256": FROZEN_MANIFEST_SHA256,
        "conditions": conditions,
        "verdict": verdict,
        "generalizes_beyond_this_corpus": (
            "No. The failure mode found here (destination-overlap linkability doesn't "
            "need identity to begin with; timing+size correlation defeats knowledge "
            "separation with no decorrelation mechanism) is a property of THIS "
            "exposure model, not yet shown to hold beyond it. Whether it generalizes "
            "requires testing on a corpus whose destination linkability comes from a "
            "genuinely different mechanism (e.g. session tokens, not destination "
            "overlap) -- named as the next falsifiable question, not claimed here."
        ),
        "limitations": [
            "Same frozen synthetic corpus as Aegis 0/0.5/1A; not real captured traffic.",
            "flow_failures and bandwidth/latency overheads for the knowledge-split "
            "itself are modeled assumptions (an extra hop's latency, protocol "
            "overhead), not measurements -- there is no real network here.",
            "The relay timing jitter and size overhead applied before relinking model "
            "INCIDENTAL real-relay noise, not a deliberate Aegis privacy mechanism -- "
            "no mitigation was added during this experiment, per the stage's own scope.",
            "SINGLE_INTERMEDIARY is reported as structurally identical to CONTROL by "
            "construction (a relay holding both pieces cannot be less informative "
            "than either alone), not as an independently measured condition.",
        ],
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2, default=str))
