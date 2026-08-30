"""Aegis 1A -- size-exposure reduction via deterministic bounded bucketing.

Aegis 0.5 found that size alone (94.4%) is the strongest driver of activity
classification in the frozen corpus -- stronger than destination and even
the full three-feature combination. This module isolates that ONE variable:
does replacing each connection's exact byte count with a deterministic
bucket ceiling actually remove useful information from an informed
observer, and at what bandwidth/latency/compatibility cost? Nothing else is
touched -- no relaying, no fake traffic, no timing perturbation.

## The policies are defined BEFORE they are evaluated

CONTROL, BUCKET-A/B/C/D exist as fixed functions before a single accuracy
number is computed, specifically so no policy can be tuned against the test
set it will be scored on. See `POLICIES` below.

## The killer test: retrain the observer

An observer that only loses accuracy because it was never shown bucketed
traffic is not evidence of anything -- it is testing a stale classifier. For
every policy this module reports BOTH: the naive-observer accuracy (trained
on ORIGINAL sizes, tested on bucketed traffic -- what an observer who
doesn't know Aegis exists sees) and the retrained-observer accuracy (trained
AND tested on bucketed traffic -- an informed adversary that adapted). Only
the retrained number is allowed to be read as "Aegis works here."

## Two observer profiles, because bucketing only touches ONE channel

Every accuracy number above is reported for TWO different observers:
`size_only_observer` (restricted to mean/std size -- isolates the causal
effect of the size transform cleanly, comparable to Aegis 0.5's size-only
94.4%) and `full_feature_observer` (destination + size + timing together --
what a REAL network observer would actually use). Bucketing transforms only
size; if destination and timing stay fully exposed, a full-feature observer
can keep classifying well from those untouched channels regardless of what
happens to size. Reporting only the size-only number would hide that a
realistic multi-channel observer barely notices; reporting only the
full-feature number would hide whether the size transform did anything at
all. Both are needed to read the result honestly.

## Whether the SEQUENCE of buckets is itself a fingerprint

Hiding exact sizes accomplishes little if the resulting sequence of bucket
tiers (small, small, huge, small, ...) is as distinctive as the sizes were.
`sequence_only_accuracy` measures a classifier that never sees a byte count
at all -- only each session's bucket-tier histogram -- so that failure mode
is measured directly rather than assumed away.

## What this explicitly does not do

Bandwidth overhead is real (bucket ceiling - actual size, exactly what a
real bucketing/padding scheme would transmit). Added latency is a STATED,
simple model (extra bytes / an assumed link speed), not a measurement --
there is no real network here to measure. Compatibility is a heuristic proxy
(how many connections expand by a large ratio), not a report of real
application breakage, because no real application exists to break. All three
are documented as such and never conflated with a live measurement.
"""

from __future__ import annotations

import math
import random
import statistics
from dataclasses import dataclass

from .aegis_baseline import (
    ACTIVITIES,
    Connection,
    Session,
    Standardizer,
    _centroid,
    _distance,
    build_corpus,
    extract_features,
    manifest_hash,
)
from .aegis_ablation import FROZEN_MANIFEST_SHA256

# A stated, simple assumption -- not a measurement. Used only to convert a
# bandwidth overhead (extra bytes) into an illustrative added-latency figure.
_ASSUMED_LINK_MBPS = 10.0
# A connection expanding by more than this ratio is flagged as a
# compatibility concern (a proxy for "a protocol with strict size
# expectations might choke on this"), not a measured breakage report.
_SEVERE_EXPANSION_RATIO = 20.0


@dataclass(frozen=True)
class BucketPolicy:
    """`boundaries` are ascending bucket ceilings covering the corpus's known
    range. A bucketed size must NEVER be smaller than the true size -- that
    would leak a false lower bound, defeating the entire point -- so a size
    past the last defined boundary grows the last tier exponentially
    (doubling) rather than silently capping downward. This only matters for
    inputs outside the range the boundaries were designed for; every policy
    here is defined to already cover the corpus's real observed maximum."""
    name: str
    description: str
    boundaries: tuple[int, ...]

    def bucket(self, size: int) -> int:
        for b in self.boundaries:
            if size <= b:
                return b
        ceiling = self.boundaries[-1]
        while ceiling < size:
            ceiling *= 2
        return ceiling

    def tier(self, size: int) -> int:
        for i, b in enumerate(self.boundaries):
            if size <= b:
                return i
        # Beyond the last defined boundary: still a distinct, ordered tier
        # per doubling, rather than colliding with the last defined tier.
        overflow_doublings = 0
        ceiling = self.boundaries[-1]
        while ceiling < size:
            ceiling *= 2
            overflow_doublings += 1
        return len(self.boundaries) - 1 + overflow_doublings


def _geometric_boundaries(start: int, cap: int, ratio: float) -> tuple[int, ...]:
    bounds = []
    value = start
    while value < cap:
        bounds.append(value)
        value = math.ceil(value * ratio)
    bounds.append(cap)
    return tuple(bounds)


# Defined once, before any evaluation, against the corpus's real observed
# size range (189B-4.46MB browsing/streaming/etc; see docs). Never adjusted
# after seeing accuracy numbers.
POLICIES: tuple[BucketPolicy, ...] = (
    BucketPolicy("BUCKET-A", "coarse: small/medium/large", (1_000, 100_000, 5_000_000)),
    BucketPolicy("BUCKET-B", "finer: 8 exponential (x4) tiers",
                (256, 1_024, 4_096, 16_384, 65_536, 262_144, 1_048_576, 5_000_000)),
    BucketPolicy("BUCKET-C", "adaptive: geometric ratio 1.25 (bounded ~25% overhead/bucket)",
                _geometric_boundaries(256, 5_000_000, 1.25)),
    BucketPolicy("BUCKET-D", "aggressive: 2 tiers, high overhead by construction",
                (5_000, 5_000_000)),
)


def _apply(session: Session, policy: BucketPolicy | None) -> Session:
    if policy is None:
        return session
    new_conns = tuple(
        Connection(c.t, c.destination, policy.bucket(c.size_bytes))
        for c in session.connections
    )
    return Session(session.session_id, session.activity, session.user_id, new_conns)


def _train_test_ids(sessions: tuple[Session, ...], train_fraction: float,
                    rng: random.Random) -> tuple[set[str], set[str]]:
    by_activity: dict[str, list[Session]] = {a: [] for a in ACTIVITIES}
    for s in sessions:
        by_activity[s.activity].append(s)
    train_ids: set[str] = set()
    test_ids: set[str] = set()
    for group in by_activity.values():
        shuffled = list(group)
        rng.shuffle(shuffled)
        cut = max(1, int(len(shuffled) * train_fraction))
        train_ids.update(s.session_id for s in shuffled[:cut])
        test_ids.update(s.session_id for s in shuffled[cut:])
    return train_ids, test_ids


## Two observer profiles, not one
#
# A classifier restricted to (mean_size, std_size) isolates the causal
# effect of size bucketing cleanly -- exactly what "does this policy defeat
# a SIZE-based observer" needs. But bucketing here touches ONLY size, so a
# REALISTIC observer that also has destination and timing (which nothing in
# Aegis 1A transforms) could still classify well from those untouched
# channels regardless of what happens to size. Reporting only the
# size-only number would hide that; reporting only the full-feature number
# would hide whether the size transform itself did anything. Both are
# measured, for different questions.
_SIZE_FIELDS = ("mean_size", "std_size")


def _field_names(sessions: list[Session]) -> tuple[str, ...]:
    return tuple(extract_features(sessions[0]).__dataclass_fields__)


def _fit(sessions: list[Session], fields: tuple[str, ...]) -> tuple[Standardizer, dict]:
    vectors = [tuple(getattr(extract_features(s), f) for f in fields) for s in sessions]
    standardizer = Standardizer(vectors)
    by_activity: dict[str, list[tuple[float, ...]]] = {a: [] for a in ACTIVITIES}
    for s, v in zip(sessions, vectors):
        by_activity[s.activity].append(standardizer.apply(v))
    centroids = {a: _centroid(vs) for a, vs in by_activity.items() if vs}
    return standardizer, centroids


def _predict(session: Session, fields: tuple[str, ...],
            standardizer: Standardizer, centroids: dict) -> str:
    v = standardizer.apply(tuple(getattr(extract_features(session), f) for f in fields))
    return min(centroids, key=lambda a: _distance(v, centroids[a]))


def _accuracy(test_sessions: list[Session], fields: tuple[str, ...],
             standardizer: Standardizer, centroids: dict) -> float:
    if not test_sessions:
        return 0.0
    correct = sum(_predict(s, fields, standardizer, centroids) == s.activity
                 for s in test_sessions)
    return round(correct / len(test_sessions), 4)


def _sequence_only_vector(session: Session, policy: BucketPolicy) -> tuple[float, ...]:
    """A session's activity signature using ONLY bucket-tier membership --
    no byte count ever enters this vector. Tests whether the sequence of
    tiers is itself a fingerprint even when exact sizes are gone.

    Vector length is fixed at len(policy.boundaries) for every session, so
    all sessions' vectors stay comparable; a size beyond the policy's top
    defined boundary (BucketPolicy.tier()'s overflow-doubling case, which
    does not occur for this frozen corpus -- every policy's top boundary
    already covers its real observed maximum) collapses into the last tier
    here rather than growing the vector. That collision only affects this
    internal signature representation, never the actual bucketed size a
    connection would transmit (bucket() itself never truncates downward).
    """
    n_tiers = len(policy.boundaries)
    counts = [0] * n_tiers
    for c in session.connections:
        counts[min(policy.tier(c.size_bytes), n_tiers - 1)] += 1
    total = sum(counts) or 1
    return tuple(count / total for count in counts)


def _sequence_only_accuracy(train: list[Session], test: list[Session],
                            policy: BucketPolicy) -> float:
    vectors = [_sequence_only_vector(s, policy) for s in train]
    by_activity: dict[str, list[tuple[float, ...]]] = {a: [] for a in ACTIVITIES}
    for s, v in zip(train, vectors):
        by_activity[s.activity].append(v)
    centroids = {a: _centroid(vs) for a, vs in by_activity.items() if vs}
    if not test:
        return 0.0
    correct = 0
    for s in test:
        v = _sequence_only_vector(s, policy)
        predicted = min(centroids, key=lambda a: _distance(v, centroids[a]))
        correct += int(predicted == s.activity)
    return round(correct / len(test), 4)


def _overhead_and_cost(sessions: tuple[Session, ...], policy: BucketPolicy) -> dict:
    ratios: list[float] = []
    extra_bytes: list[int] = []
    severe = 0
    for s in sessions:
        for c in s.connections:
            bucketed = policy.bucket(c.size_bytes)
            extra = bucketed - c.size_bytes
            extra_bytes.append(extra)
            ratio = bucketed / c.size_bytes if c.size_bytes else 1.0
            ratios.append(ratio)
            if ratio > _SEVERE_EXPANSION_RATIO:
                severe += 1

    bandwidth_overhead_pct = round(
        100.0 * sum(extra_bytes) / sum(c.size_bytes for s in sessions for c in s.connections), 2)

    # Stated model: extra bytes / assumed link speed -> added transmission
    # time. Not a measurement -- there is no real network here.
    latency_ms = sorted((eb * 8 / (_ASSUMED_LINK_MBPS * 1_000_000)) * 1000 for eb in extra_bytes)

    def pct(p: float) -> float:
        if not latency_ms:
            return 0.0
        idx = min(len(latency_ms) - 1, int((len(latency_ms) - 1) * p))
        return round(latency_ms[idx], 3)

    return {
        "bandwidth_overhead_pct": bandwidth_overhead_pct,
        "mean_expansion_ratio": round(statistics.fmean(ratios), 3),
        "max_expansion_ratio": round(max(ratios), 3),
        "modeled_added_latency_ms": {
            "assumption": f"{_ASSUMED_LINK_MBPS} Mbps link, extra_bytes / bandwidth",
            "p50": pct(0.50), "p95": pct(0.95), "p99": pct(0.99),
        },
        "compatibility_concern": {
            "severe_expansion_threshold_ratio": _SEVERE_EXPANSION_RATIO,
            "connections_flagged": severe,
            "total_connections": len(ratios),
            "note": "a heuristic proxy for 'a protocol with strict size "
                    "expectations might choke on this', not measured real "
                    "application breakage -- no real application exists here.",
        },
    }


def run(seed: int = 20260830) -> dict:
    sessions = build_corpus(seed=seed)
    current_hash = manifest_hash(sessions)
    if current_hash != FROZEN_MANIFEST_SHA256:
        raise RuntimeError(
            "aegis_baseline's corpus generator changed since the Aegis 0/0.5 "
            f"baseline was measured (expected {FROZEN_MANIFEST_SHA256}, got "
            f"{current_hash}). Aegis 1A numbers would not be comparable.")

    rng = random.Random(seed + 7)
    train_ids, test_ids = _train_test_ids(sessions, 0.7, rng)
    by_id = {s.session_id: s for s in sessions}
    train_original = [by_id[i] for i in train_ids]
    test_original = [by_id[i] for i in test_ids]
    all_fields = _field_names(sessions)

    profiles = {"size_only_observer": _SIZE_FIELDS, "full_feature_observer": all_fields}
    naive_fit = {
        profile: _fit(train_original, fields) for profile, fields in profiles.items()
    }
    control_accuracy = {
        profile: _accuracy(test_original, fields, *naive_fit[profile])
        for profile, fields in profiles.items()
    }

    results: dict[str, dict] = {
        "CONTROL": {
            "description": "no transform -- exact observed sizes",
            "naive_observer_accuracy": control_accuracy,
            "retrained_observer_accuracy": control_accuracy,
            "sequence_only_accuracy": None,
            "bandwidth_overhead_pct": 0.0,
        }
    }

    for policy in POLICIES:
        test_bucketed = [_apply(by_id[i], policy) for i in test_ids]
        train_bucketed = [_apply(by_id[i], policy) for i in train_ids]

        naive_acc = {
            profile: _accuracy(test_bucketed, fields, *naive_fit[profile])
            for profile, fields in profiles.items()
        }
        retrained_acc = {}
        for profile, fields in profiles.items():
            standardizer, centroids = _fit(train_bucketed, fields)
            retrained_acc[profile] = _accuracy(test_bucketed, fields, standardizer, centroids)
        seq_acc = _sequence_only_accuracy(train_bucketed, test_bucketed, policy)
        cost = _overhead_and_cost(sessions, policy)

        results[policy.name] = {
            "description": policy.description,
            "boundaries": list(policy.boundaries),
            "naive_observer_accuracy": naive_acc,
            "retrained_observer_accuracy": retrained_acc,
            "sequence_only_accuracy": seq_acc,
            **cost,
        }

    return {
        "evidence_class": "synthetic mechanism evaluation",
        "independent": False,
        "stage": "Aegis 1A -- size-exposure reduction via deterministic bucketing",
        "frozen_baseline_manifest_sha256": FROZEN_MANIFEST_SHA256,
        "random_chance_accuracy": round(1.0 / len(ACTIVITIES), 4),
        "results": results,
        "limitations": [
            "Same frozen synthetic corpus as Aegis 0/0.5; not real captured traffic.",
            "Only size is transformed here -- no relaying, no fake traffic, no "
            "timing perturbation, per the isolation requirement for this stage.",
            "modeled_added_latency_ms is a stated model (extra bytes / an "
            "assumed 10 Mbps link), not a real measurement -- there is no "
            "real network in this harness.",
            "compatibility_concern is a heuristic proxy (severe expansion "
            "ratio), not a report of real application breakage.",
            "naive_observer_accuracy tests an observer that doesn't know "
            "Aegis exists; only retrained_observer_accuracy should be read "
            "as evidence a policy actually removes information from an "
            "informed adversary.",
        ],
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2, default=str))
