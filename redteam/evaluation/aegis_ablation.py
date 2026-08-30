"""Aegis 0.5 -- feature ablation on the frozen Aegis 0 baseline.

"Run toward the hardest problem -- but first identify which problem is
actually hardest." Aegis 0 measured that a network observer gets 91.7%
activity-classification accuracy and 78.4% balanced cross-session
linkability from destination + size + timing features combined. Before
building any mitigation, this asks which of those three feature groups is
actually carrying that information advantage -- destination alone,
timing alone, size alone, or only some combination.

This module does NOT touch aegis_baseline.py. `FROZEN_MANIFEST_SHA256`
below is asserted against in tests: the corpus Aegis 0 measured must stay
exactly what any later Aegis stage is compared against, or an Aegis
mechanism could end up quietly engineered to beat this particular
classifier instead of reducing network inference in general.
"""

from __future__ import annotations

import random
import statistics
from typing import Iterable

from .aegis_baseline import (
    ACTIVITIES,
    Session,
    Standardizer,
    _centroid,
    _destination_set,
    _distance,
    _jaccard,
    _train_test_split,
    build_corpus,
    extract_features,
    manifest_hash,
)

# Pinned at the time Aegis 0's baseline was measured. A mismatch here means
# the corpus generator changed -- which invalidates every ablation number
# below, since they would no longer be measuring the same baseline.
FROZEN_MANIFEST_SHA256 = (
    "334b749d4148082bc464f985d46a6c1fec49425f9a8a8f13675efdd0ff7e8658"
)

# Every Features field, grouped into the three exposure dimensions the
# essay's own ablation table asks about. n_connections is grouped under
# timing (a temporal/volume characteristic -- how often, not how big or
# where), a classification choice made explicit here rather than left
# ambiguous.
FEATURE_GROUPS: dict[str, tuple[str, ...]] = {
    "destination": ("n_distinct_destinations", "top_destination_share"),
    "size": ("mean_size", "std_size"),
    "timing": ("n_connections", "mean_ipi", "std_ipi", "duration"),
}

_ALL_FIELDS = tuple(f for group in FEATURE_GROUPS.values() for f in group)


def _subset_vector(features, fields: tuple[str, ...]) -> tuple[float, ...]:
    return tuple(getattr(features, name) for name in fields)


def _fit_predict_accuracy(sessions: tuple[Session, ...], fields: tuple[str, ...],
                          rng: random.Random) -> dict:
    train, test = _train_test_split(sessions, 0.7, rng)
    train_vectors = [_subset_vector(extract_features(s), fields) for s in train]
    standardizer = Standardizer(train_vectors)

    by_activity: dict[str, list[tuple[float, ...]]] = {a: [] for a in ACTIVITIES}
    for s, v in zip(train, train_vectors):
        by_activity[s.activity].append(standardizer.apply(v))
    centroids = {a: _centroid(vs) for a, vs in by_activity.items() if vs}

    correct = 0
    for s in test:
        v = standardizer.apply(_subset_vector(extract_features(s), fields))
        predicted = min(centroids, key=lambda a: _distance(v, centroids[a]))
        correct += int(predicted == s.activity)
    return {"accuracy": round(correct / len(test), 4) if test else 0.0,
           "test": len(test)}


def _linkability_for_fields(sessions: tuple[Session, ...],
                            fields: tuple[str, ...]) -> dict:
    """Same balanced-accuracy methodology as aegis_baseline, restricted to a
    destination-set overlap that is only meaningful when `destination` is in
    the feature set -- for size/timing-only ablations, linkability is instead
    measured via Euclidean closeness in that restricted, standardized feature
    space, since there is no destination information to overlap at all."""
    candidates = [s for s in sessions if any(
        d.startswith("fav-") for d in _destination_set(s))]
    if len(candidates) < 4:
        return {"pairs": 0, "note": "not enough sessions with personal destinations"}

    use_destination_overlap = "destination" in _group_name_for(fields)
    same_scores: list[float] = []
    diff_scores: list[float] = []

    if use_destination_overlap:
        for i, a in enumerate(candidates):
            for b in candidates[i + 1:]:
                if a.activity != b.activity:
                    continue
                score = _jaccard(_destination_set(a), _destination_set(b))
                (same_scores if a.user_id == b.user_id else diff_scores).append(score)
    else:
        vectors = {s.session_id: _subset_vector(extract_features(s), fields)
                  for s in candidates}
        standardizer = Standardizer(list(vectors.values()))
        std = {sid: standardizer.apply(v) for sid, v in vectors.items()}
        # Similarity as inverse distance so "higher = more similar", matching
        # the Jaccard convention used for the destination-overlap case.
        for i, a in enumerate(candidates):
            for b in candidates[i + 1:]:
                if a.activity != b.activity:
                    continue
                d = _distance(std[a.session_id], std[b.session_id])
                score = 1.0 / (1.0 + d)
                (same_scores if a.user_id == b.user_id else diff_scores).append(score)

    if not same_scores or not diff_scores:
        return {"pairs": 0, "note": "no comparable same/different-user pairs"}

    all_scores = sorted(set(same_scores + diff_scores))
    best_balanced = 0.0
    for threshold in all_scores:
        tpr = sum(s >= threshold for s in same_scores) / len(same_scores)
        tnr = sum(s < threshold for s in diff_scores) / len(diff_scores)
        balanced = 0.5 * (tpr + tnr)
        if balanced > best_balanced:
            best_balanced = balanced

    return {"pairs": len(same_scores) + len(diff_scores),
           "balanced_accuracy": round(best_balanced, 4),
           "balanced_random_chance": 0.5,
           "method": "destination_overlap" if use_destination_overlap else "feature_distance"}


def _group_name_for(fields: tuple[str, ...]) -> str:
    return "+".join(name for name, group_fields in FEATURE_GROUPS.items()
                    if set(group_fields) & set(fields))


def _combinations() -> dict[str, tuple[str, ...]]:
    d, s, t = FEATURE_GROUPS["destination"], FEATURE_GROUPS["size"], FEATURE_GROUPS["timing"]
    return {
        "destination_only": d,
        "size_only": s,
        "timing_only": t,
        "destination+size": d + s,
        "destination+timing": d + t,
        "size+timing": s + t,
        "all_three": d + s + t,
    }


def run(seed: int = 20260830) -> dict:
    sessions = build_corpus(seed=seed)
    current_hash = manifest_hash(sessions)
    if current_hash != FROZEN_MANIFEST_SHA256:
        raise RuntimeError(
            "aegis_baseline's corpus generator has changed since the Aegis 0 "
            f"baseline was measured (expected {FROZEN_MANIFEST_SHA256}, got "
            f"{current_hash}) -- every ablation number below would silently "
            "stop being comparable to the frozen 91.7%/78.4% baseline. Fix "
            "the drift or re-freeze deliberately, do not ignore this.")

    combos = _combinations()
    activity_results: dict[str, dict] = {}
    linkability_results: dict[str, dict] = {}
    for name, fields in combos.items():
        # A stable per-combination offset, deliberately NOT Python's built-in
        # hash() (randomized per-process for str unless PYTHONHASHSEED is
        # fixed) -- determinism here matters as much as in the corpus itself.
        offset = sum(ord(c) for c in name)
        rng = random.Random(seed + 1 + offset)
        activity_results[name] = _fit_predict_accuracy(sessions, fields, rng)
        linkability_results[name] = _linkability_for_fields(sessions, fields)

    return {
        "evidence_class": "synthetic mechanism evaluation",
        "independent": False,
        "stage": "Aegis 0.5 -- feature ablation (which feature group carries "
                "the Aegis 0 baseline's information advantage)",
        "frozen_baseline_manifest_sha256": FROZEN_MANIFEST_SHA256,
        "feature_groups": {k: list(v) for k, v in FEATURE_GROUPS.items()},
        "activity_classification_by_combination": {
            name: {**activity_results[name], "random_chance": round(1.0 / len(ACTIVITIES), 4)}
            for name in combos
        },
        "linkability_by_combination": linkability_results,
        "limitations": [
            "Same synthetic corpus as Aegis 0 (manifest pinned above); this "
            "still measures a fixed generative model, not real captured traffic.",
            "n_connections is classified under 'timing' (a frequency/volume "
            "characteristic), not its own group -- a documented judgment "
            "call, not an additional hidden feature group.",
            "Linkability for feature sets without destination information "
            "falls back to standardized feature-distance similarity rather "
            "than destination-set overlap, since there is nothing to overlap "
            "-- the two methods are not numerically comparable to each "
            "other, only each to its own random-chance baseline.",
        ],
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2, default=str))
