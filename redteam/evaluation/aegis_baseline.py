"""Aegis 0 -- Measurement. No mitigation exists yet, on purpose.

"If you can't measure leakage, you can't claim you're improving privacy."
Before Aegis transforms a single packet, this establishes the number any
future transformation has to beat: given ONLY what a network-level observer
can actually see -- destination, size, and timing, never process/app
identity, which is invisible on the wire -- how much can it infer about
controlled benign activity?

Two questions, matching the exposure model's own dimensions:

  1. ACTIVITY CLASSIFICATION -- browsing vs streaming vs messaging vs file
     sync vs software update vs background telemetry: can an observer tell
     them apart from connection-level metadata alone?
  2. CROSS-SESSION LINKABILITY -- can an observer tell that two separate
     sessions belong to the SAME user, from the destinations each one
     touches, without ever seeing a stable identifier?

The classifier here is a deterministic nearest-centroid over engineered
features -- no ML library, print-the-math auditable, matching the "don't
jump to AI" principle applied to Detection Architecture v2. It exists to be
a real, non-strawman adversary: if it doesn't clear random chance by a wide
margin, it isn't a meaningful baseline for a later Aegis mechanism to beat.

Evidence class: synthetic mechanism evaluation. This is a fabricated corpus
with a fixed generative model (see build_corpus), not captured real traffic.
It measures how classifiable THIS synthetic model of benign activity is, not
how classifiable a real machine's real traffic is. That gap is the honest
limit of every stage of Aegis until a live capture exists -- see
docs/AEGIS_0_MEASUREMENT_BASELINE.md.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
import statistics
from dataclasses import asdict, dataclass

SCHEMA = "valkyrie-aegis-baseline/1"

ACTIVITIES = (
    "browsing", "streaming", "messaging", "file_sync",
    "software_update", "background_telemetry",
)

# One synthetic generative recipe per activity class -- deliberately NOT
# perfectly separable (real traffic classes overlap too), but each class has
# a genuinely different shape, exactly like real browsing/streaming/
# messaging/sync/update/telemetry traffic differs on the wire.
_RECIPES = {
    "browsing":            {"n": (8, 30), "ipi": (0.5, 4.0), "size": (200, 4000),
                            "dest_pool": 200, "dest_per_session": (4, 15)},
    "streaming":           {"n": (10, 40), "ipi": (1.5, 2.5), "size": (60000, 120000),
                            "dest_pool": 4, "dest_per_session": (1, 2)},
    "messaging":           {"n": (20, 60), "ipi": (2.0, 15.0), "size": (80, 400),
                            "dest_pool": 2, "dest_per_session": (1, 2)},
    "file_sync":           {"n": (3, 10), "ipi": (10.0, 60.0), "size": (20000, 90000),
                            "dest_pool": 1, "dest_per_session": (1, 1)},
    "software_update":     {"n": (1, 3), "ipi": (60.0, 300.0), "size": (500000, 4000000),
                            "dest_pool": 3, "dest_per_session": (1, 1)},
    "background_telemetry": {"n": (10, 25), "ipi": (25.0, 35.0), "size": (150, 600),
                             "dest_pool": 5, "dest_per_session": (2, 4)},
}


@dataclass(frozen=True)
class Connection:
    t: float
    destination: str
    size_bytes: int


@dataclass(frozen=True)
class Session:
    session_id: str
    activity: str
    user_id: str
    connections: tuple[Connection, ...]

    def manifest_record(self) -> dict:
        return {"session_id": self.session_id, "activity": self.activity,
                "user_id": self.user_id,
                "connections": [asdict(c) for c in self.connections]}


@dataclass(frozen=True)
class Features:
    n_connections: int
    mean_size: float
    std_size: float
    mean_ipi: float
    std_ipi: float
    n_distinct_destinations: int
    top_destination_share: float
    duration: float


def _destination_pool_for(activity: str, user_id: str) -> list[str]:
    """The class-general pool of possible destinations, PLUS a small
    per-user "favorites" subset layered on top -- the honest source of
    cross-session linkability signal, exactly like a real person's repeated
    browsing destinations, not an artificial marker planted for the test."""
    recipe = _RECIPES[activity]
    general = [f"{activity}-dest-{i}" for i in range(recipe["dest_pool"])]
    if activity in ("browsing", "background_telemetry"):
        favorites = [f"fav-{user_id}-{i}" for i in range(3)]
        return general + favorites
    return general


def _make_session(rng: random.Random, activity: str, user_id: str,
                  session_id: str) -> Session:
    recipe = _RECIPES[activity]
    pool = _destination_pool_for(activity, user_id)
    k = min(len(pool), rng.randint(*recipe["dest_per_session"]))
    # Favor a user's own favorites when present, same as real repeat visits.
    favorites = [d for d in pool if d.startswith("fav-")]
    rest = [d for d in pool if not d.startswith("fav-")]
    chosen: list[str] = []
    if favorites:
        chosen += rng.sample(favorites, min(len(favorites), max(1, k // 2)))
    remaining = k - len(chosen)
    if remaining > 0 and rest:
        chosen += rng.sample(rest, min(remaining, len(rest)))
    if not chosen:
        chosen = rng.sample(pool, k)

    n = rng.randint(*recipe["n"])
    t = 0.0
    conns = []
    for _ in range(n):
        t += max(0.05, rng.uniform(*recipe["ipi"]) * rng.uniform(0.6, 1.4))
        size = int(rng.uniform(*recipe["size"]) * rng.uniform(0.85, 1.15))
        dest = rng.choice(chosen)
        conns.append(Connection(round(t, 3), dest, max(1, size)))
    return Session(session_id, activity, user_id, tuple(conns))


def build_corpus(seed: int = 20260830, sessions_per_class: int = 40,
                 n_users: int = 12) -> tuple[Session, ...]:
    """Deterministic synthetic corpus: every class gets the same session
    count, and browsing/background_telemetry sessions are distributed across
    n_users so cross-session linkability has real same-user pairs to find."""
    rng = random.Random(seed)
    sessions: list[Session] = []
    counter = 0
    for activity in ACTIVITIES:
        for i in range(sessions_per_class):
            user_id = f"user-{i % n_users}"
            counter += 1
            sessions.append(_make_session(rng, activity, user_id,
                                          f"{activity}-{counter:04d}"))
    return tuple(sessions)


def manifest_hash(sessions: tuple[Session, ...]) -> str:
    payload = [s.manifest_record() for s in sessions]
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def extract_features(session: Session) -> Features:
    """Only what a network observer can see: sizes, timing, destination
    identifiers. Never the process/app name -- that's invisible on the wire,
    and using it here would make the whole baseline dishonest."""
    conns = session.connections
    sizes = [c.size_bytes for c in conns]
    times = [c.t for c in conns]
    ipis = [b - a for a, b in zip(times, times[1:])] or [0.0]
    dests = [c.destination for c in conns]
    top_share = (max(dests.count(d) for d in set(dests)) / len(dests)) if dests else 0.0
    return Features(
        n_connections=len(conns),
        mean_size=statistics.fmean(sizes) if sizes else 0.0,
        std_size=statistics.pstdev(sizes) if len(sizes) > 1 else 0.0,
        mean_ipi=statistics.fmean(ipis),
        std_ipi=statistics.pstdev(ipis) if len(ipis) > 1 else 0.0,
        n_distinct_destinations=len(set(dests)),
        top_destination_share=top_share,
        duration=(times[-1] - times[0]) if times else 0.0,
    )


_FEATURE_NAMES = tuple(Features.__dataclass_fields__)


def _vector(features: Features) -> tuple[float, ...]:
    return tuple(getattr(features, name) for name in _FEATURE_NAMES)


class Standardizer:
    """z-score each feature using TRAIN-set statistics only, so the test set
    never leaks its own distribution into the classifier's notion of scale."""

    def __init__(self, vectors: list[tuple[float, ...]]) -> None:
        cols = list(zip(*vectors))
        self.means = [statistics.fmean(c) for c in cols]
        self.stdevs = [statistics.pstdev(c) or 1.0 for c in cols]

    def apply(self, vector: tuple[float, ...]) -> tuple[float, ...]:
        return tuple((v - m) / s for v, m, s in zip(vector, self.means, self.stdevs))


def _centroid(vectors: list[tuple[float, ...]]) -> tuple[float, ...]:
    cols = list(zip(*vectors))
    return tuple(statistics.fmean(c) for c in cols)


def _distance(a: tuple[float, ...], b: tuple[float, ...]) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


@dataclass(frozen=True)
class ActivityClassifier:
    """Deterministic nearest-centroid classifier, fit on a TRAIN split."""
    standardizer: Standardizer
    centroids: dict  # activity -> standardized centroid vector

    @classmethod
    def fit(cls, sessions: list[Session]) -> "ActivityClassifier":
        vectors = [_vector(extract_features(s)) for s in sessions]
        standardizer = Standardizer(vectors)
        by_activity: dict[str, list[tuple[float, ...]]] = {a: [] for a in ACTIVITIES}
        for s, v in zip(sessions, vectors):
            by_activity[s.activity].append(standardizer.apply(v))
        centroids = {a: _centroid(vs) for a, vs in by_activity.items() if vs}
        return cls(standardizer, centroids)

    def predict(self, session: Session) -> str:
        v = self.standardizer.apply(_vector(extract_features(session)))
        return min(self.centroids, key=lambda a: _distance(v, self.centroids[a]))


def _train_test_split(sessions: tuple[Session, ...], train_fraction: float,
                      rng: random.Random) -> tuple[list[Session], list[Session]]:
    by_activity: dict[str, list[Session]] = {a: [] for a in ACTIVITIES}
    for s in sessions:
        by_activity[s.activity].append(s)
    train: list[Session] = []
    test: list[Session] = []
    for activity, group in by_activity.items():
        shuffled = list(group)
        rng.shuffle(shuffled)
        cut = max(1, int(len(shuffled) * train_fraction))
        train += shuffled[:cut]
        test += shuffled[cut:]
    return train, test


def _activity_classification_report(sessions: tuple[Session, ...],
                                    rng: random.Random) -> dict:
    train, test = _train_test_split(sessions, 0.7, rng)
    clf = ActivityClassifier.fit(train)
    correct = 0
    confusion: dict[str, dict[str, int]] = {a: {b: 0 for b in ACTIVITIES} for a in ACTIVITIES}
    for s in test:
        predicted = clf.predict(s)
        confusion[s.activity][predicted] += 1
        correct += int(predicted == s.activity)
    accuracy = correct / len(test) if test else 0.0
    return {
        "train": len(train), "test": len(test),
        "accuracy": round(accuracy, 4),
        "random_chance": round(1.0 / len(ACTIVITIES), 4),
        "confusion_matrix": confusion,
    }


def _destination_set(session: Session) -> frozenset[str]:
    return frozenset(c.destination for c in session.connections)


def _jaccard(a: frozenset, b: frozenset) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def _linkability_report(sessions: tuple[Session, ...], rng: random.Random) -> dict:
    """Can an observer tell two sessions belong to the same user, using only
    destination-set overlap -- no stable identifier is ever used, exactly the
    constraint a real network observer faces."""
    # Restrict to sessions that actually touch a personal-favorite
    # destination; a class with no personal destinations (e.g.
    # software_update, drawn from a tiny shared pool) would make every pair
    # look "linked" for a reason that has nothing to do with the user, so
    # it's excluded here rather than silently inflating the score.
    candidates = [s for s in sessions if any(
        d.startswith("fav-") for d in _destination_set(s))]
    if len(candidates) < 4:
        return {"pairs": 0, "note": "not enough sessions with personal "
                                    "destinations to measure linkability"}

    same_user_scores: list[float] = []
    diff_user_scores: list[float] = []
    for i, a in enumerate(candidates):
        for b in candidates[i + 1:]:
            if a.activity != b.activity:
                continue
            score = _jaccard(_destination_set(a), _destination_set(b))
            (same_user_scores if a.user_id == b.user_id else diff_user_scores).append(score)

    if not same_user_scores or not diff_user_scores:
        return {"pairs": 0, "note": "no comparable same/different-user pairs"}

    # Same-user pairs are rare by construction (one user, one activity) next
    # to different-user pairs -- 94 vs 1427 in a typical run here. Raw
    # accuracy under that imbalance is dominated by the trivial "always guess
    # different" rule (~93.8% on its own), so the threshold is chosen to
    # maximize BALANCED accuracy (mean of same-user recall and
    # different-user recall) instead, and the majority-class floor is
    # reported explicitly so raw accuracy can never be misread as skill.
    all_scores = sorted(set(same_user_scores + diff_user_scores))
    best_balanced, best_threshold, best_raw = 0.0, 0.0, 0.0
    for threshold in all_scores:
        tpr = sum(s >= threshold for s in same_user_scores) / len(same_user_scores)
        tnr = sum(s < threshold for s in diff_user_scores) / len(diff_user_scores)
        balanced = 0.5 * (tpr + tnr)
        if balanced > best_balanced:
            tp = sum(s >= threshold for s in same_user_scores)
            tn = sum(s < threshold for s in diff_user_scores)
            best_raw = (tp + tn) / (len(same_user_scores) + len(diff_user_scores))
            best_balanced, best_threshold = balanced, threshold

    majority_class_floor = max(len(same_user_scores), len(diff_user_scores)) / (
        len(same_user_scores) + len(diff_user_scores))

    return {
        "pairs": len(same_user_scores) + len(diff_user_scores),
        "same_user_pairs": len(same_user_scores),
        "different_user_pairs": len(diff_user_scores),
        "mean_same_user_overlap": round(statistics.fmean(same_user_scores), 4),
        "mean_different_user_overlap": round(statistics.fmean(diff_user_scores), 4),
        "best_threshold_balanced_accuracy": round(best_balanced, 4),
        "best_threshold_raw_accuracy": round(best_raw, 4),
        "majority_class_floor": round(majority_class_floor, 4),
        "balanced_random_chance": 0.5,
        "threshold_used": round(best_threshold, 4),
        "note": "compare balanced_accuracy to balanced_random_chance (0.5), "
                "not raw_accuracy to majority_class_floor -- same/different "
                "pairs are heavily imbalanced (see docstring)",
    }


def run(seed: int = 20260830) -> dict:
    sessions = build_corpus(seed=seed)
    rng = random.Random(seed + 1)
    return {
        "evidence_class": "synthetic mechanism evaluation",
        "independent": False,
        "stage": "Aegis 0 -- Measurement (no privacy transformation applied)",
        "manifest_sha256": manifest_hash(sessions),
        "corpus": {"total_sessions": len(sessions),
                  "activities": list(ACTIVITIES),
                  "sessions_per_activity": len(sessions) // len(ACTIVITIES)},
        "activity_classification": _activity_classification_report(sessions, rng),
        "cross_session_linkability": _linkability_report(sessions, rng),
        "limitations": [
            "Synthetic corpus with a fixed generative model, not captured "
            "real traffic -- this measures how classifiable THIS model of "
            "benign activity is, not a real machine's real traffic.",
            "The classifier sees only destination identifier, size, and "
            "timing -- never process/app identity, which is invisible on "
            "the wire. That is deliberate: it is the honest observer model.",
            "No mitigation exists yet. This number is the baseline every "
            "future Aegis stage (1: exposure minimization, 2: identity/"
            "activity separation, 3: traffic-analysis resistance) must beat "
            "-- and must be re-measured against a classifier retrained "
            "KNOWING that mechanism exists, or the improvement is an "
            "illusion (see docs/AEGIS_0_MEASUREMENT_BASELINE.md).",
        ],
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, default=str))
