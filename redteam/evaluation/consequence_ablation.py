#!/usr/bin/env python3
"""Consequence ablation - does combining privacy and endpoint provenance
actually beat either signal alone?

Evidence class: synthetic mechanism evaluation (structural selectivity).
Independent: no.
Stage: first ablation of `valkyrie/edr/consequence.py`.

THIS IS NOT A DETECTION RATE. It does not run the product, replay an attack,
or touch a live host. Per this project's own standing rule, detection efficacy
is established only by real Atomic Red Team execution on a disposable host
(see docs/LIVE_FIRE_EVALUATION.md). What this measures is narrower and
different: given a population of causal structures, how SELECTIVE is each
decision rule - how often does it fire on ordinary machine activity, and does
it still fire on the cross-layer case it exists to catch.

## Research question

The 2026-09-05 roadmap states the product hypothesis:

    "a local system can distinguish an intended disclosure from a suspicious
    consequence more accurately when it combines scoped user intent with
    endpoint provenance. Test that against privacy-only and endpoint-only
    baselines."

That is the question here, and nothing more. Three arms see the identical
corpus and the identical learned baseline:

  A. privacy-only   - what NYX alone reports: a third-party personal-data
                      disclosure occurred somewhere in this lineage.
  B. endpoint-only  - what the endpoint/causal layer alone reports: a
                      descendant process made an egress this host rarely makes.
  C. combined       - valkyrie/edr/consequence.py, unmodified, imported.

Arm C is the real shipping function. Arms A and B are deliberately written as
the STRONGEST honest version of each half - A is exactly NYX's own observation
predicate, B reuses the same rarity threshold and the same descendant rule the
combined detector uses. B is given the matured baseline too. Neither arm is a
strawman; the only thing removed is the other domain's evidence.

## Why the corpus is shaped the way it is

The result depends entirely on whether the population resembles a real
machine, so the shape mix is the load-bearing assumption and is stated openly:

  * Third-party tracking is UBIQUITOUS in ordinary browsing. A privacy
    observation is therefore a common event, not a rare one.
  * Rare egress is ORDINARY in developer and updater workloads. A
    never-seen-before destination is a routine consequence of installing a
    package or an update, not an intrusion.

Those two facts are what make each single-domain arm noisy, and they are the
honest reason a combination could help. If either were false on a given
machine, this result would not transfer to it. The corpus is hash-frozen so a
later edit cannot silently move the numbers.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from valkyrie.edr.causal_detect import (           # noqa: E402
    MIN_OBSERVATIONS, MIN_SESSIONS, CausalBaseline,
)
from valkyrie.edr.consequence import (             # noqa: E402
    _EGRESS_KINDS, score_privacy_consequence,
)

# Pinned after the first clean run; a corpus edit must fail loudly rather than
# quietly reporting different numbers against a different population.
FROZEN_MANIFEST_SHA256 = \
    "722161dbc0c7f0012311060cf0a8ee6c38f0ec0c8fe0a29994bba8212a435e7e"


# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------

def _sub(owner: str, *, children=(), artifacts=(), inferred=0,
         truncated=False, evicted=0) -> dict:
    """One causality subgraph in the wire shape causality.subgraph() returns."""
    cgo = {"key": "1/1", "pid": 1, "name": owner, "parent_key": ""}
    tree = []
    for i, cname in enumerate(children, start=2):
        tree.append({"key": f"{i}/1", "pid": i, "name": cname,
                     "parent_key": "1/1"})
    return {
        "found": True, "cgo": cgo, "chain": [cgo], "tree": tree,
        "truncated": truncated, "evicted": evicted, "inferred_nodes": inferred,
        "artifacts": [dict(a) for a in artifacts],
    }


def _leak(proc: str, host: str, category: str = "identifier") -> dict:
    """A masked NYX privacy observation, in the metadata-only shape the
    consequence module requires (never raw content)."""
    return {"kind": "nyx_leak", "process": proc,
            "data": {"category": category, "destination_host": host}}


def _egress(proc: str, subject: str, kind: str = "dns") -> dict:
    return {"kind": kind, "process": proc, "data": {"subject": subject}}


def build_corpus() -> list[dict]:
    """Labeled population. `cross_layer` is the ground truth: a genuine
    privacy disclosure that was followed by an unusual descendant egress in
    the same lineage."""
    items: list[dict] = []

    def add(label: str, cross_layer: bool, sub: dict, note: str) -> None:
        items.append({"label": label, "cross_layer": cross_layer,
                      "sub": sub, "note": note})

    # -- Ordinary browsing. Tracking is everywhere; this is the dominant shape
    #    on a real desktop and the reason a bare privacy signal cannot carry a
    #    security verdict on its own.
    for i, tracker in enumerate([
            "doubleclick.net", "google-analytics.com", "facebook.net",
            "scorecardresearch.com", "hotjar.com", "segment.io",
            "branch.io", "adnxs.com", "criteo.com", "taboola.com"]):
        add("benign_browsing_tracked", False,
            _sub("chrome.exe",
                 artifacts=[_leak("chrome.exe", tracker),
                            _egress("chrome.exe", tracker)]),
            f"routine page load disclosing to {tracker}")

    # Same, but the browser also fetched a routine, frequently-seen resource
    # through a helper - still nothing unusual.
    for host in ["cdn.jsdelivr.net", "fonts.gstatic.com", "ajax.googleapis.com"]:
        add("benign_browsing_helper_common", False,
            _sub("chrome.exe", children=["chrome.exe"],
                 artifacts=[_leak("chrome.exe", "doubleclick.net"),
                            _egress("chrome.exe", host)]),
            f"tracked page plus a common resource fetch ({host})")

    # -- Developer / updater work. Novel destinations are the NORMAL outcome of
    #    installing something; this is why a bare rarity signal cannot carry a
    #    security verdict on its own either.
    for i, host in enumerate([
            "registry.npmjs.org", "files.pythonhosted.org", "crates.io",
            "proxy.golang.org", "nuget.org", "rubygems.org",
            "download.jetbrains.com", "objects.githubusercontent.com"]):
        add("benign_dev_rare_egress", False,
            _sub("code.exe", children=["node.exe"],
                 artifacts=[_egress("node.exe", f"pkg{i}.{host}")]),
            f"build/install pulling a never-seen package host ({host})")

    for i, host in enumerate(["update.microsoft.com", "dl.delivery.mp.microsoft.com"]):
        add("benign_updater_rare_egress", False,
            _sub("msiexec.exe", children=["updater.exe"],
                 artifacts=[_egress("updater.exe", f"cdn{i}.{host}")]),
            "updater reaching a novel CDN edge")

    # -- Hard negatives: each isolates ONE guard in the combined rule, so a
    #    regression that removes a guard shows up here as a new false positive
    #    rather than passing silently.
    add("guard_egress_from_owner_itself", False,
        _sub("chrome.exe",
             artifacts=[_leak("chrome.exe", "tracker.example"),
                        _egress("chrome.exe", "never-seen-host.example")]),
        "leak + rare egress, but the browser itself made it (no descendant)")

    add("guard_incomplete_provenance", False,
        _sub("chrome.exe", children=["helper.exe"], inferred=1,
             artifacts=[_leak("chrome.exe", "tracker.example"),
                        _egress("helper.exe", "never-seen-host.example")]),
        "would fire, but ancestry was partly guessed")

    add("guard_non_interactive_owner", False,
        _sub("svchost.exe", children=["helper.exe"],
             artifacts=[_leak("svchost.exe", "tracker.example"),
                        _egress("helper.exe", "never-seen-host.example")]),
        "no human-facing document/browser owner at the root")

    add("guard_ambiguous_destination", False,
        _sub("chrome.exe", children=["helper.exe"],
             artifacts=[_leak("chrome.exe", "tracker-a.example"),
                        _leak("chrome.exe", "tracker-b.example"),
                        _egress("helper.exe", "never-seen-host.example")]),
        "two disclosure destinations - cannot name one consequence")

    # -- The case the detector exists for: a real disclosure in a human-facing
    #    lineage, followed by a descendant reaching somewhere this host does
    #    not normally go.
    for i, (cat, tracker, dest) in enumerate([
            ("identifier", "tracker.example", "collect-99.exfil.example"),
            ("location",   "geo.tracker.example", "geo-drop.exfil.example"),
            ("contact",    "leadgen.example", "crm-drop.exfil.example"),
            ("financial",  "pay-track.example", "settle.exfil.example")]):
        add("cross_layer_consequence", True,
            _sub("chrome.exe", children=["helper.exe"],
                 artifacts=[_leak("chrome.exe", tracker, cat),
                            _egress("helper.exe", dest)]),
            f"{cat} disclosed to {tracker}, then a rare descendant egress")

    add("cross_layer_consequence", True,
        _sub("winword.exe", children=["helper.exe"],
             artifacts=[_leak("winword.exe", "doctrack.example"),
                        _egress("helper.exe", "doc-drop.exfil.example", "network")]),
        "document lineage: disclosure then rare descendant network egress")

    # -- BLIND-SPOT PROBE. Identical in intent to the cases above, but the
    #    descendant egress is made by a process name this host runs constantly
    #    (node.exe). `CausalBaseline.artifact_rarity` is keyed on
    #    (process_name, artifact_kind) and never looks at the destination, so
    #    a novel destination reached through an ordinary process name has
    #    rarity 0.0. This probe exists to MEASURE that, not to pad the score.
    add("cross_layer_common_process_name", True,
        _sub("chrome.exe", children=["node.exe"],
             artifacts=[_leak("chrome.exe", "tracker.example"),
                        _egress("node.exe", "never-seen-drop.exfil.example")]),
        "same consequence, but egress rides a routinely-seen process name")

    return items


def manifest_sha256(corpus: list[dict]) -> str:
    """Stable hash of the corpus, so results always name the population they
    were measured on."""
    payload = json.dumps(
        [{"label": c["label"], "cross_layer": c["cross_layer"], "sub": c["sub"]}
         for c in corpus],
        sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


# ---------------------------------------------------------------------------
# The learned baseline
# ---------------------------------------------------------------------------

def learn_baseline(corpus: list[dict]) -> CausalBaseline:
    """Mature the baseline on BENIGN structures only - the honest analogue of
    a machine that has been running normally for a while.

    The true-positive structures are never learned from; letting the baseline
    see them would teach it that the thing being detected is normal, which
    would be measuring nothing. Benign items are replayed until the maturity
    guards are satisfied, exactly as a real host would accumulate them.
    """
    baseline = CausalBaseline()
    # Learn ONLY from ordinary-activity structures. The `guard_*` items are
    # adversarial probes built to isolate one guard each - they are not "what
    # this machine normally does", and learning from them poisons the very
    # thing under test. (Found the hard way: the first run of this ablation
    # learned from them, which taught the baseline that `helper.exe` making
    # DNS queries is routine and suppressed 4 of 5 true positives.)
    benign = [c for c in corpus
              if not c["cross_layer"] and c["label"].startswith("benign_")]
    sessions = max(MIN_SESSIONS, 3)
    per_session = -(-MIN_OBSERVATIONS // sessions) + 1     # ceil, plus margin
    for _ in range(sessions):
        baseline.start_session()
        for i in range(per_session):
            baseline.observe_subgraph(benign[i % len(benign)]["sub"])
    return baseline


# ---------------------------------------------------------------------------
# The three arms
# ---------------------------------------------------------------------------

def arm_privacy_only(sub: dict, baseline: CausalBaseline) -> bool:
    """NYX's own predicate: personal data crossed to a third party here."""
    return any(str(a.get("kind") or "").lower() == "nyx_leak"
               for a in sub.get("artifacts") or [])


def arm_endpoint_only(sub: dict, baseline: CausalBaseline) -> bool:
    """The endpoint half alone: a descendant made a rare egress. Same rarity
    threshold, same descendant rule, same matured baseline the combined
    detector gets - only the privacy evidence is withheld."""
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
        if subject and baseline.artifact_rarity(proc, kind) >= 0.90:
            return True
    return False


def arm_combined(sub: dict, baseline: CausalBaseline) -> bool:
    """The shipping function, imported unmodified."""
    return score_privacy_consequence(sub, baseline).fires


ARMS = {
    "privacy-only":  arm_privacy_only,
    "endpoint-only": arm_endpoint_only,
    "combined":      arm_combined,
}


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

def run() -> dict:
    corpus = build_corpus()
    digest = manifest_sha256(corpus)
    if FROZEN_MANIFEST_SHA256 and digest != FROZEN_MANIFEST_SHA256:
        raise SystemExit(
            f"corpus changed: {digest} != frozen {FROZEN_MANIFEST_SHA256}. "
            "Re-freeze deliberately if the change is intended.")

    baseline = learn_baseline(corpus)
    if not baseline.mature:
        raise SystemExit("baseline failed to mature - the ablation would be void")

    results: dict = {"manifest_sha256": digest,
                     "baseline": {"observations": baseline.observations,
                                  "sessions": baseline.sessions,
                                  "mature": baseline.mature},
                     "corpus_size": len(corpus),
                     "cross_layer_cases": sum(1 for c in corpus if c["cross_layer"]),
                     "benign_cases": sum(1 for c in corpus if not c["cross_layer"]),
                     "arms": {}}

    for name, fn in ARMS.items():
        tp = fp = fn_miss = 0
        fired_benign: list[str] = []
        missed: list[str] = []
        for case in corpus:
            fired = bool(fn(case["sub"], baseline))
            if case["cross_layer"]:
                if fired:
                    tp += 1
                else:
                    fn_miss += 1
                    missed.append(case["note"])
            elif fired:
                fp += 1
                fired_benign.append(f'{case["label"]}: {case["note"]}')
        total_pos = tp + fp
        precision = (tp / total_pos) if total_pos else None
        recall = tp / max(1, results["cross_layer_cases"])
        results["arms"][name] = {
            "true_positives": tp, "false_positives": fp, "missed": fn_miss,
            "precision": precision, "recall": recall,
            "fired_on_benign": fired_benign, "missed_cases": missed,
        }

    # Why the combined arm declined each benign structure - the refusal
    # reasons are the mechanism, so they are reported rather than summarized.
    refusals: dict[str, int] = {}
    for case in corpus:
        if case["cross_layer"]:
            continue
        finding = score_privacy_consequence(case["sub"], baseline)
        if not finding.fires:
            key = finding.suppressed_by or "unspecified"
            refusals[key] = refusals.get(key, 0) + 1
    results["combined_refusal_reasons"] = refusals
    return results


def main(argv: list[str]) -> int:
    if "--freeze" in argv:
        print(manifest_sha256(build_corpus()))
        return 0

    r = run()
    print("\n=== consequence ablation: privacy-only vs endpoint-only vs combined ===")
    print("EVIDENCE CLASS: synthetic mechanism evaluation. NOT a detection rate.")
    print(f"\ncorpus {r['corpus_size']} structures "
          f"({r['benign_cases']} benign, {r['cross_layer_cases']} cross-layer)")
    print(f"manifest sha256 {r['manifest_sha256'][:16]}...")
    print(f"baseline matured at {r['baseline']['observations']} observations "
          f"across {r['baseline']['sessions']} sessions "
          f"(gates: {MIN_OBSERVATIONS}/{MIN_SESSIONS})")

    print(f"\n{'arm':<16}{'caught':>8}{'missed':>8}{'false pos':>11}{'precision':>11}")
    print("-" * 54)
    for name, a in r["arms"].items():
        prec = "n/a" if a["precision"] is None else f"{a['precision']*100:.0f}%"
        print(f"{name:<16}{a['true_positives']:>8}{a['missed']:>8}"
              f"{a['false_positives']:>11}{prec:>11}")

    for name, a in r["arms"].items():
        if a["fired_on_benign"]:
            print(f"\n{name} fired on {len(a['fired_on_benign'])} benign structures, e.g.:")
            for line in a["fired_on_benign"][:4]:
                print(f"  - {line}")
        if a["missed_cases"]:
            print(f"\n{name} missed:")
            for line in a["missed_cases"]:
                print(f"  - {line}")

    print("\ncombined arm's refusal reasons on benign structures:")
    for reason, n in sorted(r["combined_refusal_reasons"].items(),
                            key=lambda kv: -kv[1]):
        print(f"  {n:>3}x  {reason}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
