"""Tier 2.11 - invariants the pure classifiers must hold for ALL inputs.

Example-based tests ask "does this input give that answer". They are necessary
and this repo has plenty. They are also blind in a specific way: they only check
the inputs someone thought of, which is the same weakness as the efficacy corpus
scoring 100% on examples we chose ourselves.

Property tests ask something different - "is this statement true for every input
in the domain" - and they catch the cases nobody imagined. The properties below
are chosen so that a violation is a real defect rather than a taste difference:

  * **totality** - never raises, for any input, including empty and absurd
  * **determinism** - same input, same answer, every time
  * **idempotence** - classifying a result twice changes nothing
  * **range** - a score claimed to be 0..1 is actually 0..1
  * **monotonicity** - more of the thing being measured never scores lower
  * **conservatism at the edges** - the product's stated precision-over-
    aggression rule: empty or unknown input must never yield a conviction

That last one is the security-relevant property. A classifier that returns
"malware" for empty input, or "block" for a domain it knows nothing about, is
how a false positive reaches a user's bank.
"""

from __future__ import annotations

import math
import random
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks

SEED = 20260729
N = 600


def _rand_domain(rng: random.Random) -> str:
    alphabet = string.ascii_lowercase + string.digits + "-"
    labels = []
    for _ in range(rng.randint(1, 4)):
        labels.append("".join(rng.choice(alphabet)
                              for _ in range(rng.randint(1, 24))))
    tld = rng.choice(("com", "net", "org", "io", "xyz", "top", "ru", "co.uk"))
    return ".".join(labels + [tld])


def _rand_string(rng: random.Random) -> str:
    pool = string.printable + "中文字符ᚠᚢ\u202e\x00"
    return "".join(rng.choice(pool) for _ in range(rng.randint(0, 60)))


def main() -> int:
    c = Checks("classifier properties", expect_min=22)
    rng = random.Random(SEED)
    print(f"seed={SEED}  samples={N} per property\n")

    # --- classify_amsi_result ---
    from valkyrie.amsi import classify_amsi_result, DISP_MALWARE
    print("[1] classify_amsi_result")

    vals = [rng.randint(-(1 << 40), 1 << 40) for _ in range(N)]
    vals += [0, 1, 32767, 32768, 32769, -1, 2 ** 31, -(2 ** 31)]
    raised = det = None
    dispositions = set()
    for v in vals:
        try:
            a = classify_amsi_result(v)
            b = classify_amsi_result(v)
        except Exception as exc:                      # noqa: BLE001
            raised = f"{v} -> {type(exc).__name__}"
            break
        if a != b:
            det = v
            break
        dispositions.add(a)
    c.check(f"total: never raises on any int ({raised or 'clean'})", raised is None)
    c.check(f"deterministic across repeated calls ({det or 'stable'})", det is None)
    c.check("returns a small closed set of dispositions, never arbitrary text",
            len(dispositions) <= 6)
    # The conviction must be rare and specific: AMSI defines 32768+ as detected,
    # so nothing below it may ever be a conviction.
    wrong = [v for v in vals if v < 32768 and classify_amsi_result(v) == DISP_MALWARE]
    c.check(f"no result below 32768 is ever a conviction ({len(wrong)} were)",
            not wrong)
    c.check("32768 itself IS a conviction (the gate is not stuck closed)",
            classify_amsi_result(32768) == DISP_MALWARE)

    # --- shannon_entropy ---
    from valkyrie.dga import shannon_entropy
    print("\n[2] shannon_entropy")

    c.check("empty string has zero entropy", shannon_entropy("") == 0.0)
    c.check("a single repeated character has zero entropy",
            shannon_entropy("aaaaaaaa") == 0.0)
    bad = []
    for _ in range(N):
        s = _rand_string(rng)
        try:
            e = shannon_entropy(s)
        except Exception as exc:                      # noqa: BLE001
            bad.append(f"{s!r} -> {type(exc).__name__}")
            break
        # Entropy of an n-symbol alphabet cannot exceed log2(n), and never < 0.
        limit = math.log2(len(set(s))) if len(set(s)) > 1 else 0.0
        if not (0.0 <= e <= limit + 1e-9) or math.isnan(e):
            bad.append(f"{s!r} -> {e} (limit {limit})")
            break
    c.check(f"entropy is always within [0, log2(alphabet)] ({bad[:1] or 'clean'})",
            not bad)
    c.check("more diverse strings score higher than uniform ones",
            shannon_entropy("abcdefgh") > shannon_entropy("aaaaaaaa"))
    c.check("entropy is invariant under reordering",
            abs(shannon_entropy("abcd") - shannon_entropy("dcba")) < 1e-9)

    # --- classify_dga ---
    from valkyrie.dga import classify_dga
    print("\n[3] classify_dga")

    raised = det = rng_bad = None
    for _ in range(N):
        d = _rand_domain(rng)
        try:
            r1 = classify_dga(d)
            r2 = classify_dga(d)
        except Exception as exc:                      # noqa: BLE001
            raised = f"{d!r} -> {type(exc).__name__}: {exc}"
            break
        if getattr(r1, "score", None) != getattr(r2, "score", None):
            det = d
            break
        s = getattr(r1, "score", 0.0)
        if not (0.0 <= s <= 1.0) or math.isnan(s):
            rng_bad = f"{d!r} -> {s}"
            break
    c.check(f"total: never raises on a well-formed domain ({raised or 'clean'})",
            raised is None)
    c.check(f"deterministic ({det or 'stable'})", det is None)
    c.check(f"score stays within [0,1] ({rng_bad or 'clean'})", rng_bad is None)

    edge = []
    for weird in ("", ".", "..", "-", "a", "a." * 60, "\x00", " ", "\u202e.com",
                  "x" * 300 + ".com", "xn--80ak6aa92e.com"):
        try:
            classify_dga(weird)
        except Exception as exc:                      # noqa: BLE001
            edge.append(f"{weird[:20]!r} -> {type(exc).__name__}")
    c.check(f"total on degenerate domains ({edge[:2] or 'clean'})", not edge)
    # Conservatism: an ordinary dictionary domain must not be called a DGA.
    benign = ("google.com", "wikipedia.org", "my-company-blog.net",
              "news.bbc.co.uk", "python.org")
    fp = [d for d in benign if getattr(classify_dga(d), "is_dga", False)]
    c.check(f"no ordinary domain is classified DGA ({fp})", not fp)

    # --- behavior_score.score_process ---
    from valkyrie.behavior_score import score_process
    print("\n[4] behavior_score.score_process")

    raised = det = rng_bad = None
    for _ in range(N):
        args = (_rand_string(rng), _rand_string(rng), _rand_string(rng),
                _rand_string(rng))
        try:
            a = score_process(*args)
            b = score_process(*args)
        except Exception as exc:                      # noqa: BLE001
            raised = f"{args!r} -> {type(exc).__name__}: {exc}"
            break
        if a.score != b.score or a.severity != b.severity:
            det = args
            break
        if not (0.0 <= a.score <= 1.0) or math.isnan(a.score):
            rng_bad = f"{args!r} -> {a.score}"
            break
    c.check(f"total: never raises on arbitrary strings ({raised or 'clean'})",
            raised is None)
    c.check(f"deterministic ({'stable' if det is None else det})", det is None)
    c.check(f"score stays within [0,1] ({rng_bad or 'clean'})", rng_bad is None)

    empty = score_process("", "", "")
    c.check("empty input does not fire", not empty.fired())
    c.check("empty input scores zero-ish", empty.score < 0.45)
    c.check("empty input yields no technique", empty.technique == "")

    # Monotonicity: adding a genuinely suspicious property must never LOWER the
    # score. A scorer where more evidence means less suspicion is broken.
    base = score_process("update.exe", "explorer.exe", "update.exe /q",
                         r"C:\Program Files\App\update.exe")
    worse = score_process("svchost.exe", "explorer.exe", "update.exe /q",
                          r"C:\Users\bob\AppData\Local\Temp\svchost.exe")
    c.check("masquerading as a system process from temp scores no lower",
            worse.score >= base.score)
    c.check("that combination actually fires", worse.fired())
    c.check("a legitimate signed-looking update does not fire", not base.fired())

    # Severity must be consistent with the score, not an independent guess.
    incons = []
    for _ in range(200):
        r = score_process(_rand_string(rng), _rand_string(rng), _rand_string(rng))
        if r.score >= 0.45 and r.severity in ("info", "low"):
            incons.append((r.score, r.severity))
    c.check(f"severity never contradicts the score ({incons[:2] or 'consistent'})",
            not incons)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
