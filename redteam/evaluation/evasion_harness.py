"""Evasion tier - obfuscated variants of every command-line technique in the
Tier A catalog, scored through the SAME real classifiers Tier A uses.

## Why this exists

`docs/adr/0042-command-line-normalization.md` measured evasion resistance
against a hand-built 12-variant corpus (3/8 -> 12/12) and said plainly what
was still missing: "the red-team catalog replays unobfuscated command
lines... An obfuscated-variant evaluation tier is the honest way to score
it, and does not exist yet." This is that tier.

## What this measures, precisely

For every in-scope Tier A technique whose `probe_input` carries a `cmdline`
field (25 of 40 - the rest are DNS/network/registry/entropy techniques that
have no command-line syntax to obfuscate), this generates obfuscated
variants of that exact command line and re-runs the technique's OWN probe
function - the real classifier, unchanged - against each variant. It reuses
`replay_harness.run_technique` directly, so a variant is scored by the exact
same DETECT/CONDITIONAL/MISS gate as unobfuscated Tier A: `counted_as_detected`
still requires `predicted_tier_b == "DETECT"`, the real code firing, no
known_mismatch, and host preconditions met. Nothing here is scored more
leniently than Tier A.

## Transforms

Four transforms that mechanically apply to (almost) any command line, chosen
to match the categories in the backlog and in ADR 0042's own corpus:

  * `caret_escape`      - cmd.exe caret escaping (`n^et`)
  * `quote_split`       - token-splitting empty quote pairs (`us""er`)
  * `powershell_concat` - PowerShell string concatenation (`('ne'+'t')`)
  * `unicode_fullwidth` - full-width Latin homoglyphs on the leading token

Not attempted here, and why: **env-var expansion** (`%COMSPEC:~0,1%...`) only
makes sense against a literal path substring most catalog entries don't
contain, and **base64 `-EncodedCommand`** only makes sense wrapping an actual
PowerShell payload - forcing either onto an arbitrary technique's cmdline
would produce a syntactically bogus "obfuscated" string that proves nothing.
Both are ALREADY measured directly and honestly by
`tests/test_cmdline_normalize.py`'s dedicated corpus (12/12, per ADR 0042);
duplicating that badly here would be worse than not duplicating it at all.

A transform that cannot apply to a given cmdline (e.g. `quote_split` on a
string with no 4+ letter run) returns None and the (technique, transform)
pair is recorded as N/A, not as a false pass or a false fail.

## Honest boundary

This is still Tier A: classifier-input replay, not a live attack. It answers
"does the code recognise this exact obfuscated shape", not "would this
survive a live obfuscated Atomic Red Team run." The two techniques already
known to miss at baseline (`disc-local-accounts`, `lat-psexec-smb`) cannot
regress further - they are reported as baseline misses, not evasion wins.

Run:  PYTHONUTF8=1 python redteam/evaluation/evasion_harness.py
"""

from __future__ import annotations

import dataclasses
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from catalog import CATALOG_VERSION, Technique, all_in_scope   # noqa: E402
from replay_harness import _build_ctx, run_technique           # noqa: E402

TIER = "A_replay_evasion"

# ---------------------------------------------------------------------------
# Transforms - pure string -> string|None. None means "does not apply to
# this input shape", recorded honestly rather than faked or silently skipped.
# ---------------------------------------------------------------------------

_WORD = re.compile(r"[A-Za-z]{4,}")


def _caret_escape(cmd: str) -> Optional[str]:
    """cmd.exe treats `^` before any character as a no-op escape. Applied to
    every 4+ letter run, matching ADR 0042's own `n^et us^er` example."""
    def repl(m: "re.Match[str]") -> str:
        w = m.group(0)
        return w[0] + "^" + w[1:]
    out, n = _WORD.subn(repl, cmd)
    return out if n else None


def _quote_split(cmd: str) -> Optional[str]:
    """cmd.exe's token-splitting quote: a quote pair wrapped around a single
    MIDDLE character is invisible to the parser but breaks a substring match
    - 'user' -> 'u"s"er', matching the exact `n"e"t` shape in ADR 0042 and
    cmdline_normalize.py's own _RE_SPLIT_QUOTE (quote with a word character
    on BOTH sides). An earlier draft of this transform used an adjacent empty
    pair ('us""er'), which is a different, non-matching shape - verified
    against the real normalizer directly, not assumed."""
    m = _WORD.search(cmd)
    if not m:
        return None
    w = m.group(0)
    mid = len(w) // 2
    spliced = w[:mid] + '"' + w[mid] + '"' + w[mid + 1:]
    return cmd[:m.start()] + spliced + cmd[m.end():]


def _ps_concat(cmd: str) -> Optional[str]:
    """PowerShell string-concatenation on the LEADING token only (the
    exe/verb a rule most often keys on): 'net user ...' -> "& ('ne'+'t')
    user ...". Requires the leading token to be a bare alphabetic word
    (optionally with a simple extension) - a UNC path or flag as the first
    token has no natural concat form, so this returns None for those."""
    parts = cmd.split(" ", 1)
    first = parts[0]
    m = re.match(r"^([A-Za-z]{2,})(\.[A-Za-z]{1,4})?$", first)
    if not m:
        return None
    base, ext = m.group(1), (m.group(2) or "")
    mid = len(base) // 2
    frag = f"('{base[:mid]}'+'{base[mid:]}'{('+' + repr(ext)) if ext else ''})"
    rest = f" {parts[1]}" if len(parts) > 1 else ""
    return f"& {frag}{rest}"


def _unicode_fullwidth(cmd: str) -> Optional[str]:
    """Full-width Latin homoglyphs (U+FF21-FF5A / U+FF01-FF5E range) on the
    first 4+ letter run - renders identically to a human, byte-different to
    naive substring matching. Same unicode-substitution class cmdline_normalize
    folds back to ASCII."""
    m = _WORD.search(cmd)
    if not m:
        return None
    w = m.group(0)
    fw = "".join(chr(ord(ch) + 0xFEE0) if "a" <= ch.lower() <= "z" else ch for ch in w)
    return cmd[:m.start()] + fw + cmd[m.end():]


# ---------------------------------------------------------------------------
# HEAVIER PLATES (added 2026-08-23). The four transforms above each hit a fold
# `cmdline_normalize` already implements, so they resist at 100% - a scale
# with no travel left. Progressive overload needs weight the bar does not yet
# move: transforms that stack (which the single-transform tier never stressed
# against the normalizer's fixed-point loop) and at least one class the
# normalizer does not fold at all, so the loop always has a next thing to chase.
# These are scored through the exact same real classifier gate - nothing here
# is lenient.
# ---------------------------------------------------------------------------

def _random_case(cmd: str) -> Optional[str]:
    """Alternating-case the first 4+ letter run (`whoami` -> `WhOaMi`).
    Deterministic (position parity, not RNG) so a run is reproducible and a
    regression is attributable. Rule matching is expected to be
    case-insensitive, so this is the cheap plate that CONFIRMS that property
    rather than one expected to open headroom."""
    m = _WORD.search(cmd)
    if not m:
        return None
    w = m.group(0)
    flipped = "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(w))
    if flipped == w:
        return None
    return cmd[:m.start()] + flipped + cmd[m.end():]


def _comma_delimit(cmd: str) -> Optional[str]:
    """Replace the FIRST inter-token space with a comma. cmd.exe treats `,`
    (and `;`) as argument delimiters, so `whoami /priv` -> `whoami,/priv` runs
    the same - but `normalize_cmdline` only collapses WHITESPACE (`_RE_WS`), it
    does not fold delimiter commas. This is the one plate here expected to open
    real headroom: a rule keying on the contiguous `whoami /priv` string sees a
    different token stream. If it evades, that is the next thing to fix - which
    is the entire point of keeping a plate the bar cannot lift yet."""
    i = cmd.find(" ")
    if i <= 0 or i == len(cmd) - 1:
        return None
    return cmd[:i] + "," + cmd[i + 1:]


def _compound_cmd(cmd: str) -> Optional[str]:
    """Two cmd.exe folds stacked: caret-escape THEN quote-split, on different
    runs. The single-transform tier never checked that the normalizer's
    fixed-point loop unwinds MORE THAN ONE obfuscation from the same string -
    which is exactly what a real operator does. Resistance here means the loop
    actually reached a fixed point, not just that each fold works alone."""
    step = _caret_escape(cmd)
    if step is None:
        return None
    step2 = _quote_split(step)
    return step2 if step2 and step2 != step else None


def _compound_triple(cmd: str) -> Optional[str]:
    """Three fold classes stacked: full-width homoglyph + caret + quote-split.
    The heaviest plate - it forces unicode-fold, caret-strip and quote-strip to
    all fire and compose to one canonical string within MAX_ROUNDS. If the loop
    ever stops one round short, this is the variant that catches it."""
    step = _unicode_fullwidth(cmd)
    if step is None:
        return None
    step = _caret_escape(step) or step
    step = _quote_split(step) or step
    return step if step != cmd else None


TRANSFORMS = {
    "caret_escape":      _caret_escape,
    "quote_split":       _quote_split,
    "powershell_concat": _ps_concat,
    "unicode_fullwidth": _unicode_fullwidth,
    # heavier plates
    "random_case":       _random_case,
    "comma_delimit":     _comma_delimit,
    "compound_cmd":      _compound_cmd,
    "compound_triple":   _compound_triple,
}


def _variant(t: Technique, name: str, cmdline: str) -> Technique:
    return dataclasses.replace(
        t, id=f"{t.id}__{name}",
        probe_input={**t.probe_input, "cmdline": cmdline},
    )


def main() -> int:
    ctx = _build_ctx()
    techniques = [t for t in all_in_scope() if "cmdline" in t.probe_input]

    print(f"Evasion tier: {len(techniques)}/{len(all_in_scope())} in-scope "
          f"techniques carry a command line to obfuscate.\n")

    baseline: dict[str, dict] = {}
    per_transform: dict[str, dict[str, dict]] = {name: {} for name in TRANSFORMS}
    not_applicable: dict[str, list[str]] = {name: [] for name in TRANSFORMS}

    for t in techniques:
        base_rec = run_technique(t, ctx)
        baseline[t.id] = base_rec
        original = t.probe_input["cmdline"]
        for name, fn in TRANSFORMS.items():
            obf = fn(original)
            if obf is None:
                not_applicable[name].append(t.id)
                continue
            variant = _variant(t, name, obf)
            rec = run_technique(variant, ctx)
            rec["baseline_cmdline"] = original
            rec["obfuscated_cmdline"] = obf
            rec["obfuscation"] = name
            per_transform[name][t.id] = rec

    # --- Scorecard ---
    n = len(techniques)
    base_hits = sum(1 for r in baseline.values() if r["counted_as_detected"])
    print(f"Baseline (unobfuscated), same {n}-technique subset: "
          f"{base_hits}/{n} ({100 * base_hits / n:.1f}%)\n")

    print(f"{'transform':<20} {'applicable':<12} {'still detected':<16} "
          f"{'evaded':<8} {'rate':>8}")
    summary = {}
    for name in TRANSFORMS:
        recs = per_transform[name]
        applicable = len(recs)
        still = sum(1 for r in recs.values() if r["counted_as_detected"])
        # "Evaded" = baseline detected it, obfuscation made it stop.
        evaded = [tid for tid, r in recs.items()
                 if baseline[tid]["counted_as_detected"] and not r["counted_as_detected"]]
        # resisted = baseline-detected AND the obfuscated variant still detected.
        # Recorded explicitly (not just as a count) so the ratchet ledger can
        # detect a PER-TECHNIQUE regression - a variant that used to be resisted
        # and now evades - not merely a drop in the aggregate rate.
        resisted = sorted(tid for tid, r in recs.items()
                          if baseline[tid]["counted_as_detected"]
                          and r["counted_as_detected"])
        rate = (still / applicable) if applicable else float("nan")
        summary[name] = {
            "applicable": applicable, "not_applicable": len(not_applicable[name]),
            "still_detected": still, "evaded_count": len(evaded),
            "evaded_ids": evaded, "resisted_ids": resisted,
            "resistance_rate": rate,
        }
        print(f"{name:<20} {applicable:<12} {still:<16} {len(evaded):<8} "
              f"{f'{100*rate:.1f}%' if applicable else 'n/a':>8}")

    # Worst case per technique: an attacker only needs ONE working evasion.
    any_evasion: list[str] = []
    for t in techniques:
        if not baseline[t.id]["counted_as_detected"]:
            continue   # already a baseline miss - not a NEW evasion
        for name in TRANSFORMS:
            rec = per_transform[name].get(t.id)
            if rec is not None and not rec["counted_as_detected"]:
                any_evasion.append(f"{t.id} (via {name})")
                break
    baseline_detected = [t.id for t in techniques if baseline[t.id]["counted_as_detected"]]
    print(f"\nOf {len(baseline_detected)} techniques detected at baseline, "
          f"{len(any_evasion)} have at least one obfuscated variant that "
          f"evades ({100 * len(any_evasion) / max(1, len(baseline_detected)):.1f}%).")
    if any_evasion:
        print("Evadable at baseline-detected status:")
        for e in any_evasion:
            print(f"  - {e}")

    print(f"\nHonest scope: env-var expansion and base64 -EncodedCommand were "
          f"deliberately NOT applied generically here — see this file's "
          f"module docstring. They are measured directly by "
          f"tests/test_cmdline_normalize.py (12/12, ADR 0042).")

    # --- Write results ---
    out_dir = Path(__file__).resolve().parent / "results"
    out_dir.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = out_dir / f"{ts}__evasion.json"
    out_path.write_text(json.dumps({
        "tier": TIER, "catalog_version": CATALOG_VERSION, "generated_at": ts,
        "techniques_with_cmdline": n,
        "baseline_detected": base_hits,
        "transforms": summary,
        "records": {
            "baseline": baseline,
            **{f"obfuscated__{name}": recs for name, recs in per_transform.items()},
        },
    }, indent=2), encoding="utf-8")
    print(f"\nResults written to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
