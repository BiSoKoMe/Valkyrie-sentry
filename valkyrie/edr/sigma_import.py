"""Sigma rule import — take the community's detection content, safely.

WHY
---
SigmaHQ publishes 3000+ threat-detection rules under the Detection Rule License
1.1, explicitly so tools can use them. That is a decade of collective detection
engineering, freely given - and hand-writing rule #169 while ignoring it is the
definition of working hard instead of working smart.

THE TRAP, AND WHY MOST OF THIS FILE IS REFUSALS
-----------------------------------------------
Importing 3000 rules blindly would be the single fastest way to destroy
Valkyrie's one non-negotiable property: **never interfere with the user's work.**
Sigma's corpus is deliberately broad - it includes hunting rules meant to be
tuned per-environment, low-confidence leads, and rules whose false-positive
field literally reads "Unknown". Loading those wholesale would turn a tool with
zero measured false positives into an alert cannon.

So this importer is a funnel, and every stage is allowed to say no:

  1. **Shape gate.** Only ``process_creation`` rules convert - that is the one
     Sigma logsource whose fields (Image/ParentImage/CommandLine) map onto
     Valkyrie's Rule without inventing semantics. Registry/network/file Sigma
     rules are SKIPPED with a reason rather than approximated, because a rule
     that means something subtly different from what its author wrote is worse
     than no rule.
  2. **Condition gate.** Only simple single-selection conditions convert. Sigma
     supports ``1 of them``, ``not filter``, aggregations - expressing those
     wrongly in a flat Rule is how you get silent mis-detection, so they are
     skipped, counted, and reported.
  3. **Confidence gate.** ``level: low``/``informational`` are hunting leads,
     not detections. Skipped by default.
  4. **FALSE-POSITIVE GATE (the non-negotiable one).** Every converted rule is
     run against the benign corpus. It fires on even one legitimate command ->
     REJECTED, no matter how good the rule looks. This reuses the exact gate
     the adaptive learner uses, because "content from outside" deserves *more*
     scrutiny than content we wrote, not less.
  5. **Duplicate gate.** A rule whose behaviour an existing Valkyrie rule
     already covers is skipped - imported breadth should not silently shadow
     tuned local content.

Pure: ``convert`` and ``import_rules`` are functions over parsed YAML dicts and
return decisions plus reasons. Nothing is written and no rule is activated -
the caller decides what to do with the approved set, exactly as with
``adaptive.py``. Attribution is preserved on every imported rule (DRL 1.1 asks
for it, and an analyst should be able to see where a detection came from).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

from ..behavioral_rules import Rule
from .adaptive import BENIGN_CORPUS
from .elastic_import import full_benign_corpus


class SigmaVerdict(str, Enum):
    IMPORTED = "imported"
    SKIP_LOGSOURCE = "skipped_unsupported_logsource"
    SKIP_CONDITION = "skipped_complex_condition"
    SKIP_LEVEL = "skipped_low_confidence"
    SKIP_NO_FIELDS = "skipped_no_mappable_fields"
    REJECT_FP = "rejected_false_positive"
    SKIP_DUPLICATE = "skipped_duplicate"


# Sigma level -> Valkyrie severity. `low`/`informational` are hunting leads.
_LEVEL_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium"}
_MIN_LEVELS = frozenset(_LEVEL_SEVERITY)

# The only logsource whose fields map cleanly onto Valkyrie's Rule.
_SUPPORTED_CATEGORY = "process_creation"

# Conditions we can express exactly. Anything else is skipped, not guessed.
_SIMPLE_CONDITION = re.compile(r"^\s*selection\w*\s*$", re.I)

_ATTACK_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)


@dataclass
class SigmaResult:
    sigma_id: str
    title: str
    verdict: SigmaVerdict
    rule: Optional[dict] = None
    reasons: tuple = ()
    fired_on: tuple = ()          # benign samples it wrongly matched

    @property
    def imported(self) -> bool:
        return self.verdict == SigmaVerdict.IMPORTED

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        d["reasons"] = list(self.reasons)
        d["fired_on"] = list(self.fired_on)
        return d


def _basename(value: str) -> str:
    """'\\rundll32.exe' or 'C:\\W\\rundll32.exe' -> 'rundll32.exe'."""
    v = str(value or "").strip().strip("'\"").lower()
    return v.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]


def _as_list(v) -> list:
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple)) else [v]


def _technique_from_tags(tags) -> str:
    for t in _as_list(tags):
        m = _ATTACK_TAG.match(str(t).strip())
        if m:
            return m.group(1).upper()
    return ""


def convert(sigma: dict) -> tuple:
    """Convert one parsed Sigma rule to a Valkyrie Rule.

    Returns ``(Rule | None, verdict, reasons)``. Never raises on malformed
    input - a bad rule is skipped with a reason, because an importer that dies
    on one file cannot process a 3000-rule corpus.
    """
    title = str(sigma.get("title") or "untitled")
    sid = str(sigma.get("id") or title)

    # --- gate 1: logsource shape -----------------------------------------
    logsource = sigma.get("logsource") or {}
    category = str(logsource.get("category") or "").lower()
    if category != _SUPPORTED_CATEGORY:
        return (None, SigmaVerdict.SKIP_LOGSOURCE,
                (f"logsource category {category or '(none)'!r} does not map onto "
                 f"Valkyrie's process Rule; approximating it would change what "
                 f"the author actually wrote",))

    # --- gate 3: confidence ----------------------------------------------
    level = str(sigma.get("level") or "").lower()
    if level not in _MIN_LEVELS:
        return (None, SigmaVerdict.SKIP_LEVEL,
                (f"level {level or '(none)'!r} is a hunting lead, not a "
                 f"detection - importing it would add noise, not coverage",))

    # --- gate 2: condition complexity ------------------------------------
    detection = sigma.get("detection") or {}
    condition = detection.get("condition")
    conds = " ".join(str(c) for c in _as_list(condition))
    if not _SIMPLE_CONDITION.match(conds):
        return (None, SigmaVerdict.SKIP_CONDITION,
                (f"condition {conds!r} uses Sigma logic (or/not/1 of/aggregation) "
                 f"that a flat Rule cannot express exactly; skipped rather than "
                 f"approximated",))

    sel_key = next((k for k in detection if k.lower().startswith("selection")), None)
    selection = detection.get(sel_key) or {}
    if not isinstance(selection, dict):
        return (None, SigmaVerdict.SKIP_CONDITION,
                ("selection is a list of maps (implicit OR); not expressible "
                 "as one flat Rule",))

    images: list = []
    parents: list = []
    cmd_all: list = []

    for raw_field, raw_val in selection.items():
        field_name, _, modifier = str(raw_field).partition("|")
        f = field_name.strip().lower()
        values = [str(v) for v in _as_list(raw_val)]
        if not values:
            continue
        if f == "image":
            images.extend(_basename(v) for v in values)
        elif f == "parentimage":
            parents.extend(_basename(v) for v in values)
        elif f in ("commandline", "originalfilename"):
            # Sigma `contains` semantics; multiple values in ONE field are OR,
            # which a single cmd_all cannot express - only take it when there is
            # exactly one, otherwise the rule would become stricter than written.
            if len(values) == 1:
                cmd_all.append(values[0].strip().strip("'\"").lower())
            else:
                return (None, SigmaVerdict.SKIP_CONDITION,
                        (f"field {f!r} lists {len(values)} alternatives (OR); a "
                         f"single cmd_all would wrongly require all of them",))
        # every other Sigma field (hashes, User, IntegrityLevel, ...) has no
        # Valkyrie equivalent and is ignored - noted below if nothing mapped.

    if not (images or parents or cmd_all):
        return (None, SigmaVerdict.SKIP_NO_FIELDS,
                ("no Image/ParentImage/CommandLine field mapped; the rule keys "
                 "on data Valkyrie does not carry",))

    technique = _technique_from_tags(sigma.get("tags"))
    rid = "sigma-" + re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:48]
    rule = Rule(
        id=rid,
        technique=technique or "unmapped",
        severity=_LEVEL_SEVERITY[level],
        label="sigma_import",
        reason=f"{title} (SigmaHQ, DRL 1.1, id={sid})",
        images=tuple(dict.fromkeys(images)),
        parents=tuple(dict.fromkeys(parents)),
        cmd_all=tuple(dict.fromkeys(cmd_all)),
    )
    return (rule, SigmaVerdict.IMPORTED, ())


def import_rules(sigma_rules: list, *,
                 benign_corpus: Optional[list] = None,
                 existing_rule_ids: Optional[set] = None,
                 existing_shapes: Optional[set] = None) -> list:
    """Run a corpus of parsed Sigma rules through every gate.

    Returns a list of SigmaResult - the caller decides what to activate. The
    false-positive gate is applied to EVERY converted rule; nothing reaches the
    approved set without surviving the benign corpus.
    """
    # Defaults to the hand-written corpus PLUS the benign knowledge harvested
    # from a real EDR fleet's exclusion lists - imported content is measured
    # against what actually breaks on real machines, not only against what this
    # developer thought to write down.
    corpus = full_benign_corpus() if benign_corpus is None else benign_corpus
    existing_ids = existing_rule_ids or set()
    shapes = existing_shapes or set()
    out: list = []

    for sigma in sigma_rules:
        if not isinstance(sigma, dict):
            continue
        title = str(sigma.get("title") or "untitled")
        sid = str(sigma.get("id") or title)
        rule, verdict, reasons = convert(sigma)
        if rule is None:
            out.append(SigmaResult(sid, title, verdict, reasons=reasons))
            continue

        # --- gate 5: duplicate --------------------------------------------
        shape = (rule.images, rule.parents, rule.cmd_all)
        if rule.id in existing_ids or shape in shapes:
            out.append(SigmaResult(sid, title, SigmaVerdict.SKIP_DUPLICATE,
                                   rule=_rule_dict(rule),
                                   reasons=("an existing rule already covers "
                                            "this behaviour shape",)))
            continue

        # --- gate 4: FALSE POSITIVES (non-negotiable) ---------------------
        fps = tuple(f"{img} :: {cmd}"
                    for (img, par, cmd) in corpus
                    if rule.matches(img.lower(), par.lower(), cmd, ""))
        if fps:
            out.append(SigmaResult(
                sid, title, SigmaVerdict.REJECT_FP, rule=_rule_dict(rule),
                fired_on=fps,
                reasons=(f"fires on {len(fps)} legitimate command(s); imported "
                         f"content gets MORE scrutiny than our own, not less",)))
            continue

        shapes.add(shape)
        out.append(SigmaResult(sid, title, SigmaVerdict.IMPORTED,
                               rule=_rule_dict(rule),
                               reasons=("converted cleanly, 0 false positives "
                                        f"across {len(corpus)} benign commands",)))
    return out


def summarise(results: list) -> dict:
    counts: dict = {}
    for r in results:
        counts[r.verdict.value] = counts.get(r.verdict.value, 0) + 1
    return {"total": len(results),
            "imported": sum(1 for r in results if r.imported),
            "by_verdict": counts}


def _rule_dict(r: Rule) -> dict:
    return {"id": r.id, "technique": r.technique, "severity": r.severity,
            "label": r.label, "reason": r.reason, "images": list(r.images),
            "parents": list(r.parents), "cmd_all": list(r.cmd_all)}
