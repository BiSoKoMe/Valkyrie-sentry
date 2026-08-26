"""Elastic endpoint rule import — the detections, and the harder-won exclusions.

WHAT THIS IS
------------
Elastic publishes the actual behavioural detection content that ships in their
endpoint agent (`elastic/protections-artifacts`, Elastic License 2.0, which
grants use, copy, distribute and derivative works). It is a real EDR vendor's
rule corpus, written by their threat team, given away.

TWO THINGS COME OUT OF EACH RULE, AND THE SECOND IS WORTH MORE
--------------------------------------------------------------
1. **Detection logic** - which Valkyrie can import only where it can express the
   rule *exactly*. This is a minority of the corpus, and that is expected: their
   rules key on call stacks, code-signature state, API provenance and argument
   counts that Valkyrie does not collect.

2. **False-positive exclusions** - the tail of every mature rule::

       not process.args : ("https://mirror.init7.net/ctan/systems*",
                           "https://dl.google.com/*", "texlive/curl")
       not (process.parent.command_line like~ "*VoicemodInstaller*")
       not user.id : "S-1-5-18"          /* avoid breaking privileged install */

   That is not detection logic. That is a list of **real legitimate software
   that tripped this rule on real machines**, accumulated across a fleet far
   larger than one developer can simulate. A LaTeX mirror. A voice-changer
   installer. Google's own updater. Privileged installers running as SYSTEM.

   Valkyrie's prime directive is to never interfere with the user's work, and
   the binding constraint on that is knowing what "the user's work" looks like.
   These exclusions answer exactly that, and they answer it for rules Valkyrie
   wrote itself - a benign fact is true regardless of which rule discovered it.

   **So the harvest runs on every rule, including the ones we refuse to
   import.** A rule we cannot express still tells us what is safe.

THE RULE THAT MUST NOT BE BROKEN: NEVER DROP A CONJUNCT
-------------------------------------------------------
An EQL rule is a conjunction: ``anchor and anchor and not exclusion and ...``.
Removing any conjunct makes the rule STRICTLY BROADER than the one Elastic
tested. Import the positive half of a rule while quietly discarding an exclusion
you could not parse, and you have shipped a rule with *more* false positives
than its author ever accepted - on somebody's actual machine.

So every top-level clause must be either expressible or provably redundant with
Valkyrie's evaluation context. One unparseable clause - positive or negative -
fails the whole import, by name, with a reason. This is why the importer refuses
far more than it accepts, and why that is the correct outcome rather than a
limitation to be tuned away later.

WHERE VALKYRIE IS ACTUALLY AHEAD
--------------------------------
``descendant of [process where process.name : ("winword.exe", ...)]`` is a
lineage predicate. Sigma cannot express it, so a Sigma-shaped importer loses it.
Valkyrie has a causality graph, so this converts into an ancestor constraint
intact. Borrowed content lands *less* degraded here than in the format most
tools import from.

Pure: parsing and conversion are functions over a parsed TOML dict. Nothing is
written and no rule is activated.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import Optional

from ..behavioral_rules import Rule
from .adaptive import BENIGN_CORPUS
from .content_license import License, Provenance, ShipMode, classify, may_ship


class ElasticVerdict(str, Enum):
    IMPORTED = "imported"
    SKIP_LICENSE = "skipped_license"
    SKIP_OS = "skipped_not_windows"
    SKIP_TELEMETRY = "skipped_needs_telemetry_we_lack"
    SKIP_UNPARSEABLE = "skipped_clause_not_parseable"
    SKIP_NO_ANCHOR = "skipped_no_positive_anchor"
    SKIP_DEAD = "skipped_would_never_match"
    REJECT_FP = "rejected_false_positive"
    SKIP_DUPLICATE = "skipped_duplicate"


# A process basename Valkyrie can actually compare. Rule.matches uses exact
# membership, so anything else silently NEVER fires.
_VALID_BASENAME = re.compile(r"^[a-z0-9][a-z0-9._+~-]*\.[a-z0-9]{1,8}$")


def _dead_names(names: list) -> list:
    """Names that would make an imported rule silently unmatchable.

    Two real cases from the corpus, both of which imported "successfully" and
    detected nothing:

      * ``autoit*.exe`` - Elastic match a wildcard; Valkyrie compares basenames
        exactly, so the rule can never fire.
      * ``-appvscript`` - an argument that leaked into the parent list through a
        mis-bounded clause, i.e. a parser bug wearing the shape of a rule.

    A dead rule is WORSE than a refused one. A refusal is visible and counted; a
    dead rule inflates the coverage number while contributing no detection,
    which is precisely the fake-parity failure this project refuses to ship.
    """
    return [n for n in names if not _VALID_BASENAME.match(n or "")]


# --- EQL surface Valkyrie can actually express ----------------------------
# image / parent / command line, plus ancestry via the causality graph.
_F_IMAGE = ("process.name", "process.executable", "process.pe.original_file_name")
_F_PARENT = ("process.parent.name", "process.parent.executable")
_F_CMD = ("process.command_line", "process.args")
_F_PARENT_CMD = ("process.parent.command_line", "process.parent.args")

# Clauses whose truth Valkyrie's evaluation context already guarantees, so
# dropping them does NOT broaden the rule. Kept deliberately tiny - every entry
# here is an assertion about the engine, not a convenience.
_IMPLIED = (
    re.compile(r'^event\.action\s*==?\s*"start"$', re.I),
    re.compile(r'^event\.type\s*==?\s*"start"$', re.I),
)

_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_HEAD = re.compile(r"^\s*\w+\s+where\s+", re.I)
_DESCENDANT = re.compile(
    r"descendant\s+of\s*\[\s*process\s+where\s+([^\]]+)\]", re.I | re.S)
_ATTACK_T = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.I)


# ---------------------------------------------------------------------------
# tokenising: split a conjunction at top level, respecting quotes and brackets
# ---------------------------------------------------------------------------

# Real EQL wraps across lines, so the operator that joins two conjuncts is
# " and\n " as often as " and ". Matching the literal string " and " parses a
# real rule as one malformed clause - which fails safe, but for the wrong
# reason, and silently refuses content that is genuinely importable.
_AND_BOUNDARY = re.compile(r"\s+and\s+", re.I)
_OR_BOUNDARY = re.compile(r"\s+or\s+", re.I)


def _split_top_level_and(expr: str) -> list:
    """Split ``a and b and (c and d)`` into ['a', 'b', '(c and d)'].

    Depth- and quote-aware: a bare regex split would tear apart the nested
    parenthesised groups that every real Elastic rule uses.
    """
    out, buf, depth, quote = [], [], 0, ""
    i, n = 0, len(expr)
    while i < n:
        ch = expr[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if depth == 0 and ch.isspace():
            mo = _AND_BOUNDARY.match(expr, i)
            if mo:
                out.append("".join(buf).strip())
                buf = []
                i = mo.end()
                continue
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        out.append(tail)
    return [c for c in out if c]


def _strip_outer_parens(clause: str) -> str:
    c = clause.strip()
    while c.startswith("(") and c.endswith(")"):
        depth, ok = 0, True
        for i, ch in enumerate(c):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i != len(c) - 1:
                    ok = False
                    break
        if not ok:
            break
        c = c[1:-1].strip()
    return c


_CLAUSE = re.compile(
    r"^\s*(?P<field>[A-Za-z][\w.]*)\s*"
    r"(?P<op>:|==|like~|like|regex~|in~|in)\s*"
    r"(?P<values>.+)$", re.S | re.I)

_STRINGS = re.compile(r"\"((?:[^\"\\]|\\.)*)\"|'((?:[^'\\]|\\.)*)'")


def _parse_clause(clause: str) -> Optional[tuple]:
    """``process.name : ("a.exe", "b.exe")`` -> ('process.name', ['a.exe','b.exe']).

    Returns None when the clause is not a simple field/value comparison - which
    the caller must treat as fatal, never as ignorable.
    """
    m = _CLAUSE.match(_strip_outer_parens(clause))
    if not m:
        return None
    values = [(a or b) for a, b in _STRINGS.findall(m.group("values"))]
    if not values:
        return None
    return (m.group("field").lower(), values)


def _basename(v: str) -> str:
    """``?:\\Windows\\System32\\curl.exe`` -> ``curl.exe``; ``*\\x.exe`` -> ``x.exe``."""
    s = str(v or "").strip().strip("*").replace("/", "\\")
    return s.rsplit("\\", 1)[-1].strip().lower()


def _depattern(v: str) -> str:
    """A wildcard pattern -> the literal substring Valkyrie matches on.

    Elastic's string dialect has to be undone or the result never matches a real
    command line: ``\\\\`` is an escaped single backslash, and ``?:`` is their
    any-drive-letter wildcard. Leaving those in place produces corpus entries
    that silently match nothing, which is worse than having none - a benign
    corpus that cannot fire gives a false all-clear.
    """
    s = str(v or "").strip().strip("*").strip().lower()
    s = s.replace('\\"', '"').replace("\\\\", "\\")
    if s.startswith("?:"):
        s = "c:" + s[2:]
    return s.replace("?:\\", "c:\\")


# ---------------------------------------------------------------------------
# the harvest: benign facts
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BenignFact:
    """One piece of real-world "this is legitimate" knowledge, lifted from a
    rule's exclusion tail and kept with its provenance.

    These are the exclusions a vendor accumulated by breaking real software on
    real machines and being told about it. They are valid independently of the
    rule that discovered them.
    """

    image: str          # process it applies to ("" = any)
    parent: str         # parent process ("" = any)
    marker: str         # the literal that marks it benign
    where: str          # which field the marker came from
    source_rule: str    # upstream rule name, for audit
    note: str = ""      # the author's own comment, when they left one

    def to_corpus_entry(self) -> tuple:
        """Render as a ``(image, parent, cmdline)`` benign-corpus triple.

        **Never invents an image or parent.** An earlier version substituted a
        plausible-looking ``svchost.exe`` when the exclusion did not name a
        process, and then prepended it to the command line. That manufactured
        false positives that no real machine would ever produce, which is the
        same sin as hiding real ones - it makes the audit number meaningless in
        the other direction.

        An empty image or parent means **unconstrained**: this command line is
        benign whatever runs it. The FP gate is responsible for interpreting
        that (see :func:`fires_on_benign`), not this renderer.
        """
        cmd = self.marker
        if not self.where.endswith(("command_line", "args")) or not cmd:
            cmd = self.marker
        return (self.image, self.parent, cmd.replace("*", " ").strip())

    def to_dict(self) -> dict:
        return asdict(self)


# A harvested "benign marker" that still contains EQL syntax is spill from a
# clause the parser did not cleanly bound - not knowledge about real software.
_EQL_GARBAGE = re.compile(
    r"(\bprocess\.\w|\buser\.id\b|\blike~|\bnot\s+\(|\)\s+and\b|\band\s+not\b"
    r"|\bevent\.action\b|\bdescendant\s+of\b)", re.I)


def _find_negations(expr: str) -> list:
    """Every ``not ...`` sub-expression, AT ANY NESTING DEPTH.

    Deliberately greedier than :func:`_split_top_level_and`. Elastic authors
    bury exclusions inside parenthesised ``or`` groups, so a top-level-only scan
    would miss most of the very knowledge this module exists to collect.

    The asymmetry is the design, not an inconsistency: being greedy while
    HARVESTING benign facts can only ever make Valkyrie more cautious, whereas
    being greedy while IMPORTING a detection makes it fire on more things. One
    direction is safe to over-reach in; the other is not.
    """
    out: list = []
    i, n, quote = 0, len(expr), ""
    while i < n:
        ch = expr[i]
        if quote:
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            i += 1
            continue
        is_word = (expr[i:i + 3].lower() == "not"
                   and (i == 0 or not (expr[i - 1].isalnum() or expr[i - 1] == "_"))
                   and i + 3 < n and not (expr[i + 3].isalnum() or expr[i + 3] == "_"))
        if not is_word:
            i += 1
            continue

        j = i + 3
        while j < n and expr[j].isspace():
            j += 1

        if j < n and expr[j] == "(":                 # not ( ... )
            depth, k, q = 0, j, ""
            while k < n:
                c = expr[k]
                if q:
                    if c == q:
                        q = ""
                elif c in "\"'":
                    q = c
                elif c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            out.append(expr[j + 1:k])
            i = k + 1
            continue

        depth, k, q = 0, j, ""                        # not field : "..."
        while k < n:
            c = expr[k]
            if q:
                if c == q:
                    q = ""
                k += 1
                continue
            if c in "\"'":
                q = c
                k += 1
                continue
            if c in "([":
                depth += 1
            elif c in ")]":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and c.isspace() and (_AND_BOUNDARY.match(expr, k)
                                                 or _OR_BOUNDARY.match(expr, k)):
                break
            k += 1
        out.append(expr[j:k])
        i = k
    return out


def harvest_exclusions(rule: dict) -> list:
    """Pull every benign fact out of a rule's ``not`` clauses.

    Runs regardless of whether the rule's DETECTION can be imported - a rule we
    refuse still knows what legitimate software looks like, and that knowledge
    protects the 168 rules Valkyrie wrote itself.
    """
    body_d = rule.get("rule") or rule
    query = str(body_d.get("query") or "")
    name = str(body_d.get("name") or "unnamed")
    if not query:
        return []

    body = _HEAD.sub("", _COMMENT.sub(" ", query)).strip()
    facts: list = []

    for inner in _find_negations(body):
        # An exclusion may itself be a conjunction:
        #   not (process.parent.name : "cmd.exe" and process.parent.args : ("*.bat*"))
        img = par = ""
        markers: list = []
        for sub in _split_top_level_and(inner) or [inner]:
            parsed = _parse_clause(sub)
            if not parsed:
                continue
            field, values = parsed
            if field in _F_IMAGE:
                img = img or _basename(values[0])
            elif field in _F_PARENT:
                par = par or _basename(values[0])
            elif field in _F_CMD or field in _F_PARENT_CMD:
                markers.extend((field, v) for v in values)

        for field, val in markers:
            lit = _depattern(val)
            if len(lit) < 4:            # too short to mean anything benign
                continue
            if _EQL_GARBAGE.search(lit):
                # A "benign marker" containing EQL syntax is parser spill, not
                # knowledge. Left in, it becomes a corpus entry that can never
                # match anything real - a silent all-clear.
                continue
            facts.append(BenignFact(image=img, parent=par, marker=lit,
                                    where=field, source_rule=name))
    return facts


# ---------------------------------------------------------------------------
# conversion
# ---------------------------------------------------------------------------

@dataclass
class ElasticResult:
    rule_id: str
    name: str
    verdict: ElasticVerdict
    rule: Optional[dict] = None
    provenance: Optional[dict] = None
    reasons: tuple = ()
    fired_on: tuple = ()
    benign_facts: tuple = ()

    @property
    def imported(self) -> bool:
        return self.verdict == ElasticVerdict.IMPORTED

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        d["reasons"] = list(self.reasons)
        d["fired_on"] = list(self.fired_on)
        d["benign_facts"] = [f.to_dict() if isinstance(f, BenignFact) else f
                             for f in self.benign_facts]
        return d


def _provenance(body: dict) -> Provenance:
    lic = classify(body.get("license"))
    return Provenance(source="elastic/protections-artifacts",
                      rule_id=str(body.get("id") or ""),
                      author="Elastic",
                      license=lic,
                      version=str(body.get("version") or ""),
                      url="https://github.com/elastic/protections-artifacts")


def _technique(rule: dict) -> str:
    for threat in (rule.get("threat") or []):
        for tech in (threat.get("technique") or []):
            tid = str(tech.get("id") or "").strip().upper()
            if _ATTACK_T.match(tid):
                return tid
    return ""


def convert(rule: dict, *, mode: ShipMode = ShipMode.COMMERCIAL_PRODUCT) -> tuple:
    """Convert one parsed Elastic rule TOML into a Valkyrie Rule.

    Returns ``(Rule | None, verdict, reasons, provenance)``. Never raises: a
    corpus of a thousand files cannot be processed by an importer that dies on
    one of them.
    """
    body = rule.get("rule") or rule
    name = str(body.get("name") or "unnamed")
    prov = _provenance(body)

    # --- gate 0: LICENCE, per rule, before anything else -----------------
    decision = may_ship(prov, mode)
    if not decision.allowed:
        return (None, ElasticVerdict.SKIP_LICENSE, (decision.reason,), prov)

    # --- gate 1: platform -------------------------------------------------
    os_list = [str(o).lower() for o in (body.get("os_list") or [])]
    if os_list and "windows" not in os_list:
        return (None, ElasticVerdict.SKIP_OS,
                (f"targets {os_list}; Valkyrie's process rules are Windows",), prov)

    query = str(body.get("query") or "")
    if not query.strip():
        return (None, ElasticVerdict.SKIP_UNPARSEABLE,
                ("rule carries no query",), prov)

    stripped = _COMMENT.sub(" ", query)
    if not _HEAD.match(stripped.strip()) or \
            not re.match(r"^\s*process\s+where\s", stripped.strip(), re.I):
        return (None, ElasticVerdict.SKIP_TELEMETRY,
                ("not a process-event rule; file/registry/library/api event "
                 "sources are separate telemetry Valkyrie does not evaluate "
                 "through behavioural process rules",), prov)

    body_expr = _HEAD.sub("", stripped.strip())

    images: list = []
    parents: list = []
    cmd_all: list = []
    ancestors: list = []
    cmd_not: list = []
    parents_not: list = []
    images_not: list = []
    narrowed = 0        # exclusions applied more broadly than upstream wrote them

    # --- EVERY top-level conjunct must be handled. Dropping one broadens --
    for clause in _split_top_level_and(body_expr):
        c = _strip_outer_parens(clause).strip()
        if not c:
            continue

        if any(p.match(c) for p in _IMPLIED):
            continue                      # guaranteed by evaluation context

        # A COMPOUND exclusion: not (A and B). "Not both" cannot be written as a
        # flat exclusion list, but excluding on A alone is strictly NARROWER than
        # upstream - it suppresses a superset of what Elastic suppresses. That
        # can cost a detection and can never add a false positive, so it is
        # allowed and counted rather than refused.
        if re.match(r"^not\s*\(", c, re.I):
            inner = _strip_outer_parens(re.sub(r"^not\s+", "", c, flags=re.I))
            subs = _split_top_level_and(inner)
            applied = False
            for sub in subs:
                p2 = _parse_clause(sub)
                if not p2:
                    continue
                f2, v2 = p2
                if f2 in _F_CMD or f2 in _F_PARENT_CMD:
                    cmd_not.extend(x for x in (_depattern(v) for v in v2) if x)
                    applied = True
                elif f2 in _F_PARENT:
                    parents_not.extend(_basename(v) for v in v2)
                    applied = True
                elif f2 in _F_IMAGE:
                    images_not.extend(_basename(v) for v in v2)
                    applied = True
            if not applied:
                return (None, ElasticVerdict.SKIP_TELEMETRY,
                        (f"compound exclusion {c[:60]!r} keys only on telemetry "
                         f"Valkyrie does not collect; ignoring it would make the "
                         f"rule BROADER than the one Elastic tested",), prov)
            if len(subs) > 1:
                narrowed += 1
            continue

        # ancestry — expressible here, unlike in Sigma
        mo = _DESCENDANT.search(c)
        if mo and re.match(r"^descendant\s+of", c, re.I):
            parsed = _parse_clause(mo.group(1))
            if not parsed or parsed[0] not in _F_IMAGE:
                return (None, ElasticVerdict.SKIP_UNPARSEABLE,
                        (f"ancestry predicate not parseable: {c[:70]!r}",), prov)
            ancestors.extend(_basename(v) for v in parsed[1])
            continue

        negated = bool(re.match(r"^not\s", c, re.I))
        parsed = _parse_clause(re.sub(r"^not\s+", "", c, flags=re.I))

        if parsed is None:
            return (None, ElasticVerdict.SKIP_UNPARSEABLE,
                    (f"clause {c[:70]!r} is not a simple comparison; importing "
                     f"the rule without it would make it BROADER than the one "
                     f"Elastic tested",), prov)

        field, values = parsed

        if negated:
            # Rule.cmd_not / parents_not / images_not can now ENFORCE an
            # exclusion, so a rule that carries one is no longer refused
            # outright. The direction of error is what matters: applying an
            # exclusion makes the rule NARROWER than upstream, which can cost a
            # detection but can never add a false positive. Failing to apply one
            # makes it BROADER, which ships false positives onto a real machine.
            # Narrower is acceptable and counted; broader is not.
            if field in _F_CMD or field in _F_PARENT_CMD:
                cmd_not.extend(_depattern(v) for v in values if _depattern(v))
            elif field in _F_PARENT:
                parents_not.extend(_basename(v) for v in values)
            elif field in _F_IMAGE:
                images_not.extend(_basename(v) for v in values)
            else:
                # An exclusion on telemetry we do not carry (user.id,
                # code signature, args_count) cannot be enforced at all, and
                # dropping it would let the rule fire where Elastic's would not.
                return (None, ElasticVerdict.SKIP_TELEMETRY,
                        (f"exclusion keys on {field!r}, which Valkyrie does not "
                         f"collect; ignoring it would make the rule BROADER than "
                         f"the one Elastic tested. Its benign facts are still "
                         f"harvested",), prov)
            continue

        if field in _F_IMAGE:
            images.extend(_basename(v) for v in values)
        elif field in _F_PARENT:
            parents.extend(_basename(v) for v in values)
        elif field in _F_CMD:
            if len(values) > 1:
                return (None, ElasticVerdict.SKIP_UNPARSEABLE,
                        (f"{field} lists {len(values)} alternatives (OR); a single "
                         f"cmd_all would wrongly require all of them",), prov)
            lit = _depattern(values[0])
            if lit:
                cmd_all.append(lit)
        else:
            return (None, ElasticVerdict.SKIP_TELEMETRY,
                    (f"clause keys on {field!r}, which Valkyrie does not collect; "
                     f"silently ignoring it would broaden the rule",), prov)

    if not (images or parents or ancestors):
        return (None, ElasticVerdict.SKIP_NO_ANCHOR,
                ("no process/parent/ancestor anchor; a command-line-only rule is "
                 "too broad to import safely",), prov)

    # --- gate: would this rule be silently DEAD once imported? -----------
    dead = _dead_names(images + parents + ancestors)
    if dead:
        return (None, ElasticVerdict.SKIP_DEAD,
                (f"process name(s) {dead[:3]} cannot match Valkyrie's exact "
                 f"basename comparison (wildcard, or a mis-parsed argument); "
                 f"importing it would add coverage on paper and no detection in "
                 f"fact",), prov)

    tid = _technique(rule)
    rid = "elastic-" + re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:48]
    out = Rule(
        id=rid,
        technique=tid or "unmapped",
        severity="high",
        label="elastic_import",
        reason=f"{name} — {prov.attribution()}",
        images=tuple(dict.fromkeys(images)),
        images_not=tuple(dict.fromkeys(images_not)),
        parents=tuple(dict.fromkeys(parents + ancestors)),
        parents_not=tuple(dict.fromkeys(parents_not)),
        cmd_all=tuple(dict.fromkeys(cmd_all)),
        cmd_not=tuple(dict.fromkeys(cmd_not)),
    )
    note = (decision.reason,)
    if narrowed:
        note += (f"{narrowed} compound exclusion(s) applied more broadly than "
                 f"written: strictly narrower than upstream, so it may cost a "
                 f"detection but cannot add a false positive",)
    return (out, ElasticVerdict.IMPORTED, note, prov)


def import_rules(rules: list, *,
                 mode: ShipMode = ShipMode.COMMERCIAL_PRODUCT,
                 benign_corpus: Optional[list] = None,
                 existing_rule_ids: Optional[set] = None,
                 existing_shapes: Optional[set] = None) -> list:
    """Run a corpus of Elastic rules through every gate.

    The benign harvest runs on EVERY rule, including refused ones - that is the
    point of the exercise, not a side effect.
    """
    corpus = list(full_benign_corpus() if benign_corpus is None else benign_corpus)
    existing_ids = existing_rule_ids or set()
    shapes = existing_shapes or set()
    out: list = []

    for raw in rules:
        if not isinstance(raw, dict):
            continue
        body = raw.get("rule") or raw
        name = str(body.get("name") or "unnamed")
        rid = str(body.get("id") or name)

        facts = tuple(harvest_exclusions(raw))
        rule, verdict, reasons, prov = convert(raw, mode=mode)

        if rule is None:
            out.append(ElasticResult(rid, name, verdict, provenance=prov.to_dict(),
                                     reasons=reasons, benign_facts=facts))
            continue

        shape = (rule.images, rule.parents, rule.cmd_all)
        if rule.id in existing_ids or shape in shapes:
            out.append(ElasticResult(rid, name, ElasticVerdict.SKIP_DUPLICATE,
                                     rule=_rule_dict(rule),
                                     provenance=prov.to_dict(),
                                     reasons=("an existing rule already covers "
                                              "this behaviour shape",),
                                     benign_facts=facts))
            continue

        fps = tuple(f"{img} :: {cmd}" for (img, par, cmd) in corpus
                    if rule.matches(img.lower(), par.lower(), cmd.lower(), ""))
        if fps:
            out.append(ElasticResult(
                rid, name, ElasticVerdict.REJECT_FP, rule=_rule_dict(rule),
                provenance=prov.to_dict(), fired_on=fps, benign_facts=facts,
                reasons=(f"fires on {len(fps)} legitimate command(s); imported "
                         f"content gets MORE scrutiny than our own, not less",)))
            continue

        shapes.add(shape)
        out.append(ElasticResult(rid, name, ElasticVerdict.IMPORTED,
                                 rule=_rule_dict(rule), provenance=prov.to_dict(),
                                 reasons=reasons, benign_facts=facts))
    return out


def summarise(results: list) -> dict:
    counts: dict = {}
    for r in results:
        counts[r.verdict.value] = counts.get(r.verdict.value, 0) + 1
    facts = [f for r in results for f in r.benign_facts]
    return {
        "total": len(results),
        "imported": sum(1 for r in results if r.imported),
        "by_verdict": counts,
        # the number that actually matters: real-world benign knowledge gained,
        # including from every rule we refused to import.
        "benign_facts_harvested": len(facts),
        "benign_facts_from_refused_rules":
            sum(len(r.benign_facts) for r in results if not r.imported),
    }


def corpus_from_facts(facts: list) -> list:
    """Turn harvested facts into benign-corpus triples, de-duplicated."""
    seen, out = set(), []
    for f in facts:
        entry = f.to_corpus_entry() if isinstance(f, BenignFact) else tuple(f)
        if entry[2] and entry not in seen:
            seen.add(entry)
            out.append(entry)
    return out


_CORPUS_FILE = (Path(__file__).resolve().parent.parent
                / "defaults" / "benign_corpus.elastic.json")
_CORPUS_CACHE: Optional[list] = None


def load_harvested_corpus(path: Optional[Path] = None) -> list:
    """Load the persisted benign corpus harvested from Elastic's exclusions.

    Returns the **attributable** entries only - the ones that name the process
    they belong to - because those are the ones a false-positive gate can
    honestly evaluate. Returns an empty list if the file is missing or damaged:
    a corpus that fails to load must degrade to "we know less", never to an
    exception that takes an import gate offline.
    """
    global _CORPUS_CACHE
    if path is None and _CORPUS_CACHE is not None:
        return _CORPUS_CACHE
    target = Path(path) if path else _CORPUS_FILE
    entries: list = []
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
        entries = [tuple(e) for e in data.get("attributable", [])
                   if isinstance(e, (list, tuple)) and len(e) == 3]
    except Exception:   # noqa: BLE001
        entries = []
    if path is None:
        _CORPUS_CACHE = entries
    return entries


def full_benign_corpus() -> list:
    """Valkyrie's hand-written benign commands PLUS the harvested fleet knowledge.

    This is the corpus every false-positive gate should be measured against. The
    hand-written half covers the developer's own machine; the harvested half
    covers software that broke on somebody else's - which is the half a solo
    project cannot generate at any level of effort.
    """
    return list(BENIGN_CORPUS) + load_harvested_corpus()


def attributable(entries: list) -> list:
    """The subset of harvested entries that NAME the process they belong to.

    Only these are valid false-positive evidence. An exclusion that gives a
    command-line fragment without saying which binary ran it is real knowledge,
    but it is not a test case: pairing that fragment with a process of our own
    choosing invents an assertion Elastic never made. Two earlier versions of
    this audit were wrong in exactly opposite directions - one fabricated
    ``svchost.exe`` as the runner, the other substituted whichever image the
    rule under test happened to target, which "proved" that a credential-dumper
    rule false-positives on a backup path. Both produced confident numbers about
    software combinations that have never existed.
    """
    return [e for e in entries if e[0] and e[2]]


def fires_on_benign(rule, entries: list) -> list:
    """Which harvested benign entries does ``rule`` wrongly fire on?

    Evaluates ONLY entries that name their own process (see :func:`attributable`),
    so every hit corresponds to a (binary, command line) pair a real EDR fleet
    actually observed and had to carve out.
    """
    hits: list = []
    for (img, par, cmd) in attributable(entries):
        try:
            if rule.matches(img.lower(), (par or "").lower(), (cmd or "").lower(), ""):
                hits.append((img, par or "(any)", cmd))
        except Exception:   # noqa: BLE001 — a corpus must never crash a gate
            continue
    return hits


def _rule_dict(r: Rule) -> dict:
    return {"id": r.id, "technique": r.technique, "severity": r.severity,
            "label": r.label, "reason": r.reason, "images": list(r.images),
            "images_not": list(r.images_not), "parents": list(r.parents),
            "parents_not": list(r.parents_not), "cmd_all": list(r.cmd_all),
            "cmd_not": list(r.cmd_not)}
