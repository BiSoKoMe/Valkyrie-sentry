"""Command-line normalization - defeat obfuscation BEFORE the rules run.

THE PROBLEM THIS SOLVES
-----------------------
Every rule in `behavioral_rules.py` matches lowercase substrings against a raw
command line. That is correct logic and it is trivially evaded. Measured
against the shipped 40-rule engine, all of these run a backdoor-account
creation or a shadow-copy deletion and match NOTHING:

    n^et us^er hacker /a^dd            cmd.exe caret escaping
    n"e"t user hacker /add             token-splitting quotes
    & ('ne'+'t') user hacker /add      PowerShell string concatenation
    vssa`dmin delete shadows           PowerShell backtick escaping
    [char]118+[char]115+[char]115      character arithmetic

5 of 8 trivial variants evaded the entire rule set. No adversary has typed a
clean command line in a decade, so the honest reading is that the measured
detection rate was against unobfuscated inputs only.

Adding more rules cannot fix this - the evasion is upstream of matching. One
normalization pass in front of the engine is worth more than several hundred
additional rules, because it restores EVERY existing rule against EVERY
obfuscated variant at once.

DESIGN CONTRACT
---------------
  * **Pure and total.** No I/O, no clock, no OS calls. Never raises - a
    normalizer that throws on hostile input is itself the vulnerability.
  * **Bounded.** Input is capped, the transform loop is capped, and every
    expansion is length-limited, so a crafted command line cannot cause
    quadratic blowup on the process-creation hot path.
  * **Additive, never lossy.** `classify_behavior` matches the RAW string and
    the normalized string and unions the hits. Normalization can only ever add
    detections, so a rule that depends on raw syntax cannot be broken by it.
  * **Obfuscation is itself a signal.** Transforms are split into `COSMETIC`
    (whitespace, case, environment variables - completely normal) and
    `EVASIVE` (caret, backtick, token-splitting quotes, char arithmetic,
    concatenation - these have no legitimate reason to appear). Only EVASIVE
    transforms set `obfuscated`, so ordinary commands are not labeled.

HONEST BOUNDARY
---------------
This handles *syntactic* obfuscation. It does not emulate PowerShell, so a
payload built by runtime logic (a decryption loop, a WMI-sourced string, a
download-then-invoke) still reaches the engine opaque. Full coverage needs
script emulation or AMSI's post-deobfuscation view (`amsi.py` already consumes
the latter for script blocks). This closes the large, cheap, mechanical half.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass

# Hot-path bounds. A command line longer than this is truncated for matching
# purposes - real ones are far shorter, and the cap is what keeps a hostile
# 2 MB argument from turning process creation into a regex denial of service.
MAX_INPUT = 8192
MAX_DECODED = 8192
MAX_ROUNDS = 3          # decoding can reveal further obfuscation; bounded

# Transform classes. COSMETIC appears in normal commands constantly; EVASIVE
# does not, so only EVASIVE contributes to the obfuscation verdict.
# "concat_benign" is a join of meaningfully-sized fragments - ordinary string
# building in program text (python -c, a git commit message). The join is still
# performed for matching; it just is not evidence of evasion.
COSMETIC = frozenset({"env_expand", "whitespace", "shortpath", "concat_benign",
                      "format_op_benign"})
# unicode_fold is EVASIVE, not cosmetic: nobody types `ｎｅｔ` (full-width
# Latin) or embeds a zero-width joiner mid-keyword by accident - both exist
# only to break string matching. Caveat: U+3000 (ideographic space) can appear
# legitimately in CJK filenames, so this signal alone is MEDIUM, never a block.
EVASIVE = frozenset({"caret", "backtick", "split_quotes", "char_arith",
                     "concat", "b64_decode", "unicode_fold", "format_op"})

# Environment variables worth expanding: the ones attackers actually use to
# hide a binary path. Values are the canonical defaults, NOT read from this
# machine's environment - normalization must stay pure and deterministic.
_ENV = {
    "comspec": r"c:\windows\system32\cmd.exe",
    "systemroot": r"c:\windows",
    "windir": r"c:\windows",
    "programdata": r"c:\programdata",
    "programfiles": r"c:\program files",
    "programfiles(x86)": r"c:\program files (x86)",
    "public": r"c:\users\public",
    "temp": r"c:\windows\temp",
    "tmp": r"c:\windows\temp",
    "appdata": r"c:\users\user\appdata\roaming",
    "localappdata": r"c:\users\user\appdata\local",
    "userprofile": r"c:\users\user",
    "allusersprofile": r"c:\programdata",
}

_SHORTPATH = {
    "progra~1": "program files",
    "progra~2": "program files (x86)",
    "windows~1": "windows",
    "docume~1": "documents and settings",
}

# %VAR% and %VAR:~offset,length% (the substring form used to build characters
# one at a time, e.g. %COMSPEC:~0,1% -> "c").
_RE_ENV = re.compile(r"%([a-z0-9_()]+)(?::~(-?\d+)(?:,(-?\d+))?)?%", re.I)
# PowerShell $env:VAR and ${env:VAR}
_RE_PSENV = re.compile(r"\$\{?env:([a-z0-9_()]+)\}?", re.I)
# 'abc' + "def" + 'ghi'  ->  abcdefghi
# Optional wrapping parens are consumed too: PowerShell writes the evasion as
# `& ('ne'+'t') user /add`, and leaving the parens behind yields "(net) user",
# which still fails a "net user" substring match - i.e. the concat transform
# would fire but recover nothing. The parens are grouping syntax, not part of
# the resolved command token.
_RE_CONCAT = re.compile(
    r"""\(?\s*(['"])([^'"]{0,64})\1(?:\s*\+\s*(['"])([^'"]{0,64})\3)+\s*\)?""")
_RE_CONCAT_PART = re.compile(r"""(['"])([^'"]{0,64})\1""")
# [char]110 + [char]101 ...  and  [char[]](110,101,116). Codepoints may be
# decimal (110) OR hex (0x6e) - obfuscators use both, and a decimal-only matcher
# leaves `[char]0x6e+[char]0x65+[char]0x74` (=>"net") fully un-normalized.
_CODE = r"(?:0x[0-9a-f]{1,6}|\d{1,7})"
_RE_CHAR_ARITH = re.compile(
    rf"""\[char\]\s*{_CODE}(?:\s*\+\s*\[char\]\s*{_CODE})*""", re.I)
_RE_CHAR_ONE = re.compile(rf"\[char\]\s*({_CODE})", re.I)
_RE_CHAR_ARRAY = re.compile(r"\[char\[\]\]\s*\(\s*([0-9a-fx\s,]{1,512})\)", re.I)
# PowerShell format operator:  "{0}{1}" -f 'ne','t'  ->  net . The template is a
# quoted string containing {N} placeholders; the args are a comma-separated list
# of quoted literals. Only literal args are resolvable (a variable arg leaves the
# placeholder in place, so a benign `"{0:N2}" -f $x` is untouched).
_RE_FORMAT = re.compile(
    r"""(['"])((?:[^'"]){0,256}?\{\d+\}(?:[^'"]){0,256}?)\1"""
    r"""\s*-f\s*((?:\s*(['"])[^'"]{0,64}\4\s*,?)+)""", re.I)
_RE_FMT_ARG = re.compile(r"""(['"])([^'"]{0,64})\1""")
# -enc / -encodedcommand <base64>
_RE_ENC = re.compile(
    r"(?:-|/)(?:e|ec|enc|encod|encodedcommand)\s+([A-Za-z0-9+/=]{16,})", re.I)
# FromBase64String('....')
_RE_FROMB64 = re.compile(
    r"frombase64string\s*\(\s*['\"]([A-Za-z0-9+/=]{16,})['\"]", re.I)
_RE_WS = re.compile(r"\s+")
# A quote is TOKEN-SPLITTING (obfuscation) only when it sits BETWEEN TWO WORD
# CHARACTERS: n"e"t. Requiring \w on both sides - not merely \S - is what
# keeps option-value quoting safe: `findstr /C:"net user"` has ':' before the
# quote, so it is left alone. An earlier \S version stripped it and turned a
# benign findstr into a T1136.001 hit; the benign corpus caught it.
# One OR MORE quotes between two word chars: n"e"t AND the empty-pair form
# ad""d (which cmd.exe also collapses to `add`). A single \S-safe guard on both
# sides keeps option-value quoting (`/C:"net user"`) untouched.
_RE_SPLIT_QUOTE = re.compile(r"(?<=\w)['\"]+(?=\w)")
# A concatenation is EVASIVE only when a fragment is short enough to have no
# purpose but evasion. `'ne'+'t'` fragments a single keyword; `'hello' +
# 'world'` inside `python -c "..."` is ordinary source code and must NOT be
# flagged. The JOIN still happens either way (it can only help matching) -
# this threshold governs only whether it counts as obfuscation.
_EVASIVE_FRAGMENT_LEN = 3
# Zero-width and BOM characters used to break up keywords invisibly.
_ZERO_WIDTH = dict.fromkeys(
    [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD], None)


@dataclass(frozen=True)
class Normalized:
    """Result of one normalization pass. `text` is what rules should match."""
    text: str
    transforms: tuple = ()
    decoded: tuple = ()          # plaintext recovered from base64 payloads

    @property
    def changed(self) -> bool:
        return bool(self.transforms)

    @property
    def obfuscated(self) -> bool:
        """True only when an EVASIVE transform fired - a command that merely
        used an environment variable or extra whitespace is not obfuscated."""
        return any(t in EVASIVE for t in self.transforms)

    @property
    def obfuscation_signals(self) -> tuple:
        return tuple(t for t in self.transforms if t in EVASIVE)


def _fold_unicode(s: str) -> str:
    """Full-width/homoglyph forms and zero-width separators -> plain ASCII."""
    s = s.translate(_ZERO_WIDTH)
    out = []
    for ch in s:
        o = ord(ch)
        # Full-width ASCII block U+FF01..U+FF5E maps to U+0021..U+007E.
        if 0xFF01 <= o <= 0xFF5E:
            out.append(chr(o - 0xFEE0))
        elif o == 0x3000:            # ideographic space
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)


def _fold_delimiters(s: str) -> str:
    """cmd.exe accepts `,` and `;` as argument delimiters equivalent to a
    space, so `whoami,/priv` and `net;user` run exactly like their spaced
    forms - but a rule keying on the contiguous `whoami /priv` string never
    sees them. Fold UNQUOTED `,`/`;` to a space so the spaced canonical form
    is matchable.

    Structure-aware: a comma is a delimiter only at the TOP LEVEL. Commas
    inside `"a,b"` (a quoted argument value), inside `(...)` (a `[char[]]`
    array like `(0x76,0x73)` or PowerShell arithmetic) and inside `%...%` (an
    env-substring spec like `%COMSPEC:~0,1%`) are STRUCTURAL - folding them
    breaks the very transforms char-arith and env-expand exist to unwind, which
    is exactly the regression the first draft of this caused. So this skips any
    comma/semicolon that is inside a quote, inside parentheses, or inside a
    percent pair, and folds only the rest.

    Even outside those, `classify_behavior` matches the ORIGINAL string too, so
    the normalized alternative can only ADD detections, never remove one - the
    same safety property the rest of this module relies on. Runs BEFORE quote
    stripping so its quote-awareness still has quotes to see.

    Found by the comma_delimit plate in redteam/evaluation/evasion_harness.py
    (4 techniques evaded at 80.8% resistance); generalizes the fix rather than
    listing the four."""
    out = []
    quote = ""
    depth = 0          # parenthesis nesting
    in_pct = False     # inside a %...% pair
    for ch in s:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
            out.append(ch)
        elif ch == "%":
            in_pct = not in_pct
            out.append(ch)
        elif ch == "(":
            depth += 1
            out.append(ch)
        elif ch == ")":
            depth = max(0, depth - 1)
            out.append(ch)
        elif ch in ",;" and depth == 0 and not in_pct:
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)


def _expand_env(s: str) -> str:
    def repl(m: re.Match) -> str:
        val = _ENV.get(m.group(1).lower())
        if val is None:
            return m.group(0)
        off, ln = m.group(2), m.group(3)
        if off is None:
            return val
        try:
            i = int(off)
            if ln is None:
                return val[i:]
            n = int(ln)
            return val[i:i + n] if n >= 0 else val[i:n]
        except (ValueError, IndexError):
            return val
    s = _RE_ENV.sub(repl, s)
    return _RE_PSENV.sub(
        lambda m: _ENV.get(m.group(1).lower(), m.group(0)), s)


def _join_concat(s: str) -> tuple[str, bool]:
    """'ne'+'t' -> net. Returns (text, was_evasive).

    The join always happens - recovering the plaintext can only help matching.
    `was_evasive` is True only when some fragment is <= _EVASIVE_FRAGMENT_LEN,
    i.e. a keyword was chopped into pieces too small to be meaningful source
    code. That distinction is what separates `('ne'+'t')` (evasion) from
    `python -c "print('hello' + 'world')"` (ordinary program text).
    """
    evasive = False

    def repl(m: re.Match) -> str:
        nonlocal evasive
        parts = [p.group(2) for p in _RE_CONCAT_PART.finditer(m.group(0))]
        if any(len(p) <= _EVASIVE_FRAGMENT_LEN for p in parts):
            evasive = True
        return "".join(parts)

    return _RE_CONCAT.sub(repl, s), evasive


def _code_to_int(tok: str):
    """Parse a codepoint token - decimal (110) or hex (0x6e) - or None."""
    tok = tok.strip()
    try:
        return int(tok, 16) if tok.lower().startswith("0x") else int(tok)
    except (ValueError, OverflowError):
        return None


def _resolve_char_arith(s: str) -> str:
    """[char]110+[char]101+[char]116 -> net ; [char[]](110,101) -> ne. Decimal
    and hex (0x6e) codepoints both supported."""
    def repl_chain(m: re.Match) -> str:
        out = []
        for c in _RE_CHAR_ONE.finditer(m.group(0)):
            v = _code_to_int(c.group(1))
            if v is None or not (0 <= v <= 0x10FFFF):
                return m.group(0)
            out.append(chr(v))
        return "".join(out) if out else m.group(0)

    def repl_array(m: re.Match) -> str:
        out = []
        for tok in m.group(1).split(","):
            if not tok.strip():
                continue
            v = _code_to_int(tok)
            if v is None or not (0 <= v <= 0x10FFFF):
                return m.group(0)
            out.append(chr(v))
        return "".join(out) if out else m.group(0)

    s = _RE_CHAR_ARRAY.sub(repl_array, s)
    return _RE_CHAR_ARITH.sub(repl_chain, s)


def _resolve_format(s: str) -> tuple[str, bool]:
    """`"{0}{1}" -f 'ne','t'` -> `net`. Returns (text, was_evasive).

    The substitution always happens (recovering the string can only help
    matching); `was_evasive` is True only when a resolved fragment is short
    enough (<= _EVASIVE_FRAGMENT_LEN) to be keyword-splitting rather than
    ordinary formatting - mirrors the concat design so `"{0:N2}" -f 'total'`
    (one long literal) is not flagged as obfuscation."""
    evasive = False

    def repl(m: re.Match) -> str:
        nonlocal evasive
        tmpl = m.group(2)
        args = [a.group(2) for a in _RE_FMT_ARG.finditer(m.group(3))]
        if not args:
            return m.group(0)

        def sub_ph(ph: re.Match) -> str:
            i = int(ph.group(1))
            return args[i] if 0 <= i < len(args) else ph.group(0)

        resolved = re.sub(r"\{(\d+)\}", sub_ph, tmpl)
        if any(len(a) <= _EVASIVE_FRAGMENT_LEN for a in args):
            evasive = True
        return resolved

    return _RE_FORMAT.sub(repl, s), evasive


def _decode_b64_payloads(s: str) -> list[str]:
    """Recover plaintext from -EncodedCommand / FromBase64String payloads.

    PowerShell's -EncodedCommand is UTF-16LE; FromBase64String is usually
    UTF-8. Both are attempted and whichever yields mostly-printable text is
    kept. Never raises on malformed base64."""
    out: list[str] = []
    for m in list(_RE_ENC.finditer(s)) + list(_RE_FROMB64.finditer(s)):
        blob = m.group(1)
        if len(blob) > MAX_DECODED:
            continue
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4),
                                   validate=False)
        except Exception:
            continue
        for enc in ("utf-16-le", "utf-8"):
            try:
                txt = raw.decode(enc, errors="strict")
            except (UnicodeDecodeError, LookupError):
                continue
            printable = sum(1 for c in txt if c.isprintable() or c.isspace())
            if txt and printable / len(txt) > 0.85:
                out.append(txt[:MAX_DECODED])
                break
    return out


def normalize_cmdline(cmdline: str) -> Normalized:
    """Strip syntactic obfuscation from a command line. Pure; never raises.

    Returns the normalized text plus which transforms fired. Callers should
    match rules against BOTH the original and `.text` (see classify_behavior)
    so normalization can only add detections, never remove them.
    """
    try:
        raw = (cmdline or "")[:MAX_INPUT]
        if not raw:
            return Normalized("")

        fired: list[str] = []
        decoded: list[str] = []
        cur = raw

        for _ in range(MAX_ROUNDS):
            before = cur

            s = _fold_unicode(cur)
            if s != cur:
                fired.append("unicode_fold")
            cur = s

            # cmd.exe caret and PowerShell backtick both escape the NEXT
            # character; for substring matching, dropping the escape char
            # recovers the keyword (n^et -> net, vssa`dmin -> vssadmin).
            if "^" in cur:
                s = cur.replace("^", "")
                if s != cur:
                    fired.append("caret")
                cur = s
            if "`" in cur:
                s = cur.replace("`", "")
                if s != cur:
                    fired.append("backtick")
                cur = s

            # Delimiter fold is quote-aware and must run BEFORE quote stripping
            # (which discards the quote state it depends on) and before concat
            # (whose `+` joins are never commas), so a `,`/`;` between tokens
            # becomes a space without touching a comma inside a quoted value.
            s = _fold_delimiters(cur)
            if s != cur:
                fired.append("delimiter_fold")
            cur = s

            # ORDER MATTERS: concat and char-arithmetic are QUOTE-DELIMITED, so
            # they must run BEFORE quote stripping. Running split_quotes first
            # turned ('ne'+'t') into (ne+t) and the concat transform then had
            # nothing to join - the evasion survived. Found by test [1].
            s, concat_evasive = _join_concat(cur)
            if s != cur:
                fired.append("concat" if concat_evasive else "concat_benign")
            cur = s

            # Format operator is also quote-delimited, so it runs alongside
            # concat BEFORE quote-stripping (same ordering lesson as concat).
            s, fmt_evasive = _resolve_format(cur)
            if s != cur:
                fired.append("format_op" if fmt_evasive else "format_op_benign")
            cur = s

            s = _resolve_char_arith(cur)
            if s != cur:
                fired.append("char_arith")
            cur = s

            s = _RE_SPLIT_QUOTE.sub("", cur)
            if s != cur:
                fired.append("split_quotes")
            cur = s

            s = _expand_env(cur)
            if s != cur:
                fired.append("env_expand")
            cur = s

            new_decoded = _decode_b64_payloads(cur)
            if new_decoded:
                for d in new_decoded:
                    if d not in decoded:
                        decoded.append(d)
                        fired.append("b64_decode")

            for frag, canon in _SHORTPATH.items():
                if frag in cur.lower():
                    cur = re.sub(re.escape(frag), canon, cur, flags=re.I)
                    fired.append("shortpath")

            if cur == before:
                break

        s = _RE_WS.sub(" ", cur).strip()
        if s != cur:
            fired.append("whitespace")
        cur = s

        # Decoded payloads are appended so a single substring match covers both
        # the outer command and any recovered inner script.
        if decoded:
            cur = (cur + " " + " ".join(decoded))[:MAX_INPUT + MAX_DECODED]

        return Normalized(text=cur,
                          transforms=tuple(dict.fromkeys(fired)),
                          decoded=tuple(decoded))
    except Exception:
        # Total by contract: any unforeseen input returns the original text
        # rather than breaking process-creation handling.
        return Normalized(text=(cmdline or "")[:MAX_INPUT])
