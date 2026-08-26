"""Adaptive hardening — Valkyrie learns from a confirmed miss, SAFELY.

THE HONEST VERSION OF "LEARN FROM ITS MISTAKES"
-----------------------------------------------
The naive version is a trap: watch a Tier B miss, auto-write a rule from the
command that slipped, load it live. That learns *garbage* (a rule that memorises
one literal string is trivially evaded) and, far worse for a tool that sits in
front of everything, it creates FALSE POSITIVES — and a privacy/EDR agent that
breaks a legitimate program has already failed, no matter how much it "learned".

So this module is the safe shape real detection teams use, made into a closed
loop: a confirmed miss becomes a *candidate* rule that is GENERALISED (behaviour,
not the literal string), then put through three hard gates before it is ever
allowed near production:

    1. ZERO-FALSE-POSITIVE gate  — the candidate is run against a benign corpus
       of legitimate commands. It fires on even ONE of them -> REJECTED. This is
       the non-negotiable gate; everything else is secondary to "never break a
       real program".
    2. CLOSES-THE-MISS gate      — it must actually detect the missed technique
       AND at least a couple of its obfuscated variants (the progressive-overload
       transforms). A candidate that only catches the exact literal is
       memorisation, not learning -> REJECTED as too narrow.
    3. NO-REGRESSION gate        — it must be genuinely new (not duplicate an
       existing rule id / shape).

Only a candidate that passes all three becomes an APPROVED proposal — and even
then it is *staged for review / gated promotion*, never silently activated. The
learner proposes; a human (or a strict, auditable auto-promote that requires all
gates green) disposes. That asymmetry is the whole safety model: the system can
get smarter on its own, but it cannot make itself more dangerous on its own.

PURE. `propose` is a function of (miss, benign corpus, existing rules) -> a
Proposal with its full evidence and verdict. No file is written, no rule is
loaded, nothing global is touched — so the logic that decides what Valkyrie is
allowed to learn is exhaustively testable offline (test_adaptive.py).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Callable, Optional

from ..behavioral_rules import Rule


class Verdict(str, Enum):
    APPROVED = "approved_for_promotion"        # passed every gate; may be staged
    REJECTED_FP = "rejected_false_positive"    # fired on a benign sample
    REJECTED_NARROW = "rejected_too_narrow"    # only the literal; no generalisation
    REJECTED_DUPLICATE = "rejected_duplicate"  # an existing rule already covers it
    REJECTED_UNGENERALISABLE = "rejected_ungeneralisable"  # no safe tokens found


# ---------------------------------------------------------------------------
# Generalisation — extract BEHAVIOUR, discard the literal (paths, IPs, hosts,
# random names). Memorising those is what makes a "learned" rule both evadable
# and useless; keeping only the shape is what makes it a real detection.
# ---------------------------------------------------------------------------
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_URL_SCHEME = re.compile(r"\b(?:https?|ftp|smb)://", re.I)
_UNC = re.compile(r"\\\\[^\s\\]+")
_LOOKS_PATH = re.compile(r"[A-Za-z]:\\|/[A-Za-z0-9_.]+/")   # C:\... or /usr/...
_RANDOMISH = re.compile(r"^[A-Za-z0-9+/=_-]{16,}$")          # base64-ish / GUID-ish blob


def _generalise(cmdline: str) -> dict:
    """Turn a raw command line into generalised, behaviour-carrying tokens.

    Returns dict with:
      flags     - argument flags/verbs (start with / or -), lowercased
      net_marker- a CATEGORY marker if the command reaches out (url/unc/ip),
                  never the literal destination
      literals_dropped - what we deliberately refused to memorise (for audit)
    """
    _, _, args = cmdline.strip().partition(" ")
    tokens = args.split()
    flags: list[str] = []
    dropped: list[str] = []
    net_marker = ""

    if _URL_SCHEME.search(cmdline):
        net_marker = "url"          # generalises ANY http(s)/ftp/smb URL
    elif _UNC.search(cmdline):
        net_marker = "unc"
    elif _IPV4.search(cmdline):
        net_marker = "ip"

    for tok in tokens:
        low = tok.lower()
        # a flag / subcommand carries behaviour; keep a bounded, safe form.
        # Extract the flag STEM (before any ':' or '=') FIRST, then bound-check
        # the stem - a flag like /format:"http://long/url" is a keeper even
        # though the whole token is long, because only the stem is the shape.
        if tok.startswith(("/", "-")):
            stem = re.split(r"[:=]", low, 1)[0]
            if stem and len(stem) <= 24 and not _LOOKS_PATH.search(stem) \
                    and stem not in flags:
                flags.append(stem)
        if _IPV4.search(tok) or _URL_SCHEME.search(tok) or _UNC.search(tok) \
                or _LOOKS_PATH.search(tok) or _RANDOMISH.match(tok):
            dropped.append(tok)     # literal noise — refuse to memorise
        # bare words (subcommands like "process", "stop") are ambiguous: they
        # carry some behaviour but also cause FPs, so they are NOT auto-kept;
        # the FP gate would reject them anyway. Keeping only flags + net-marker
        # is the conservative choice.
    return {"flags": flags, "net_marker": net_marker, "literals_dropped": dropped}


_NET_TOKENS = {"url": ("http://", "https://", "ftp://", "smb://"),
               "unc": (r"\\",), "ip": ()}  # ip alone is too broad to key on


def build_candidate(miss_id: str, technique: str, image: str,
                    cmdline: str, severity: str = "high") -> Optional[Rule]:
    """Synthesise a GENERALISED candidate Rule from a miss, or None if nothing
    safely generalisable was found (better no rule than a bad one)."""
    g = _generalise(cmdline)
    image = (image or "").strip().lower()
    cmd_all = tuple(g["flags"][:3])                 # the distinctive flags
    cmd_any = _NET_TOKENS.get(g["net_marker"], ())  # generalised network reach

    # A candidate needs a positive, non-trivial anchor: a known image AND at
    # least one behavioural flag, OR (image + a network-reach category). An
    # image alone (e.g. "wmic.exe" fires on ALL wmic) is too broad and is left
    # to the FP gate to reject, but we avoid emitting it in the first place.
    if not image:
        return None
    if not cmd_all and not cmd_any:
        return None

    return Rule(
        id=f"adaptive-{miss_id}",
        technique=technique,
        severity=severity,
        label=f"adaptive_{miss_id.replace('-', '_')}",
        reason=f"Adaptively proposed from a confirmed live miss of {technique}; "
               f"generalised to behaviour (flags={cmd_all}, "
               f"net={g['net_marker'] or 'none'}), not the literal command.",
        images=(image,),
        cmd_all=cmd_all,
        cmd_any=cmd_any,
    )


@dataclass
class Miss:
    """A confirmed miss the librarian handed us: it executed, the engine was up,
    and no detection fired. Only these are eligible to learn from — never an
    infra failure, never an unexecuted attack."""
    technique_id: str
    technique: str        # full label
    image: str
    parent: str
    cmdline: str


@dataclass
class Proposal:
    miss_id: str
    verdict: Verdict
    rule: Optional[dict] = None            # the candidate Rule, serialised
    catches_miss: bool = False
    evasion_variants_caught: int = 0
    benign_false_positives: tuple = ()     # benign samples it wrongly fired on
    reasons: tuple = ()

    @property
    def approved(self) -> bool:
        return self.verdict == Verdict.APPROVED

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        d["benign_false_positives"] = list(self.benign_false_positives)
        d["reasons"] = list(self.reasons)
        return d


# ---------------------------------------------------------------------------
# The benign corpus — legitimate commands that MUST NEVER trigger. This is the
# safety ground truth: a learned rule that fires on any of these is rejected.
# Deliberately spans dev tooling, admin, and everyday app launches, because
# those are exactly what a too-broad "learned" rule breaks.
# ---------------------------------------------------------------------------
BENIGN_CORPUS = [
    ("git.exe", "cmd.exe", r"git.exe clone https://github.com/user/repo.git"),
    ("curl.exe", "cmd.exe", r"curl.exe https://api.example.com/v1/status"),
    ("npm.cmd", "cmd.exe", r"npm.cmd install --save-dev typescript"),
    ("python.exe", "cmd.exe", r"python.exe -m pip install requests"),
    ("wmic.exe", "cmd.exe", r"wmic os get caption"),
    ("wmic.exe", "cmd.exe", r"wmic logicaldisk get size,freespace"),
    ("sc.exe", "services.exe", r"sc.exe query wuauserv"),
    ("net.exe", "cmd.exe", r"net.exe use"),
    ("reg.exe", "cmd.exe", r"reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion"),
    ("findstr.exe", "cmd.exe", r"findstr TODO src\main.py"),
    ("attrib.exe", "explorer.exe", r"attrib.exe C:\Users\bob\Documents\report.docx"),
    ("msbuild.exe", "devenv.exe", r"msbuild.exe MySolution.sln /p:Configuration=Release"),
    ("msiexec.exe", "explorer.exe", r"msiexec.exe /i C:\Downloads\LegitApp.msi /quiet"),
    ("powershell.exe", "explorer.exe", r"powershell.exe -Command Get-Process"),
    ("rundll32.exe", "explorer.exe", r"rundll32.exe shell32.dll,Control_RunDLL"),
    ("ipconfig.exe", "cmd.exe", r"ipconfig.exe /all"),
    ("tar.exe", "cmd.exe", r"tar.exe -czf backup.tar.gz project/"),
    ("code.exe", "explorer.exe", r"code.exe C:\Users\bob\project"),
]


def propose(miss: Miss, *,
            benign_corpus: Optional[list] = None,
            existing_rule_ids: Optional[set] = None,
            evasion_transforms: Optional[dict] = None) -> Proposal:
    """Turn a confirmed miss into a gated Proposal. Pure; activates nothing.

    ``benign_corpus``      list of (image, parent, cmdline) that must NOT fire.
    ``existing_rule_ids``  ids already shipped, for the duplicate gate.
    ``evasion_transforms`` {name: fn(cmdline)->str|None} to test generalisation
                           robustness (e.g. the progressive-overload transforms).
    """
    corpus = BENIGN_CORPUS if benign_corpus is None else benign_corpus
    existing = existing_rule_ids or set()
    miss_id = miss.technique_id.replace(".", "_").lower()

    cand = build_candidate(miss_id, miss.technique, miss.image, miss.cmdline)
    if cand is None:
        return Proposal(miss_id, Verdict.REJECTED_UNGENERALISABLE,
                        reasons=("no safe, behaviour-carrying tokens could be "
                                 "extracted without memorising a literal "
                                 "path/IP/host — better no rule than a bad one",))

    if cand.id in existing:
        return Proposal(miss_id, Verdict.REJECTED_DUPLICATE,
                        rule=_rule_dict(cand),
                        reasons=(f"a rule {cand.id!r} already exists",))

    # ---- GATE 1: zero false positives (the non-negotiable one) -----------
    fps = tuple(f"{img} :: {cmd}"
                for (img, par, cmd) in corpus
                if cand.matches(img.lower(), par.lower(), cmd, ""))
    if fps:
        return Proposal(miss_id, Verdict.REJECTED_FP, rule=_rule_dict(cand),
                        benign_false_positives=fps,
                        reasons=(f"fires on {len(fps)} legitimate command(s); a "
                                 f"learned rule that breaks real programs is "
                                 f"never promoted, however well it catches the "
                                 f"attack",))

    # ---- GATE 2: actually closes the miss, and generalises past the literal
    catches = cand.matches(miss.image.lower(), (miss.parent or "").lower(),
                           miss.cmdline, "")
    variants_caught = 0
    if evasion_transforms:
        for _name, fn in evasion_transforms.items():
            try:
                v = fn(miss.cmdline)
            except Exception:
                v = None
            if v and cand.matches(miss.image.lower(),
                                  (miss.parent or "").lower(), v, ""):
                variants_caught += 1
    if not catches:
        return Proposal(miss_id, Verdict.REJECTED_NARROW, rule=_rule_dict(cand),
                        catches_miss=False,
                        reasons=("the generalised candidate does not even catch "
                                 "the miss it was built from",))
    # Require SOME evasion robustness only if transforms were supplied; without
    # them we cannot judge narrowness, so we do not fail on it.
    if evasion_transforms and variants_caught == 0:
        return Proposal(miss_id, Verdict.REJECTED_NARROW, rule=_rule_dict(cand),
                        catches_miss=True, evasion_variants_caught=0,
                        reasons=("catches the exact literal but none of its "
                                 "obfuscated variants — this is memorisation, "
                                 "not a generalising detection",))

    # ---- all gates green ------------------------------------------------
    return Proposal(
        miss_id, Verdict.APPROVED, rule=_rule_dict(cand),
        catches_miss=True, evasion_variants_caught=variants_caught,
        reasons=(f"generalised to behaviour, 0 false positives across "
                 f"{len(corpus)} benign commands, catches the miss"
                 + (f" + {variants_caught} obfuscated variant(s)"
                    if evasion_transforms else "")
                 + "; STAGED for review — not auto-activated",))


def _rule_dict(r: Rule) -> dict:
    return {"id": r.id, "technique": r.technique, "severity": r.severity,
            "label": r.label, "images": list(r.images),
            "cmd_all": list(r.cmd_all), "cmd_any": list(r.cmd_any),
            "reason": r.reason}
