"""DGA (Domain Generation Algorithm) detector - corroborated, offline, precise.

Malware families that use DGAs generate large numbers of algorithmic domains
(`xjkqvw92hd8skwlqz3ty.com`) and try them until one resolves to the current C2.
The domains look random because they are - which is exactly what makes them hard
to catch *without* also flagging the many legitimate domains that look random
(CDN hash hostnames, short consonant-heavy brands). A naive "high entropy = block"
rule false-positives on `d1anzknqnc1kmb.cloudfront.net` and breaks real sites.

This detector is deliberately built for **precision first** (the project rule:
a false positive breaks a real site; precision > aggression). It fires only when
several independent signals agree on the domain's **registrable label** - never
on a subdomain, so a gibberish CDN hostname under a real parent is structurally
ignored:

  1. Registrable-label length    (DGA labels are long; short brands excluded).
  2. Shannon entropy             (repetitive/dictionary labels excluded).
  3. Bigram implausibility       (the linguistic signal: fraction of adjacent
                                  character pairs that never occur in a corpus
                                  of real words/brands - DGA gibberish is ~all
                                  rare pairs, real words are mostly common ones).

Only when all three clear their thresholds is a domain called DGA, and the
confidence blends the three so a longer, higher-entropy, more-implausible label
scores higher. Everything here is a **pure function** - no state, no network, no
per-call cost beyond the label - so it is deterministic and trivially testable.

HONEST BOUNDARY: this targets **long-label** DGA families (necurs, ramnit, gozi,
murofet, qakbot - 12-24 char registrable labels), which are the majority of
modern families. **Short-label** DGAs (some Conficker variants, 8-11 chars) are
out of scope: at that length the bigram/entropy signal cannot separate DGA from
real short brands without an unacceptable false-positive rate, which needs an
internet-scale trained model (marked "needs infra" in docs/GAP_ANALYSIS.md - we
do not fake it). This is a strong local signal, not a model. It is one voice in
the pipeline, corroborated by DNS timing, intel, and process context.
"""

from __future__ import annotations

import collections
import math
from dataclasses import dataclass

from .config import DGA_MIN_ENTROPY, DGA_MIN_LEN, DGA_MIN_RARE_BIGRAM


# --- Bigram model ---
# A deliberately simple, transparent, offline model: the set of character
# bigrams that occur in a corpus of common English words + major brand/domain
# tokens. Any bigram NOT in this set is "rare" (linguistically implausible).
# Built at import from readable source words so the model is auditable and easy
# to extend - not an opaque trained blob. Digits and hyphens are handled in the
# scorer (a letter/digit boundary counts as rare - interior digits are unusual
# in real registrable labels but ubiquitous in DGA output).
_CORPUS_WORDS = (
    # high-frequency English words (give the common-bigram backbone)
    "the of and to in is was he for it with as his on be at by had not are but "
    "from or have an they which one you were her all she there would their we him "
    "been has when who will more no if out so said what up its about into than them "
    "can only other new some could time these two may then do first any my now such "
    "like our over man me even most made after also did many before must through back "
    "years where much your way well down should because each just those people mister "
    "how too little state good very make world still own see men work long get here "
    "between both life being under never day same another know while last might great "
    "old year off come since against go came right used take three states himself few "
    "house use during without again place american around however home small found "
    "mrs thought went say part once general high upon school every don does got united "
    "left number course war until always away something fact though water less public "
    "put think almost hand enough far took head yet government system set better told "
    "nothing night end why called didnt eyes find going look asked later knew point "
    # tech / brand / domain tokens (so real brands are not flagged as gibberish)
    "google microsoft amazon apple netflix spotify github gitlab cloudflare wikipedia "
    "reddit linkedin instagram pinterest dropbox salesforce atlassian shopify zendesk "
    "mailchimp squarespace digitalocean stackoverflow bitbucket sourceforge wordpress "
    "facebook twitter youtube whatsapp tumblr flickr twitch discord slack notion figma "
    "cloudfront amazonaws gstatic googleusercontent githubusercontent fbcdn licdn ytimg "
    "akamai fastly cdn origin static assets media content delivery network service api "
    "login secure account portal dashboard analytics tracking pixel beacon telemetry "
    "washington national international american express bank america booking cambridge "
    "dictionary understanding grammarly crunchyroll kickstarter thesaurus merriamwebster "
    "paypal stripe adobe oracle nvidia intel cisco vmware redhat ubuntu debian fedora "
    "python java rust golang kotlin swift docker kubernetes terraform ansible jenkins"
)


def _build_common_bigrams(corpus: str) -> frozenset:
    out: set[str] = set()
    for word in corpus.split():
        w = word.strip().lower()
        for i in range(len(w) - 1):
            pair = w[i:i + 2]
            if pair.isalpha():
                out.add(pair)
    return frozenset(out)


_COMMON_BIGRAMS = _build_common_bigrams(_CORPUS_WORDS)

# Common two-label public suffixes, so the registrable label of `foo.co.uk` is
# `foo` (not `co`) and a random `<gibberish>.co.uk` is scored on the gibberish.
_MULTI_SUFFIXES = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "gov.au", "edu.au",
    "co.jp", "or.jp", "ne.jp", "co.kr", "co.nz", "co.za", "co.in", "co.il",
    "com.br", "com.cn", "com.mx", "com.tr", "com.sg", "com.hk", "com.tw",
})


def shannon_entropy(s: str) -> float:
    """Shannon entropy of ``s`` in bits per character (0 for empty)."""
    if not s:
        return 0.0
    counts = collections.Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def registrable_label(domain: str) -> str:
    """The registrable (second-level) label of a hostname.

    `xjkqvw92hd8skwlqz3ty.com` -> `xjkqvw92hd8skwlqz3ty`
    `d1anzknqnc1kmb.cloudfront.net` -> `cloudfront`   (subdomain ignored)
    `random.co.uk` -> `random`
    """
    parts = (domain or "").strip().strip(".").lower().split(".")
    parts = [p for p in parts if p]
    if len(parts) < 2:
        return parts[0] if parts else ""
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_SUFFIXES:
        return parts[-3]
    return parts[-2]


def rare_bigram_fraction(label: str) -> float:
    """Fraction of adjacent character pairs that are linguistically implausible.

    A pair is "rare" if it is not a bigram of any corpus word, OR it crosses a
    letter/digit boundary or contains a digit (interior digits are unusual in
    real registrable labels but common in DGA output). ~0 for real words,
    approaching 1 for algorithmic gibberish.
    """
    if len(label) < 2:
        return 0.0
    pairs = [label[i:i + 2] for i in range(len(label) - 1)]
    rare = 0
    counted = 0
    for p in pairs:
        # Hyphens are a *negative* DGA signal (algorithmic domains don't
        # hyphenate; real brands do: `libjpeg-turbo`, `coca-cola`). Treat a
        # hyphen as a word separator - skip the pair so it neither inflates
        # nor deflates the score - which keeps hyphenated brands well clear.
        if "-" in p:
            continue
        counted += 1
        if p.isalpha():
            if p not in _COMMON_BIGRAMS:
                rare += 1
        else:
            rare += 1        # digit-adjacent pair (interior digits are unusual)
    return rare / counted if counted else 0.0


@dataclass(frozen=True)
class DgaResult:
    is_dga: bool
    confidence: float          # 0.0-1.0 (0 when not DGA)
    label: str                 # the registrable label evaluated
    reason: str
    entropy: float = 0.0
    rare_fraction: float = 0.0


def classify_dga(domain: str) -> DgaResult:
    """Classify a hostname's registrable label as DGA or not. Pure.

    Fires only when length, entropy, and bigram-implausibility all clear their
    thresholds (see module docstring) - a single strong signal is never enough,
    which is what keeps this off legitimate random-looking hostnames.
    """
    label = registrable_label(domain)
    n = len(label)
    if n < DGA_MIN_LEN:
        return DgaResult(False, 0.0, label, "label too short for DGA analysis")

    ent = shannon_entropy(label)
    rare = rare_bigram_fraction(label)

    if ent < DGA_MIN_ENTROPY or rare < DGA_MIN_RARE_BIGRAM:
        return DgaResult(False, 0.0, label,
                         "does not meet DGA corroboration threshold",
                         entropy=round(ent, 3), rare_fraction=round(rare, 3))

    # All three agree -> DGA. Confidence blends how far past each floor we are,
    # weighted toward the linguistic (bigram) signal, which is the discriminator.
    rare_c = (rare - DGA_MIN_RARE_BIGRAM) / (1.0 - DGA_MIN_RARE_BIGRAM)
    ent_c = min(1.0, (ent - DGA_MIN_ENTROPY) / (4.5 - DGA_MIN_ENTROPY))
    len_c = min(1.0, (n - DGA_MIN_LEN) / (24 - DGA_MIN_LEN))
    confidence = min(1.0, 0.70 + 0.20 * rare_c + 0.06 * ent_c + 0.04 * len_c)

    reason = (f"DGA-like registrable label '{label}' "
              f"(len {n}, entropy {ent:.2f}, {rare*100:.0f}% implausible bigrams)")
    return DgaResult(True, round(confidence, 3), label, reason,
                     entropy=round(ent, 3), rare_fraction=round(rare, 3))
