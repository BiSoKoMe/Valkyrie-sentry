"""Behavioral anomaly scorer — Valkyrie's *own nose*, not a list of known smells.

The IOA rule engine (behavioral_rules.py) is a list: 32 exact command shapes,
each a photograph of one known attack. It cannot see a threat nobody
photographed. This module is the complementary half — the part that
*generalizes*. It scores the **intrinsic wrongness** of a process the way a
drug dog scores a scent: not "does this match sample #14," but "does this smell
like something hiding."

The idea is a weak-signal ensemble. No single signal is a verdict. A process
running from a temp folder is not malware — installers do it. A binary with a
high-entropy name is not malware — some legit tools ship GUIDs. But *masquerade
+ temp-exec + obfuscated command line + impossible ancestry* compounding
together is a scent no benign program emits, and — crucially — it fires on
malware the rule list has never seen, because it keys on the *shape of hiding*,
not on specific strings.

Design (matches the project's precision-over-aggression standard: a false
positive breaks a user's machine, so the bar to FIRE is high):

  * Every signal is INTRINSIC and GENERALIZING — a masquerading system-process
    name, execution from a low-trust directory, measured command-line
    obfuscation, an impossible parent→child lineage, a name that looks
    machine-generated or double-extensioned. None keys on a known-bad literal.
  * Each signal carries a WEIGHT tuned so that no single weak signal crosses the
    firing threshold. Only a strong intrinsic tell (a masquerading system name)
    or a COMBINATION of weak ones scores as a threat. This is what keeps the
    false-positive rate near zero while still generalizing.
  * The scorer is PURE and deterministic given its inputs — unit-tested with a
    benign control for every malicious shape, exactly like the rule engine.
  * An optional per-host ancestry BASELINE lets the nose be "trained on your
    house": a parent→child pairing never seen on this machine adds a small lift,
    so genuinely novel local activity stands out. Off by default (stateless).

This is detection, not prevention, and a score is not a proof — see the honest
boundary in docs/adr/0028. But it is the difference between a scanner that only
recognizes catalogued malware and one that can smell a brand-new sample.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Callable, Optional

from .telemetry import (SEV_CRITICAL, SEV_HIGH, SEV_INFO, SEV_LOW, SEV_MEDIUM)


# ── Output types ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Signal:
    """One intrinsic tell that contributed to the score."""
    name: str
    weight: float
    reason: str
    technique: str = ""      # optional ATT&CK hint the top signal contributes


@dataclass(frozen=True)
class BehaviorScore:
    score: float                     # 0.0 .. 1.0, capped
    severity: str
    signals: tuple                   # tuple[Signal, ...], strongest first
    technique: str                   # dominant signal's ATT&CK id, or ""
    reason: str                      # human summary

    def fired(self) -> bool:
        """A threat-grade scent: score crossed the medium bar."""
        return self.score >= _FIRE_THRESHOLD


# The firing bar. Weights below are tuned around it: a lone weak signal
# (max 0.35) stays under it; a strong intrinsic tell or a combination clears it.
_FIRE_THRESHOLD = 0.45

# score → severity. Mirrors the weak-signal accumulation: one strong tell = high,
# a stacked combination = critical.
_SEV_BANDS = (
    (0.85, SEV_CRITICAL),
    (0.65, SEV_HIGH),
    (0.45, SEV_MEDIUM),
    (0.25, SEV_LOW),
)


def _severity_for(score: float) -> str:
    for threshold, sev in _SEV_BANDS:
        if score >= threshold:
            return sev
    return SEV_INFO


# ── Vocabularies (small, explicit) ──────────────────────────────────────────

# Windows core processes that ALWAYS live in System32 (or SysWOW64). Seeing one
# of these names anywhere else is one of the highest-signal tells in all of EDR:
# malware loves to wear the uniform of a trusted system process.
_SYSTEM_IMAGES = frozenset({
    "svchost.exe", "lsass.exe", "services.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "smss.exe", "spoolsv.exe", "taskhostw.exe", "dllhost.exe",
    "conhost.exe", "sihost.exe", "fontdrvhost.exe", "lsm.exe", "ctfmon.exe",
})
_SYSTEM_DIRS = ("\\windows\\system32\\", "\\windows\\syswow64\\",
                "\\windows\\winsxs\\")

# Interpreters / script hosts — the payload delivery vehicles. Running one of
# these from a low-trust directory, or as a child of a document/browser, is the
# generalizing core of "living off the land."
_INTERPRETERS = frozenset({
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe", "msbuild.exe",
    "installutil.exe", "regasm.exe", "regsvcs.exe", "cmstp.exe", "hh.exe",
})

# Applications that open attacker-controlled content and should essentially
# NEVER spawn an interpreter. A parent→child edge from any of these to a shell
# is the classic macro/exploit foothold — and this generalizes across every
# payload, unlike a rule that names one command.
_DOC_AND_NET_APPS = frozenset({
    # Office
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
    "msaccess.exe", "mspub.exe", "visio.exe",
    # Browsers
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
    "iexplore.exe",
    # PDF / readers
    "acrord32.exe", "acrobat.exe", "foxitreader.exe", "sumatrapdf.exe",
    # Comms (common phishing delivery)
    "teams.exe", "slack.exe", "zoom.exe", "discord.exe", "thunderbird.exe",
})

# Internet-facing service processes. One of these spawning a shell is the
# textbook web-shell / exploited-service pattern (T1505.003), and no command
# string is involved to write a rule against.
_SERVER_PROCS = frozenset({
    "w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe", "tomcat9.exe",
    "java.exe", "sqlservr.exe", "mysqld.exe", "php-cgi.exe", "node.exe",
    "ws_tomcatservice.exe", "aspnet_wp.exe",
})
_SHELLS = frozenset({"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
                     "cscript.exe", "mshta.exe", "bash.exe", "sh.exe"})

# Low-trust, user-writable execution locations. Kept TIGHT on purpose: AppData\
# Local\<app>\ and Program Files are where legitimate updaters and apps live, so
# only genuinely low-trust roots are here. A plain exe from one of these is a
# weak signal (installers do it); an INTERPRETER from one is stronger.
_LOWTRUST_DIRS = (
    "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\temp\\", "\\tmp\\",
    "\\$recycle.bin\\", "\\recycler\\", "\\programdata\\temp\\",
    "\\users\\public\\", "\\downloads\\", "\\perflogs\\",
)

# Double-extension lure: a document-looking name with an executable tail.
_LURE_STEMS = ("pdf", "doc", "docx", "xls", "xlsx", "ppt", "txt", "jpg", "jpeg",
               "png", "gif", "rtf", "csv", "htm", "html", "zip", "invoice",
               "scan", "receipt", "resume", "cv")
_EXE_TAILS = ("exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs",
              "vbe", "wsf", "hta", "lnk", "ps1")

# Bidirectional / control unicode used to disguise a file's real extension
# (the "Trojan Source" trick: a RIGHT-TO-LEFT OVERRIDE before `gpj.exe`
# makes it render as `invoice.exe.jpg` while still executing as .exe).
#
# Written as escapes, never as the literal characters. These are exactly the
# codepoints that make source unreadable, so embedding them raw would make
# this file's own diff untrustworthy and trips Trojan-Source scanners
# (bandit B613) on our own detector. A detector for a trick must not
# perform the trick.
_BIDI = (
    "\u202a",  # LEFT-TO-RIGHT EMBEDDING
    "\u202b",  # RIGHT-TO-LEFT EMBEDDING
    "\u202c",  # POP DIRECTIONAL FORMATTING
    "\u202d",  # LEFT-TO-RIGHT OVERRIDE
    "\u202e",  # RIGHT-TO-LEFT OVERRIDE
    "\u200e",  # LEFT-TO-RIGHT MARK
    "\u200f",  # RIGHT-TO-LEFT MARK
    "\u2066",  # LEFT-TO-RIGHT ISOLATE
    "\u2067",  # RIGHT-TO-LEFT ISOLATE
    "\u2068",  # FIRST STRONG ISOLATE
    "\u2069",  # POP DIRECTIONAL ISOLATE
)


# ── Small pure helpers ──────────────────────────────────────────────────────

def _basename(path: str) -> str:
    p = path.replace("/", "\\")
    return p.rsplit("\\", 1)[-1] if "\\" in p else p


def shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char) of a string. 0 for empty."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_machine_generated(stem: str) -> bool:
    """True if an executable's base name looks algorithmically generated
    (DGA-style): long, high-entropy, vowel-starved or digit-heavy. Pure.

    Precision guardrails: short names and ordinary words (which have vowels and
    low entropy) are rejected, so 'chrome', 'update', 'setup' never trip it.
    """
    s = re.sub(r"[^a-z0-9]", "", stem.lower())
    if len(s) < 10:
        return False
    letters = [c for c in s if c.isalpha()]
    digits = [c for c in s if c.isdigit()]
    vowels = sum(1 for c in letters if c in "aeiou")
    vowel_ratio = vowels / len(letters) if letters else 0.0
    digit_ratio = len(digits) / len(s)
    ent = shannon_entropy(s)
    # High entropy AND (few vowels OR many digits): the fingerprint of a random
    # string. Real words keep vowel_ratio ~0.35-0.45 (so the discriminator
    # rejects them even at high entropy). The 3.0 floor is deliberately below
    # log2(10)=3.32 so a 10-char near-random name can still qualify.
    return ent >= 3.0 and (vowel_ratio < 0.26 or digit_ratio >= 0.30)


_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{30,}={0,3}")
_HEX_BLOB = re.compile(r"(?:0x)?[0-9a-fA-F]{40,}")
_IP_LITERAL = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL = re.compile(r"\b(?:https?|ftp)://", re.I)
_CHARCODE = ("[char]", "-join", "[convert]::", "frombase64string",
             "[system.text.encoding]", "::frombase64", "[system.convert]",
             "char[]]", "-bxor", "-replace")
_ENV_SPLICE = ("%comspec:~", "%path:~", "%windir:~", "cmd/c set",
               "${env:", "%programdata:~", "%public:~")


def obfuscation_strength(cmd: str) -> tuple[float, list[str]]:
    """Measure how *obfuscated* a command line looks, 0.0 .. 1.0, plus the tells.

    This is the generalizing crown jewel: it scores obfuscation by SHAPE
    (encoded blobs, char-code reassembly, escape-character spam, env-var
    splicing, format-operator string building) rather than by matching known
    bad strings — so a brand-new obfuscated command still smells. Pure.
    """
    if not cmd:
        return 0.0, []
    low = cmd.lower()
    n = max(len(cmd), 1)
    strength = 0.0
    tells: list[str] = []

    # Long base64 / hex blob embedded in the command → encoded payload. 30 chars
    # is already well past ordinary tokens/GUIDs (32 hex) and squarely in
    # payload territory; a lone blob only contributes, it does not fire.
    b64 = _B64_BLOB.search(cmd)
    if b64 and len(b64.group(0)) >= 30:
        strength += 0.3
        tells.append("embedded encoded blob")
    elif _HEX_BLOB.search(cmd):
        strength += 0.25
        tells.append("embedded hex blob")

    # PowerShell -EncodedCommand family.
    if any(t in low for t in ("-enc ", "-enc:", "-encodedcommand", " -ec ",
                              "-e ja", "-e sq")):
        strength += 0.3
        tells.append("encoded-command switch")

    # Char-code / bit-twiddle reassembly — building a string to dodge scanners.
    cc = sum(1 for t in _CHARCODE if t in low)
    if cc:
        strength += min(0.3, 0.15 * cc)
        tells.append("char-code/bitwise string reassembly")

    # Escape-character spam: caret in cmd.exe, backtick in PowerShell. Density
    # relative to length distinguishes obfuscation from the odd literal caret.
    # Heavy escaping is essentially never benign, so it is weighted to fire on
    # its own — no legitimate command carets every character.
    carets = cmd.count("^")
    ticks = cmd.count("`")
    if carets >= 6 and carets / n > 0.03:
        strength += 0.45
        tells.append("caret-escape obfuscation")
    if ticks >= 6 and ticks / n > 0.03:
        strength += 0.45
        tells.append("backtick-escape obfuscation")

    # Environment-variable substring splicing to assemble commands.
    if any(t in low for t in _ENV_SPLICE):
        strength += 0.2
        tells.append("environment-variable splicing")

    # Format-operator string building: -f with many {N} slots.
    if " -f " in low and len(re.findall(r"\{\d+\}", cmd)) >= 3:
        strength += 0.2
        tells.append("format-operator string building")

    # Concatenation spam: many quoted fragments glued with '+'.
    if cmd.count("'+'") + cmd.count('"+"') >= 4:
        strength += 0.2
        tells.append("concatenation obfuscation")

    return min(1.0, strength), tells


# ── The scoring context and signal detectors ────────────────────────────────

@dataclass(frozen=True)
class _Ctx:
    image: str           # lowercased basename
    parent: str          # lowercased parent basename
    cmd: str             # lowercased command line
    raw_cmd: str         # original-case command line
    path: str            # lowercased, backslash-normalized full image path
    raw_image: str       # original-case image basename (for unicode checks)


class AncestryBaseline:
    """Per-host frequency of parent→child process pairings — the 'trained on
    your house' memory. Pure and in-memory; the caller decides persistence.

    A pairing observed many times here is normal *for this machine*; one never
    seen adds a small lift to the score, so novel local activity stands out even
    when its individual command looks unremarkable.
    """

    def __init__(self, warmup: int = 5) -> None:
        self._pairs: dict[tuple[str, str], int] = {}
        self._warmup = max(1, warmup)   # ignore rarity until the host is learned

    @property
    def total(self) -> int:
        return sum(self._pairs.values())

    def observe(self, parent: str, child: str) -> None:
        key = ((parent or "").lower(), (child or "").lower())
        self._pairs[key] = self._pairs.get(key, 0) + 1

    def is_rare(self, parent: str, child: str) -> bool:
        # Don't call anything rare until we've seen enough of this host to have
        # a baseline — otherwise everything is "rare" on a cold start.
        if self.total < self._warmup:
            return False
        key = ((parent or "").lower(), (child or "").lower())
        return self._pairs.get(key, 0) == 0


def _sig_masquerade(c: _Ctx) -> Optional[Signal]:
    # A core system process name running from anywhere but a system directory.
    if c.image in _SYSTEM_IMAGES and c.path:
        if not any(d in c.path for d in _SYSTEM_DIRS):
            return Signal("masquerade_system_image", 0.75,
                          f"'{c.image}' is a Windows system process but is "
                          f"running from a non-system path",
                          "T1036.005 — Match Legitimate Name or Location")
    return None


def _sig_system_typosquat(c: _Ctx) -> Optional[Signal]:
    # Look-alike of a system process name: svch0st, scvhost, lsas, csrsss…
    stem = c.image.rsplit(".", 1)[0]
    for sysname in _SYSTEM_IMAGES:
        sys_stem = sysname.rsplit(".", 1)[0]
        if stem == sys_stem:
            return None  # exact name → handled by masquerade, not typosquat
        if _near(stem, sys_stem):
            return Signal("system_name_lookalike", 0.5,
                          f"'{c.image}' closely resembles system process "
                          f"'{sysname}' (typosquat)",
                          "T1036.005 — Match Legitimate Name or Location")
    return None


def _sig_double_extension(c: _Ctx) -> Optional[Signal]:
    parts = c.image.split(".")
    if len(parts) >= 3 and parts[-1] in _EXE_TAILS and parts[-2] in _LURE_STEMS:
        return Signal("double_extension", 0.6,
                      f"'{c.raw_image}' disguises an executable as a "
                      f"'{parts[-2]}' document",
                      "T1036.007 — Double File Extension")
    return None


def _sig_bidi_trick(c: _Ctx) -> Optional[Signal]:
    if any(ch in c.raw_image for ch in _BIDI):
        return Signal("bidi_filename_trick", 0.7,
                      "file name contains right-to-left / bidi control "
                      "characters that disguise its real extension",
                      "T1036.002 — Right-to-Left Override")
    return None


def _sig_random_name(c: _Ctx) -> Optional[Signal]:
    stem = c.image.rsplit(".", 1)[0]
    if looks_machine_generated(stem):
        return Signal("machine_generated_name", 0.35,
                      f"'{c.image}' has a machine-generated / high-entropy name",
                      "T1036 — Masquerading")
    return None


def _sig_lowtrust_exec(c: _Ctx) -> Optional[Signal]:
    if c.path and any(d in c.path for d in _LOWTRUST_DIRS):
        if c.image in _INTERPRETERS:
            # A real interpreter lives in System32; a copy of one running from
            # Temp/Downloads is a renamed/relocated binary dodging path
            # allowlists — strong enough to fire on its own.
            return Signal("interpreter_from_lowtrust", 0.5,
                          f"interpreter '{c.image}' is executing from a "
                          f"low-trust directory",
                          "T1059 — Command & Scripting Interpreter")
        return Signal("exec_from_lowtrust", 0.3,
                      f"'{c.image}' is executing from a low-trust / "
                      f"user-writable directory",
                      "T1204 — User Execution")
    return None


def _sig_impossible_ancestry(c: _Ctx) -> Optional[Signal]:
    # Web/DB server spawning a shell → web-shell / exploited service.
    if c.parent in _SERVER_PROCS and c.image in _SHELLS:
        return Signal("server_spawned_shell", 0.6,
                      f"internet-facing service '{c.parent}' spawned a shell "
                      f"('{c.image}') — web-shell pattern",
                      "T1505.003 — Web Shell")
    # Document/browser/comms app spawning an interpreter → macro/exploit foothold.
    if c.parent in _DOC_AND_NET_APPS and c.image in _INTERPRETERS:
        return Signal("document_spawned_interpreter", 0.5,
                      f"'{c.parent}' (opens untrusted content) spawned "
                      f"interpreter '{c.image}'",
                      "T1059 — Command & Scripting Interpreter")
    return None


def _sig_obfuscated_cmd(c: _Ctx) -> Optional[Signal]:
    strength, tells = obfuscation_strength(c.raw_cmd)
    if strength >= 0.25:
        # Weight tracks the measured strength: mild obfuscation only compounds,
        # heavy obfuscation (caret spam, blob + char-code reassembly) clears the
        # firing bar on its own.
        weight = min(0.6, strength)
        return Signal("obfuscated_command", weight,
                      "command line is obfuscated (" + ", ".join(tells) + ")",
                      "T1027 — Obfuscated Files or Information")
    return None


# Script-proxy LOLBins have no legitimate reason to load remote/UNC content —
# regsvr32/mshta/rundll32 pulling a remote scriptlet is the Squiblydoo family,
# essentially never benign. General interpreters (powershell/cmd) DO legitimately
# fetch URLs (developers hit internal services constantly), so those only compound.
_SCRIPT_PROXY = frozenset({
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "cscript.exe", "wscript.exe",
    "cmstp.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "hh.exe",
})


def _sig_lolbin_remote(c: _Ctx) -> Optional[Signal]:
    # An interpreter/LOLBin whose command reaches out to the network (URL, raw
    # IP, or UNC path) — the download-and-run shape, independent of the payload.
    if c.image in _INTERPRETERS or c.image in _SHELLS:
        has_url = bool(_URL.search(c.raw_cmd))
        has_ip = bool(_IP_LITERAL.search(c.raw_cmd))
        has_unc = "\\\\" in c.raw_cmd and not c.raw_cmd.strip().startswith("\\\\?\\")
        if has_url or has_ip or has_unc:
            what = ("a URL" if has_url else "a raw IP address" if has_ip
                    else "a UNC network path")
            if c.image in _SCRIPT_PROXY:
                return Signal("script_proxy_remote", 0.55,
                              f"script-proxy binary '{c.image}' references "
                              f"{what} (remote scriptlet execution)",
                              "T1218 — System Binary Proxy Execution")
            return Signal("lolbin_network_fetch", 0.35,
                          f"'{c.image}' command references {what} "
                          f"(remote fetch/execute shape)",
                          "T1105 — Ingress Tool Transfer")
    return None


# Ordered: strongest / most specific intrinsic tells first (affects which
# technique becomes dominant on ties).
_SIGNALS: tuple[Callable[[_Ctx], Optional[Signal]], ...] = (
    _sig_masquerade,
    _sig_bidi_trick,
    _sig_double_extension,
    _sig_impossible_ancestry,
    _sig_system_typosquat,
    _sig_obfuscated_cmd,
    _sig_lolbin_remote,
    _sig_lowtrust_exec,
    _sig_random_name,
)


def _near(a: str, b: str) -> bool:
    """Cheap edit-distance-1 look-alike test for short process-name stems.

    True when `a` is one character substitution/insertion/deletion away from
    `b` (and not equal). Used only for short system-process stems, so the O(len)
    cost is trivial and it won't collide with ordinary long words.
    """
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):                          # substitution
        diffs = sum(1 for x, y in zip(a, b) if x != y)
        return diffs == 1
    # insertion / deletion: walk the shorter against the longer.
    short, lng = (a, b) if len(a) < len(b) else (b, a)
    i = j = 0
    skipped = False
    while i < len(short) and j < len(lng):
        if short[i] == lng[j]:
            i += 1
            j += 1
        elif skipped:
            return False
        else:
            skipped = True
            j += 1
    return True


def score_process(image: str, parent: str, cmdline: str, path: str = "", *,
                  baseline: Optional[AncestryBaseline] = None) -> BehaviorScore:
    """Score a process start by intrinsic wrongness. Pure given its inputs.

    Returns a BehaviorScore whose ``.fired()`` is True only when the accumulated
    scent crosses the firing bar — a strong tell or a compounding combination,
    never a single weak signal.
    """
    im = _basename(image or "").lower()
    par = _basename(parent or "").lower()
    ctx = _Ctx(
        image=im,
        parent=par,
        cmd=(cmdline or "").lower(),
        raw_cmd=cmdline or "",
        path=(path or "").lower().replace("/", "\\"),
        raw_image=_basename(image or ""),
    )

    signals: list[Signal] = []
    for detect in _SIGNALS:
        sig = detect(ctx)
        if sig is not None:
            signals.append(sig)

    # Host baseline lift: a never-before-seen parent→child pairing on this
    # machine. Small on its own — it only tips a case already near the bar.
    if baseline is not None and im and baseline.is_rare(par, im):
        signals.append(Signal("rare_ancestry_for_host", 0.15,
                              f"'{par}' → '{im}' has never been seen on this "
                              f"host", ""))

    signals.sort(key=lambda s: s.weight, reverse=True)
    score = min(1.0, sum(s.weight for s in signals))
    severity = _severity_for(score)
    technique = next((s.technique for s in signals if s.technique), "")
    reason = "; ".join(s.reason for s in signals)
    return BehaviorScore(score=round(score, 3), severity=severity,
                         signals=tuple(signals), technique=technique,
                         reason=reason)


def classify_anomaly(image: str, parent: str, cmdline: str, path: str = "", *,
                     baseline: Optional[AncestryBaseline] = None) -> Optional[dict]:
    """Collector-facing convenience mirroring behavioral_rules.classify_behavior.

    Returns {severity, labels, technique, reason, score, signals} when the nose
    FIRES (crossed the threshold), else None — so a below-bar scent never raises
    a detection on its own.
    """
    result = score_process(image, parent, cmdline, path, baseline=baseline)
    if not result.fired():
        return None
    return {
        "severity": result.severity,
        "technique": result.technique,
        "labels": [s.name for s in result.signals],
        "reason": result.reason,
        "score": result.score,
        "signals": [(s.name, s.weight) for s in result.signals],
    }
