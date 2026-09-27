"""Public Suffix List lookup - the "site" (eTLD+1) of a hostname, computed the
way a browser computes it.

Nyx's whole third-party judgement is "is the destination a different SITE from
the page that sent it". For a long time that was approximated as "the last two
labels" (``dns_tunnel.registrable_base``), which is right for ``example.com``
and silently wrong everywhere a public suffix has more than one label:

  * ``bbc.co.uk`` and ``tracker.co.uk`` both became ``co.uk`` - the SAME first
    party - so a disclosure between them was invisible, and every UK, Japanese,
    Australian, Brazilian... site was scored as one giant site.
  * ``alice.github.io`` and ``mallory.github.io`` (two unrelated owners on a
    shared host - the PSL's private section exists precisely for this) became
    one site, and so did every customer of ``cloudfront.net``,
    ``s3.amazonaws.com``, ``vercel.app``, ``herokuapp.com``...
  * Site-scoped personas were keyed on ``co.uk``, so every UK site shared one
    fake identity - the cross-site correlation they exist to prevent.

Browsers answer "same site?" with the Public Suffix List, including its private
section, so this module does too. The list is vendored (``defaults/
public_suffix_list.dat``, MPL-2.0, fetched from publicsuffix.org - see its own
header for the version) and parsed once, offline; nothing here ever touches the
network.

Fail-loud, not silent: if the data file is missing (e.g. a build that forgot to
bundle it) lookups fall back to the old last-two-labels rule so browsing keeps
working, but :func:`status` reports ``loaded: False`` and the reason, so a
degraded install can be seen instead of quietly scoring every ``.co.uk`` site
as one.
"""

from __future__ import annotations

import ipaddress
import threading
from pathlib import Path

PSL_PATH = Path(__file__).resolve().parent / "defaults" / "public_suffix_list.dat"

_lock = threading.Lock()
_rules: frozenset[str] | None = None
_wildcards: frozenset[str] = frozenset()     # "ck" for the rule "*.ck"
_exceptions: frozenset[str] = frozenset()    # "www.ck" for the rule "!www.ck"
_status: dict = {"loaded": False, "rules": 0, "version": "", "error": "not loaded yet"}


def _idna(label_rule: str) -> str:
    """ASCII (punycode) form of a rule, so a host that arrives as ``xn--...``
    - which is how hostnames appear in a URL - still matches a rule the list
    writes in Unicode. Returns "" when the rule has no valid IDNA form."""
    try:
        return label_rule.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return ""


def _load() -> None:
    global _rules, _wildcards, _exceptions, _status
    rules: set[str] = set()
    wild: set[str] = set()
    exc: set[str] = set()
    version = ""
    try:
        text = PSL_PATH.read_text(encoding="utf-8")
    except OSError as e:
        _rules = frozenset()
        _status = {"loaded": False, "rules": 0, "version": "",
                   "error": f"{PSL_PATH.name} unreadable ({e.__class__.__name__}); "
                            f"falling back to last-two-labels"}
        return
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("// VERSION:"):
            version = line.split(":", 1)[1].strip()
        if not line or line.startswith("//"):
            continue
        rule = line.split()[0].lower()
        forms = {rule}
        if not rule.isascii():
            forms.add(_idna(rule.lstrip("!").removeprefix("*.")))
        for form in forms:
            if not form:
                continue
            if rule.startswith("!"):
                exc.add(form.lstrip("!") if form.startswith("!") else form)
            elif rule.startswith("*."):
                wild.add(form.removeprefix("*."))
            else:
                rules.add(form)
    _rules, _wildcards, _exceptions = frozenset(rules), frozenset(wild), frozenset(exc)
    _status = {"loaded": bool(rules), "rules": len(rules) + len(wild) + len(exc),
               "version": version,
               "error": "" if rules else f"{PSL_PATH.name} contained no rules"}


def _ensure_loaded() -> None:
    if _rules is None:
        with _lock:
            if _rules is None:
                _load()


def status() -> dict:
    """Whether the real list is in use (vs the degraded fallback), and which
    version - for health surfaces, so a missing data file is visible."""
    _ensure_loaded()
    return dict(_status)


def _normalise(host: str) -> str:
    return (host or "").strip().lower().rstrip(".")


def public_suffix(host: str) -> str:
    """The public suffix of ``host`` per the PSL algorithm (longest matching
    rule; exception rules win; the implicit default rule is ``*``)."""
    h = _normalise(host)
    if not h:
        return ""
    labels = h.split(".")
    _ensure_loaded()
    if not _rules:                       # degraded: behave like the old helper
        return labels[-1]
    for i in range(len(labels)):
        cand = ".".join(labels[i:])
        if cand in _exceptions:
            return ".".join(labels[i + 1:])
        if cand in _rules:
            return cand
        if i + 1 < len(labels) and ".".join(labels[i + 1:]) in _wildcards:
            return cand
    return labels[-1]


def site_of(host: str) -> str:
    """The registrable domain (eTLD+1) of ``host`` - what a browser calls its
    "site". An IP literal is its own site. A host that is itself a public
    suffix (``github.io``) is returned unchanged rather than invented into
    something longer."""
    h = _normalise(host)
    if not h:
        return ""
    try:
        ipaddress.ip_address(h.strip("[]"))
        return h
    except ValueError:
        pass
    _ensure_loaded()
    labels = h.split(".")
    if not _rules:
        return ".".join(labels[-2:]) if len(labels) >= 2 else h
    suffix = public_suffix(h)
    n = suffix.count(".") + 1 if suffix else 0
    if len(labels) <= n:
        return h
    return ".".join(labels[-(n + 1):])
