"""A malformed rules file must never break DNS resolution.

`valkyrie_rules.yaml` is the one file this product invites users to hand-edit,
and its own header says "edit and save; changes take effect within 5 seconds".
The matcher it feeds runs INSIDE `DNSInterceptor._decide`, synchronously, with
a real DNS query waiting. So an exception there does not just drop a rule - it
breaks name resolution for the whole machine, on every query, until someone
notices and fixes the YAML.

Verified before the fix: five of six plausible malformed shapes raised.

    - domain:                 -> TypeError (null domain)
    - domain: 12345           -> TypeError (numeric)
    - domain: [a.com]         -> TypeError (list)
    - evil.com                -> AttributeError (bare string, no `domain:` key)
    -                         -> AttributeError (null entry)

The bare-string case matters most: writing `- evil.com` instead of
`- domain: evil.com` is the single most likely mistake with this format, and
it took the DNS path down.

Also fixed here: matching used `fnmatch.fnmatch`, which applies
`os.path.normcase` - case-insensitive on Windows, case-sensitive on Linux. The
same rules file silently behaved differently per platform, and domains are
case-insensitive by definition.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks
from valkyrie.rules import RuleSet, RulesLoader, _sanitize


def main() -> int:
    c = Checks("rules robustness", expect_min=18)

    # --- REGRESSION: malformed entries must not raise ---
    print("\n[1] REGRESSION: no malformed rule shape may raise on the DNS path")
    shapes = {
        "null domain (`- domain:`)":     [{"domain": None}],
        "missing domain key":            [{"process": "chrome"}],
        "numeric domain":                [{"domain": 12345}],
        "list domain":                   [{"domain": ["a.com"]}],
        "bare string entry":             ["evil.com"],
        "null entry":                    [None],
        "entry is a list":               [["a.com"]],
        "boolean domain":                [{"domain": True}],
        "rules is not a list":           "not-a-list",
        "rules is None":                 None,
    }
    for label, raw in shapes.items():
        try:
            rs = RuleSet(allow=[], block=_sanitize(raw))
            rs.is_always_blocked("example.com", "firefox.exe")
            ok = True
        except Exception as exc:                 # noqa: BLE001
            ok = False
            print(f"    RAISED on {label}: {type(exc).__name__}: {exc}")
        c.check(f"survives {label}", ok)

    # --- The most likely typo must still DO what the user meant ---
    print("\n[2] `- evil.com` shorthand is honoured, not silently dropped")
    rs = RuleSet(allow=[], block=_sanitize(["evil.com"]))
    c.check("a bare-string rule actually blocks that domain",
            rs.is_always_blocked("evil.com", "firefox.exe"))
    c.check("...and does not block an unrelated domain",
            not rs.is_always_blocked("good.com", "firefox.exe"))

    # --- Case-insensitivity, identically on every platform ---
    print("\n[3] domain matching is case-insensitive on every platform")
    rs = RuleSet(allow=[], block=_sanitize([{"domain": "*.evil.com"}]))
    for d in ("bad.evil.com", "BAD.EVIL.COM", "Bad.Evil.Com"):
        c.check(f"{d} matches *.evil.com", rs.is_always_blocked(d, "firefox.exe"))
    rs2 = RuleSet(allow=[], block=_sanitize([{"domain": "*.EVIL.com"}]))
    c.check("an upper-case PATTERN also matches a lower-case domain",
            rs2.is_always_blocked("bad.evil.com", "firefox.exe"))
    c.check("a trailing dot (fully-qualified form) still matches",
            rs.is_always_blocked("bad.evil.com.", "firefox.exe"))

    # --- Process scoping still works ---
    print("\n[4] process-scoped rules still scope")
    rs = RuleSet(allow=[], block=_sanitize(
        [{"domain": "*.ads.com", "process": "chrome"}]))
    c.check("matches the named process", rs.is_always_blocked("x.ads.com", "chrome.exe"))
    c.check("does not match a different process",
            not rs.is_always_blocked("x.ads.com", "firefox.exe"))

    # --- A broken file must not wipe a working ruleset ---
    print("\n[5] a broken file keeps the last good ruleset")
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "rules.yaml"
        p.write_text("always_block:\n  - domain: bad.test\n", encoding="utf-8")
        loader = RulesLoader(path=p)
        loader._load()
        c.check("the good ruleset loaded",
                loader.get().is_always_blocked("bad.test", "x.exe"))
        p.write_text("always_block:\n  - domain: [unclosed\n", encoding="utf-8")
        loader._load()
        c.check("a later BROKEN file does not silently unblock the domain "
                "(stale-but-safe beats empty)",
                loader.get().is_always_blocked("bad.test", "x.exe"))

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
