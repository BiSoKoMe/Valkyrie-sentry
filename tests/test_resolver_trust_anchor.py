#!/usr/bin/env python3
"""valkyrie/resolver.py's DNSSEC trust-anchor bootstrap.

``auto-trust-anchor-file`` only MAINTAINS an anchor that already exists (RFC
5011 rollover) - it does not create one from nothing. Pointing Unbound at a
root.key that has never existed makes its validator module fail to
initialize and the WHOLE PROCESS EXIT on every single start. Observed live on
the owner's actual installed service: root.key never existed, and
unbound.log showed nothing but repeated "fatal error: failed to init
modules" across separate restarts, days apart - the local recursive
resolver never once came up; DNS still worked only because the caller (see
UnboundManager.start()'s 3-second probe loop) falls back to external DNS,
silently losing the local-recursion privacy benefit and DNSSEC validation.

``_seed_trust_anchor()`` runs ``unbound-anchor`` (shipped next to
``unbound`` for exactly this one-time secure bootstrap) before Unbound ever
starts. These checks never invoke a real ``unbound-anchor`` or touch a real
DATA_DIR - ``subprocess.run`` is monkeypatched to a fake, and only temporary
paths are used.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks


def main() -> int:
    import valkyrie.resolver as resolver

    c = Checks("resolver.py DNSSEC trust-anchor bootstrap", expect_min=6)

    with tempfile.TemporaryDirectory(prefix="vlk-anchor-test-") as td:
        tmp = Path(td)
        fake_unbound_bin = tmp / "unbound.exe"
        fake_unbound_bin.write_text("not a real binary")

        print("[1] an anchor that already exists is left alone - no subprocess run")
        existing = tmp / "already-there.key"
        existing.write_text("seeded")
        calls = []
        real_run = resolver.subprocess.run
        resolver.subprocess.run = lambda *a, **k: calls.append((a, k))
        try:
            ok = resolver._seed_trust_anchor(existing, str(fake_unbound_bin))
        finally:
            resolver.subprocess.run = real_run
        c.check("returns True for an anchor that already exists", ok is True)
        c.check("never shells out when nothing needs bootstrapping", calls == [])

        print("\n[2] a missing anchor triggers unbound-anchor next to the "
              "unbound binary, and success is judged by the file existing "
              "afterward, not by the subprocess exit code")
        missing = tmp / "root.key"
        anchor_bin = tmp / (
            "unbound-anchor.exe" if resolver._SYSTEM == "Windows" else "unbound-anchor")
        anchor_bin.write_text("fake anchor tool")

        def _fake_run_creates_file(cmd, **kwargs):
            # unbound-anchor's own exit code is not a plain success signal
            # (see the function's docstring) - simulate it writing the file
            # and then returning a NON-zero code, proving the caller judges
            # success by the file, not the return code.
            Path(cmd[2]).write_text("bootstrapped")
            class _Result:
                returncode = 1
            return _Result()

        resolver.subprocess.run = _fake_run_creates_file
        try:
            ok2 = resolver._seed_trust_anchor(missing, str(fake_unbound_bin))
        finally:
            resolver.subprocess.run = real_run
        c.check("returns True once the file exists, regardless of exit code",
                ok2 is True)
        c.check("the anchor tool actually ran with -a <dest>", missing.exists())

        print("\n[3] no anchor tool anywhere - degrade to False, never crash, "
              "never invoke a nonexistent binary")
        anchor_bin.unlink()
        missing.unlink()
        real_which = resolver._which
        resolver._which = lambda name: None
        called = {"n": 0}

        def _fake_run_should_not_fire(*a, **k):
            called["n"] += 1
            raise AssertionError("should never be invoked with no anchor tool")

        resolver.subprocess.run = _fake_run_should_not_fire
        try:
            ok3 = resolver._seed_trust_anchor(missing, str(fake_unbound_bin))
        finally:
            resolver.subprocess.run = real_run
            resolver._which = real_which
        c.check("returns False when no bootstrap tool can be found", ok3 is False)
        c.check("never attempts to run a binary that isn't there", called["n"] == 0)

    print("\n[4] the conf template drops the DNSSEC line entirely when no "
          "anchor is available, instead of pointing at a file that will "
          "never exist and killing Unbound's validator at startup")
    rendered_without = resolver._UNBOUND_CONF_TEMPLATE.format(
        port=5301, logfile="x", root_hints="y",
        trust_anchor_directive="", tls_cert_directive="", forward_zone="",
    )
    c.check("no auto-trust-anchor-file line when bootstrap failed",
            "auto-trust-anchor-file" not in rendered_without)

    print("\n[5] the conf template DOES include it once an anchor exists - "
          "this is additive, not a permanent downgrade")
    rendered_with = resolver._UNBOUND_CONF_TEMPLATE.format(
        port=5301, logfile="x", root_hints="y",
        trust_anchor_directive='    auto-trust-anchor-file: "z/root.key"',
        tls_cert_directive="", forward_zone="",
    )
    c.check("auto-trust-anchor-file line present when an anchor was seeded",
            'auto-trust-anchor-file: "z/root.key"' in rendered_with)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
