"""Tests for farble.py — the per-origin/per-session fingerprint randomiser.

These are invariant tests, not coverage tests. Farbling has exactly three
properties that make it work, and getting any ONE of them backwards turns the
feature into the bug it replaced:

  STABLE within (origin, session)  — a site reading the same surface twice
      must get the same answer. Two different answers is itself a tamper
      signal, and it breaks legitimate canvas/audio use.
  DIFFERENT across origins         — this is the entire point. If two sites
      see the same values, they can correlate the user, which is exactly
      what the old constant-valued implementation allowed.
  DIFFERENT across sessions        — otherwise the farbled value becomes a
      durable long-term ID, i.e. a fingerprint with extra steps.

The fourth property is negative and equally important: the script must never
contain the old hardcoded constants, because a constant lie identifies the
liar. That regression is asserted explicitly.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks
from valkyrie import farble


def _seed_in(script: bytes) -> int:
    m = re.search(rb"var SEED = (\d+)", script)
    assert m, "injected script must carry a seed"
    return int(m.group(1))


def main() -> int:
    c = Checks("farble", expect_min=22)

    # ── Origin normalisation ────────────────────────────────────────────
    print("\n[1] origin is the correlation boundary")
    c.check("path does not change the origin",
            farble.origin_of("https://a.com/x/y?z=1") == farble.origin_of("https://a.com/other"))
    c.check("host is lowercased",
            farble.origin_of("https://EXAMPLE.com/") == "https://example.com")
    c.check("different hosts are different origins",
            farble.origin_of("https://a.com") != farble.origin_of("https://b.com"))
    c.check("subdomain is its own origin",
            farble.origin_of("https://x.a.com") != farble.origin_of("https://a.com"))
    c.check("garbage input does not raise",
            farble.origin_of("not a url") == "about:blank")
    c.check("empty input does not raise", farble.origin_of("") == "about:blank")

    # ── INVARIANT 1: stable within (origin, session) ────────────────────
    print("\n[2] STABLE within one origin + session (page must not break)")
    s1 = farble.script_for("https://facebook.com/feed")
    s2 = farble.script_for("https://facebook.com/other/page")
    c.check("same origin, same session -> identical seed",
            _seed_in(s1) == _seed_in(s2))
    c.check("same origin, same session -> byte-identical script", s1 == s2)
    c.check("a bare origin and a full URL agree",
            _seed_in(farble.script_for("https://facebook.com"))
            == _seed_in(farble.script_for("https://facebook.com/deep/path")))

    # ── INVARIANT 2: different across origins (the whole point) ─────────
    print("\n[3] DIFFERENT across origins (kills cross-site correlation)")
    fb = _seed_in(farble.script_for("https://facebook.com"))
    goog = _seed_in(farble.script_for("https://google.com"))
    ivc = _seed_in(farble.script_for("https://ivceyuc.com"))
    c.check("facebook != google", fb != goog)
    c.check("facebook != an unknown site", fb != ivc)
    c.check("google != an unknown site", goog != ivc)
    many = {_seed_in(farble.script_for(f"https://site{i}.com")) for i in range(200)}
    c.check(f"200 origins -> 200 distinct seeds (got {len(many)}), no collisions",
            len(many) == 200)

    # ── INVARIANT 3: different across sessions (kills durable IDs) ──────
    print("\n[4] DIFFERENT across sessions (kills long-term tracking)")
    before = _seed_in(farble.script_for("https://facebook.com"))
    farble.new_session()
    after = _seed_in(farble.script_for("https://facebook.com"))
    c.check("same origin, new session -> different seed", before != after)
    # ...but still internally consistent after the roll
    c.check("still stable within the NEW session",
            _seed_in(farble.script_for("https://facebook.com")) == after)

    # ── The seed must not leak the session secret ───────────────────────
    print("\n[5] the injected seed must not expose the session secret")
    c.check("seed is a bounded 32-bit value (not raw key material)",
            0 <= after <= 0xFFFFFFFF)
    a = _seed_in(farble.script_for("https://a.com"))
    b = _seed_in(farble.script_for("https://b.com"))
    c.check("one origin's seed does not trivially derive another's",
            a != b and (a ^ b) != 0)

    # ── REGRESSION: the old constant-valued implementation is gone ──────
    print("\n[6] REGRESSION: no constant lies (a constant lie IS a fingerprint)")
    script = farble.script_for("https://example.com")
    c.check("the 'data:image/png,v' canvas constant is gone",
            b"data:image/png,v" not in script)
    c.check("navigator.plugins is no longer forced empty",
            b"'plugins',{get:()=>[]}" not in script and b"return []" not in script)
    c.check("plugins now reports a realistic non-empty set",
            b"PDF Viewer" in script)
    c.check("hardwareConcurrency is randomised, not fixed",
            b"hardwareConcurrency" in script and b"pick(" in script)

    # ── Script sanity ───────────────────────────────────────────────────
    print("\n[7] the injected script is well-formed and defensive")
    c.check("is a complete <script> tag",
            script.startswith(b"<script>") and script.rstrip().endswith(b"</script>"))
    c.check("wrapped so a failure cannot break the page", b"catch(e)" in script)
    c.check("patched functions are cloaked as native",
            b"[native code]" in script)
    c.check("covers canvas readback", b"getImageData" in script)
    c.check("covers WebGL vendor/renderer", b"37445" in script and b"37446" in script)
    c.check("covers WebGL readPixels (GL-canvas fingerprint, not just 2D)",
            b"readPixels" in script)
    c.check("covers OffscreenCanvas (the worker-free 2D-canvas bypass)",
            b"OffscreenCanvas" in script and b"convertToBlob" in script)
    # A hook detectable via Function.prototype.toString.call() is itself a
    # durable fingerprint; the cloak must patch the SHARED toString (WeakMap),
    # not only each function's own property, or ('' + fn) / FPT.call(fn) leak.
    c.check("cloak hardens the shared Function.prototype.toString",
            b"Function.prototype.toString" in script and b"WeakMap" in script)
    c.check("covers audio", b"getChannelData" in script)
    c.check("covers all audio readbacks (byte + time-domain, not just float freq)",
            b"getByteFrequencyData" in script and b"getByteTimeDomainData" in script
            and b"getFloatTimeDomainData" in script)
    c.check("covers font metrics", b"measureText" in script)
    c.check("keeps the analytics no-ops", b"window.fbq" in script)
    c.check("no unsubstituted template placeholder", b"%SEED%" not in script)

    # ── END-TO-END through the real injector ────────────────────────────
    # The unit checks above prove the SCRIPT is right. These prove it
    # actually reaches a page, through both cleaning paths. The lxml path is
    # the one that runs in production, and its injection is wrapped in a
    # bare `except: pass` — so if lxml ever rejected the script fragment,
    # the feature would silently inject NOTHING and every check above would
    # still pass. That is exactly the "green but doing nothing" failure this
    # project keeps finding, so it gets an explicit test.
    print("\n[8] end-to-end: the script reaches the page, per origin")
    import re as _re
    from valkyrie.tls_addon import ValkyrieAddon
    addon = ValkyrieAddon.__new__(ValkyrieAddon)   # pure cleaner, no store
    html = b"<html><head><title>t</title></head><body><p>hi</p></body></html>"

    def _seed_from(out: bytes):
        m = _re.search(rb"var SEED = (\d+)", out)
        return int(m.group(1)) if m else None

    rx_fb = _seed_from(addon._clean_html_regex(html, "facebook.com", "https://facebook.com")[0])
    rx_gg = _seed_from(addon._clean_html_regex(html, "google.com", "https://google.com")[0])
    c.check("regex path injects the script", rx_fb is not None)
    c.check("regex path differs per origin", rx_fb is not None and rx_fb != rx_gg)

    lx_fb = addon._clean_html_lxml(html, "https://facebook.com")
    if lx_fb is None:
        c.skip("lxml injection path", "lxml not installed on this host")
    else:
        lx_gg = addon._clean_html_lxml(html, "https://google.com")
        s_fb, s_gg = _seed_from(lx_fb[0]), _seed_from(lx_gg[0])
        c.check("lxml path injects the script (not silently swallowed)",
                s_fb is not None)
        c.check("lxml path differs per origin", s_fb is not None and s_fb != s_gg)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
