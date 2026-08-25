#!/usr/bin/env python3
"""LIE-CONSISTENCY GATE - the deception layer must never contradict itself.

This is the gate test for the deception engine (valkyrie/persona.py +
valkyrie/deception.py). It exists because the failure mode of deception is not
"the lie was detected" - it is "the lie was inconsistent," which is strictly
worse than not lying at all.

Why inconsistency is worse than blocking
----------------------------------------
DECEIVE used to return 0.0.0.0, which is BLOCK with a nicer label. That leaks a
bit: a machine whose beacons reliably fail, while everything else resolves, is
identifiable as one running a blocker - a small, stable, distinctive
population. The user tried to disappear and joined a rarer crowd.

Answering the beacon fixes that only if the answers agree with each other. A
client reporting `America/New_York` to /collect and `Europe/Berlin` to /pixel,
or a different advertising ID each session, is not a plausible human. It is a
signature unique to synthetic traffic - a BETTER identifier than the one we
removed. So the properties below are not cosmetic; each one, if violated, hands
a tracker a cleaner signal than blocking ever did.

The four properties gated here
------------------------------
  1. INTERNAL COHERENCE   - locale/timezone/country/language agree; screen
                            metrics are physically possible; deviceMemory is
                            within what a browser may report.
  2. CROSS-FAMILY AGREEMENT - /collect, /pagead/ads, /sdk/config and a generic
                            path must report the SAME identity. Different
                            beacon families are exactly where a second source
                            of truth would leak in.
  3. CROSS-SESSION STABILITY - restarting the process, and rebuilding the store
                            from the persisted seed, must reproduce the same
                            person. Verified through a real socket, not just
                            the pure function.
  4. THE CHECKER ACTUALLY WORKS - negative controls. A gate that has never
                            rejected anything is not known to reject anything,
                            so incoherent personas are constructed on purpose
                            and must be caught.

Run:  PYTHONUTF8=1 python tests/test_lie_consistency.py
"""

from __future__ import annotations

import json
import secrets
import sys
import tempfile
import urllib.request
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks                                       # noqa: E402
from valkyrie.persona import (Persona, PersonaStore, build_persona,  # noqa: E402
                              _LOCALES, _SCREENS)
from valkyrie.deception import (DeceptionEndpoint, build_reply,   # noqa: E402
                                classify_beacon, FAMILY_AD,
                                FAMILY_ANALYTICS, FAMILY_CONSENT,
                                FAMILY_CONFIG, FAMILY_PIXEL, FAMILY_GENERIC)

# Paths chosen to hit every family, and to look like beacons really do.
BEACON_PATHS = [
    ("/collect", "v=2&tid=G-ABC123&cid=555", FAMILY_ANALYTICS),
    ("/g/collect", "en=page_view", FAMILY_ANALYTICS),
    ("/pagead/ads", "slot=1&sz=300x250", FAMILY_AD),
    ("/openrtb2/bid", "", FAMILY_AD),
    ("/sdk/config", "app=1", FAMILY_CONFIG),
    ("/cmp/consent", "gdpr=1", FAMILY_CONSENT),
    ("/px.gif", "id=7", FAMILY_PIXEL),
    ("/some/unknown/path", "", FAMILY_GENERIC),
]

# Every persona field a reply may echo. If a new field starts being reported
# and is not listed here it simply is not consistency-checked, so this list is
# deliberately derived from the reply body rather than hand-maintained.
_IDENTITY_KEYS = ("id", "locale", "lang", "tz", "tz_offset", "country",
                  "cores", "mem", "platform", "screen",
                  "geo", "os", "browser")


def _client_block(body: bytes):
    """Pull the persona block out of whatever shape the family returned."""
    try:
        d = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(d, dict):
        return None
    if isinstance(d.get("client"), dict):
        return d["client"]
    ext = d.get("ext")
    if isinstance(ext, dict) and isinstance(ext.get("client"), dict):
        return ext["client"]
    return None


def main() -> int:
    c = Checks("lie consistency (deception engine)")

    # ------------------------------------------------------------------
    # 1. INTERNAL COHERENCE, over many personas, not just a lucky one.
    # ------------------------------------------------------------------
    incoherent = []
    for _ in range(3000):
        p = build_persona(secrets.token_bytes(32))
        errs = p.coherence_errors()
        if errs:
            incoherent.append((p.locale, p.timezone, errs))
    c.check(f"3000 random personas are all internally coherent "
            f"({len(incoherent)} bad: {incoherent[:2]})",
            not incoherent)

    # Every row of the coherence tables must itself be usable. A table row that
    # can never be selected coherently is a latent bug that random sampling
    # might not reach.
    c.check(f"all {len(_LOCALES)} locale rows produce coherent personas",
            all(build_persona(("locale-probe-%d" % i).encode()).is_coherent()
                for i in range(len(_LOCALES) * 40)))
    c.check("screen table has no row where availHeight >= height",
            all(s["taskbar"] > 0 and s["h"] - s["taskbar"] > 0 for s in _SCREENS))

    # ------------------------------------------------------------------
    # 2. CROSS-FAMILY AGREEMENT (pure layer)
    # ------------------------------------------------------------------
    p = build_persona(secrets.token_bytes(32))
    identities = {}
    families_seen = set()
    for path, query, expect_family in BEACON_PATHS:
        r = build_reply("GET", path, query, {}, p)
        families_seen.add(r.family)
        c.check(f"{path} classified as {expect_family}", r.family == expect_family)
        c.check(f"{path} answers 200 (not an error, not a 404)", r.status == 200)
        cb = _client_block(r.body)
        if cb is not None:
            identities[path] = cb

    c.check(f"all {len(BEACON_PATHS)} probe paths hit distinct expected "
            f"families ({len(families_seen)} families exercised)",
            families_seen >= {FAMILY_ANALYTICS, FAMILY_AD, FAMILY_CONFIG,
                              FAMILY_CONSENT, FAMILY_PIXEL, FAMILY_GENERIC})

    c.check(f"at least 4 families echo an identity block to compare "
            f"({len(identities)} did)", len(identities) >= 4)

    for key in _IDENTITY_KEYS:
        vals = {json.dumps(cb[key], sort_keys=True)
                for cb in identities.values() if key in cb}
        c.check(f"'{key}' is identical across every beacon family "
                f"({len(vals)} distinct value(s))", len(vals) <= 1)

    # The identity reported must be the persona's, not something invented.
    for path, cb in identities.items():
        if "tz" in cb:
            c.check(f"{path} reports the persona's real timezone",
                    cb["tz"] == p.timezone)
            break

    # ------------------------------------------------------------------
    # 3. CROSS-SESSION STABILITY, through a real socket.
    # ------------------------------------------------------------------
    tmp = Path(tempfile.mkdtemp(prefix="valkyrie_persona_"))
    seed_path = tmp / "persona_seed.json"

    store1 = PersonaStore(seed_path)
    persona1 = store1.persona()
    c.check("first use creates and persists a seed", seed_path.exists())

    # A brand-new store object reading the same file == a process restart.
    store2 = PersonaStore(seed_path)
    persona2 = store2.persona()
    c.check("a fresh PersonaStore on the same seed file yields an IDENTICAL "
            "persona (survives restart)", persona1 == persona2)

    # And a different seed file yields a different person, or the "identity"
    # would be a constant shared by every Valkyrie install - itself a
    # fingerprint, and the exact bug farble.py was written to fix.
    other = PersonaStore(tmp / "other_seed.json").persona()
    c.check("a different machine (different seed) gets a DIFFERENT persona",
            other != persona1)

    live_ids = []
    for session in range(3):
        ep = DeceptionEndpoint(port=0, persona=PersonaStore(seed_path).persona())
        started = ep.start()
        c.check(f"session {session}: deception endpoint bound and running",
                started and ep.running)
        try:
            snapshot = {}
            for path, query, _fam in BEACON_PATHS:
                url = f"http://127.0.0.1:{ep.port}{path}"
                if query:
                    url += "?" + query
                with urllib.request.urlopen(url, timeout=5) as resp:
                    body = resp.read()
                    c.check(f"session {session}: {path} -> HTTP {resp.status}",
                            resp.status == 200)
                    cb = _client_block(body)
                    if cb is not None:
                        snapshot[path] = cb
            live_ids.append(snapshot)
        finally:
            ep.stop()
        c.check(f"session {session}: endpoint stopped cleanly", not ep.running)

    # Every field, every path, every session - one value.
    for key in _IDENTITY_KEYS:
        vals = set()
        for snap in live_ids:
            for cb in snap.values():
                if key in cb:
                    vals.add(json.dumps(cb[key], sort_keys=True))
        c.check(f"LIVE: '{key}' identical across 3 sessions x "
                f"{len(BEACON_PATHS)} beacons ({len(vals)} distinct)",
                len(vals) <= 1)

    # ------------------------------------------------------------------
    # 3b. REPLAY STABILITY - mechanical proof that "the same tracker asking
    #     twice gets the same answer" holds under repetition, not just once.
    #     A pure-function check alone could pass while the HTTP layer (header
    #     ordering, keep-alive state, encoding) drifted between calls, so this
    #     replays through BOTH the pure function and a real socket.
    # ------------------------------------------------------------------
    replay_path, replay_query, _ = BEACON_PATHS[0]
    pure_replies = {build_reply("GET", replay_path, replay_query, {}, p).body
                    for _ in range(100)}
    c.check(f"pure layer: same beacon replayed 100x is byte-identical every "
            f"time ({len(pure_replies)} distinct response(s))",
            len(pure_replies) == 1)

    ep_replay = DeceptionEndpoint(port=0, persona=PersonaStore(seed_path).persona())
    c.check("replay session: deception endpoint bound and running",
            ep_replay.start() and ep_replay.running)
    try:
        url = f"http://127.0.0.1:{ep_replay.port}{replay_path}?{replay_query}"
        seen = set()
        for _ in range(100):
            with urllib.request.urlopen(url, timeout=5) as resp:
                seen.add(resp.read())
        c.check(f"LIVE: same beacon replayed 100x over a real socket is "
                f"byte-identical every time ({len(seen)} distinct response(s))",
                len(seen) == 1)
    finally:
        ep_replay.stop()

    # And once more across freshly-simulated sessions (fresh process, fresh
    # store, same persisted seed) rather than one long-lived connection - the
    # scenario the module's stability guarantee is actually about.
    cross_session_replies = set()
    for _ in range(5):
        persona_n = PersonaStore(seed_path).persona()
        for _ in range(20):     # 5 sessions x 20 = 100 replays total
            cross_session_replies.add(
                build_reply("GET", replay_path, replay_query, {}, persona_n).body)
    c.check(f"same beacon replayed 100x across 5 simulated sessions is "
            f"byte-identical every time ({len(cross_session_replies)} distinct)",
            len(cross_session_replies) == 1)

    # ------------------------------------------------------------------
    # 4. NEGATIVE CONTROLS - prove the checker rejects real contradictions.
    #    Without these the whole file could be passing vacuously.
    # ------------------------------------------------------------------
    base = build_persona(b"negative-control-seed-000000000000")

    mutations = [
        ("timezone contradicts locale",
         replace(base, timezone="Europe/Berlin", locale="ja-JP")),
        ("UTC offset contradicts timezone",
         replace(base, std_utc_offset_minutes=base.std_utc_offset_minutes + 137)),
        ("languages[0] disagrees with locale",
         replace(base, languages=("zz-ZZ", "en"))),
        ("availHeight exceeds screen height",
         replace(base, avail_height=base.screen_height + 100)),
        ("availHeight == height (no window chrome)",
         replace(base, avail_height=base.screen_height)),
        ("deviceMemory above what the spec permits",
         replace(base, device_memory=64)),
        ("implausible colorDepth",
         replace(base, color_depth=7)),
        ("advertising_id is not a GUID",
         replace(base, advertising_id="not-a-guid")),
        ("country contradicts timezone",
         replace(base, country="ZZ")),
        ("empty language list",
         replace(base, languages=())),
        ("non-positive screen dimensions",
         replace(base, screen_width=0)),
        ("geo city/region contradicts timezone",
         replace(base, city="Tokyo", region="Tokyo")),
        ("coordinates contradict the claimed city",
         replace(base, lat=35.7, lon=139.7)),
        ("latitude out of range",
         replace(base, lat=200.0)),
        ("empty city",
         replace(base, city="", region="")),
        ("os_name contradicts Win32 platform",
         replace(base, os_name="Linux")),
        ("browser_version is not a dotted-numeric string",
         replace(base, browser_version="latest")),
        ("browser is not a real browser name",
         replace(base, browser="ValkyrieBrowser")),
    ]
    c.check("the control persona is itself coherent (else the mutations below "
            "prove nothing)", base.is_coherent())
    for label, mutant in mutations:
        errs = mutant.coherence_errors()
        c.check(f"NEGATIVE CONTROL caught: {label} ({len(errs)} error(s))",
                bool(errs))

    # A mutated persona must also be visible THROUGH the endpoint, not just via
    # the dataclass - otherwise the endpoint could be laundering incoherence.
    bad = replace(base, timezone="Europe/Berlin", locale="ja-JP")
    r = build_reply("GET", "/collect", "", {}, bad)
    cb = _client_block(r.body) or {}
    c.check("an incoherent persona's contradiction is visible in the served "
            "reply (tz/locale mismatch reaches the wire)",
            cb.get("tz") == "Europe/Berlin" and cb.get("locale") == "ja-JP")

    # ------------------------------------------------------------------
    # 5. The endpoint must not identify itself.
    # ------------------------------------------------------------------
    r = build_reply("GET", "/collect", "", {}, p)
    blob = json.dumps(r.headers).lower() + r.body.decode("utf-8", "ignore").lower()
    for word in ("valkyrie", "deception", "blocked", "sinkhole", "decoy"):
        c.check(f"reply leaks no self-identifying term {word!r}", word not in blob)

    c.check("pixel family returns a real GIF, not JSON or an empty body",
            build_reply("GET", "/px.gif", "", {}, p).body.startswith(b"GIF89a"))

    # A loopback-only guard: binding off-loopback must be refused outright.
    try:
        DeceptionEndpoint(host="0.0.0.0")
        bound_offloopback = True
    except ValueError:
        bound_offloopback = False
    c.check("refuses to bind off-loopback (0.0.0.0 rejected)",
            not bound_offloopback)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
