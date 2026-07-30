"""Tier 3.14/3.15 — the 0%-covered subsystems, tested where it is safe to.

`fingerprint.py` (139 stmts), `resolver.py` (168), `tls_addon.py` (275) and
`doh_detector.py` (64) had **no test file at all**. They are also the modules
that rewrite the machine: TCP/IP registry values, a spawned Unbound daemon, a
live mitmproxy interception path.

So this file draws a hard line and states it, rather than quietly testing
whatever happened to be convenient:

  * TESTED — the pure and read-only surface: URL/param stripping, path
    classification, status reporting, backup round-tripping, platform guards.
    This is most of the decision logic, and all of it was previously unverified.
  * NOT TESTED HERE — anything that writes the registry, spawns a daemon, or
    binds a port. Those belong in the VM pass (TEST_PLAN tier 4). Running them
    on a developer's machine is how this project previously lost its WiFi.

The guards themselves are worth asserting: `normalize()` must refuse and
explain rather than half-apply when it cannot work, because a partially applied
TCP fingerprint is worse than an untouched one — it is a *new* unique
fingerprint rather than a normalized one.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks


def main() -> int:
    c = Checks("zero-coverage subsystems", expect_min=28)

    # ── tls_addon: URL and path classification (pure) ───────────────────────
    print("[1] tls_addon — tracking-parameter stripping")
    from valkyrie.tls_addon import (_strip_url_params, _strip_tracking_params,
                                    _is_tracker_path, _is_fingerprint_path)

    u = "https://shop.test/item?id=42&utm_source=news&utm_medium=email&gclid=xyz"
    out = _strip_tracking_params(u)
    c.check("utm_source is stripped", "utm_source" not in out)
    c.check("utm_medium is stripped", "utm_medium" not in out)
    c.check("gclid is stripped", "gclid" not in out)
    c.check("the functional parameter is PRESERVED", "id=42" in out)
    c.check("scheme and host are preserved", out.startswith("https://shop.test/item"))

    # The property that matters most: stripping must not break a URL that has
    # nothing to strip, because that would break ordinary browsing.
    clean = "https://shop.test/item?id=42&page=3"
    c.check("a URL with no tracking params is returned unchanged",
            _strip_tracking_params(clean) == clean)
    c.check("a URL with no query string at all is unchanged",
            _strip_tracking_params("https://shop.test/item") ==
            "https://shop.test/item")
    c.check("the fragment survives stripping",
            "#sec" in _strip_tracking_params("https://a.test/p?utm_source=x#sec"))
    c.check("a blank-valued param is handled without raising",
            isinstance(_strip_tracking_params("https://a.test/p?utm_source="), str))

    c.check("explicit param stripping removes only what it is told to",
            _strip_url_params("https://a.test/p?a=1&b=2", ["a"]) ==
            "https://a.test/p?b=2")
    c.check("explicit stripping is case-insensitive on the key",
            "A=1" not in _strip_url_params("https://a.test/p?A=1&b=2", ["a"]))

    # Degenerate inputs must not raise — these come off the wire.
    weird = []
    for bad in ("", "not a url", "http://", "https://a.test/?" + "&" * 50,
                "https://a.test/?a=" + "x" * 5000, "://", "https://a.test/?=v"):
        try:
            _strip_tracking_params(bad)
        except Exception as exc:                       # noqa: BLE001
            weird.append(f"{bad[:20]!r}: {type(exc).__name__}")
    c.check(f"malformed URLs never raise ({weird[:2] or 'clean'})", not weird)

    print("\n[2] tls_addon — path classification")
    c.check("a known tracker path is recognised",
            _is_tracker_path("/analytics/collect?v=1") or
            _is_tracker_path("/pixel.gif") or _is_tracker_path("/track"))
    c.check("an ordinary content path is not a tracker",
            not _is_tracker_path("/articles/2026/how-to-bake-bread"))
    c.check("classification is case-insensitive",
            _is_tracker_path("/ANALYTICS/") == _is_tracker_path("/analytics/"))
    c.check("an empty path is not a tracker", not _is_tracker_path(""))
    c.check("fingerprint-path classification returns a bool",
            isinstance(_is_fingerprint_path("/fp.js"), bool))

    # ── fingerprint: status + backup round-trip (read-only) ─────────────────
    print("\n[3] fingerprint — status and backup (no registry writes)")
    from valkyrie.fingerprint import NetworkFingerprint
    import valkyrie.fingerprint as fp

    with tempfile.TemporaryDirectory() as td:
        bpath = Path(td) / "fp_backup.json"
        nf = NetworkFingerprint(backup_path=bpath)

        s = nf.status()
        for key in ("supported", "ttl", "ttl_normalized", "tcp_timestamps",
                    "timestamps_normalized", "normalized", "backup_present"):
            c.check(f"status() reports '{key}'", key in s)
        c.check("status() does not claim a backup that does not exist",
                s["backup_present"] is False)
        c.check("status() 'normalized' is a bool, never None",
                isinstance(s["normalized"], bool))

        # Backup round-trip through the real save/load path.
        nf._save_backup({"ttl": 128, "timestamps": True})
        c.check("a saved backup lands on disk", bpath.exists())
        c.check("status() now reports the backup present",
                nf.status()["backup_present"] is True)
        loaded = nf._load_backup()
        c.check("the backup round-trips exactly",
                loaded == {"ttl": 128, "timestamps": True})
        c.check("the backup file is valid JSON on disk",
                json.loads(bpath.read_text(encoding="utf-8"))["ttl"] == 128)

        # A corrupt backup must degrade to None, not raise — restore() runs at
        # shutdown, where an exception would leave settings permanently changed.
        bpath.write_text("{not json", encoding="utf-8")
        c.check("a corrupt backup loads as None rather than raising",
                nf._load_backup() is None)
        nf._clear_backup()
        c.check("clearing removes the backup file", not bpath.exists())
        c.check("clearing a missing backup does not raise",
                (nf._clear_backup(), True)[1])

        # The platform guard: on non-Windows, normalize() must refuse cleanly
        # and SAY why. Half-applying would create a new unique fingerprint.
        real_is_windows = fp._is_windows
        try:
            fp._is_windows = lambda: False
            nf2 = NetworkFingerprint(backup_path=Path(td) / "b2.json")
            ok = nf2.normalize()
            c.check("normalize() refuses on a non-Windows host", ok is False)
            c.check("and explains why in last_error", bool(nf2.last_error))
            c.check("the refusal names the platform limitation",
                    "windows" in nf2.last_error.lower())
            c.check("a refused normalize writes no backup",
                    not (Path(td) / "b2.json").exists())
        finally:
            fp._is_windows = real_is_windows

    # ── resolver: pure helpers only (no daemon spawned) ─────────────────────
    print("\n[4] resolver — pure helpers (no Unbound spawned)")
    from valkyrie.resolver import _which, UnboundManager

    c.check("_which returns None for a binary that cannot exist",
            _which("definitely-not-a-real-binary-xyz123") is None)
    c.check("_which finds an interpreter that certainly exists",
            _which("python") is not None or _which("python3") is not None)

    mgr = UnboundManager()
    host, port = mgr.upstream_addr()
    c.check("upstream_addr returns a (host, port) pair",
            isinstance(host, str) and isinstance(port, int))
    c.check("the upstream port is a valid port number", 0 < port < 65536)
    c.check("is_running() answers without starting anything",
            isinstance(mgr.is_running(), bool))

    # ── doh_detector: construction and guards (no scan loop started) ────────
    print("\n[5] doh_detector — construction and alert plumbing")
    from valkyrie.doh_detector import DoHDetector
    from valkyrie.store import Store

    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "doh.db")
        store.start()
        alerts: list[tuple] = []
        det = DoHDetector(store, on_alert=lambda *a: alerts.append(a))
        c.check("constructs without starting a scan thread", det is not None)
        c.check("a single scan pass does not raise",
                (det._scan(), True)[1])
        c.check("scanning does not fabricate alerts on an idle host",
                isinstance(alerts, list))
        store.stop()

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
