#!/usr/bin/env python3
"""Layered configuration overlay (valkyrie/settings.py).

Pins the precedence and validation contract of ADR-0006:
  code defaults  <  config file  <  environment variables
with a hard guarantee that a stock deployment (no file, no env) is a no-op, and
that an explicitly-bad value fails loud instead of running misconfigured.

Exercises settings.load() directly with an injected environ + temp dir so the
test is deterministic and needs no subprocess.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def main() -> int:
    from valkyrie import settings
    from valkyrie.settings import ConfigError

    print("\n=== layered configuration overlay ===\n")

    # Representative base drawn from real config.py defaults.
    base = {
        "DNS_LISTEN_PORT": 5300,
        "WEB_HOST": "127.0.0.1",
        "WEB_PORT": 8090,
        "DNS_LOCAL_ONLY": False,
        "BEHAVIORAL_BLOCK_SCORE": 0.7,
        "DNS_TIMEOUT": 3.0,
    }

    with tempfile.TemporaryDirectory() as td:
        cfg_dir = Path(td)

        print("[1] No file, no env -> defaults unchanged, no overrides")
        resolved, ov = settings.load(base, config_dir=cfg_dir, environ={})
        _check("resolved equals base", resolved == base)
        _check("no overrides reported", ov == [])

        print("\n[2] Environment override (typed + provenance)")
        env = {"VALKYRIE_DNS_LISTEN_PORT": "53",
               "VALKYRIE_WEB_HOST": "0.0.0.0",
               "VALKYRIE_DNS_LOCAL_ONLY": "true",
               "VALKYRIE_DNS_TIMEOUT": "1.5"}
        resolved, ov = settings.load(base, config_dir=cfg_dir, environ=env)
        _check("int coerced (53)", resolved["DNS_LISTEN_PORT"] == 53)
        _check("str applied", resolved["WEB_HOST"] == "0.0.0.0")
        _check("bool 'true' -> True", resolved["DNS_LOCAL_ONLY"] is True)
        _check("float coerced (1.5)", resolved["DNS_TIMEOUT"] == 1.5)
        _check("four overrides recorded", len(ov) == 4)
        _check("override provenance is env", all("env " in o.source for o in ov))

        print("\n[3] Config file override + env-beats-file precedence")
        (cfg_dir / "valkyrie.yaml").write_text(
            "DNS_LISTEN_PORT: 5301\nWEB_PORT: 9000\n", encoding="utf-8")
        env = {"VALKYRIE_DNS_LISTEN_PORT": "5555"}
        resolved, ov = settings.load(base, config_dir=cfg_dir, environ=env)
        _check("env wins over file", resolved["DNS_LISTEN_PORT"] == 5555)
        _check("file value applied", resolved["WEB_PORT"] == 9000)
        _check("both changes recorded once each", len(ov) == 2)

        print("\n[4] Invalid values fail loud")
        for label, env in [
            ("out-of-range port", {"VALKYRIE_WEB_PORT": "99999"}),
            ("non-numeric int", {"VALKYRIE_DNS_LISTEN_PORT": "abc"}),
            ("score above 1.0", {"VALKYRIE_BEHAVIORAL_BLOCK_SCORE": "5"}),
            ("bad bool", {"VALKYRIE_DNS_LOCAL_ONLY": "maybe"}),
        ]:
            try:
                settings.load(base, config_dir=cfg_dir, environ=env)
                _check(f"{label} raises ConfigError", False)
            except ConfigError:
                _check(f"{label} raises ConfigError", True)

        print("\n[5] Unknown file keys are ignored (forward-compat)")
        (cfg_dir / "valkyrie.yaml").write_text(
            "NOT_A_REAL_SETTING: 42\nWEB_PORT: 8095\n", encoding="utf-8")
        resolved, ov = settings.load(base, config_dir=cfg_dir, environ={})
        _check("unknown key ignored", "NOT_A_REAL_SETTING" not in resolved)
        _check("known key still applied", resolved["WEB_PORT"] == 8095)

        print("\n[6] VALKYRIE_CONFIG pointing at a missing file fails loud")
        try:
            settings.load(base, config_dir=cfg_dir,
                          environ={"VALKYRIE_CONFIG": str(cfg_dir / "nope.yaml")})
            _check("missing explicit config raises", False)
        except ConfigError:
            _check("missing explicit config raises", True)

    print("\n[7] describe() lists overridable settings")
    d = settings.describe()
    keys = {x["key"] for x in d}
    _check("describe() includes DNS_LISTEN_PORT", "DNS_LISTEN_PORT" in keys)
    _check("describe() includes WEB_HOST", "WEB_HOST" in keys)

    print("\n[8] Integration: config module exposes CONFIG_OVERRIDES")
    from valkyrie import config as c
    _check("config.CONFIG_OVERRIDES exists and is a list",
           isinstance(c.CONFIG_OVERRIDES, list))

    print("\n" + "=" * 48)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
