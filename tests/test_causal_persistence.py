#!/usr/bin/env python3
"""The causal baseline must survive restarts, or the detector is dead code.

WHY THIS TEST EXISTS
--------------------
causal_detect.py refuses to raise a detection until its baseline has MATURED:
300 observed structures across 3 sessions. That gate is correct - scoring
rarity against a baseline that has seen almost nothing produces confident
nonsense.

But the baseline lived only in memory. `load_causal_baseline` and
`save_causal_baseline` existed on the engine and were never called from
`__main__.py`, so every launch started from zero and the maturity gate could
never be reached. The whole subsystem was shipped, wired, tested offline - and
permanently silent in production. Nothing failed; it just never spoke.

That is the most expensive kind of bug, because every other test passes. So the
property is asserted here directly: learn, restart, learn, restart, and the
detector must actually become able to fire.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402
from valkyrie.edr.causal_detect import CausalBaseline  # noqa: E402
from valkyrie.edr.engine import EdrEngine  # noqa: E402


_SUB = {
    "found": True,
    "cgo": {"key": "winword|1", "name": "winword.exe"},
    "nodes": [{"name": "winword.exe", "pid": 1}, {"name": "powershell.exe", "pid": 2}],
    "edges": [{"parent": "winword.exe", "child": "powershell.exe"}],
    "artifacts": [{"kind": "registry", "value": r"HKCU\Software\...\Run\x"}],
}


class _Persist:
    """Just the persistence surface of the engine, exercised as the engine
    exercises it - no store, no threads, no sensors."""

    load_causal_baseline = EdrEngine.load_causal_baseline
    save_causal_baseline = EdrEngine.save_causal_baseline

    def __init__(self) -> None:
        self._causal_baseline = CausalBaseline()
        self._causal_baseline_path = None


def _session(path: Path, n: int) -> _Persist:
    e = _Persist()
    e.load_causal_baseline(path)
    for _ in range(n):
        e._causal_baseline.observe_subgraph(_SUB)
    e.save_causal_baseline()
    return e


def main() -> int:
    c = Checks("Causal baseline persistence — the detector can actually mature",
               expect_min=10)

    tmp = Path(tempfile.mkdtemp()) / "causal_baseline.json"

    # ================================================================ [1]
    print("\n[1] a first session learns, and its learning is written down")
    e1 = _session(tmp, 120)
    c.check("observed 120 structures", e1._causal_baseline.observations == 120)
    c.check("session counted", e1._causal_baseline.sessions == 1)
    c.check("NOT yet mature (one session is not a baseline)",
            not e1._causal_baseline.mature)
    c.check("the baseline file exists after saving", tmp.exists())

    # ================================================ [KEYSTONE]
    print("\n[KEYSTONE] a NEW process carries the previous session's learning "
          "forward — this is the property whose absence made the detector inert")
    e2 = _Persist()
    e2.load_causal_baseline(tmp)
    c.check("observations survived the restart",
            e2._causal_baseline.observations == 120)
    c.check("the session counter advanced, not reset",
            e2._causal_baseline.sessions == 2)

    # ================================================================ [2]
    print("\n[2] across three sessions it MATURES and may finally fire")
    _session(tmp, 120)                       # session 2 content
    e3 = _session(tmp, 120)                  # session 3
    c.check("observations accumulated across sessions",
            e3._causal_baseline.observations >= 300)
    c.check("three sessions reached", e3._causal_baseline.sessions >= 3)
    c.check("THE DETECTOR IS NOW MATURE (was permanently False before)",
            e3._causal_baseline.mature)

    # ================================================================ [3]
    print("\n[3] a torn write cannot wipe what was already learned")
    intact = tmp.read_text(encoding="utf-8")
    # simulate a save interrupted mid-flight: a stray temp file left behind
    tmp.with_suffix(".json.tmp").write_text("{ half-written", encoding="utf-8")
    e4 = _Persist()
    e4.load_causal_baseline(tmp)
    c.check("the real baseline is untouched by a stray partial file",
            e4._causal_baseline.observations >= 300)
    c.check("the file itself is unchanged",
            tmp.read_text(encoding="utf-8") == intact)
    c.check("a fresh save still succeeds over the stray temp",
            e4.save_causal_baseline())

    # ================================================================ [4]
    print("\n[4] a corrupt baseline degrades to silence, never to a crash")
    bad = Path(tempfile.mkdtemp()) / "corrupt.json"
    bad.write_text("this is not json at all", encoding="utf-8")
    e5 = _Persist()
    try:
        e5.load_causal_baseline(bad)
        c.check("corrupt baseline -> fresh, immature, and NOT raising",
                e5._causal_baseline.observations == 0
                and not e5._causal_baseline.mature)
    except Exception as exc:   # noqa: BLE001
        c.fail("corrupt baseline -> fresh, immature, and NOT raising", repr(exc))

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
