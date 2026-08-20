"""Authoritative live coverage: read the distinct ATT&CK techniques that raised
an incident, straight from the EDR incident store (SQLite) with the engine
STOPPED. The live API is unreliable under battery load (even the brief read
times out while the engine drains its ingestion backlog), so the eval's
per-technique polling is flaky. The database at rest is ground truth.

Usage: python db_coverage.py <path-to-valkyrie.db>
"""
import re
import sqlite3
import sys

# A technique field may hold ONE id ("T1059"), an id + label
# ("T1059 — Command..."), or several ids joined ("T1003.001; T1055"). Extract
# every real ATT&CK id and dedupe, so "T1059" and "T1059;" are not counted as
# two distinct techniques (they were), and a multi-technique incident credits
# BOTH techniques it actually detected instead of only the first token.
_TID = re.compile(r"T\d{4}(?:\.\d{3})?")


def main() -> None:
    db = sys.argv[1]
    c = sqlite3.connect(db)
    try:
        cols = [r[1] for r in c.execute("PRAGMA table_info(edr_incidents)")]
        if not cols:
            print("edr_incidents table not found")
            return
        rows = c.execute("SELECT * FROM edr_incidents").fetchall()
    except sqlite3.Error as e:
        print("ERR reading edr_incidents:", e)
        return

    def idx(name):
        return cols.index(name) if name in cols else None

    ti, si, tli = idx("technique"), idx("severity"), idx("title")
    techs = set()
    if ti is not None:
        for r in rows:
            if r[ti]:
                techs.update(_TID.findall(str(r[ti])))
    techs = sorted(techs)
    print("TOTAL INCIDENTS:", len(rows))
    print("DISTINCT ATT&CK TECHNIQUES DETECTED:", len(techs))
    for t in techs:
        print("  DETECTED-TECH:", t)

    # ---- AIMED miss list: diff the detected set against the technique catalog
    # so every run turns "we caught N" into "here are the exact techniques that
    # missed, and what the catalog PREDICTED for each." A miss whose prediction
    # is DETECT is a measurement/harness gap (the code is believed correct); a
    # MISS/CONDITIONAL prediction is a known rule gap. That distinction is what
    # makes the next strike aimed instead of sprayed.
    try:
        import os
        _here = os.path.dirname(os.path.abspath(__file__))
        if _here not in sys.path:
            sys.path.insert(0, _here)
        import catalog as _cat
        from catalog import Technique as _Tech
        in_scope = {}
        for _nm in dir(_cat):
            _v = getattr(_cat, _nm)
            if isinstance(_v, list) and _v and all(isinstance(x, _Tech) for x in _v):
                for _t in _v:
                    if _t.in_scope():
                        in_scope.setdefault(_t.technique_id, _t)
        det = set(techs)
        _base = lambda x: x.split(".")[0]
        # A catalog sub-technique counts as covered when its exact id OR its base
        # (a coarser incident tag, e.g. "T1059" for "T1059.001") was detected.
        covered = lambda tid: tid in det or _base(tid) in det
        ids = sorted(in_scope)
        missed = [i for i in ids if not covered(i)]
        print("---- AIMED COVERAGE vs CATALOG ----")
        print("IN-SCOPE: %d   DETECTED: %d   MISSED: %d"
              % (len(ids), len(ids) - len(missed), len(missed)))
        for tid in missed:
            t = in_scope[tid]
            print("  MISS  %-11s [%-11s] %-18s %s"
                  % (tid, t.predicted_tier_b, t.tactic, t.technique_name[:44]))
    except Exception as e:
        print("(aimed miss list unavailable: %s)" % e)

    print("---- incidents (first 80) ----")
    for r in rows[:80]:
        sev = r[si] if si is not None else "?"
        tech = r[ti] if ti is not None else "?"
        title = (r[tli] if tli is not None else "") or ""
        print("  * [%s] %s :: %s" % (sev, tech, title[:90]))


if __name__ == "__main__":
    main()
