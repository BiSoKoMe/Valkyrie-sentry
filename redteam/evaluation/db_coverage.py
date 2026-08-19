"""Authoritative live coverage: read the distinct ATT&CK techniques that raised
an incident, straight from the EDR incident store (SQLite) with the engine
STOPPED. The live API is unreliable under battery load (even the brief read
times out while the engine drains its ingestion backlog), so the eval's
per-technique polling is flaky. The database at rest is ground truth.

Usage: python db_coverage.py <path-to-valkyrie.db>
"""
import sqlite3
import sys


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
    techs = sorted({
        (r[ti] or "").split(" ")[0]
        for r in rows if ti is not None and r[ti]
    })
    print("TOTAL INCIDENTS:", len(rows))
    print("DISTINCT ATT&CK TECHNIQUES DETECTED:", len(techs))
    for t in techs:
        print("  DETECTED-TECH:", t)
    print("---- incidents (first 80) ----")
    for r in rows[:80]:
        sev = r[si] if si is not None else "?"
        tech = r[ti] if ti is not None else "?"
        title = (r[tli] if tli is not None else "") or ""
        print("  * [%s] %s :: %s" % (sev, tech, title[:90]))


if __name__ == "__main__":
    main()
