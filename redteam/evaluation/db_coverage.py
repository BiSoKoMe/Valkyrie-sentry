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
# ("T1059 - Command..."), or several ids joined ("T1003.001; T1055"). Extract
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

    # Also mine the DETECTION rows. A correlation/sequence detection (e.g. the
    # reconnaissance-burst IOA) records EVERY contributing technique in its
    # details JSON under "all_techniques" -- but the incident it folds into has
    # only ONE `technique` column, so reading incidents alone credits just the
    # first of a burst and scores the rest as missed even though Valkyrie
    # genuinely detected them. Read the detections and their all_techniques so a
    # burst that named T1082/T1057/T1018 is credited for all three, not one.
    # Precise, not greedy: only the detection's own `technique` and its
    # all_techniques list -- never free-text prose -- so nothing is over-counted.
    import json as _json
    try:
        for dtech, ddetails in c.execute(
                "SELECT technique, details FROM edr_detections"):
            if dtech:
                techs.update(_TID.findall(str(dtech)))
            if ddetails:
                try:
                    dd = _json.loads(ddetails)
                except (ValueError, TypeError):
                    dd = None
                if isinstance(dd, dict):
                    for a in dd.get("all_techniques") or []:
                        techs.update(_TID.findall(str(a)))
    except sqlite3.Error:
        pass    # older DB without edr_detections -- incident count still valid

    techs = sorted(techs)
    print("TOTAL INCIDENTS:", len(rows))
    # HONESTY (2026-08-24): this counts every technique that appears on ANY
    # incident in the store. It is an UPPER BOUND, not a detection count: an
    # incident here is NOT proven to be linked to an executed attack, so engine
    # self-activity, correlation spillover, or a stale row all inflate it. On
    # run 32681983369 this read 18 while union_coverage.py (which requires the
    # detection to be attributed to an executed technique within its window)
    # read 9-10. The execution-linked number is the authoritative one; THIS is
    # the ceiling. Labelled accordingly so it can never again be quoted as "N
    # detected end-to-end".
    print("TECHNIQUES WITH AN INCIDENT IN THE STORE "
          "(UPPER BOUND, not execution-linked):", len(techs))
    print("  -> authoritative execution-linked count: see union_coverage.py / "
          "the evidence librarian (evidence.py). This number is a ceiling.")
    for t in techs:
        print("  INCIDENT-TECH:", t)

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
        no_incident = [i for i in ids if not covered(i)]
        # HONESTY (2026-08-24): a catalog technique with no incident is NOT
        # necessarily "MISSED". Reading the DB at rest cannot tell whether that
        # technique was executed at all. It may be:
        #   - NOT_TESTED  (skipped destructive, or no runnable command), or
        #   - INCONCLUSIVE (its sensor was off by config, e.g. --no-dns /
        #                   --no-firewall turn off the DNS/network path), or
        #   - a genuine MISS (executed, engine up, sensor live, not caught).
        # db_coverage has no execution facts, so it MUST NOT collapse these into
        # one "MISSED" number. It lists "no incident in store" and defers the
        # classification to the evidence librarian, which has the execution
        # chain. Calling all of these "missed" is exactly the dishonest
        # denominator (run 32681983369 read "MISSED: 24" when 7 never executed
        # and 3 had their sensor off).
        print("---- CATALOG TECHNIQUES WITH NO INCIDENT IN THE STORE ----")
        print("IN-SCOPE: %d   WITH-INCIDENT (ceiling): %d   NO-INCIDENT: %d"
              % (len(ids), len(ids) - len(no_incident), len(no_incident)))
        print("  NOTE: 'no incident' is NOT 'missed'. It conflates NOT_TESTED "
              "(skipped / no command), INCONCLUSIVE (sensor off by config), and "
              "genuine MISS. Classify with evidence.py, which has execution "
              "facts; do NOT compute a detection rate from this list.")
        for tid in no_incident:
            t = in_scope[tid]
            print("  NO-INCIDENT  %-11s [predicts %-11s] %-18s %s"
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
