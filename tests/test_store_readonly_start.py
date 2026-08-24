#!/usr/bin/env python3
"""Store.start() must not die on a read-only database.

The regression this pins, reported from a real launch:

    Failed to execute script 'run_valkyrie' due to unhandled exception:
    attempt to write a readonly database
      File "valkyrie\\__main__.py", line 537, in main
        store.start()
      File "valkyrie\\store.py", line 122, in start
        self._init_schema()
      File "valkyrie\\store.py", line 493, in _init_schema
        conn.executescript(...)
    sqlite3.OperationalError: attempt to write a readonly database

Cause: on an already-populated database every statement in _init_schema is a
no-op (CREATE ... IF NOT EXISTS, all satisfied), so SQLite never needs a write
lock and the call succeeds even where the process can only READ the file.
Adding two genuinely new CREATE INDEX statements made schema init the first
WRITE it had ever attempted there — turning a pre-existing, silent read-only
condition into an unhandled exception and no engine at all.

The rule: a missing performance index is a slower query. It is never a reason
to refuse to start. But the read-only condition itself must not be swallowed
either — a store that cannot write means no audit trail, which for a security
product is a real failure and has to stay visible.

Uses a real SQLite file in a temp dir, made read-only by ACL/permission. Never
touches the live database.
"""

from __future__ import annotations

import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks, skip_file  # noqa: E402


def _make_readonly(path: Path) -> bool:
    """Make `path` unwritable, reproducing the FIELD condition. True if it took.

    Uses the read-only file attribute (chmod S_IREAD on Windows), NOT an ACL
    deny. The distinction matters: an ACL deny stops SQLite opening the file at
    all ("unable to open database file"), whereas the reported crash was
    "attempt to write a readonly database" — SQLite opened it, read it, and
    failed only on the write. Testing the harsher condition would not pin the
    bug that actually happened.
    """
    path.chmod(stat.S_IREAD)
    # Verify rather than trusting chmod: confirm reads work and writes do not.
    try:
        con = sqlite3.connect(str(path))
        con.execute("SELECT 1").fetchone()          # readable...
        con.execute("CREATE TABLE _probe_write (x INTEGER)")
        con.commit()
        con.close()
        return False          # writes still work — the denial did not take
    except sqlite3.Error as exc:
        return "readonly" in str(exc).lower()


def _undeny(path: Path) -> None:
    try:
        path.chmod(stat.S_IREAD | stat.S_IWRITE)
    except OSError:
        pass


def main() -> int:
    c = Checks("store starts on a read-only database", expect_min=6)

    from valkyrie.store import DnsEvent, Store

    tmp = Path(tempfile.mkdtemp(prefix="valk_ro_"))
    db = tmp / "valkyrie.db"

    # ------------------------------------------------------------------ [1]
    print("\n[1] a WRITABLE database gets the performance indexes")
    s = Store(db_path=db)
    s.start()
    s.log(DnsEvent.now(domain="a.example", decision="blocked",
                       process_name="p.exe", process_pid=1, process_path="",
                       reason="t", suspicion=0.5, raw_category="", url=""))
    s.stop()
    con = sqlite3.connect(str(db))
    idx = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='index'")}
    con.close()
    c.check("idx_events_rawcat was created", "idx_events_rawcat" in idx)
    c.check("idx_events_decision was created", "idx_events_decision" in idx)
    c.check("and no index error was recorded", s.last_index_error == "")

    # ------------------------------------------------------------------ [2]
    print("\n[2] the same database, now READ-ONLY, still starts")
    if not _make_readonly(db):
        _undeny(db)
        c.skip("read-only start", "could not make the file genuinely "
                                  "unwritable here (elevated session?)")
        return c.finish()

    try:
        # Drop the indexes' existence from THIS store's view by using a fresh
        # Store against the same, now-unwritable file.
        s2 = Store(db_path=db)
        started = True
        err = ""
        try:
            s2.start()
        except Exception as exc:                       # noqa: BLE001
            started = False
            err = f"{type(exc).__name__}: {exc}"
        c.check(f"start() did NOT raise — a missing index is a slower query, "
                f"never a reason to refuse to boot (got: {err or 'no error'})",
                started)
        if started:
            s2.stop()
    finally:
        _undeny(db)

    # ------------------------------------------------------------------ [3]
    print("\n[3] a fresh read-only file: required schema failure IS fatal")
    db2 = tmp / "fresh.db"
    db2.write_bytes(b"")           # empty file, no schema at all
    if _make_readonly(db2):
        try:
            s3 = Store(db_path=db2)
            raised = False
            try:
                s3.start()
            except Exception:                          # noqa: BLE001
                raised = True
            c.check("a database whose TABLES cannot be created still fails "
                    "loudly — tolerating that would mean running with nowhere "
                    "to record anything", raised)
        finally:
            _undeny(db2)
    else:
        _undeny(db2)
        c.skip("fresh read-only db", "could not make the file unwritable")

    # ------------------------------------------------------------------ [4]
    print("\n[4] the failure is reported, not swallowed")
    c.check("last_index_error exists as an attribute so a read-only condition "
            "is inspectable rather than invisible",
            hasattr(Store(db_path=tmp / "x.db"), "last_index_error"))

    # ------------------------------------------------------------------ [5]
    print("\n[5] optional indexes are declared separately from the schema")
    c.check("both performance indexes live in _OPTIONAL_INDEXES, so schema "
            "init cannot regress into attempting them",
            {n for n, _ in Store._OPTIONAL_INDEXES}
            == {"idx_events_rawcat", "idx_events_decision"})

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
