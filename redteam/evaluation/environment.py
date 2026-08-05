"""Runtime evidence about the HOST the evaluation is running on.

This used to be its own probe implementation. It moved to
`valkyrie/sysmon_manager.py` (2026-08-05, ADR 0048) because Sysmon presence
is no longer only an evaluation-time concern — the shipped product now
depends on the same fact at startup (to decide whether it is running
degraded) and at runtime (to detect the sensor tampering this exact probe
was extended to catch). Re-exporting here means the red-team evaluation
scores Tier A against the SAME probe the product uses to make real
decisions, instead of a second implementation that could silently drift
from it — precisely the kind of measurement/product divergence ADR 0045 and
ADR 0046 both found the hard way.

See `valkyrie/sysmon_manager.py` for the implementation and full history:
why Sysmon is a first-class dependency, the 2026-08-04 finding that a
mainstream consumer AV can silently remove the driver with no uninstall
trail, and why that makes "Sysmon absent/degraded" a MAIN path to design
for rather than an edge case.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from valkyrie.sysmon_manager import (   # noqa: E402,F401
    FRESHNESS_SECONDS,
    SysmonEnvironment,
    check_requirements,
    probe_sysmon,
)

if __name__ == "__main__":
    e = probe_sysmon()
    print(f"Sysmon present        : {e.present}  ({e.service_state})")
    print(f"Log enabled           : {e.log_enabled}  records={e.log_record_count}")
    print(f"Newest event age (s)  : {e.newest_event_age_seconds}")
    print(f"Collection live       : {e.collection_live} (threshold {FRESHNESS_SECONDS}s)")
    print(f"Configured EIDs       : {list(e.configured_eids)}")
    print(f"Config hash           : {e.config_hash or '(unread)'}")
    if e.errors:
        print(f"Errors                : {list(e.errors)}")
    for eid in (1, 3, 7, 8, 10):
        verdict = "AVAILABLE" if e.provides(eid) else f"NOT AVAILABLE -- {e.why_not(eid)}"
        print(f"  EID {eid:<3}            : {verdict}")
