r"""Incident-storm investigation - isolated reproduction (2026-08-26).

INVESTIGATION ONLY. Adds no detection rules, changes no thresholds, changes
no correlation logic. Reproduces, in isolation, the three techniques whose
settle windows carried almost all of GitHub Actions Run 3's 789 false
positives (T1090 netsh portproxy: 163, T1216 SyncAppvPublishingServer: 35,
T1197 BITS Jobs: 24), PLUS a zero-technique CONTROL phase that runs neither
atomic - to separate "does merely running Valkyrie and polling it over
loopback generate incidents" from "does this specific atomic cause it".

WHY THIS RUNS ON windows-latest, NOT THE LOCAL HOST
------------------------------------------------------
The storm was observed on a GitHub-hosted windows-latest runner. This dev
host is a different machine (different psutil version, different background
process mix, a different network stack) - reproducing on the same class of
environment that produced the anomaly is the point, not a convenience.

WHY THIS PRESERVES THE RAW DB
------------------------------
The original Run 3 job destroyed its runner (and the SQLite file with it)
before anyone could read the individual incident/detection ROWS - only the
harness's own aggregate JSON survived. This script never lets that happen:
it stops Valkyrie, then copies the live .db file to the workspace (which
survives as an uploaded artifact) BEFORE the temp data dir is deleted, and
dumps every incident and detection row (not just counts) to JSON.

SAFETY (same discipline as live_safe.py / live_safe_ext.py)
--------------------------------------------------------------
- T1090: netsh portproxy add v4tov4 (loopback-to-loopback only), deleted at
  the end of this phase.
- T1197: bitsadmin /transfer of a small, local, harmless file (no internet
  fetch) to a temp path, deleted after.
- T1216: SyncAppvPublishingServer.vbs invoked with a payload that only
  writes a marker file (no calc.exe, no download) - App-V is a Windows
  optional feature that may not be present; this phase is skipped (recorded
  as such) rather than faked if the binary is absent.
- Isolated engine instance, isolated temp data dir, the same restricted
  `_ENGINE_FLAGS` as live_safe.py. Nothing destructive.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from redteam.evaluation.live_safe import start_engine, stop_engine, _get, COMMAND_TIMEOUT_S

RESULTS_DIR = Path(__file__).resolve().parent / "results"
POLL_INTERVAL_S = 1.0
PHASE_WINDOW_S = 30.0   # matches run_live_evaluation.ps1's -DetectWindowSeconds


def _run(argv: tuple, timeout: float = COMMAND_TIMEOUT_S) -> tuple[int, str]:
    if not argv:
        return 0, ""
    print(f"    $ {' '.join(argv)}")
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, shell=False)
        out = (p.stdout or "") + (p.stderr or "")
        if out.strip():
            print(f"      -> {out.strip()[:300]}")
        return p.returncode, out
    except subprocess.TimeoutExpired:
        return -1, "TIMEOUT"
    except FileNotFoundError as exc:
        return -2, f"NOT FOUND: {exc}"


def _poll_window(api_base: str, label: str, window_s: float) -> list[dict]:
    """Poll /api/edr/incidents every second for window_s seconds, exactly the
    cadence run_live_evaluation.ps1 uses, and return every distinct snapshot
    size seen (so a mid-window incident-count jump is visible, not just the
    final number)."""
    samples = []
    deadline = time.time() + window_s
    while time.time() < deadline:
        try:
            incidents = _get(api_base, "/api/edr/incidents?limit=500")
            items = incidents if isinstance(incidents, list) else incidents.get("incidents", [])
            samples.append({"t": round(time.time(), 2), "count": len(items)})
        except Exception as exc:
            samples.append({"t": round(time.time(), 2), "error": str(exc)})
        time.sleep(POLL_INTERVAL_S)
    print(f"    [{label}] polled {len(samples)}x over {window_s}s, "
         f"incident count: {samples[0].get('count') if samples else '?'} -> "
         f"{samples[-1].get('count') if samples else '?'}")
    return samples


def phase_control(api_base: str) -> dict:
    """No atomic at all - just start, then poll like the harness does.
    Isolates whether self-traffic alone (Valkyrie's own API being polled
    over loopback) generates incidents with zero attacker action."""
    print("\n[CONTROL] no atomic executed - polling only")
    samples = _poll_window(api_base, "control", PHASE_WINDOW_S)
    return {"phase": "control", "argv": None, "samples": samples}


def phase_t1090(api_base: str) -> dict:
    print("\n[T1090] netsh portproxy (loopback v4tov4)")
    setup = ("netsh", "interface", "portproxy", "add", "v4tov4",
             "listenaddress=127.0.0.1", "listenport=48901",
             "connectaddress=127.0.0.1", "connectport=8090")
    rc, out = _run(setup)
    samples = _poll_window(api_base, "T1090", PHASE_WINDOW_S)
    cleanup = ("netsh", "interface", "portproxy", "delete", "v4tov4",
              "listenaddress=127.0.0.1", "listenport=48901")
    crc, cout = _run(cleanup)
    return {"phase": "T1090", "argv": list(setup), "setup_rc": rc,
           "cleanup_rc": crc, "samples": samples}


def phase_t1197(api_base: str, workdir: Path) -> dict:
    print("\n[T1197] bitsadmin transfer (local file, no internet)")
    src = workdir / "bits_source.txt"
    dst = workdir / "bits_dest.txt"
    src.write_text("harmless test payload\n" * 10, encoding="utf-8")
    argv = ("bitsadmin", "/transfer", "storm_repro_job",
            str(src), str(dst))
    rc, out = _run(argv)
    samples = _poll_window(api_base, "T1197", PHASE_WINDOW_S)
    try:
        dst.unlink(missing_ok=True)
        src.unlink(missing_ok=True)
    except Exception:
        pass
    return {"phase": "T1197", "argv": list(argv), "setup_rc": rc, "samples": samples}


def phase_t1216(api_base: str, workdir: Path) -> dict:
    print("\n[T1216] SyncAppvPublishingServer script proxy")
    sync_paths = [
        Path(r"C:\Windows\System32\SyncAppvPublishingServer.vbs"),
    ]
    found = next((p for p in sync_paths if p.exists()), None)
    if found is None:
        print("    SyncAppvPublishingServer.vbs not present on this host - "
             "App-V is an optional Windows feature. SKIPPED, not faked.")
        return {"phase": "T1216", "skipped": True,
               "reason": "SyncAppvPublishingServer.vbs not present"}
    marker = workdir / "t1216_marker.txt"
    payload = f"n; New-Item -Path '{marker}' -ItemType File -Force | Out-Null"
    argv = ("cscript.exe", "/b", str(found), payload)
    rc, out = _run(argv)
    samples = _poll_window(api_base, "T1216", PHASE_WINDOW_S)
    try:
        marker.unlink(missing_ok=True)
    except Exception:
        pass
    return {"phase": "T1216", "argv": list(argv), "setup_rc": rc, "samples": samples}


def main() -> int:
    print("=== Incident-storm isolated reproduction ===")
    proc, api_base, data_dir = start_engine()
    workdir = Path(data_dir)
    results = {"api_base": api_base, "data_dir": data_dir, "phases": []}
    try:
        sensors_before = _get(api_base, "/api/telemetry/endpoint")
        print(f"[ENGINE] endpoint telemetry: {sensors_before}")

        results["phases"].append(phase_control(api_base))
        results["phases"].append(phase_t1090(api_base))
        results["phases"].append(phase_t1197(api_base, workdir))
        results["phases"].append(phase_t1216(api_base, workdir))

        try:
            results["sensors_status_end"] = _get(api_base, "/api/sensors/status")
        except Exception as exc:
            results["sensors_status_end"] = {"error": str(exc)}
    finally:
        boot_output = stop_engine(proc)
        print("\n[ENGINE] stdout/stderr tail:")
        print(boot_output[-3000:])

        # PRESERVE THE DB BEFORE THE TEMP DIR IS EVER TOUCHED.
        db_candidates = list(Path(data_dir).rglob("*.db"))
        RESULTS_DIR.mkdir(exist_ok=True)
        ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        preserved_db = None
        if db_candidates:
            preserved_db = RESULTS_DIR / f"{ts}__storm_repro.db"
            shutil.copy2(db_candidates[0], preserved_db)
            print(f"[PRESERVE] copied {db_candidates[0]} -> {preserved_db}")
        else:
            print("[PRESERVE] WARNING: no .db file found under data_dir")

    results["preserved_db"] = str(preserved_db) if preserved_db else None
    out_path = RESULTS_DIR / f"{ts}__storm_repro.json"
    out_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    print(f"\nwrote {out_path}")

    # Immediate raw dump from the preserved DB, while we're here.
    if preserved_db:
        import sqlite3
        conn = sqlite3.connect(str(preserved_db))
        try:
            inc_cols = [r[1] for r in conn.execute("PRAGMA table_info(edr_incidents)")]
            det_cols = [r[1] for r in conn.execute("PRAGMA table_info(edr_detections)")]
            incidents = [dict(zip(inc_cols, r)) for r in conn.execute("SELECT * FROM edr_incidents")]
            detections = [dict(zip(det_cols, r)) for r in conn.execute("SELECT * FROM edr_detections")]
        finally:
            conn.close()
        dump_path = RESULTS_DIR / f"{ts}__storm_repro_rows.json"
        dump_path.write_text(json.dumps({"incidents": incidents, "detections": detections},
                                        indent=2, default=str), encoding="utf-8")
        print(f"wrote {dump_path}")
        print(f"\nRAW COUNTS: {len(incidents)} incidents, {len(detections)} detections")
        from collections import Counter
        cat_counts = Counter(d.get("category") for d in detections)
        print(f"detections by category: {dict(cat_counts)}")
        ent_counts = Counter(d.get("entity") for d in detections if d.get("category") == "network")
        print(f"network detections by entity (top 10): {ent_counts.most_common(10)}")
        empty_entity = sum(1 for d in detections
                          if d.get("category") == "network" and not d.get("entity") and not d.get("process_name"))
        print(f"network detections with EMPTY entity AND EMPTY process_name: {empty_entity}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
