#!/usr/bin/env python3
"""Forensics triage collection — offline bundle + integrity tests.

  [1] Full bundle from a real EdrEngine incident (temp store)
  [2] Manifest hashes verify (chain-of-custody integrity round-trip)
  [3] Event slice: only events inside the ±window are captured
  [4] Artifact failure is recorded, not fatal (partial triage)
  [5] Tamper detection: modified artifact fails verify_bundle
  [6] Collection benchmark
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import time
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def main() -> int:
    from valkyrie.store import Store, DnsEvent
    from valkyrie.edr import EdrEngine
    from valkyrie.edr.schema import Detection
    from valkyrie.forensics import (
        TriageCollector, collect_event_slice, verify_bundle,
    )

    print("\n=== forensics triage collection ===\n")

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        store = Store(db_path=tdp / "f.db")
        store.start()
        engine = EdrEngine(store)
        engine.start()

        # Seed store events + one incident.
        store.log(DnsEvent.now(domain="evil.example", decision="blocked",
                               process_name="bad.exe", process_pid=1,
                               process_path="", reason="threat_intel",
                               suspicion=1.0, raw_category="threat_intel"))
        inc_id = engine.report_detection(Detection(
            source="test", severity="high", category="c2",
            title="beacon to evil.example", entity="evil.example",
            process_name="bad.exe"))
        _check("incident created", bool(inc_id))
        # Let the async store writer flush the DNS event.
        deadline = time.monotonic() + 3
        while not store.recent_events(limit=5) and time.monotonic() < deadline:
            time.sleep(0.05)

        print("[1] Bundle collection")
        coll = TriageCollector(engine, store, out_dir=tdp / "forensics")
        manifest = coll.collect(inc_id)
        bundle = Path(manifest["bundle_path"])
        _check("bundle zip exists", bundle.exists())
        _check("incident artifact always present",
               "incident.json" in manifest["artifacts"])
        _check("host context collected", "host.json" in manifest["artifacts"])
        _check("bundle hash recorded", len(manifest.get("bundle_sha256", "")) == 64)
        with zipfile.ZipFile(bundle) as z:
            inc_doc = json.loads(z.read("incident.json"))
            _check("incident doc carries detections",
                   inc_doc.get("title") == "beacon to evil.example"
                   and len(inc_doc.get("detections", [])) == 1)
            _check("MANIFEST.json inside bundle", "MANIFEST.json" in z.namelist())

        print("\n[2] Integrity verification round-trip")
        v = verify_bundle(bundle)
        _check("verify_bundle ok", v["ok"] and not v["mismatched"])

        print("\n[3] Event slice windowing")
        events = [
            {"timestamp": "2026-07-19T12:00:00+00:00", "domain": "in.example"},
            {"timestamp": "2026-07-19T11:35:00+00:00", "domain": "in2.example"},
            {"timestamp": "2026-07-19T09:00:00+00:00", "domain": "out.example"},
            {"timestamp": "garbage", "domain": "junk.example"},
        ]
        class _S:
            def recent_events(self, limit=0): return events
        sl = collect_event_slice(_S(), "2026-07-19T12:00:00+00:00", window_min=30)
        doms = {e["domain"] for e in sl}
        _check("in-window events kept", {"in.example", "in2.example"} <= doms)
        _check("out-of-window + junk excluded",
               "out.example" not in doms and "junk.example" not in doms)

        print("\n[4] Artifact failure is recorded, not fatal")
        import valkyrie.forensics as F
        real = F.collect_asep_snapshot
        F.collect_asep_snapshot = lambda: (_ for _ in ()).throw(OSError("denied"))
        try:
            m2 = coll.collect(inc_id)
            _check("bundle still produced",
                   Path(m2["bundle_path"]).exists())
            _check("failure recorded in manifest",
                   "persistence.json" in m2["collection_errors"])
        finally:
            F.collect_asep_snapshot = real

        print("\n[5] Tamper detection")
        tampered = tdp / "tampered.zip"
        with zipfile.ZipFile(bundle) as zin, \
             zipfile.ZipFile(tampered, "w") as zout:
            for name in zin.namelist():
                data = zin.read(name)
                if name == "incident.json":
                    data = data.replace(b"beacon", b"BENIGN")
                zout.writestr(name, data)
        vt = verify_bundle(tampered)
        _check("tampered artifact detected",
               not vt["ok"] and "incident.json" in vt["mismatched"])

        print("\n[6] Collection benchmark")
        t0 = time.perf_counter()
        coll.collect(inc_id)
        dt = time.perf_counter() - t0
        print(f"      full live bundle in {dt*1000:.0f} ms")
        _check("bundle under 30 s", dt < 30)

        engine.stop()
        store.stop()

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
