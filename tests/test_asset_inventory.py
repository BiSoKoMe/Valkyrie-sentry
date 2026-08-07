#!/usr/bin/env python3
"""Asset inventory (valkyrie/asset_inventory.py, CIS Controls #1/#2 +
Clinton ch.9).

  [1]   Real, read-only enumeration against THIS host — proves the module
        actually works, not just that it doesn't crash on empty input.
  [2-3] Pure diff/collector logic against constructed (not live) snapshots,
        for determinism.
  [4]   Removals are never emitted (the safe direction of change).
  [5]   is_trusted_os_path labeling, reused from trust.py, not reimplemented.
  [6]   Reuses PersistenceCollector for boot_items WITHOUT re-diffing/
        re-emitting that signal — persistence_telemetry already owns it.
  [7]   The 'asset_change' pre-gate hook in ingest_telemetry(): reaches
        correlation, never alone raises a standalone incident.
  [8]   GET /api/asset-inventory.

SAFETY: every enumeration function here is read-only (registry reads, live
socket table reads via psutil). Nothing in this file or in
asset_inventory.py writes, deletes, starts, or stops anything.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from harness import Checks   # noqa: E402

from valkyrie import asset_inventory as ai                    # noqa: E402
from valkyrie.telemetry import ACT_OBSERVED, CAT_ASSET, SEV_INFO   # noqa: E402

c = Checks("asset inventory (CIS Controls #1/#2)", expect_min=25)


# ---------------------------------------------------------------------------
# [1] Real read-only enumeration against this host
# ---------------------------------------------------------------------------

def test_real_enumeration_on_this_host() -> None:
    print("\n[1] real read-only enumeration against this machine")
    snap = ai.take_snapshot()
    c.check("snapshot_software() returns a dict", isinstance(snap.software, dict))
    c.check("snapshot_listening_ports() returns a dict",
            isinstance(snap.listening_ports, dict))
    c.check("snapshot_kernel_drivers() returns a dict",
            isinstance(snap.kernel_drivers, dict))
    c.check("this real Windows host has at least SOME installed software",
            len(snap.software) > 0)
    c.check("this real Windows host has at least SOME kernel drivers",
            len(snap.kernel_drivers) > 0)
    c.check("counts() matches the actual dict sizes",
            snap.counts()["software"] == len(snap.software)
            and snap.counts()["kernel_drivers"] == len(snap.kernel_drivers))
    c.check("no persistence_collector given -> boot_items is empty, not an error",
            snap.boot_items == {})
    for name, meta in list(snap.software.items())[:20]:
        c.check(f"software entry '{name[:30]}' has the expected shape",
                {"version", "publisher", "install_location"} <= set(meta.keys()))
        break   # one representative check is enough; just prove the shape


# ---------------------------------------------------------------------------
# [2] diff_snapshots logic (constructed, deterministic)
# ---------------------------------------------------------------------------

def test_diff_snapshots() -> None:
    print("\n[2] diff_snapshots(): added/removed computed correctly per category")
    old = ai.AssetSnapshot(
        software={"App A": {"version": "1.0"}},
        listening_ports={"tcp:80": {"pid": 1}},
        kernel_drivers={"driverA": {"image_path": "x"}},
    )
    new = ai.AssetSnapshot(
        software={"App A": {"version": "1.0"}, "App B": {"version": "2.0"}},
        listening_ports={},   # tcp:80 closed
        kernel_drivers={"driverA": {"image_path": "x"}, "driverB": {"image_path": "y"}},
    )
    delta = ai.diff_snapshots(old, new)
    c.check("new software detected as added", "App B" in delta.software_added)
    c.check("unchanged software not in added or removed",
            "App A" not in delta.software_added and "App A" not in delta.software_removed)
    c.check("closed port detected as removed", "tcp:80" in delta.ports_removed)
    c.check("no new ports -> ports_added empty", delta.ports_added == {})
    c.check("new driver detected as added", "driverB" in delta.drivers_added)
    c.check("is_empty() is False when there's a real delta", not delta.is_empty())

    same = ai.diff_snapshots(old, old)
    c.check("diffing identical snapshots -> is_empty() True", same.is_empty())


# ---------------------------------------------------------------------------
# [3] AssetInventoryCollector.poll_once() — baseline seeding + emit-on-add
# ---------------------------------------------------------------------------

def test_collector_seeds_baseline_and_emits_on_add() -> None:
    print("\n[3] first poll seeds silently; later polls emit only for NEW items")
    events = []
    collector = ai.AssetInventoryCollector(emit=events.append, interval=9999)

    seq = [
        ai.AssetSnapshot(software={"App A": {"version": "1.0", "publisher": "",
                                             "install_location": ""}}),
        ai.AssetSnapshot(software={"App A": {"version": "1.0", "publisher": "",
                                             "install_location": ""},
                                   "App B": {"version": "2.0", "publisher": "Acme",
                                            "install_location": r"C:\Temp\appb"}}),
    ]
    with patch.object(collector, "current_snapshot", side_effect=seq):
        n1 = collector.poll_once()
        c.check("first poll seeds the baseline and emits nothing", n1 == 0 and events == [])
        n2 = collector.poll_once()
        c.check("second poll emits exactly one event for the ONE new app",
                n2 == 1 and len(events) == 1)

    ev = events[0]
    c.check("event category is CAT_ASSET", ev.category == CAT_ASSET)
    c.check("event severity is ALWAYS INFO (weak signal, per the task)",
            ev.severity == SEV_INFO)
    c.check("event action is OBSERVED, not FLAGGED (never a standalone alert)",
            ev.action == ACT_OBSERVED)
    c.check("event activity names the change type", ev.activity == "new_installed_software")
    c.check("event carries the 'asset_change' label for the correlation pre-gate",
            "asset_change" in ev.labels)
    c.check("event names the specific app in its target/fields",
            ev.target.get("identity") == "App B")


def test_removed_items_never_emit() -> None:
    print("\n[4] removed items are the safe direction of change -- never emitted")
    events = []
    collector = ai.AssetInventoryCollector(emit=events.append, interval=9999)
    seq = [
        ai.AssetSnapshot(listening_ports={"tcp:8080": {"pid": 1, "process": "x.exe", "addr": "0.0.0.0"}}),
        ai.AssetSnapshot(listening_ports={}),   # port closed
    ]
    with patch.object(collector, "current_snapshot", side_effect=seq):
        collector.poll_once()
        n2 = collector.poll_once()
    c.check("a closed port emits ZERO events", n2 == 0 and events == [])


# ---------------------------------------------------------------------------
# [5] is_trusted_os_path labeling (reused, not reimplemented)
# ---------------------------------------------------------------------------

def test_trusted_path_labeling() -> None:
    print("\n[5] a change from a trusted OS path is labeled, not suppressed")
    events = []
    collector = ai.AssetInventoryCollector(emit=events.append, interval=9999)
    seq = [
        ai.AssetSnapshot(kernel_drivers={}),
        ai.AssetSnapshot(kernel_drivers={
            "TrustedDrv": {"image_path": r"\SystemRoot\System32\drivers\trusted.sys",
                          "start": "1"},
            "SuspectDrv": {"image_path": r"C:\Users\bob\AppData\Local\Temp\evil.sys",
                          "start": "1"},
        }),
    ]
    with patch.object(collector, "current_snapshot", side_effect=seq):
        collector.poll_once()
        collector.poll_once()

    c.check("both new drivers are still reported (never suppressed)", len(events) == 2)
    by_identity = {e.target.get("identity"): e for e in events}
    trusted_ev = by_identity.get("TrustedDrv")
    suspect_ev = by_identity.get("SuspectDrv")
    c.check("trusted System32 path IS labeled trusted_os_path",
            trusted_ev is not None and "trusted_os_path" in trusted_ev.labels)
    c.check("a user-writable Temp path is NOT labeled trusted_os_path",
            suspect_ev is not None and "trusted_os_path" not in suspect_ev.labels)
    c.check("both are STILL SEV_INFO regardless of trust -- labeling informs "
            "correlation, it does not escalate severity itself",
            trusted_ev.severity == SEV_INFO and suspect_ev.severity == SEV_INFO)


# ---------------------------------------------------------------------------
# [6] Reuses PersistenceCollector for boot_items, doesn't re-diff it
# ---------------------------------------------------------------------------

def test_reuses_persistence_collector_without_duplicating_detection() -> None:
    print("\n[6] boot_items come from PersistenceCollector.snapshot() (reuse, "
          "not reimplementation), and are never separately diffed/emitted")
    fake_pc = MagicMock()
    fake_pc.snapshot.return_value = {
        "registry_run_key": {"HKCU\\...\\Run::Evil": "C:\\evil.exe"},
    }
    snap = ai.take_snapshot(persistence_collector=fake_pc)
    c.check("boot_items comes straight from PersistenceCollector.snapshot()",
            snap.boot_items == fake_pc.snapshot.return_value)
    c.check("PersistenceCollector.snapshot() was actually called (real reuse, "
            "not a coincidental empty dict)", fake_pc.snapshot.called)

    # AssetDelta structurally has no boot_items fields at all -- diffing can't
    # possibly touch that signal even if callers changed boot_items between
    # snapshots.
    c.check("AssetDelta has no boot_items field (structurally cannot "
            "duplicate persistence_telemetry's own detection)",
            not hasattr(ai.AssetDelta(), "boot_items_added"))

    events = []
    collector = ai.AssetInventoryCollector(emit=events.append, interval=9999,
                                           persistence_collector=fake_pc)
    seq = [
        ai.AssetSnapshot(boot_items={"registry_run_key": {"a": "1"}}),
        ai.AssetSnapshot(boot_items={"registry_run_key": {"a": "1", "b": "2"}}),
    ]
    with patch.object(collector, "current_snapshot", side_effect=seq):
        collector.poll_once()
        n2 = collector.poll_once()
    c.check("a boot_items-only change between polls emits NOTHING from "
            "AssetInventoryCollector (persistence_telemetry's own live "
            "poller is what detects that, at its own severity)",
            n2 == 0 and events == [])


# ---------------------------------------------------------------------------
# [7] ingest_telemetry() pre-gate hook: reaches correlation, never a
#     standalone incident on its own
# ---------------------------------------------------------------------------

def test_ingest_telemetry_pregate_hook() -> None:
    print("\n[7] 'asset_change' reaches _correlate_sequence, never alone "
          "raises a standalone incident (Windows Update installs constantly)")
    from valkyrie.edr.engine import EdrEngine
    from valkyrie.store import Store

    tmp = Path(tempfile.mkdtemp(prefix="valkyrie_assetinv_"))
    store = Store(db_path=tmp / "t.db")
    store.start()
    engine = EdrEngine(store)
    engine.start()

    with patch.object(engine, "_correlate_sequence") as mock_seq:
        inc_id = engine.ingest_telemetry({
            "category": "asset", "activity": "new_installed_software",
            "action": "observed", "severity": "info",
            "labels": ["asset_change", "new_installed_software"],
            "reason": "new_installed_software: Some App", "actor_name": "setup.exe",
            "actor_pid": 4242, "fields": {}})
        c.check("a single INFO asset-change event raises NO standalone incident",
                inc_id is None)
        c.check("but it DID reach _correlate_sequence (the pre-gate hook works)",
                mock_seq.called)

    c.check("no incidents exist from one asset-change event alone",
            engine.list_incidents() == [])

    engine.stop()
    store.stop()


# ---------------------------------------------------------------------------
# [8] API surface
# ---------------------------------------------------------------------------

def test_api_endpoint() -> None:
    print("\n[8] GET /api/asset-inventory")
    try:
        from starlette.testclient import TestClient   # noqa: F401
    except Exception as exc:                          # noqa: BLE001
        c.skip("API endpoint checks", f"test client unavailable: {exc}")
        return
    try:
        from valkyrie.web.server import create_app, state
    except ImportError as exc:
        c.skip("API endpoint checks", f"fastapi/web stack unavailable: {exc}")
        return

    from testclient_compat import make_client   # noqa: E402

    prior = state.asset_inventory
    try:
        state.asset_inventory = None
        app = create_app()
        client = make_client(app, "127.0.0.1")
        resp = client.get("/api/asset-inventory")
        c.check("no collector wired -> 503, not a crash", resp.status_code == 503)

        fake = MagicMock()
        fake.current_snapshot.return_value = ai.AssetSnapshot(
            software={"X": {"version": "1", "publisher": "", "install_location": ""}})
        fake.is_running.return_value = True
        state.asset_inventory = fake
        app2 = create_app()
        client2 = make_client(app2, "127.0.0.1")
        resp2 = client2.get("/api/asset-inventory")
        c.check("collector wired -> 200", resp2.status_code == 200)
        body = resp2.json()
        c.check("response has counts/software/listening_ports/kernel_drivers",
                {"counts", "software", "listening_ports", "kernel_drivers"} <= set(body.keys()))
        c.check("counts reflects the fake snapshot", body["counts"]["software"] == 1)
        c.check("no POST route exists (read-only monitoring surface)",
                client2.post("/api/asset-inventory").status_code == 405)
    finally:
        state.asset_inventory = prior


def main() -> int:
    print("=" * 60)
    print("Asset inventory (CIS Controls #1/#2 + Clinton ch.9)")
    print("=" * 60)
    test_real_enumeration_on_this_host()
    test_diff_snapshots()
    test_collector_seeds_baseline_and_emits_on_add()
    test_removed_items_never_emit()
    test_trusted_path_labeling()
    test_reuses_persistence_collector_without_duplicating_detection()
    test_ingest_telemetry_pregate_hook()
    test_api_endpoint()
    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
