"""Tests for the Ransomware Shield.

Runs standalone (`python tests/test_ransomware_shield.py`) or under pytest.
No real files outside a temp dir are touched, and no real processes are
suspended (response_mode='monitor' in the trip test), so this is safe to run
anywhere.
"""
from __future__ import annotations

import sys
import time
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.ransomware_shield import (  # noqa: E402
    RansomwareShield, CanaryManager, shannon_entropy, _CANARY_BODY,
)


# --- entropy ---
def test_entropy_extremes():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 4096) == 0.0
    uniform = bytes(range(256)) * 16
    assert shannon_entropy(uniform) > 7.99          # ~8.0 bits/byte
    assert shannon_entropy(_CANARY_BODY) < 5.0      # readable text is low-entropy


# --- canary lifecycle ---
def test_canary_deploy_verify_restore():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        mgr = CanaryManager(d / "manifest.json", dirs=[d])
        n = mgr.deploy()
        assert n >= 1
        assert mgr.verify() == []                    # nothing tripped yet

        victim = Path(mgr.canaries[0].path)
        victim.write_bytes(b"ENCRYPTED-BY-RANSOMWARE" * 50)
        tripped = mgr.verify()
        assert len(tripped) == 1
        assert tripped[0].path == str(victim)

        assert mgr.restore(tripped) == 1
        assert mgr.verify() == []                     # re-armed

        # Deletion also trips.
        victim.unlink()
        assert len(mgr.verify()) == 1


def test_manifest_persistence():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        mpath = d / "manifest.json"
        CanaryManager(mpath, dirs=[d]).deploy()
        reloaded = CanaryManager(mpath, dirs=[d])
        assert reloaded.load_manifest() >= 1
        assert reloaded.verify() == []                # matches on-disk state


# --- detection path (safe simulation) ---
def test_simulate_detects_encryption():
    shield = RansomwareShield(Path(tempfile.gettempdir()) / "rw_manifest.json",
                              response_mode="monitor")
    with tempfile.TemporaryDirectory() as td:
        res = shield.simulate(Path(td))
    assert res["detected"] is True
    assert res["tripped"] >= 1
    assert res["encrypted_flagged"] is True          # random bytes => high entropy


class _FakeEdr:
    def __init__(self):
        self.detections = []

    def report_detection(self, det):
        self.detections.append(det)
        return "inc-test"


def test_trip_raises_critical_incident():
    edr = _FakeEdr()
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        shield = RansomwareShield(
            d / "manifest.json", edr=edr, response_mode="monitor",
            poll_interval=0.5, cooldown=0.0, dirs=[d],
        )
        assert shield.start() is True
        try:
            # Simulate ransomware encrypting a canary.
            victim = Path(shield.manager.canaries[0].path)
            victim.write_bytes(b"\x00\x01\x02\x03" * 500)   # tripped
            # Let the monitor loop observe it.
            deadline = time.time() + 5
            while not edr.detections and time.time() < deadline:
                time.sleep(0.2)
        finally:
            shield.stop()

    assert edr.detections, "no incident was raised on canary trip"
    det = edr.detections[0]
    assert det.severity == "critical"
    assert det.category == "ransomware"
    assert det.technique == "T1486"
    assert shield.stats["detections"] >= 1


# --- observability + safety ---
def test_status_shape():
    shield = RansomwareShield(Path(tempfile.gettempdir()) / "rw_status.json",
                              response_mode="suspend")
    st = shield.status()
    for key in ("enabled", "armed", "running", "response_mode", "canaries",
                "detections", "processes_stopped"):
        assert key in st
    assert st["response_mode"] == "suspend"


def test_invalid_response_mode_defaults_safe():
    shield = RansomwareShield(Path(tempfile.gettempdir()) / "rw_x.json",
                              response_mode="nuke-everything")
    assert shield.response_mode == "suspend"          # never an unsafe/unknown mode


# --- performance benchmark ---
def test_verify_is_cheap():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        mgr = CanaryManager(d / "m.json", dirs=[d])
        mgr.deploy()
        t0 = time.perf_counter()
        for _ in range(50):
            mgr.verify()
        elapsed = time.perf_counter() - t0
        # 50 full verifies of the canary set must be well under a second.
        assert elapsed < 1.0, f"verify too slow: {elapsed:.3f}s for 50 passes"


# --- standalone runner ---
if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  FAIL  {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
